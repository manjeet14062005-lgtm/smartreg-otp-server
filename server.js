// ╔══════════════════════════════════════════════════════════════════════╗
// ║  SmartReg Pro — Express Server                                       ║
// ║  Handles: OTP (Twilio) + AI (Claude) + Payments (Razorpay)          ║
// ║                                                                      ║
// ║  New Endpoints:                                                      ║
// ║    POST /razorpay/create-order  → Create one-time payment order      ║
// ║    POST /razorpay/create-sub    → Create recurring subscription      ║
// ║    POST /razorpay/verify        → Verify payment signature           ║
// ║    POST /razorpay/cancel-sub    → Cancel subscription                ║
// ║    POST /razorpay/webhook       → Razorpay event webhook             ║
// ╚══════════════════════════════════════════════════════════════════════╝

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const crypto   = require("crypto");
const twilio   = require("twilio");
const Razorpay = require("razorpay");

const app  = express();
const PORT = process.env.PORT || 3001;

// Raw body for webhook signature verification MUST come before express.json()
app.use("/razorpay/webhook", express.raw({ type: "application/json" }));
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000", "https://localhost:3000", process.env.FRONTEND_URL || "*"],
  methods: ["GET", "POST"],
}));

// ── Twilio ────────────────────────────────────────────────────────────
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken  = process.env.TWILIO_AUTH_TOKEN;
const serviceSid = process.env.TWILIO_SERVICE_SID;

function getClient() {
  if (!accountSid || !authToken) throw new Error("Twilio credentials not configured.");
  return twilio(accountSid, authToken);
}
const rateMap = new Map();
function isRateLimited(phone) {
  const now = Date.now(), prev = rateMap.get(phone) || { count: 0, start: now };
  if (now - prev.start > 60000) { rateMap.set(phone, { count: 1, start: now }); return false; }
  if (prev.count >= 3) return true;
  rateMap.set(phone, { count: prev.count + 1, start: prev.start });
  return false;
}
function toE164(phone) {
  let p = String(phone).replace(/[\s\-\(\)]/g, "");
  if (/^\+\d{10,15}$/.test(p)) return p;
  if (/^91\d{10}$/.test(p))    return `+${p}`;
  if (/^\d{10}$/.test(p))      return `+91${p}`;
  if (/^0\d{10}$/.test(p))     return `+91${p.slice(1)}`;
  return null;
}
function maskPhone(e164) {
  if (!e164 || e164.length < 7) return "****";
  return e164.slice(0, 3) + "*".repeat(e164.length - 7) + e164.slice(-4);
}

// ── Razorpay (lazy init — server starts fine without keys) ────────────
let _razorpay = null;
function getRazorpay() {
  if (_razorpay) return _razorpay;
  const key_id     = process.env.RAZORPAY_KEY_ID;
  const key_secret = process.env.RAZORPAY_KEY_SECRET;
  if (!key_id || !key_secret) {
    throw new Error("Razorpay not configured. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to your .env or Render env vars.");
  }
  _razorpay = new Razorpay({ key_id, key_secret });
  return _razorpay;
}

// After creating plans in Razorpay Dashboard, add these to Render env vars
const PLAN_IDS = {
  pro_monthly:        process.env.RAZORPAY_PLAN_PRO_MONTHLY  || "",
  pro_annual:         process.env.RAZORPAY_PLAN_PRO_ANNUAL   || "",
  enterprise_monthly: process.env.RAZORPAY_PLAN_ENT_MONTHLY  || "",
  enterprise_annual:  process.env.RAZORPAY_PLAN_ENT_ANNUAL   || "",
};

// ════════════════════════════════════════════════════════════════════════
// POST /send-otp
// ════════════════════════════════════════════════════════════════════════
app.post("/send-otp", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ success: false, message: "Phone required." });
    const e164 = toE164(phone);
    if (!e164) return res.status(400).json({ success: false, message: "Invalid phone." });
    if (isRateLimited(e164)) return res.status(429).json({ success: false, message: "Too many OTP requests. Wait 1 min." });
    await getClient().verify.v2.services(serviceSid).verifications.create({ to: e164, channel: "sms" });
    return res.json({ success: true, message: `OTP sent to ${maskPhone(e164)}` });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /verify-otp
// ════════════════════════════════════════════════════════════════════════
app.post("/verify-otp", async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) return res.status(400).json({ success: false, message: "Phone and code required." });
    const e164 = toE164(phone);
    if (!e164) return res.status(400).json({ success: false, message: "Invalid phone." });
    const check = await getClient().verify.v2.services(serviceSid).verificationChecks.create({ to: e164, code: String(code).trim() });
    const verified = check.status === "approved";
    return res.json({ success: true, verified, message: verified ? "Phone verified! ✅" : "Incorrect OTP." });
  } catch (err) {
    if (err.status === 404 || err.code === 20404) return res.status(404).json({ success: false, message: "OTP expired. Request a new one." });
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /claude-ai
// ════════════════════════════════════════════════════════════════════════
app.post("/claude-ai", async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ success: false, message: "prompt required." });
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(500).json({ success: false, message: "Anthropic key not set." });
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-haiku-4-5-20251001", max_tokens: 1000, messages: [{ role: "user", content: prompt }] }),
    });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json({ success: false, message: data.error?.message });
    return res.json({ success: true, text: data.content?.[0]?.text || "" });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /razorpay/create-order  — one-time payment
// Body: { amount (paise), planId, userId, cycle }
// ════════════════════════════════════════════════════════════════════════
app.post("/razorpay/create-order", async (req, res) => {
  try {
    const { amount, planId, userId, cycle = "monthly" } = req.body;
    if (!amount || !planId || !userId) return res.status(400).json({ success: false, message: "amount, planId, userId required." });
    const order = await getRazorpay().orders.create({
      amount:   Math.round(amount),
      currency: "INR",
      receipt:  `rcpt_${userId.slice(0,8)}_${Date.now()}`,
      notes:    { planId, userId, cycle },
    });
    console.log(`✅ Order created: ${order.id} ₹${amount/100} plan=${planId}`);
    return res.json({ success: true, orderId: order.id, amount: order.amount, currency: order.currency, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error("❌ create-order:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /razorpay/create-sub  — recurring subscription
// Body: { planKey, userId, email, name }
// planKey: "pro_monthly" | "pro_annual" | "enterprise_monthly" | "enterprise_annual"
// ════════════════════════════════════════════════════════════════════════
app.post("/razorpay/create-sub", async (req, res) => {
  try {
    const { planKey, userId, email = "", name = "" } = req.body;
    if (!planKey || !userId) return res.status(400).json({ success: false, message: "planKey and userId required." });
    const planId = PLAN_IDS[planKey];
    if (!planId) return res.status(400).json({ success: false, message: `Plan ID for "${planKey}" not set. Add RAZORPAY_PLAN_${planKey.toUpperCase()} to Render env vars.` });
    const sub = await getRazorpay().subscriptions.create({
      plan_id: planId, total_count: planKey.includes("annual") ? 3 : 12, quantity: 1,
      notes: { userId, email, name, planKey },
    });
    console.log(`✅ Subscription created: ${sub.id} plan=${planKey}`);
    return res.json({ success: true, subscriptionId: sub.id, planKey, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error("❌ create-sub:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /razorpay/verify  — verify payment signature
// Body: { razorpay_order_id OR razorpay_subscription_id,
//         razorpay_payment_id, razorpay_signature,
//         userId, planId, cycle }
// ════════════════════════════════════════════════════════════════════════
app.post("/razorpay/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, razorpay_subscription_id, userId, planId, cycle } = req.body;
    const secret = process.env.RAZORPAY_KEY_SECRET;
    let isValid  = false;

    if (razorpay_order_id) {
      const expected = crypto.createHmac("sha256", secret).update(`${razorpay_order_id}|${razorpay_payment_id}`).digest("hex");
      isValid = expected === razorpay_signature;
    } else if (razorpay_subscription_id) {
      const expected = crypto.createHmac("sha256", secret).update(`${razorpay_payment_id}|${razorpay_subscription_id}`).digest("hex");
      isValid = expected === razorpay_signature;
    }

    if (!isValid) {
      console.warn("❌ Signature mismatch userId:", userId);
      return res.status(400).json({ success: false, message: "Payment verification failed — invalid signature." });
    }

    const payment = await getRazorpay().payments.fetch(razorpay_payment_id);
    console.log(`✅ Payment verified: ${razorpay_payment_id} ₹${payment.amount/100} method=${payment.method}`);

    return res.json({
      success: true, verified: true,
      paymentId: razorpay_payment_id,
      orderId:   razorpay_order_id || null,
      subId:     razorpay_subscription_id || null,
      amount:    payment.amount, currency: payment.currency,
      method:    payment.method, planId, cycle, userId,
    });
  } catch (err) {
    console.error("❌ verify:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /razorpay/cancel-sub
// Body: { subscriptionId, cancelAtCycleEnd }
// ════════════════════════════════════════════════════════════════════════
app.post("/razorpay/cancel-sub", async (req, res) => {
  try {
    const { subscriptionId, cancelAtCycleEnd = true } = req.body;
    if (!subscriptionId) return res.status(400).json({ success: false, message: "subscriptionId required." });
    const result = await getRazorpay().subscriptions.cancel(subscriptionId, cancelAtCycleEnd);
    console.log(`✅ Subscription cancelled: ${subscriptionId}`);
    return res.json({ success: true, status: result.status });
  } catch (err) {
    console.error("❌ cancel-sub:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════
// POST /razorpay/webhook
// Set URL in Razorpay Dashboard: https://smartreg-otp.onrender.com/razorpay/webhook
// Enable events: payment.captured, subscription.activated,
//                subscription.charged, subscription.cancelled, payment.failed
// ════════════════════════════════════════════════════════════════════════
app.post("/razorpay/webhook", (req, res) => {
  try {
    const secret    = process.env.RAZORPAY_WEBHOOK_SECRET || "";
    const signature = req.headers["x-razorpay-signature"] || "";
    const rawBody   = req.body;

    if (secret) {
      const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
      if (expected !== signature) {
        console.warn("❌ Webhook signature mismatch");
        return res.status(400).json({ success: false });
      }
    }

    const event = JSON.parse(rawBody.toString());
    console.log(`📡 Webhook: ${event.event}`);

    switch (event.event) {
      case "payment.captured": {
        const p = event.payload.payment.entity;
        const { userId, planId, cycle } = p.notes || {};
        console.log(`💰 Captured: ${p.id} ₹${p.amount/100} user=${userId} plan=${planId}`);
        // TODO (production): use Firebase Admin SDK to update Firestore:
        // admin.firestore().doc(`billing/${userId}`).update({ plan: planId, cycle, status: "active", paymentId: p.id })
        break;
      }
      case "subscription.activated":
        console.log(`🔄 Sub activated: ${event.payload.subscription.entity.id}`); break;
      case "subscription.charged":
        console.log(`💳 Sub charged: ${event.payload.subscription.entity.id}`); break;
      case "subscription.cancelled":
        console.log(`🚫 Sub cancelled: ${event.payload.subscription.entity.id}`); break;
      case "payment.failed":
        console.warn(`❌ Payment failed: ${event.payload.payment.entity.error_description}`); break;
      default:
        console.log(`ℹ️  Event: ${event.event}`);
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("❌ webhook error:", err.message);
    return res.status(500).json({ success: false });
  }
});

// ════════════════════════════════════════════════════════════════════════
// GET /health
// ════════════════════════════════════════════════════════════════════════
app.get("/health", (req, res) => {
  res.json({
    status: "ok", service: "SmartReg Pro Server",
    twilio:   !!accountSid ? "✅" : "❌ missing",
    razorpay: !!process.env.RAZORPAY_KEY_ID ? "✅" : "❌ missing",
    claude:   !!process.env.ANTHROPIC_API_KEY ? "✅" : "❌ missing",
    plans: Object.entries(PLAN_IDS).map(([k,v]) => `${k}: ${v ? "✅" : "❌"}`),
    timestamp: new Date().toISOString(),
  });
});

app.listen(PORT, () => {
  console.log(`🚀 SmartReg Server on port ${PORT}`);
  console.log(`   Twilio:   ${accountSid ? "✅" : "❌ NOT SET"}`);
  console.log(`   Razorpay: ${process.env.RAZORPAY_KEY_ID ? "✅" : "❌ NOT SET — add RAZORPAY_KEY_ID"}`);
  console.log(`   Claude:   ${process.env.ANTHROPIC_API_KEY ? "✅" : "❌ NOT SET"}`);
});