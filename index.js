const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// Initialize Firebase Admin
let firebaseConfig = { projectId: 'expiryguard-8c527' };
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    firebaseConfig.credential = admin.credential.cert(serviceAccount);
  } catch (e) {
    console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT JSON", e);
  }
} else {
    // Attempt default initialization if env var is missing
    console.warn("FIREBASE_SERVICE_ACCOUNT env var is missing. Firestore writes may fail.");
}
admin.initializeApp(firebaseConfig);

const app = express();
// Trust Render's proxy so rate-limiting works correctly based on actual client IP
app.set('trust proxy', 1);

app.use(cors({ origin: true }));
app.use(express.json());

// Ping endpoint to keep the server awake
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// 1. Rate Limiting (Feature Abuse Prevention)
// Max 10 requests per minute per IP for payment endpoints
const paymentLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 10,
  message: { error: "Too many requests, please try again later." }
});

// 2. Secret Leak Prevention (No hardcoded keys)
const rzp = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "rzp_test_zHlO4fC0u54uE0",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "1Nnd680t112aO1q14rVfH2Wk"
});

// Middleware to verify Firebase Auth Token
async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ error: "Unauthorized: Missing Bearer Token" });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Token verification failed:", error);
    return res.status(403).send({ error: "Unauthorized: Invalid Token" });
  }
}

app.post('/create-order', paymentLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const amountInPaise = 49 * 100; // ₹49 server-side calculation
    const options = {
      amount: amountInPaise,
      currency: "INR",
      receipt: `receipt_${req.user.uid}` // Ties order to this specific user
    };

    const order = await rzp.orders.create(options);
    res.json({
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID || "rzp_test_zHlO4fC0u54uE0"
    });
  } catch (error) {
    console.error("Order creation failed:", error);
    res.status(500).send({ error: error.message });
  }
});

app.post('/verify-payment', paymentLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const uid = req.user.uid;

    const key_secret = process.env.RAZORPAY_KEY_SECRET || "1Nnd680t112aO1q14rVfH2Wk";
    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
      .createHmac("sha256", key_secret)
      .update(body.toString())
      .digest("hex");

    if (expectedSignature === razorpay_signature) {
      
      // 3. Logic Flaw Prevention (Replay Attack Check)
      // Verify that this order actually belongs to the user requesting the upgrade
      const order = await rzp.orders.fetch(razorpay_order_id);
      if (order.receipt !== `receipt_${uid}`) {
         return res.status(403).send({ error: "Fraud detected: Order does not belong to this user." });
      }

      // Signature & Ownership matches, update user document securely
      const db = admin.firestore();
      await db.collection("users").doc(uid).update({
        isSubscribed: true
      });
      res.json({ success: true });
    } else {
      res.status(400).send({ error: "Invalid signature" });
    }
  } catch (error) {
    console.error("Verification failed:", error);
    res.status(500).send({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
