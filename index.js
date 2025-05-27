import express from 'express';
import https from 'https';
import crypto from 'crypto';
import bodyParser from 'body-parser';

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware to get raw body
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

app.post('/paypal-webhook', async (req, res) => {
  const headers = req.headers;
  const rawBody = req.rawBody;

  console.log("---- PAYPAL WEBHOOK RECEIVED ----");
  console.log("Headers:", headers);
  console.log("Raw Body:", rawBody);
  console.log("-------------------------------");

  const transmissionId = headers['paypal-transmission-id'];
  const transmissionTime = headers['paypal-transmission-time'];
  const certUrl = headers['paypal-cert-url'];
  const authAlgo = headers['paypal-auth-algo'];
  const transmissionSig = headers['paypal-transmission-sig'];
  const webhookId = process.env.PAYPAL_WEBHOOK_ID || 'YOUR_WEBHOOK_ID_HERE';

  // Debug: Log the webhookId used
  console.log("🛠 Using webhookId:", webhookId);

  if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig || !webhookId) {
    console.error("❌ Missing headers for signature validation");
    return res.status(400).send('Missing headers');
  }

  try {
    const cert = await fetchCertificate(certUrl);
    
    console.log("📜 Certificate fetched (first 200 chars):", cert.slice(0, 200), '...');

    const hashedBody = crypto.createHash('sha256').update(rawBody, 'utf8').digest('hex');
    const expectedSigString = [
      transmissionId,
      transmissionTime,
      webhookId,
      hashedBody
    ].join('|');

    console.log("🔐 Signature base string:", expectedSigString);

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(expectedSigString, 'utf8');
    verifier.end();

    console.log("🔍 Verifying signature...");
    const signatureIsValid = verifier.verify(cert, transmissionSig, 'base64');

    if (!signatureIsValid) {
      console.warn("❌ Invalid webhook signature. Ignoring webhook.");
      return res.status(400).send('Invalid signature');
    }

    console.log("✅ Valid PayPal Webhook Signature");
    console.log("📦 Webhook Event:", req.body);

    return res.status(200).send('OK');
  } catch (err) {
    console.error("💥 Error validating webhook:", err);
    return res.status(500).send('Internal Server Error');
  }
});

function fetchCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(certUrl, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => resolve(data));
    }).on('error', err => reject(err));
  });
}

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
