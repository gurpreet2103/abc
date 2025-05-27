const express = require('express');
const https = require('https');
const crypto = require('crypto');
const bodyParser = require('body-parser');

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
  const webhookId = process.env.PAYPAL_WEBHOOK_ID || 'YOUR_WEBHOOK_ID_HERE'; // You must set this

  if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig || !webhookId) {
    console.error("Missing headers for signature validation");
    return res.status(400).send('Missing headers');
  }

  try {
    // Step 1: Fetch PayPal public certificate
    const cert = await fetchCertificate(certUrl);

    // Step 2: Construct expected signed string
    const expectedSigString = [
      transmissionId,
      transmissionTime,
      webhookId,
      crypto.createHash('sha256').update(rawBody, 'utf8').digest('hex')
    ].join('|');

    // Step 3: Verify signature
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(expectedSigString, 'utf8');
    verifier.end();

    const signatureIsValid = verifier.verify(cert, transmissionSig, 'base64');

    if (!signatureIsValid) {
      console.warn("Invalid webhook signature. Ignoring webhook.");
      return res.status(400).send('Invalid signature');
    }

    console.log("✅ Valid PayPal Webhook Signature");
    // Process the webhook payload
    const event = req.body;
    console.log("Webhook Event:", event);

    return res.status(200).send('OK');
  } catch (err) {
    console.error("Error validating webhook:", err);
    return res.status(500).send('Internal Server Error');
  }
});

// Helper to fetch PayPal cert
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
  console.log(`Server running on port ${PORT}`);
});
