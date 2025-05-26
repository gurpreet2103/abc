const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');

const app = express();

// Use express.json with verify to save rawBody for signature verification
app.use(express.json({
  limit: '5mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

// Utility to build the expected message string
function buildMessage(transmissionId, transmissionTime, webhookId, body) {
  return `${transmissionId}|${transmissionTime}|${webhookId}|${body}`;
}

// Verifies PayPal signature
async function verifyPayPalSignature(headers, rawBody, webhookId) {
  const {
    'paypal-cert-url': certUrl,
    'paypal-transmission-id': transmissionId,
    'paypal-transmission-sig': transmissionSig,
    'paypal-transmission-time': transmissionTime,
    'paypal-auth-algo': authAlgo,
  } = headers;

  if (!certUrl || !transmissionId || !transmissionSig || !transmissionTime || !authAlgo) {
    throw new Error('Missing PayPal headers.');
  }

  // Fetch certificate
  const certRes = await axios.get(certUrl);
  const cert = certRes.data;
  const x509 = new X509Certificate(cert);
  const publicKey = x509.publicKey;

  const message = buildMessage(transmissionId, transmissionTime, webhookId, rawBody);

  // Verify signature
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(message);
  verifier.end();

  const isValid = verifier.verify(publicKey, transmissionSig, 'base64');
  return isValid;
}

// Webhook endpoint
app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID; // Set this in your environment

  console.log('Webhook received');
  console.log('Raw body (first 100 chars):', req.rawBody?.slice(0, 100));

  try {
    const isValid = await verifyPayPalSignature(req.headers, req.rawBody, webhookId);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid PayPal signature' });
    }

    console.log('✅ Valid webhook received:', req.body);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Error verifying webhook:', err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
