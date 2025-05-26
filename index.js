const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');

const app = express();

// Middleware to capture raw body as string
app.use((req, res, next) => {
  let rawData = '';
  req.setEncoding('utf8');
  req.on('data', chunk => rawData += chunk);
  req.on('end', () => {
    req.rawBody = rawData;
    try {
      req.body = JSON.parse(rawData);
    } catch (err) {
      return res.status(400).send('Invalid JSON');
    }
    next();
  });
});

// Normalize headers
function normalizeHeaders(headers) {
  const normalized = {};
  for (const key in headers) {
    normalized[key.toLowerCase()] = headers[key];
  }
  return normalized;
}

// Build message string
function buildMessage(transmissionId, transmissionTime, webhookId, body) {
  return `${transmissionId}|${transmissionTime}|${webhookId}|${body}`;
}

// Signature verification logic
async function verifyPayPalSignature(headers, rawBody, webhookId) {
  const h = normalizeHeaders(headers);

  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];

  console.log('Headers used for verification:', {
    certUrl, transmissionId, transmissionSig, transmissionTime, authAlgo, webhookId,
  });

  if (!certUrl || !transmissionId || !transmissionSig || !transmissionTime || !authAlgo) {
    throw new Error('Missing PayPal headers.');
  }

  // Fetch certificate and extract public key as PEM
  const certRes = await axios.get(certUrl);
  const cert = certRes.data;
  const x509 = new X509Certificate(cert);
  const publicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' });

  const message = buildMessage(transmissionId, transmissionTime, webhookId, rawBody);
  console.log('Message string for verification:', message);

  // Perform verification
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(message);
  verifier.end();

  const isValid = verifier.verify(publicKeyPem, transmissionSig, 'base64');
  console.log('Signature valid?', isValid);

  return isValid;
}

// Webhook route
app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  console.log('Webhook received');
  console.log('Raw body (first 100 chars):', req.rawBody.substring(0, 100));

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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
