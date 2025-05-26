const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');
const app = express();

// Middleware to preserve raw body
app.use(express.raw({ type: 'application/json' }));

// Normalize headers to lowercase
function normalizeHeaders(headers) {
  const normalized = {};
  for (const key in headers) {
    normalized[key.toLowerCase()] = headers[key];
  }
  return normalized;
}

// Build the message string as per PayPal’s spec
function buildMessage(transmissionId, transmissionTime, webhookId, body) {
  return `${transmissionId}|${transmissionTime}|${webhookId}|${body}`;
}

// Verify that cert URL is a valid PayPal domain
function isPayPalDomain(url) {
  try {
    const { hostname } = new URL(url);
    return hostname.endsWith('paypal.com') || hostname.endsWith('paypalobjects.com');
  } catch {
    return false;
  }
}

// Signature verification
async function verifyPayPalSignature(headers, rawBody, webhookId) {
  const h = normalizeHeaders(headers);

  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];

  // Basic header validations
  if (!certUrl || !isPayPalDomain(certUrl)) throw new Error('Invalid or missing PayPal certificate URL');
  if (!transmissionId) throw new Error('Missing PayPal header: paypal-transmission-id');
  if (!transmissionSig) throw new Error('Missing PayPal header: paypal-transmission-sig');
  if (!transmissionTime) throw new Error('Missing PayPal header: paypal-transmission-time');
  if (!authAlgo) throw new Error('Missing PayPal header: paypal-auth-algo');
  if (!webhookId) throw new Error('Missing local config: PAYPAL_WEBHOOK_ID');

  let cert;
  try {
    const certRes = await axios.get(certUrl);
    cert = certRes.data;
  } catch (err) {
    throw new Error(`Failed to fetch certificate: ${err.message}`);
  }

  let publicKeyPem;
  try {
    const x509 = new X509Certificate(cert);
    publicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' });
  } catch (err) {
    throw new Error(`Failed to parse certificate: ${err.message}`);
  }

  const message = buildMessage(transmissionId, transmissionTime, webhookId, rawBody.toString());

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(message);
    verifier.end();

    return verifier.verify(publicKeyPem, transmissionSig, 'base64');
  } catch (err) {
    throw new Error(`Signature verification error: ${err.message}`);
  }
}

// Webhook route
app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const rawBody = req.body;

  if (!rawBody) {
    return res.status(400).json({ success: false, message: 'Missing raw body' });
  }

  const rawBodyStr = rawBody.toString('utf8');
  let parsedBody;

  try {
    parsedBody = JSON.parse(rawBodyStr);
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Invalid JSON' });
  }

  if (process.env.NODE_ENV !== 'production') {
    console.log('📥 Webhook received');
    console.log('Raw body (first 100 chars):', rawBodyStr.substring(0, 100));
  }

  try {
    const isValid = await verifyPayPalSignature(req.headers, rawBodyStr, webhookId);

    if (!isValid) {
      console.warn('❌ Invalid PayPal signature');
      return res.status(400).json({ success: false, message: 'Invalid PayPal signature' });
    }

    console.log('✅ Valid webhook received');
    return res.json({ success: true, data: parsedBody });
  } catch (err) {
    console.error('❌ Error verifying webhook:', err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
