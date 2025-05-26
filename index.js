const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');
const app = express();

// Middleware to preserve raw body as Buffer
app.use(express.raw({ type: 'application/json', limit: '1mb' }));

// Normalize headers to lowercase
function normalizeHeaders(headers) {
  const normalized = {};
  for (const key in headers) {
    normalized[key.toLowerCase()] = headers[key];
  }
  return normalized;
}

// Build the message string using Buffer concatenation for exact bytes
function buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer) {
  // Join with '|' as Buffer for exact binary correctness
  return Buffer.concat([
    Buffer.from(transmissionId, 'utf8'),
    Buffer.from('|'),
    Buffer.from(transmissionTime, 'utf8'),
    Buffer.from('|'),
    Buffer.from(webhookId, 'utf8'),
    Buffer.from('|'),
    rawBodyBuffer,
  ]);
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

// Cache certificate to avoid fetching every time
let cachedCerts = {};

async function getCachedCert(certUrl) {
  if (cachedCerts[certUrl]) {
    return cachedCerts[certUrl];
  }

  const res = await axios.get(certUrl, { timeout: 3000 });
  cachedCerts[certUrl] = res.data;
  return res.data;
}

// Signature verification (using Buffer message)
async function verifyPayPalSignature(headers, rawBodyBuffer, webhookId) {
  console.time('🔒 Total signature verification');

  const h = normalizeHeaders(headers);
  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];

  // Basic validations
  if (!certUrl || !isPayPalDomain(certUrl)) throw new Error('Invalid or missing PayPal certificate URL');
  if (!transmissionId) throw new Error('Missing PayPal header: paypal-transmission-id');
  if (!transmissionSig) throw new Error('Missing PayPal header: paypal-transmission-sig');
  if (!transmissionTime) throw new Error('Missing PayPal header: paypal-transmission-time');
  if (!authAlgo) throw new Error('Missing PayPal header: paypal-auth-algo');
  if (!webhookId) throw new Error('Missing local config: PAYPAL_WEBHOOK_ID');

  let cert;
  try {
    console.time('🌐 Fetch or cache cert');
    cert = await getCachedCert(certUrl);
    console.timeEnd('🌐 Fetch or cache cert');
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

  const messageBuffer = buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer);

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(messageBuffer);
    verifier.end();

    const isValid = verifier.verify(publicKeyPem, transmissionSig, 'base64');
    console.timeEnd('🔒 Total signature verification');
    return isValid;
  } catch (err) {
    throw new Error(`Signature verification error: ${err.message}`);
  }
}

// Webhook route
app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const rawBody = req.body; // Buffer from express.raw()

  if (!rawBody) {
    return res.status(400).json({ success: false, message: 'Missing raw body' });
  }

  let parsedBody;
  try {
    parsedBody = JSON.parse(rawBody.toString('utf8'));
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Invalid JSON' });
  }

  if (process.env.NODE_ENV !== 'production') {
    console.log('📥 Webhook received');
    console.log('Raw body (first 100 chars):', rawBody.toString('utf8').substring(0, 100));
  }

  try {
    console.time('✅ Webhook processing');
    // Pass raw Buffer directly here, NOT the string
    const isValid = await verifyPayPalSignature(req.headers, rawBody, webhookId);

    if (!isValid) {
      console.warn('❌ Invalid PayPal signature');
      return res.status(400).json({ success: false, message: 'Invalid PayPal signature' });
    }

    console.log('✅ Valid webhook received');
    console.timeEnd('✅ Webhook processing');
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
