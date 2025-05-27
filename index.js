const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');
require('dotenv').config();

const app = express();

// Middleware to preserve raw body
app.use(express.raw({ type: 'application/json', limit: '1mb' }));

// Normalize headers for consistent access
function normalizeHeaders(headers) {
  const normalized = {};
  for (const key in headers) {
    normalized[key.toLowerCase()] = headers[key];
  }
  return normalized;
}

// Build the message to verify
function buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer) {
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

// Check if the certificate is from a PayPal domain
function isPayPalDomain(url) {
  try {
    const { hostname } = new URL(url);
    return hostname.endsWith('paypal.com') || hostname.endsWith('paypalobjects.com');
  } catch {
    return false;
  }
}

// Optional: block known-bad certificate URLs
const blockedCerts = [
  // 'https://example.com/malicious.pem'
];

// Certificate cache
const cachedCerts = {};
const CERT_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getCachedCert(certUrl) {
  if (blockedCerts.includes(certUrl)) {
    throw new Error('Blocked certificate URL');
  }

  const now = Date.now();
  const cached = cachedCerts[certUrl];
  if (cached && now < cached.expiry) {
    console.log('✅ Certificate retrieved from cache');
    return cached.pem;
  }

  console.log('🌐 Fetching certificate from URL:', certUrl);
  const res = await axios.get(certUrl, { timeout: 5000, responseType: 'text' });

  if (res.status !== 200 || !res.data) {
    throw new Error(`Invalid response fetching certificate: HTTP ${res.status}`);
  }

  cachedCerts[certUrl] = {
    pem: res.data,
    expiry: now + CERT_TTL_MS,
  };

  console.log('✅ Certificate successfully fetched and cached.');
  return res.data;
}

// Signature verification
async function verifyPayPalSignature(headers, rawBodyBuffer, webhookId) {
  console.time('🔒 Total signature verification');
  const h = normalizeHeaders(headers);

  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];
  const headerWebhookId = h['webhook-id'];

  if (webhookId !== headerWebhookId) {
    throw new Error('Webhook ID mismatch between local config and PayPal header');
  }

  if (!certUrl || !isPayPalDomain(certUrl)) throw new Error('Invalid or missing PayPal certificate URL');
  if (!transmissionId) throw new Error('Missing paypal-transmission-id');
  if (!transmissionSig) throw new Error('Missing paypal-transmission-sig');
  if (!transmissionTime) throw new Error('Missing paypal-transmission-time');
  if (!authAlgo) throw new Error('Missing paypal-auth-algo');
  if (!webhookId) throw new Error('Missing local webhook ID');

  if (authAlgo !== 'SHA256withRSA') {
    throw new Error(`Unexpected PayPal auth algorithm: ${authAlgo}`);
  }

  const certPem = await getCachedCert(certUrl);
  console.log(`🔗 Certificate used: ${certUrl}`);

  let publicKeyPem;
  try {
    const x509 = new X509Certificate(certPem);
    publicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' });
  } catch (err) {
    throw new Error(`Failed to parse certificate: ${err.message}`);
  }

  const messageBuffer = buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer);
  const signatureBuffer = Buffer.from(transmissionSig, 'base64');

  // 🔍 Debug: show signatures and message
  console.log('📬 Signature from PayPal (base64):', transmissionSig);
  console.log('📥 Signature decoded (hex):', signatureBuffer.toString('hex'));
  console.log('📦 Message buffer (hex):', messageBuffer.toString('hex'));

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(messageBuffer);
    verifier.end();

    const isValid = verifier.verify(publicKeyPem, signatureBuffer);
    console.log(isValid ? '✅ Signature verified' : '❌ Signature invalid');

    // Optional digest for comparison (not used directly for verification)
    const digest = crypto.createHash('sha256').update(messageBuffer).digest('base64');
    console.log('🔍 SHA256 digest (optional):', digest);

    console.timeEnd('🔒 Total signature verification');
    return isValid;
  } catch (err) {
    throw new Error(`Signature verification failed: ${err.message}`);
  }
}

// Webhook endpoint
app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const rawBody = req.body;

  if (!req.headers['content-type']?.includes('application/json')) {
    return res.status(400).json({ success: false, message: 'Invalid content-type' });
  }

  if (!rawBody || !Buffer.isBuffer(rawBody)) {
    return res.status(400).json({ success: false, message: 'Missing or invalid raw body' });
  }

  let parsedBody;
  try {
    parsedBody = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ success: false, message: 'Invalid JSON' });
  }

  if (process.env.NODE_ENV !== 'production') {
    console.log('📥 Webhook body preview:', rawBody.toString('utf8').substring(0, 200));
  }

  try {
    const isValid = await verifyPayPalSignature(req.headers, rawBody, webhookId);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid PayPal signature' });
    }

    return res.json({ success: true, data: parsedBody });
  } catch (err) {
    console.error('❌ Verification error:', err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
