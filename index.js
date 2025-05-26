const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');
const CRC32 = require('crc-32'); // Add crc-32 dependency

const app = express();

// Middleware to preserve raw body as Buffer
app.use(express.raw({ type: 'application/json', limit: '1mb' }));

// Normalize headers to lowercase for consistent access
function normalizeHeaders(headers) {
  const normalized = {};
  for (const key in headers) {
    normalized[key.toLowerCase()] = headers[key];
  }
  return normalized;
}

// Build the message buffer for signature verification
function buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer) {
  // Compute CRC32 hash of raw body
  const crc32Hash = CRC32.str(rawBodyBuffer.toString('utf8')).toString();
  
  return Buffer.concat([
    Buffer.from(transmissionId, 'utf8'),
    Buffer.from('|'),
    Buffer.from(transmissionTime, 'utf8'),
    Buffer.from('|'),
    Buffer.from(webhookId, 'utf8'),
    Buffer.from('|'),
    Buffer.from(crc32Hash, 'utf8'),
    Buffer.from('|'),
    rawBodyBuffer,
  ]);
}

// Validate PayPal certificate URL domain
function isPayPalDomain(url) {
  try {
    const { hostname } = new URL(url);
    return hostname.endsWith('paypal.com') || hostname.endsWith('paypalobjects.com');
  } catch {
    return false;
  }
}

// TTL cache for certificates with expiry
const cachedCerts = {};
const CERT_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getCachedCert(certUrl) {
  const now = Date.now();

  const cached = cachedCerts[certUrl];
  if (cached && now < cached.expiry) {
    console.log('✅ Certificate retrieved from cache');
    return cached.pem;
  }

  console.log('🌐 Fetching certificate from URL:', certUrl);
  let res;
  try {
    res = await axios.get(certUrl, { timeout: 5000, responseType: 'text' });
  } catch (err) {
    throw new Error(`Failed to fetch certificate from URL: ${err.message}`);
  }

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

// Verify PayPal webhook signature
async function verifyPayPalSignature(headers, rawBodyBuffer, webhookId) {
  console.time('🔒 Total signature verification');

  const h = normalizeHeaders(headers);
  console.log('📋 PayPal headers:', h);

  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];
  const headerWebhookId = h['webhook-id']; // PayPal webhook ID header

  console.log('🔍 Local PAYPAL_WEBHOOK_ID:', webhookId);
  console.log('🔍 Header webhook-id:', headerWebhookId);

  // Strict check: local webhook ID must match header webhook ID
  if (webhookId !== headerWebhookId) {
    throw new Error('Webhook ID mismatch between local config and PayPal header');
  }

  if (!certUrl || !isPayPalDomain(certUrl)) throw new Error('Invalid or missing PayPal certificate URL');
  if (!transmissionId) throw new Error('Missing PayPal header: paypal-transmission-id');
  if (!transmissionSig) throw new Error('Missing PayPal header: paypal-transmission-sig');
  if (!transmissionTime) throw new Error('Missing PayPal header: paypal-transmission-time');
  if (!authAlgo) throw new Error('Missing PayPal header: paypal-auth-algo');
  if (!webhookId) throw new Error('Missing local config: PAYPAL_WEBHOOK_ID');

  // Validate algorithm is exactly what PayPal expects
  if (authAlgo !== 'SHA256withRSA') {
    throw new Error(`Unexpected PayPal auth algorithm: ${authAlgo}`);
  }

  // Optional: Validate timestamp to prevent replay attacks
  const timeDiff = Math.abs(new Date() - new Date(transmissionTime)) / 1000 / 60;
  if (timeDiff > 5) {
    console.warn('⚠️ Transmission time is outside acceptable window:', transmissionTime);
  }

  // Fetch or get cached certificate PEM
  const certPem = await getCachedCert(certUrl);

  let publicKeyPem;
  try {
    const x509 = new X509Certificate(certPem);
    publicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' });
    console.log('✅ Public key extracted from certificate.');
  } catch (err) {
    throw new Error(`Failed to parse certificate: ${err.message}`);
  }

  // Build message buffer exactly as PayPal expects
  const messageBuffer = buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer);

  console.log('📨 Message string for verification (utf8, snippet):');
  console.log(messageBuffer.toString('utf8', 0, 500));
  console.log('📨 Message length:', messageBuffer.length);
  console.log('🧩 Raw body length:', rawBodyBuffer.length);

  // Base64 decode signature from header
  const signatureBuffer = Buffer.from(transmissionSig, 'base64');
  console.log(`📄 Signature (base64, length=${transmissionSig.length}):`, transmissionSig);
  console.log(`📄 Signature buffer length: ${signatureBuffer.length}`);

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(messageBuffer);
    verifier.end();

    const isValid = verifier.verify(publicKeyPem, signatureBuffer);
    console.log('🔐 Signature valid?', isValid);

    // For debugging: Log SHA256 digest of the message buffer (base64)
    const digest = crypto.createHash('sha256').update(messageBuffer).digest('base64');
    console.log('🔍 SHA256 digest of message (base64):', digest);

    console.timeEnd('🔒 Total signature verification');
    return isValid;
  } catch (err) {
    throw new Error(`Signature verification error: ${err.message}`);
  }
}

// Webhook route handler
app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const rawBody = req.body; // Buffer from express.raw()

  console.log('📢 Incoming Content-Type:', req.headers['content-type']);

  if (!rawBody) {
    return res.status(400).json({ success: false, message: 'Missing raw body' });
  }

  console.log('🧩 Raw body length:', rawBody.length);
  console.log('🧩 Raw body hex prefix:', rawBody.slice(0, 20).toString('hex'));

  let parsedBody;
  try {
    parsedBody = JSON.parse(rawBody.toString('utf8'));
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Invalid JSON' });
  }

  if (process.env.NODE_ENV !== 'production') {
    console.log('📥 Webhook received');
    console.log('Raw body (first 200 chars):', rawBody.toString('utf8').substring(0, 200));
  }

  try {
    console.time('✅ Webhook processing');
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

// Start Express server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
