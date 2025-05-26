const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');
const CRC32 = require('crc-32');

const app = express();
app.use(express.raw({ type: 'application/json', limit: '1mb' }));

function normalizeHeaders(headers) {
  const normalized = {};
  for (const key in headers) {
    normalized[key.toLowerCase()] = headers[key];
  }
  return normalized;
}

function buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer) {
  const crc32Format = (process.env.CRC32_FORMAT || 'hex').toLowerCase();
  const rawCrc32 = CRC32.str(rawBodyBuffer.toString('utf8')) >>> 0;
  let crc32Hash;

  if (crc32Format === 'hex') {
    crc32Hash = rawCrc32.toString(16);
  } else if (crc32Format === 'padded') {
    crc32Hash = rawCrc32.toString().padStart(10, '0');
  } else {
    console.warn('⚠️ Invalid CRC32_FORMAT, defaulting to hex');
    crc32Hash = rawCrc32.toString(16);
  }

  const messageBuffer = Buffer.concat([
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

  return messageBuffer;
}

function isPayPalDomain(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const protocol = parsed.protocol;

    if (protocol !== 'https:') return false;
    if (hostname.includes('sandbox.paypal.com')) {
      console.warn('⚠️ Using sandbox certificate:', hostname);
    }

    return hostname.endsWith('paypal.com') || hostname.endsWith('paypalobjects.com');
  } catch {
    return false;
  }
}

const cachedCerts = {};
const CERT_TTL_MS = 60 * 60 * 1000;

async function getCachedCert(certUrl) {
  const now = Date.now();
  const cached = cachedCerts[certUrl];
  if (cached && now < cached.expiry) {
    return cached.pem;
  }

  const res = await axios.get(certUrl, { timeout: 5000, responseType: 'text' });
  if (res.status !== 200 || !res.data) {
    throw new Error(`Failed to fetch certificate: HTTP ${res.status}`);
  }

  cachedCerts[certUrl] = {
    pem: res.data,
    expiry: now + CERT_TTL_MS,
  };

  return res.data;
}

async function verifyPayPalSignature(headers, rawBodyBuffer, localWebhookId) {
  console.time('🔒 Total signature verification');
  const h = normalizeHeaders(headers);

  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];
  const headerWebhookId = h['webhook-id'];

  if (!certUrl || !isPayPalDomain(certUrl)) throw new Error('Invalid certificate URL');
  if (!transmissionId || !transmissionSig || !transmissionTime || !authAlgo || !headerWebhookId) {
    throw new Error('Missing required PayPal headers');
  }

  if (authAlgo !== 'SHA256withRSA') {
    throw new Error(`Unexpected auth algorithm: ${authAlgo}`);
  }

  if (!crypto.timingSafeEqual(Buffer.from(localWebhookId), Buffer.from(headerWebhookId))) {
    throw new Error('Webhook ID mismatch');
  }

  const certPem = await getCachedCert(certUrl);
  const x509 = new X509Certificate(certPem);
  const publicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' });

  const messageBuffer = buildMessage(transmissionId, transmissionTime, headerWebhookId, rawBodyBuffer);
  const signatureBuffer = Buffer.from(transmissionSig, 'base64');

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(messageBuffer);
  verifier.end();

  const isValid = verifier.verify(publicKeyPem, signatureBuffer);
  console.timeEnd('🔒 Total signature verification');
  return isValid;
}

app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const rawBody = req.body;

  if (!rawBody) {
    return res.status(400).json({ success: false, message: 'Missing raw body' });
  }

  if (process.env.BYPASS_SIGNATURE_VERIFICATION === 'true') {
    console.warn('⚠️ Bypassing signature verification (dev mode)');
    return res.json({ success: true, bypassed: true });
  }

  let parsedBody;
  try {
    parsedBody = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ success: false, message: 'Invalid JSON body' });
  }

  try {
    const isValid = await verifyPayPalSignature(req.headers, rawBody, webhookId);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid PayPal signature' });
    }

    return res.json({ success: true, data: parsedBody });
  } catch (err) {
    console.error('❌ Signature verification failed:', err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Optional test endpoint for n8n/dev testing
app.post('/test', express.json(), (req, res) => {
  console.log('🔬 Test request body:', req.body);
  res.json({ success: true, received: req.body });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
