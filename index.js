const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { X509Certificate } = require('crypto');
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

// Validate PayPal certificate URL domain
function isPayPalDomain(url) {
  try {
    const { hostname } = new URL(url);
    return hostname.endsWith('paypal.com') || hostname.endsWith('paypalobjects.com');
  } catch {
    return false;
  }
}

// Cache certificates to reduce repeated HTTP requests
const cachedCerts = {};
async function getCachedCert(certUrl) {
  if (cachedCerts[certUrl]) {
    console.log('✅ Certificate retrieved from cache');
    return cachedCerts[certUrl];
  }

  console.log('🌐 Fetching certificate from URL:', certUrl);
  const res = await axios.get(certUrl, { timeout: 3000 });
  cachedCerts[certUrl] = res.data;
  console.log('✅ Certificate successfully fetched.');
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
    console.log('✅ Public key extracted from certificate.');
  } catch (err) {
    throw new Error(`Failed to parse certificate: ${err.message}`);
  }

  const messageBuffer = buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer);
  console.log('📨 Message string for verification (utf8):');
  console.log(messageBuffer.toString('utf8').substring(0, 500)); // log first 500 chars or less

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(messageBuffer);
    verifier.end();

    const signatureBuffer = Buffer.from(transmissionSig, 'base64');
    console.log(`📄 Signature (base64, length=${transmissionSig.length}):`, transmissionSig);
    console.log(`📄 Signature buffer length: ${signatureBuffer.length}`);

    const isValid = verifier.verify(publicKeyPem, signatureBuffer);
    console.log('🔐 Signature valid?', isValid);

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
