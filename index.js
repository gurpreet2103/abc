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
  console.log('🔍 Environment CRC32_FORMAT:', process.env.CRC32_FORMAT);
  const rawCrc32 = CRC32.str(rawBodyBuffer.toString('utf8')) >>> 0;
  let crc32Hash;

  if (crc32Format === 'hex') {
    crc32Hash = rawCrc32.toString(16);
  } else if (crc32Format === 'padded') {
    crc32Hash = rawCrc32.toString().padStart(10, '0');
  } else {
    console.warn('⚠️ Invalid CRC32_FORMAT, defaulting to hex:', crc32Format);
    crc32Hash = rawCrc32.toString(16); // Default to hex
  }

  console.log('🔍 transmissionId:', transmissionId);
  console.log('🔍 transmissionTime:', transmissionTime);
  console.log('🔍 webhookId:', webhookId);
  console.log('🔍 rawCrc32 (unsigned):', rawCrc32);
  console.log('🔍 crc32Hash:', crc32Hash);
  console.log('🔍 crc32Format:', crc32Format);
  console.log('🔍 rawBody (first 2000 chars, truncated):', rawBodyBuffer.toString('utf8').substring(0, 2000));
  console.log('🔍 rawBody SHA256:', crypto.createHash('sha256').update(rawBodyBuffer).digest('hex'));
  console.log('🔍 rawBody CRC32 (hex for reference):', rawCrc32.toString(16));

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

  console.log('🔍 Full message buffer (first 2000 chars, truncated):', messageBuffer.toString('utf8', 0, 2000));
  console.log('🔍 messageBuffer SHA256:', crypto.createHash('sha256').update(messageBuffer).digest('hex'));
  return messageBuffer;
}

function isPayPalDomain(url) {
  try {
    const { hostname } = new URL(url);
    const isValid = hostname.endsWith('paypal.com') || hostname.endsWith('paypalobjects.com');
    if (hostname.includes('sandbox.paypal.com')) {
      console.warn('⚠️ Certificate URL indicates sandbox environment. Ensure PAYPAL_WEBHOOK_ID is for sandbox:', url);
    } else {
      console.log('✅ Certificate URL indicates production environment:', url);
    }
    return isValid;
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
    console.log('✅ Certificate retrieved from cache');
    return cached.pem;
  }

  console.log('🌐 Fetching certificate from URL:', certUrl);
  let res;
  try {
    res = await axios.get(certUrl, { timeout: 5000, responseType: 'text' });
  } catch (err) {
    throw new Error(`Failed to fetch certificate: ${err.message}`);
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

async function verifyPayPalSignature(headers, rawBodyBuffer, webhookId) {
  console.time('🔒 Total signature verification');
  const h = normalizeHeaders(headers);
  console.log('📋 PayPal headers:', h);

  const certUrl = h['paypal-cert-url'];
  const transmissionId = h['paypal-transmission-id'];
  const transmissionSig = h['paypal-transmission-sig'];
  const transmissionTime = h['paypal-transmission-time'];
  const authAlgo = h['paypal-auth-algo'];
  const headerWebhookId = h['webhook-id'];

  console.log('🔍 Local PAYPAL_WEBHOOK_ID:', webhookId);
  console.log('🔍 Header webhook-id:', headerWebhookId);

  if (webhookId !== headerWebhookId) {
    throw new Error('Webhook ID mismatch');
  }

  if (!certUrl || !isPayPalDomain(certUrl)) throw new Error('Invalid certificate URL');
  if (!transmissionId) throw new Error('Missing paypal-transmission-id');
  if (!transmissionSig) throw new Error('Missing paypal-transmission-sig');
  if (!transmissionTime) throw new Error('Missing paypal-transmission-time');
  if (!authAlgo) throw new Error('Missing paypal-auth-algo');
  if (!webhookId) throw new Error('Missing PAYPAL_WEBHOOK_ID');
  if (authAlgo !== 'SHA256withRSA') throw new Error(`Unexpected auth algorithm: ${authAlgo}`);

  const timeDiff = Math.abs(new Date() - new Date(transmissionTime)) / 1000 / 60;
  if (timeDiff > 5) {
    console.warn('⚠️ Transmission time outside acceptable window:', transmissionTime);
  }

  const certPem = await getCachedCert(certUrl);
  let publicKeyPem;
  try {
    const x509 = new X509Certificate(certPem);
    publicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' });
    console.log('✅ Public key extracted from certificate.');
  } catch (err) {
    throw new Error(`Failed to parse certificate: ${err.message}`);
  }

  const messageBuffer = buildMessage(transmissionId, transmissionTime, webhookId, rawBodyBuffer);

  console.log('📨 Message string for verification (utf8, snippet):', messageBuffer.toString('utf8', 0, 2000));
  console.log('📨 Message length:', messageBuffer.length);
  console.log('🧩 Raw body length:', rawBodyBuffer.length);

  const signatureBuffer = Buffer.from(transmissionSig, 'base64');
  console.log(`📄 Signature (base64, length=${transmissionSig.length}):`, transmissionSig);
  console.log(`📄 Signature buffer length: ${signatureBuffer.length}`);

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(messageBuffer);
    verifier.end();

    const isValid = verifier.verify(publicKeyPem, signatureBuffer);
    console.log('🔐 Signature valid?', isValid);

    const digest = crypto.createHash('sha256').update(messageBuffer).digest('base64');
    console.log('🔍 SHA256 digest of message (base64):', digest);

    console.timeEnd('🔒 Total signature verification');
    return isValid;
  } catch (err) {
    throw new Error(`Signature verification error: ${err.message}`);
  }
}

app.post('/paypal-webhook', async (req, res) => {
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const rawBody = req.body;

  console.log('📢 Incoming Content-Type:', req.headers['content-type']);
  if (!rawBody) {
    return res.status(400).json({ success: false, message: 'Missing raw body' });
  }

  console.log('🧩 Raw body length:', rawBody.length);
  console.log('🧩 Raw body hex prefix:', rawBody.slice(0, 20).toString('hex'));
  console.log('🧩 Raw body SHA256:', crypto.createHash('sha256').update(rawBody).digest('hex'));

  let parsedBody;
  try {
    parsedBody = JSON.parse(rawBody.toString('utf8'));
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Invalid JSON' });
  }

  if (process.env.NODE_ENV !== 'production') {
    console.log('📥 Webhook received');
    console.log('Raw body (first 2000 chars, truncated):', rawBody.toString('utf8').substring(0, 2000));
  }

  try {
    console.time('✅ Webhook processing');
    const isValid = await verifyPayPalSignature(req.headers, rawBody, webhookId);

    if (!isValid) {
      const crc32Format = (process.env.CRC32_FORMAT || 'hex').toLowerCase();
      const rawCrc32 = CRC32.str(rawBody.toString('utf8')) >>> 0;
      let crc32Hash = crc32Format === 'hex' ? rawCrc32.toString(16) : 
                      crc32Format === 'padded' ? rawCrc32.toString().padStart(10, '0') : 
                      rawCrc32.toString();
      const messageBuffer = buildMessage(
        req.headers['paypal-transmission-id'],
        req.headers['paypal-transmission-time'],
        req.headers['webhook-id'],
        rawBody
      );
      console.warn('❌ Invalid PayPal signature');
      return res.status(400).json({
        success: false,
        message: 'Invalid PayPal signature',
        details: {
          transmissionId: req.headers['paypal-transmission-id'],
          transmissionTime: req.headers['paypal-transmission-time'],
          webhookId: req.headers['webhook-id'],
          crc32Hash,
          crc32Format,
          rawBodySha256: crypto.createHash('sha256').update(rawBody).digest('hex'),
          messageBufferSha256: crypto.createHash('sha256').update(messageBuffer).digest('hex'),
          messageDigest: crypto.createHash('sha256').update(messageBuffer).digest('base64'),
        },
      });
    }

    console.log('✅ Valid webhook received');
    console.timeEnd('✅ Webhook processing');
    return res.json({ success: true, data: parsedBody });
  } catch (err) {
    console.error('❌ Error verifying webhook:', err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
