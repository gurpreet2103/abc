import https from 'https';
import crypto from 'crypto';

// Helper: fetch certificate from URL (cached)
const certCache = new Map();
async function fetchCert(url) {
  if (certCache.has(url)) return certCache.get(url);

  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        certCache.set(url, data);
        resolve(data);
      });
    }).on('error', reject);
  });
}

// Main verification function
async function verifyPaypalWebhook(headers, bodyRaw) {
  try {
    const {
      'paypal-transmission-id': transmissionId,
      'paypal-transmission-time': transmissionTime,
      'paypal-cert-url': certUrl,
      'paypal-auth-algo': paypalAuthAlgo,
      'paypal-transmission-sig': transmissionSig,
    } = headers;

    // Convert PayPal algo to Node.js crypto algo
    let authAlgo = paypalAuthAlgo;
    if (authAlgo === 'SHA256withRSA') authAlgo = 'RSA-SHA256';
    else if (authAlgo === 'SHA1withRSA') authAlgo = 'RSA-SHA1';
    else throw new Error(`Unsupported auth algorithm: ${authAlgo}`);

    // Create the expected message string
    // Format: transmissionId|transmissionTime|webhookId|body
    // NOTE: webhookId is usually a fixed string you get from your PayPal webhook setup
    // Replace with your actual webhook ID here:
    const webhookId = 'YOUR_PAYPAL_WEBHOOK_ID'; 

    const message = `${transmissionId}|${transmissionTime}|${webhookId}|${bodyRaw}`;

    // Fetch PayPal's public cert
    const certPem = await fetchCert(certUrl);

    // Verify signature
    const verifier = crypto.createVerify(authAlgo);
    verifier.update(message);
    verifier.end();

    const signatureBuffer = Buffer.from(transmissionSig, 'base64');
    const isValid = verifier.verify(certPem, signatureBuffer);

    return isValid;
  } catch (err) {
    console.error('Error verifying PayPal webhook:', err);
    return false;
  }
}

// Example usage in your webhook handler
// headers: incoming request headers (object)
// bodyRaw: raw string of the JSON body (exact raw text, NOT parsed JSON)
async function handleWebhook(req) {
  const headers = {
    'paypal-transmission-id': req.headers['paypal-transmission-id'],
    'paypal-transmission-time': req.headers['paypal-transmission-time'],
    'paypal-cert-url': req.headers['paypal-cert-url'],
    'paypal-auth-algo': req.headers['paypal-auth-algo'],
    'paypal-transmission-sig': req.headers['paypal-transmission-sig'],
  };

  // Assume req.rawBody is the raw string body of the request (exact, without modification)
  const bodyRaw = req.rawBody;

  const valid = await verifyPaypalWebhook(headers, bodyRaw);

  if (valid) {
    console.log('Webhook signature verified!');
    // Process webhook normally...
  } else {
    console.log('Invalid webhook signature. Ignoring webhook.');
  }
}
