import express from 'express';
import https from 'https';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to capture raw body as string
app.use((req, res, next) => {
  let data = '';
  req.setEncoding('utf8');
  req.on('data', chunk => {
    data += chunk;
  });
  req.on('end', () => {
    req.rawBody = data;
    next();
  });
});

// Cache for PayPal certs
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

async function verifyPaypalWebhook(headers, bodyRaw) {
  try {
    const {
      'paypal-transmission-id': transmissionId,
      'paypal-transmission-time': transmissionTime,
      'paypal-cert-url': certUrl,
      'paypal-auth-algo': paypalAuthAlgo,
      'paypal-transmission-sig': transmissionSig,
    } = headers;

    let authAlgo = paypalAuthAlgo;
    if (authAlgo === 'SHA256withRSA') authAlgo = 'RSA-SHA256';
    else if (authAlgo === 'SHA1withRSA') authAlgo = 'RSA-SHA1';
    else throw new Error(`Unsupported auth algorithm: ${authAlgo}`);

    // Replace with your actual PayPal webhook ID here:
    const webhookId = 'WH-54M31324A08453805-0TT498265C515724R';

    const message = `${transmissionId}|${transmissionTime}|${webhookId}|${bodyRaw}`;

    const certPem = await fetchCert(certUrl);

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

app.post('/paypal-webhook', async (req, res) => {
  const headers = {
    'paypal-transmission-id': req.headers['paypal-transmission-id'],
    'paypal-transmission-time': req.headers['paypal-transmission-time'],
    'paypal-cert-url': req.headers['paypal-cert-url'],
    'paypal-auth-algo': req.headers['paypal-auth-algo'],
    'paypal-transmission-sig': req.headers['paypal-transmission-sig'],
  };

  const bodyRaw = req.rawBody;

  const valid = await verifyPaypalWebhook(headers, bodyRaw);

  if (valid) {
    console.log('Webhook signature verified!');
    // Process webhook payload here...
    res.status(200).send('Webhook received and verified');
  } else {
    console.log('Invalid webhook signature. Ignoring webhook.');
    res.status(400).send('Invalid signature');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
