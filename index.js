const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware to retain raw body for signature verification
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

const CERT_CACHE = {};

// Fetch and cache certificate from PayPal
async function getCertificate(certUrl) {
    if (CERT_CACHE[certUrl]) {
        console.log('✅ Certificate retrieved from cache');
        return CERT_CACHE[certUrl];
    }
    console.log(`🌐 Fetching certificate from URL: ${certUrl}`);
    const res = await axios.get(certUrl);
    const cert = res.data;
    CERT_CACHE[certUrl] = cert;
    console.log('✅ Certificate successfully fetched and cached.');
    return cert;
}

// Construct the message to verify
function getMessage(transmissionId, transmissionTime, webhookId, body) {
    const message = `${transmissionId}|${transmissionTime}|${webhookId}|${body}`;
    console.log(`📦 Message buffer (raw): ${message}`);
    return message;
}

// Create SHA256 digest of the body (if needed)
function getSha256Digest(body) {
    return crypto.createHash('sha256').update(body, 'utf8').digest('base64');
}

// Main webhook endpoint
app.post('/', async (req, res) => {
    try {
        const headers = req.headers;

        const transmissionId = headers['paypal-transmission-id'];
        const transmissionTime = headers['paypal-transmission-time'];
        const certUrl = headers['paypal-cert-url'];
        const authAlgo = headers['paypal-auth-algo'];
        const transmissionSig = headers['paypal-transmission-sig'];
        const webhookId = process.env.PAYPAL_WEBHOOK_ID;
        const rawBody = req.rawBody.toString('utf8');

        console.log('📥 Received PayPal Webhook');
        console.log('🔐 Headers:', {
            'paypal-transmission-id': transmissionId,
            'paypal-transmission-time': transmissionTime,
            'paypal-cert-url': certUrl,
            'paypal-auth-algo': authAlgo,
            'paypal-transmission-sig': transmissionSig,
        });

        const bodyDigest = getSha256Digest(rawBody);
        console.log(`🔍 SHA256 Digest: ${bodyDigest}`);

        const message = getMessage(transmissionId, transmissionTime, webhookId, rawBody);

        const certificatePem = await getCertificate(certUrl);

        const verifier = crypto.createVerify(authAlgo);
        verifier.update(message, 'utf8');
        verifier.end();

        const isValid = verifier.verify(certificatePem, transmissionSig, 'base64');

        if (!isValid) {
            console.log('❌ Signature verification failed.');
            return res.status(400).send('Invalid signature');
        }

        console.log('✅ Signature verified successfully!');
        // You can process the webhook payload here (req.body)

        return res.status(200).send('OK');

    } catch (err) {
        console.error('💥 Error during verification:', err);
        return res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
});
