const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const app = express();
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf } }));

const CERT_CACHE = {};

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

function getMessage(authAlgo, certUrl, transmissionId, timeStamp, webhookId, body) {
    const message = `${transmissionId}|${timeStamp}|${webhookId}|${body}`;
    console.log(`📦 Message buffer (raw): ${message}`);
    return message;
}

function getSha256Digest(body) {
    return crypto.createHash('sha256').update(body, 'utf8').digest('base64');
}

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

        const expectedSig = transmissionSig;
        const bodyDigest = getSha256Digest(rawBody);
        console.log(`🔍 SHA256 digest: ${bodyDigest}`);

        const message = getMessage(authAlgo, certUrl, transmissionId, transmissionTime, webhookId, rawBody);

        const certificatePem = await getCertificate(certUrl);

        const verifier = crypto.createVerify(authAlgo);
        verifier.update(message, 'utf8');
        verifier.end();

        const isValid = verifier.verify(certificatePem, expectedSig, 'base64');

        if (!isValid) {
            console.log('❌ Signature invalid');
            return res.status(400).send('Invalid signature');
        }

        console.log('✅ Signature verified');
        res.status(200).send('OK');

    } catch (err) {
        console.error('💥 Error verifying PayPal signature:', err);
        res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
});
