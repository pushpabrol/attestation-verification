import express from 'express';
import Assertion from './assertion.js';
import Attestation from './attestation.js';
import dotenv from 'dotenv';
import fetch from "node-fetch";
globalThis.fetch = fetch
import { kv } from "@vercel/kv";
dotenv.config();
import jwt from 'jsonwebtoken';

//const attestationChallenge = process.env.DEMO_ATTESTATION_CHALLENGE;
const assertionChallenge = process.env.DEMO_ASSERTION_CHALLENGE;
const bundleIdentifier = process.env.DEMO_APP_BUNDLE_ID;

const app = express();
app.use(express.json());

const challengeSigningKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAJeKW5G6u7jnYDw6ILhCKLh1yOsjt+aqJjxxUZLkJleoAoGCCqGSM49
AwEHoUQDQgAEqprJ7tj0MPpffYf/kLD4f8Qs+cPT8DoC6JR+UXLkowKklRUv348B
SbYMfQkq98qDv8ldD+4GXj+Blb2dnmvdgQ==
-----END EC PRIVATE KEY-----`
const secret = 'your-very-secure-secret'; 

app.get('/challengeSigning.jwks', (req,res) => {
    res.json({
        "keys" :[
            {
                "kty": "EC",
                "kid": "IryCe7WPz2bExeK8A_jbcCvgQzMm5Ngz6KmYzk2lHTM",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": "qprJ7tj0MPpffYf_kLD4f8Qs-cPT8DoC6JR-UXLkowI",
                y: "pJUVL9-PAUm2DH0JKvfKg7_JXQ_uBl4_gZW9nZ5r3YE"
              }
        ]
    })
});

app.get('/generate-attestion-challenge', async (req, res) => {
    const correlationId = crypto.randomBytes(16).toString('hex'); // Generate a unique correlation ID
    const challenge = { correlationId, timestamp: new Date().getTime() };
    const attestationChallenge = jwt.sign(challenge, secret); // Sign with ES256 private key
    await kv.set(correlationId, attestationChallenge);
    res.json({ attestationChallenge, correlationId });
});

app.get('/generate-assertion-challenge', (req, res) => {
    res.json({ assertionChallenge });
});

// Endpoint to receive the attestation object from the iOS app
app.post('/verify-attestation', async (req, res) => {
    const attestationObject = req.body.attestationObject;
    const keyId = req.body.keyId;
    const correlationId = req.body.correlationId;
    console.log(keyId);
    if (!attestationObject || !keyId) {
        return res.status(400).send('Attestation object or key ID is missing');
    }

    try {
        const attestationChallenge = await kv.get(correlationId);
        const decoded = jwt.verify(attestationChallenge, secret);
        if(correlationId !== decoded.correlationId) res.send('Attestation is not valid, correlation error!');
        else {
        const attestation = new Attestation(attestationChallenge,bundleIdentifier, Buffer.from(attestationObject, "base64"));
        const isValid = await attestation.verify(keyId);
        // Check the response
        if (isValid) {
            res.send('Attestation is valid');
        } else {
            res.send('Attestation is not valid');
        }
    }
    } catch (error) {
        console.error('Error verifying attestation:', error);
        res.status(500).send('Internal server error');
    }
});


app.post('/verify-assertion', async (req, res) => {
    const { clientData, assertion, keyId } = req.body;

    // Verify the assertion using Apple's public key
    // The implementation depends on Apple's App Attest documentation
    console.log(clientData);
    console.log(assertion);


    const cData = JSON.parse(Buffer.from(clientData,'base64').toString('utf-8'));
    console.log(cData.challenge);
    var ass = new Assertion(Buffer.from(assertion, 'base64'));
    //const filePath = path.join("/tmp", "publicKey.pem");
    //const file = path.join(process.cwd(),  'publicKey.pem');
    //const publicKey = readFileSync("/tmp/publicKey.pem", 'utf8');
    const publicKey = await kv.get("publicKey");
    //await kv.set("publicKey", jsrsasign.KEYUTIL.getPEM(credCert.getPublicKey()));
    const isValid = await ass.verify(Buffer.from(clientData,'base64'),
         publicKey,bundleIdentifier,0,cData.challenge,assertionChallenge)

    console.log(isValid);

    if (isValid) {
        res.send({ status: 'success' });
    } else {
        res.status(400).send({ status: 'failure' });
    }
});


app.get('/', async (req, res) => {
    res.send('Attestation Server');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

