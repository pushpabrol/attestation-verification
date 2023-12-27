import express from 'express';
import Assertion from './assertion.js';
import Attestation from './attestation.js';
import dotenv from 'dotenv';
import fetch from "node-fetch";
import crypto from 'crypto';
globalThis.fetch = fetch
import { kv } from "@vercel/kv";
dotenv.config();
import jwt from 'jsonwebtoken';

//const attestationChallenge = process.env.DEMO_ATTESTATION_CHALLENGE;
//const assertionChallenge = process.env.DEMO_ASSERTION_CHALLENGE;
const bundleIdentifier = process.env.DEMO_APP_BUNDLE_ID;

const app = express();
app.use(express.json());


app.get('/generate-attestion-challenge', async (req, res) => {
    const correlationId = crypto.randomBytes(16).toString('hex'); // Generate a unique correlation ID
    const challenge = { correlationId, timestamp: new Date().getTime() };
    const attestationChallenge = jwt.sign(challenge, secret); 
    await kv.set(correlationId, attestationChallenge);
    res.json({ attestationChallenge, correlationId });
});

app.post('/generate-assertion-challenge', async (req, res) => {
    const keyId = req.body.keyId;
    const challenge = { keyId, timestamp: new Date().getTime() };
    const assertionChallenge = jwt.sign(challenge, secret); 
    await kv.set(`${keyId}-c`, assertionChallenge);
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
    const publicKey = await kv.get(keyId);
    const assertionChallenge = await kv.get(`${keyId}-c`);
    const decoded = jwt.verify(assertionChallenge, secret);
        if(keyId !== decoded.keyId) res.send('Assertion is not valid, invalid keyId!');
        else {
    // Verify the assertion using Apple's public key
    // The implementation depends on Apple's App Attest documentation
    console.log(clientData);
    console.log(assertion);


    const cData = JSON.parse(Buffer.from(clientData,'base64').toString('utf-8'));
    console.log(cData.challenge);
    var ass = new Assertion(Buffer.from(assertion, 'base64'));
    const isValid = await ass.verify(Buffer.from(clientData,'base64'),
         publicKey,bundleIdentifier,0,cData.challenge,assertionChallenge)

    console.log(isValid);

    if (isValid) {
        res.send({ status: 'success' });
    } else {
        res.status(400).send({ status: 'failure' });
    }
}
});


app.get('/', async (req, res) => {
    res.send('Attestation Server');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

