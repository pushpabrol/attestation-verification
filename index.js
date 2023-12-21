const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

// Endpoint to receive the attestation object from the iOS app
app.post('/verify-attestation', async (req, res) => {
    const attestationObject = req.body.attestationObject;
    const keyId = req.body.keyId;

    if (!attestationObject || !keyId) {
        return res.status(400).send('Attestation object or key ID is missing');
    }

    try {
        // Send the attestation object to Apple's attestation server
        const response = await axios.post('https://api.development.devicecheck.apple.com/v1/attestKey', {
            attestationObject: attestationObject,
            keyId: keyId
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        // Check the response
        if (response.status === 200 && response.data.isValid) {
            res.send('Attestation is valid');
        } else {
            res.send('Attestation is not valid');
        }
    } catch (error) {
        console.error('Error verifying attestation:', error);
        res.status(500).send('Internal server error');
    }
});

app.get('/', async (req, res) => {
    res.send('Attestation Server');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
