import express from 'express';
import cbor from 'cbor';
import jsrsasign from 'jsrsasign';
import { createHash } from 'crypto' ;

const app = express();
app.use(express.json());

// Endpoint to receive the attestation object from the iOS app
app.post('/verify-attestation', async (req, res) => {
    const attestationObject = req.body.attestationObject;
    const keyId = req.body.keyId;
    console.log(keyId);
    if (!attestationObject || !keyId) {
        return res.status(400).send('Attestation object or key ID is missing');
    }

    try {
        // Send the attestation object to Apple's attestation server
        const isValid = await validateAttestation(keyId,attestationObject);

        // Check the response
        if (response.status === 200 && isValid) {
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


const bundleIdentifier = "R82LKF5W93.com.pushp.AppAttestTest";
const validateAttestation = async function(inputKeyId, attestation){
    const keyId = Buffer.from(inputKeyId, 'base64').toString('hex');
    console.log(keyId);
    const attestationObject = (await cbor.decodeAll(Buffer.from(attestation, 'base64')))[0]; 
    console.log(attestationObject.attStmt.receipt.toString('utf-8'));
    const authData = parseAuthData(attestationObject.authData);
    console.log("aaguid", authData.aaguid.toString('utf-8'));
    console.log("credID", authData.credID.toString('hex'));
    console.log("rpIdHash", authData.rpIdHash.toString('hex'));
    
    const appIdHash =createHash('sha256').update(Buffer.from(bundleIdentifier, 'utf-8')).digest('hex');

    console.log("appIdHash", appIdHash);

    if (authData.rpIdHash.toString('hex') !== appIdHash) {
        console.error(`Invalid app`);
        return false;
    }
    
    const credCertBuffer = attestationObject.attStmt.x5c[0];
    if (credCertBuffer === undefined) {
        console.error(`Invalid attestation credential cert: ${credCertBuffer}`);
        return false;
    }
    
    const credCert = new jsrsasign.X509();
    credCert.readCertHex(credCertBuffer.toString('hex'));
    console.log(jsrsasign.KEYUTIL.getPEM(credCert.getPublicKey()));
    const credCertPubKeyPoints = (credCert.getPublicKey()).getPublicKeyXYHex();
    const credCertPubKey = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(credCertPubKeyPoints.x, 'hex'),
        Buffer.from(credCertPubKeyPoints.y, 'hex'),
    ]).toString('hex');
    const credCertPubKeyHash =createHash('sha256').update(Buffer.from(credCertPubKey, 'hex')).digest('hex');
    console.log("credCertPubKeyHash", credCertPubKeyHash);
    if (credCertPubKeyHash !== keyId) {
        console.error(`Invalid attestation credential cert public key hash: ${credCertPubKeyHash} !== ${keyId}`);
        return false;
    }
    return true;
    
}

var parseAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flagsInt      = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt
    }

    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);

    let aaguid        = undefined;
    let credID        = undefined;
    let COSEPublicKey = undefined;

    if(flags.at) {
        aaguid           = buffer.slice(0, 16);          buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);           buffer = buffer.slice(2);
        let credIDLen    = credIDLenBuf.readUInt16BE(0);
        credID           = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
        COSEPublicKey    = buffer;
    }

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

