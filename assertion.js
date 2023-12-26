import crypto from 'crypto';
import cbor from 'cbor'; // You might need to install a CBOR package


export default class Assertion {
    constructor(data) {
        const decoded = (cbor.decodeAllSync(data))[0];
        this.signature = decoded.signature;
        this.authenticatorData = new AuthenticatorData(decoded.authenticatorData);
        // TODO: Validate authenticator data before completing initialization.
    }
}

class AuthenticatorData {
    constructor(bytes) {
        this.bytes = bytes;
    }

    get rpID() {
        return this.bytes.slice(0, 32);
    }

    get counter() {
        let counter = 0;
        const counterBytes = this.bytes.slice(33, 37);
        counterBytes.forEach(byte => {
            counter = (counter << 8) | byte;
        });
        return counter;
    }
}

class ValidationError extends Error {}

Assertion.prototype.verify = async function (clientData, publicKeyPem, appID, previousCounter, receivedChallenge, storedChallenge) {
    // 1. Compute clientDataHash as the SHA256 hash of clientData.
    const clientDataHash = crypto.createHash('sha256').update(clientData).digest();

    // 2. Concatenate authenticatorData and clientDataHash
    // and apply a SHA256 hash over the result to form nonce.
    const nonce = crypto.createHash('sha256').update(Buffer.concat([this.authenticatorData.bytes, clientDataHash])).digest();

    // 3. Use the public key to verify that the assertion’s signature is valid for nonce.
    try {
    const publicKey = crypto.createPublicKey(
        publicKeyPem);
    const isSignatureValid = crypto.verify(null, nonce, publicKey, this.signature);
    console.log(isSignatureValid)
    if (!isSignatureValid) {
        throw new ValidationError('Invalid signature');
    }
    return isSignatureValid;
    }
    catch(error){
        console.log(error);
    }

    // 4. Compute the SHA256 hash of the client’s App ID, and verify
    // that it matches the RP ID in the authenticator data.
    const appIDHash = crypto.createHash('sha256').update(appID).digest();
    if (!appIDHash.equals(this.authenticatorData.rpID)) {
        throw new ValidationError('Invalid App ID');
    }

    // 5. Verify that the authenticator data’s counter value is greater
    // than the value from the previous assertion, or greater than 0
    // on the first assertion.
    if (previousCounter !== null && this.authenticatorData.counter <= previousCounter) {
        throw new ValidationError('Invalid counter');
    }

    // 6. Verify that the challenge embedded in the client data matches
    // the earlier challenge to the client.
    if (!receivedChallenge === storedChallenge) {
        throw new ValidationError('Invalid client data');
    }
};


