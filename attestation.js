import cbor from 'cbor'; // Ensure this package is installed
import fs from 'fs';
import jsrsasign from 'jsrsasign';
import { createHash } from 'crypto' ;
import ASN1 from '@lapo/asn1js';
import { kv } from "@vercel/kv";

//import writeToFile from './writeToFile.cjs';
export default class Attestation {
    constructor(challenge, bundleIdentifier,data) {
        const decoded = (cbor.decodeAllSync(data))[0];
        this.challenge = challenge;
        this.bundleIdentifier = bundleIdentifier;
        this.unParsedAuthData = decoded.authData;
        this.fmt = decoded.fmt; // Format of the attestation (e.g., "apple-appattest")
        this.attStmt = decoded.attStmt; // Attestation statement
        this.authData = new AuthenticatorData(decoded.authData);
    }
}

class AuthenticatorData {
    constructor(bytes) {
        this.bytes = bytes;
        const parsedData = this.parseAuthData(bytes);

        // Store the data in private fields
        this._rpIdHash = parsedData.rpIdHash;
        this._flagsBuf = parsedData.flagsBuf;
        this._flags = parsedData.flags;
        this._counter = parsedData.counter;
        this._counterBuf = parsedData.counterBuf;
        this._aaguid = parsedData.aaguid;
        this._COSEPublicKey = parsedData.COSEPublicKey;
        this._credID = parsedData.credID;
        // Additional fields specific to attestation
    }

    parseAuthData(buffer) {
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

    // Getter methods as in your Attestation class
    // Getter methods
    get rpIdHash() {
        return this._rpIdHash;
    }

    get credID() {
        return this._credID;
    }

    get flagsBuf() {
        return this._flagsBuf;
    }

    get flags() {
        return this._flags;
    }

    get userPresent() {
        return !!(this._flags & 0x01); // UP flag
    }

    get userVerified() {
        return !!(this._flags & 0x04); // UV flag
    }

    get hasAttestedCredential() {
        return !!(this._flags & 0x40); // AT flag
    }

    get extensionDataIncluded() {
        return !!(this._flags & 0x80); // ED flag
    }

    get aaguid() {
        return this._aaguid;
    }

    get cosePublicKey() {
        return this._COSEPublicKey;
    }

    get counter() {
        return this._counter;
    }

    get counterBuf() {
        return this._counterBuf;
    }
}

class ValidationError extends Error {}

Attestation.prototype.verify = async function (base64KeyId) {
    const keyId = Buffer.from(base64KeyId, 'base64').toString('hex');
    // The verification process for attestation will be different from assertion.
    // It typically involves:
    // 1. Verifying the clientDataJSON integrity.
    // 2. Verifying that the attestationChallenge matches the challenge in the clientDataJSON.
    // 3. Validating the attestation statement (this.attStmt) according to the format (this.fmt).
    // 4. Optionally, verifying the attestation certificate against a CA certificate (caCertPem).
    // ...
    const  NONCE_OID = "1.2.840.113635.100.8.2"
    //console.log(attestationObject.attStmt.receipt.toString('utf-8'));
    console.log("aaguid", this.authData.aaguid.toString('utf-8'));
    console.log("credID", this.authData.credID.toString('hex'));
    console.log("rpIdHash", this.authData.rpIdHash.toString('hex'));
    
    const appIdHash =createHash('sha256').update(Buffer.from(this.bundleIdentifier, 'utf-8')).digest('hex');
    console.log("appIdHash", appIdHash);

    if (this.authData.rpIdHash.toString('hex') !== appIdHash) {
        console.error(`Invalid app`);
        return false;
    }
    const clientDataHash = createHash('sha256').update(Buffer.from(this.challenge,'utf-8')).digest();
    const compositeItem = Buffer.concat([this.unParsedAuthData, clientDataHash]);

    // 3. Hash the composite item to create nonce
    const expectedNonceBuffer = createHash('sha256').update(compositeItem).digest();
    console.log("expectedNonce",expectedNonceBuffer.toString('hex') );
    const credCertBuffer = this.attStmt.x5c[0];
    if (credCertBuffer === undefined) {
        console.error(`Invalid attestation credential cert: ${credCertBuffer}`);
        return false;
    }
    let certASN1                = ASN1.decode(credCertBuffer);

    let AppleNonceExtension     = findOID(certASN1, NONCE_OID);

    if(!AppleNonceExtension)
        throw new Error(`The certificate is missing Apple Nonce Extension ${NONCE_OID}!`)

    
    let appleNonceExtensionJSON = asn1ObjectToJSON(AppleNonceExtension).data;

    let certificateNonceBuffer  = appleNonceExtensionJSON[1].data[0].data[0].data[0].data;
    console.log("certificateNonceBuffer",certificateNonceBuffer.toString('hex'));
    if(Buffer.compare(certificateNonceBuffer, expectedNonceBuffer) !== 0)
        throw new Error('Attestation certificate does not contain expected nonce!');
    
    const credCert = new jsrsasign.X509();
    credCert.readCertHex(credCertBuffer.toString('hex'));
    console.log(jsrsasign.KEYUTIL.getPEM(credCert.getPublicKey()));
    // this is a hack, for now... save the public key from Apple into a file and re use for assertion verification
    //const filePath = path.join("/tmp", "publicKey.pem");
    //fs.writeFileSync("/tmp/publicKey.pem",jsrsasign.KEYUTIL.getPEM(credCert.getPublicKey()));
    await kv.set(base64KeyId, jsrsasign.KEYUTIL.getPEM(credCert.getPublicKey()));
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
    
};


function findOID(asn1object, oid){
    if(!asn1object.sub)
        return

    for(let sub of asn1object.sub) {
        if(sub.typeName() !== 'OBJECT_IDENTIFIER' || sub.content() !== oid) {
            let result = findOID(sub, oid);

            if(result)
                return result

        } else {
            return asn1object
        }
    }
}

function asn1ObjectToJSON(asn1object) {
    let JASN1 = {
        'type': asn1object.typeName()
    }

    if(!asn1object.sub) {
        if(asn1object.typeName() === 'BIT_STRING' || asn1object.typeName() === 'OCTET_STRING')
            JASN1.data = asn1object.stream.enc.slice(asn1object.posContent(), asn1object.posEnd());
        else
            JASN1.data = asn1object.content();

        return JASN1
    }

    JASN1.data = [];
    for(let sub of asn1object.sub) {
        JASN1.data.push(asn1ObjectToJSON(sub));
    }

    return JASN1
}
