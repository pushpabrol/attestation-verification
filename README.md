# Attestation Verification Sample ( Server Side)

## Overview
This repository contains a Node.js application designed for handling and verifying attestation and assertion processes. It focuses on security and authentication mechanisms, using cryptographic operations to ensure data integrity and authenticity.

**This sample is just for demo purposes as each call for attestation will overwrite the contents of the publicKey.pem. In an actual solution the server will store this key per device+app combination**

This is the server side code for the iOs App code in https://github.com/pushpabrol/AppAttestTest

## Features
- Attestation and Assertion classes to manage cryptographic processes.
- Utilization of CBOR for decoding data.
- Integration with cryptographic libraries like `jsrsasign` and `crypto`.
- Apple App Attestation format handling.

## Installation
1. Clone the repository.
2. Install the required packages: `npm install`.
3. Copy .env.sample to .env and set the values

## Usage
1. Set environment variables for challenges and bundle identifiers.
2. Run the server: `node [entry file]`.
3. Use the provided endpoints for attestation and assertion.

## Endpoints
- `/generate-attestion-challenge`: Generates attestation challenges. TO DO... fix to make this dynamic
- `/verify-attestation`: Verifies attestation objects.
- `/generate-assertion-challenge`: Generates assertion challenges. TO DO... fix to make this dynamic
- `/verify-assertion`: Verifies assertions.

## Contributing
Contributions are welcome. Please submit pull requests for any enhancements.

## License
MIT
