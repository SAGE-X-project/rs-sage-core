# SAGE Crypto Core - WebAssembly Bindings

[![npm version](https://badge.fury.io/js/@sage-x%2Fcrypto-core.svg)](https://badge.fury.io/js/@sage-x%2Fcrypto-core)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/sage-x-project/rs-sage-core)

Core cryptographic library for SAGE with RFC 9421 support - WebAssembly bindings for JavaScript/TypeScript.

## Features

- **Ed25519 and Secp256k1** digital signatures
- **RFC 9421 HTTP Message Signatures** support
- **Multiple key formats**: Raw, PEM, DER, JWK
- **Browser and Node.js** compatibility
- **TypeScript** definitions included
- **Zero-copy operations** where possible

## Installation

```bash
npm install @sage-x/crypto-core
```

## Quick Start

```javascript
import init, { WasmKeyPair, WasmKeyType } from '@sage-x/crypto-core';

// Initialize the WASM module
await init();

// Generate a key pair
const keyPair = WasmKeyPair.generateEd25519();

// Sign a message
const message = "Hello, SAGE!";
const signature = keyPair.signString(message);

// Verify the signature
const isValid = keyPair.verifyString(message, signature);
console.log('Signature valid:', isValid);
```

## HTTP Signatures (RFC 9421)

```javascript
import { WasmHttpSigner } from '@sage-x/crypto-core';

const signer = new WasmHttpSigner(keyPair);

// Sign an HTTP request
const request = {
  method: 'POST',
  url: 'https://api.example.com/data',
  headers: {
    'Content-Type': 'application/json'
  }
};

const signedHeaders = signer.signSimpleRequest(request);
console.log('Signature:', signedHeaders.signature);
console.log('Signature-Input:', signedHeaders['signature-input']);
```

## Key Format Support

```javascript
import { WasmKeyFormat } from '@sage-x/crypto-core';

// Export to PEM
const pemKey = WasmKeyFormat.exportKeyPairToPem(keyPair);

// Import from PEM
const importedKey = WasmKeyFormat.importKeyPairFromPem(
  WasmKeyType.Ed25519,
  pemKey
);

// Export to JWK
const jwkKey = WasmKeyFormat.exportKeyPairToJwk(keyPair);
```

## Browser Usage

```html
<!DOCTYPE html>
<html>
<head>
    <script type="module">
        import init, { WasmKeyPair } from './node_modules/@sage-x/crypto-core/sage_crypto_core.js';
        
        async function main() {
            await init();
            
            const keyPair = WasmKeyPair.generateEd25519();
            const signature = keyPair.signString("Hello from browser!");
            
            console.log('Generated signature:', signature.toHex());
        }
        
        main();
    </script>
</head>
<body>
    <h1>SAGE Crypto Demo</h1>
</body>
</html>
```

## API Reference

### WasmKeyPair

- `generateEd25519()` - Generate Ed25519 key pair
- `generateSecp256k1()` - Generate Secp256k1 key pair
- `fromPrivateKeyHex(keyType, hexKey)` - Import from hex
- `signString(message)` - Sign a string message
- `verifyString(message, signature)` - Verify string signature
- `exportPrivateKeyHex()` - Export private key as hex
- `exportPublicKeyHex()` - Export public key as hex

### WasmHttpSigner

- `new WasmHttpSigner(keyPair)` - Create HTTP signer
- `signSimpleRequest(request)` - Sign HTTP request object

### WasmKeyFormat

- `exportKeyPairToPem(keyPair)` - Export to PEM format
- `importKeyPairFromPem(keyType, pemData)` - Import from PEM
- `exportKeyPairToJwk(keyPair)` - Export to JWK format
- `importKeyPairFromJwk(keyType, jwkData)` - Import from JWK

## Security Considerations

- Private keys are handled securely in WebAssembly memory
- All cryptographic operations use well-vetted Rust libraries
- Constant-time operations prevent timing attacks
- Input validation prevents malformed data issues

## Performance

The WebAssembly bindings provide excellent performance:
- Ed25519 signing: ~10,000 ops/sec
- Ed25519 verification: ~5,000 ops/sec
- Secp256k1 signing: ~8,000 ops/sec
- Secp256k1 verification: ~3,000 ops/sec

*Performance numbers are approximate and may vary by platform*

## Examples

See the [examples directory](https://github.com/sage-x-project/rs-sage-core/tree/main/examples/wasm) for complete examples:

- Basic usage
- HTTP signatures
- Key format conversion
- Performance testing

## Support

- [GitHub Issues](https://github.com/sage-x-project/rs-sage-core/issues)
- [Documentation](https://github.com/sage-x-project/rs-sage-core)
- [Security Policy](https://github.com/sage-x-project/rs-sage-core/security/policy)

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.