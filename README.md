# rs-sage-core

Core cryptographic library for SAGE (Secure Agent Guarantee Engine) written in Rust.

## Features

- **Cryptographic Primitives**
  - Ed25519 EdDSA signatures (RFC 8032)
  - Secp256k1 ECDSA signatures
  - Secure key generation using OS random
  - Key derivation and management

- **RFC 9421 HTTP Message Signatures**
  - HTTP request and response signing
  - Signature component canonicalization
  - Derived components support
  - Multiple signature algorithms

- **Key Formats & Serialization**
  - JWK (JSON Web Key) import/export
  - PEM/DER format support
  - Raw byte key handling
  - Secure key storage utilities

- **Multi-platform Support**
  - Native Rust library (no_std compatible core)
  - C FFI bindings for Go/C integration
  - WebAssembly for browser/Node.js
  - Cross-platform build support (Linux, macOS, Windows)

- **Security Features**
  - Constant-time operations
  - Secure memory clearing
  - Input validation and sanitization
  - Comprehensive test coverage including edge cases

## Usage

### Rust

```rust
use sage_crypto_core::{KeyPair, KeyType};
use sage_crypto_core::crypto::Signer;

// Generate a new key pair
let keypair = KeyPair::generate(KeyType::Ed25519)?;

// Sign a message
let message = b"Hello, SAGE!";
let signature = keypair.sign(message)?;

// Verify signature
let is_valid = keypair.verify(message, &signature)?;

// Export keys in different formats
use sage_crypto_core::formats::{KeyExporter, KeyFormat};
let jwk = keypair.public_key().export(KeyFormat::Jwk)?;
let pem = keypair.public_key().to_pem()?;

// HTTP Message Signatures (RFC 9421)
use sage_crypto_core::rfc9421::{HttpSigner, SignatureParams};
let params = SignatureParams {
    key_id: Some("my-key".to_string()),
    alg: Some("ed25519".to_string()),
    created: Some(chrono::Utc::now().timestamp()),
    ..Default::default()
};
// Note: HttpSigner implementation depends on specific use case
```

### FFI (C API for Go integration)

```c
#include "sage_crypto.h"

int main() {
    // Initialize library
    SageResult result = sage_init();
    
    // Generate Ed25519 key pair
    SageKeyPair* keypair = NULL;
    result = sage_keypair_generate(SAGE_KEY_TYPE_ED25519, &keypair);
    
    // Sign message
    const char* message = "Hello, SAGE!";
    SageSignature* signature = NULL;
    result = sage_sign(keypair, (uint8_t*)message, strlen(message), &signature);
    
    // Verify signature
    result = sage_verify_with_keypair(keypair, (uint8_t*)message, strlen(message), signature);
    
    // Clean up
    sage_signature_free(signature);
    sage_keypair_free(keypair);
    
    return 0;
}
```

### WASM (Browser/Node.js)

```javascript
import init, { WasmKeyPair, WasmKeyType, version } from './pkg/sage_crypto_core.js';

await init();

console.log('SAGE Crypto Core version:', version());

// Generate key pair
const keypair = new WasmKeyPair(WasmKeyType.Ed25519);

// Sign message
const message = new TextEncoder().encode("Hello, SAGE!");
const signature = keypair.sign(message);

// Verify signature
const isValid = keypair.verify(message, signature);

// Export keys
const publicKeyHex = keypair.exportPublicKeyHex();
const publicKeyBytes = keypair.exportPublicKey();
const privateKeyBytes = keypair.exportPrivateKey();

// Utility functions
import { sha256, generateRandomHex, bytesToHex, hexToBytes } from './pkg/sage_crypto_core.js';
const hash = sha256(message);
const randomId = generateRandomHex(16);
const hexString = bytesToHex(message);
const bytes = hexToBytes("48656c6c6f");
```

## Building

### Native Library

```bash
cargo build --release
```

### C FFI Library

```bash
cargo build --release --features ffi
# Creates target/release/libsage_crypto_core.so (Linux)
#         target/release/libsage_crypto_core.dylib (macOS)
#         target/release/sage_crypto_core.dll (Windows)
```

### WASM

```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build WASM module
wasm-pack build --target web --out-dir pkg --features wasm
```

## Testing

```bash
# Run all tests
cargo test --features wasm

# Run tests for specific features
cargo test --features ffi  # FFI tests
cargo test --no-default-features  # Core tests only

# Run doctests
cargo test --doc

# Run benchmarks
cargo bench

# Run security tests
cargo test --test security_tests

# Run edge case tests
cargo test --test edge_cases

# Run RFC 9421 compliance tests
cargo test --test rfc9421_compliance
```

## Integration with Go

The Go SAGE project can use this library through CGO:

```go
// #cgo LDFLAGS: -L${SRCDIR}/../rs-sage-core/target/release -lsage_crypto_core
// #include "../rs-sage-core/include/sage_crypto.h"
import "C"
import (
    "log"
    "unsafe"
)

func main() {
    // Initialize SAGE library
    result := C.sage_init()
    if result != C.SAGE_SUCCESS {
        log.Fatal("Failed to initialize SAGE library")
    }
    
    // Generate key pair
    var keypair *C.SageKeyPair
    result = C.sage_keypair_generate(C.SAGE_KEY_TYPE_ED25519, &keypair)
    if result != C.SAGE_SUCCESS {
        log.Fatal("Failed to generate keypair")
    }
    defer C.sage_keypair_free(keypair)
    
    // Sign message
    message := "Hello, SAGE!"
    messageBytes := []byte(message)
    var signature *C.SageSignature
    result = C.sage_sign(keypair, 
        (*C.uint8_t)(unsafe.Pointer(&messageBytes[0])), 
        C.size_t(len(messageBytes)), 
        &signature)
    if result != C.SAGE_SUCCESS {
        log.Fatal("Failed to sign message")
    }
    defer C.sage_signature_free(signature)
    
    // Verify signature
    result = C.sage_verify_with_keypair(keypair,
        (*C.uint8_t)(unsafe.Pointer(&messageBytes[0])),
        C.size_t(len(messageBytes)),
        signature)
    if result == C.SAGE_SUCCESS {
        log.Println("Signature verified successfully")
    }
}
```

## Examples

The repository includes several examples:

- **FFI Example**: `examples/ffi/basic.c` - Complete C integration example
- **WASM Example**: `examples/wasm/index.html` - Browser-based cryptographic operations
- **Advanced WASM**: `examples/wasm/advanced.html` - HTTP signing and advanced features
- **Python Integration**: `examples/python/basic_usage.py` - Python FFI bindings

## Performance

This Rust implementation provides significant performance improvements over the Go implementation:

- Ed25519 signing: ~3x faster
- Secp256k1 signing: ~2.5x faster
- RFC 9421 canonicalization: ~4x faster

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.
