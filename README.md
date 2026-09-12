# rs-sage-core

Core cryptographic library for SAGE (Secure Agent Guarantee Engine) written in Rust.

> **Status (2026-09-12): not wire-compatible with the Go core (`sage` v1.5).**
> This crate ports an earlier revision of the protocol. It signs secp256k1
> messages over SHA-256 instead of Keccak-256, encrypts sessions with
> AES-256-GCM and a counter nonce instead of ChaCha20-Poly1305 with a sequence
> header and replay window, has no JCS (RFC 8785) canonicalisation, and keeps
> a four-phase handshake that the Go core has removed. It is being aligned to
> the protocol specification in
> [sage-spec](https://github.com/SAGE-X-project/sage-spec); until that lands,
> do not use it to interoperate with the Go core. The alignment plan is in
> [sage/docs/refactoring/v2/REPO_PLAN.md](https://github.com/SAGE-X-project/sage/blob/main/docs/refactoring/v2/REPO_PLAN.md).

## Features

- **Cryptographic Primitives**
  - Ed25519 EdDSA signatures (RFC 8032)
  - Secp256k1 ECDSA over Keccak-256 (Ethereum convention: RFC 6979, low-S, `r || s || v`)
  - P-256 ECDSA over SHA-256 (raw `r || s`, low-S)
  - Secure key generation using OS random
  - Key derivation and management

- **RFC 9421 HTTP Message Signatures**
  - HTTP request and response signing
  - Signature component canonicalization
  - Derived components support
  - Multiple signature algorithms

- **HPKE & Secure Communication (Phase 4)** 🆕
  - HPKE (Hybrid Public Key Encryption) - RFC 9180
  - X25519 key exchange with HKDF
  - Session management with encryption
  - Traffic key derivation (C2S, S2C, Channel Binding)
  - MAC-authenticated encryption

- **DID (Decentralized Identifiers)**
  - DID parsing and validation
  - DID Document support
  - DID Resolution
  - Registry-backed resolution is provided by the Go core and gateway, not by this crate


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

- **Production Security (Phase 6)** 🆕
  - AES-256-GCM authenticated encryption (NIST SP 800-38D)
  - Constant-time cryptographic operations
  - Secure memory clearing with Zeroizing
  - Cryptographically secure RNG (OsRng)
  - Forward secrecy with ephemeral keys
  - Replay protection with nonce tracking
  - Security audited dependencies
  - Comprehensive test coverage (207 tests)

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

### Rust Examples (Phase 5.2) 🆕

Run with `cargo run --example <name>`:

- **basic_usage**: Fundamental cryptographic operations
  - Key generation (Ed25519, Secp256k1)
  - Message signing and verification
  - Key export in multiple formats

- **session_management**: Secure session lifecycle
  - Session creation from HPKE exporter secrets
  - Bidirectional encrypted communication (initiator ↔ responder)
  - MAC-authenticated encryption
  - Session pool management

### Platform Integration Examples

- **FFI Example**: `examples/ffi/basic.c` - Complete C integration example
- **WASM Example**: `examples/wasm/index.html` - Browser-based cryptographic operations
- **Advanced WASM**: `examples/wasm/advanced.html` - HTTP signing and advanced features
- **Python Integration**: `examples/python/basic_usage.py` - Python FFI bindings

## Performance

This Rust implementation provides significant performance improvements over the Go implementation:

- Ed25519 signing: ~3x faster
- Secp256k1 signing: ~2.5x faster
- RFC 9421 canonicalization: ~4x faster

### Benchmarks (Phase 5.4)

Detailed performance benchmarks:

| Operation | Performance | Notes |
|-----------|-------------|-------|
| Ed25519 Sign | ~23.7 µs | With OS RNG |
| Ed25519 Verify | ~49.7 µs | Constant-time |
| Secp256k1 Sign | ~31.4 µs | ECDSA |
| HPKE Handshake | ~119 µs | Full handshake |
| Session Create | ~6.9 µs | From exporter secret |
| AES-256-GCM Encrypt | ~1-2 µs | Hardware accelerated |

Run benchmarks: `cargo bench`

## Security

### Security Policy

Please review our [Security Policy](SECURITY.md) for:
- Reporting vulnerabilities responsibly
- Known security issues and mitigations
- Security best practices
- Supported versions

### Scope (2026-09)

The `handshake` (four-phase), `transport` (reqwest) and `blockchain`
(alloy / solana) modules were removed in the alignment to
[sage-spec](https://github.com/SAGE-X-project/sage-spec): the handshake is
superseded by the HPKE profile, transport belongs to the gateway, and
on-chain resolution is done by the Go core. Removing them also dropped the
`reqwest`/`h2`/`rustls` advisory chain. RSA support was removed in the
crypto alignment step (it is optional in sage-spec and carried the only
remaining advisory, RUSTSEC-2023-0071).

### Security Audit

**Last Audit**: 2025-10-14 (Phase 6.2 + Vulnerability Fix)

**Status**: ✅ All vulnerabilities resolved

**Key Findings**:
- ✅ Core cryptographic libraries: No vulnerabilities
- ✅ Constant-time operations: Properly implemented
- ✅ Memory safety: Zeroizing used correctly
- ✅ RNG: Cryptographically secure (OsRng)
- ✅ Dependencies: RUSTSEC-2025-0009 resolved (blockchain feature removed)

**Full Report**: See `docs/security_audit_phase6_2.md`

**Tools Used**:
```bash
# Check for dependency vulnerabilities
cargo audit

# Run security tests
cargo test --test security_tests
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.
