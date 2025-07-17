# rs-sage-core

Core cryptographic library for SAGE (Secure Agent Guarantee Engine) written in Rust.

## Features

- **Cryptographic Primitives**
  - Ed25519 signatures
  - Secp256k1 (ECDSA) signatures
  - Key generation and management

- **RFC 9421 Support**
  - HTTP Message Signatures
  - Request/Response signing and verification
  - Signature components handling

- **Key Formats**
  - JWK (JSON Web Key) import/export
  - PEM format support
  - Raw key handling

- **Multi-platform**
  - Native Rust library
  - C FFI bindings for Go integration
  - WASM support for browser usage

## Usage

### Rust

```rust
use sage_crypto_core::{KeyPair, KeyType, Signer};
use sage_crypto_core::rfc9421::HttpSigner;

// Generate a new key pair
let keypair = KeyPair::generate(KeyType::Ed25519)?;

// Sign a message
let message = b"Hello, SAGE!";
let signature = keypair.sign(message)?;

// Verify signature
let verified = keypair.verify(message, &signature)?;

// HTTP Message Signatures (RFC 9421)
let signer = HttpSigner::new(keypair);
let request = http::Request::builder()
    .method("POST")
    .uri("/api/v1/agent")
    .body(b"request body")?;
    
let signed_request = signer.sign_request(request)?;
```

### FFI (for Go integration)

```c
// Generate Ed25519 key pair
sage_keypair_t* keypair = sage_generate_keypair(SAGE_KEY_ED25519);

// Sign message
sage_signature_t* sig = sage_sign(keypair, message, message_len);

// Free resources
sage_free_signature(sig);
sage_free_keypair(keypair);
```

### WASM

```javascript
import init, { KeyPair, KeyType } from './sage_crypto_core_wasm.js';

await init();

// Generate key pair
const keypair = KeyPair.generate(KeyType.Ed25519);

// Sign message
const signature = keypair.sign(new TextEncoder().encode("Hello, SAGE!"));

// Export as JWK
const jwk = keypair.toJWK();
```

## Building

### Native Library

```bash
cargo build --release
```

### C FFI Library

```bash
cargo build --release
# Creates target/release/libsage_crypto_core.so (Linux)
#         target/release/libsage_crypto_core.dylib (macOS)
#         target/release/sage_crypto_core.dll (Windows)
```

### WASM

```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build WASM module
wasm-pack build --target web --out-dir pkg
```

## Testing

```bash
# Run all tests
cargo test

# Run benchmarks
cargo bench

# Run property-based tests
cargo test --features proptest
```

## Integration with Go

The Go SAGE project can use this library through CGO:

```go
// #cgo LDFLAGS: -L${SRCDIR}/../rs-sage-core/target/release -lsage_crypto_core
// #include "../rs-sage-core/include/sage_crypto.h"
import "C"
```

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
