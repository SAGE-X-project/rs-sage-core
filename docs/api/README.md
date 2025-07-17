# SAGE Crypto Core API Documentation

This directory contains comprehensive API documentation for all language bindings and interfaces.

## Available Documentation

### Core Library (Rust)
- [Rust API Documentation](./rust/index.md) - Complete Rust API reference
- [Architecture Overview](./rust/architecture.md) - Internal architecture and design

### FFI (C/C++)
- [C API Reference](./c/index.md) - Complete C API documentation
- [C++ Integration Guide](./c/cpp-integration.md) - C++ wrapper examples
- [Memory Management](./c/memory-management.md) - Safe memory usage patterns

### WebAssembly (JavaScript/TypeScript)
- [WASM API Reference](./wasm/index.md) - Complete WebAssembly API
- [Browser Integration](./wasm/browser.md) - Browser-specific usage
- [Node.js Integration](./wasm/nodejs.md) - Node.js-specific usage
- [TypeScript Definitions](./wasm/typescript.md) - Type definitions and examples

### HTTP Signatures (RFC 9421)
- [HTTP Signatures Guide](./http-signatures/index.md) - Complete RFC 9421 implementation
- [Examples](./http-signatures/examples.md) - Practical usage examples
- [Security Considerations](./http-signatures/security.md) - Security best practices

## Language-Specific Guides

### Integration Guides
- [Python Integration](./integrations/python.md) - Using FFI from Python
- [Java Integration](./integrations/java.md) - JNI wrapper examples
- [Go Integration](./integrations/go.md) - CGO integration patterns
- [C# Integration](./integrations/csharp.md) - P/Invoke usage
- [Node.js Native](./integrations/nodejs-native.md) - Native Node.js modules

### Platform-Specific Documentation
- [Linux Deployment](./platforms/linux.md) - Linux packaging and deployment
- [macOS Deployment](./platforms/macos.md) - macOS framework integration
- [Windows Deployment](./platforms/windows.md) - Windows DLL usage
- [Cross-Compilation](./platforms/cross-compile.md) - Cross-compilation guide

## Quick Reference

### Key Generation
```c
// C
SageKeyPair* keypair;
sage_keypair_generate(SAGE_KEY_TYPE_ED25519, &keypair);
```

```javascript
// JavaScript
const keyPair = WasmKeyPair.generateEd25519();
```

```rust
// Rust
let keypair = KeyPair::generate(KeyType::Ed25519)?;
```

### Digital Signatures
```c
// C
SageSignature* signature;
sage_keypair_sign_string(keypair, "Hello, World!", &signature);
```

```javascript
// JavaScript
const signature = keyPair.signString("Hello, World!");
```

```rust
// Rust
let signature = keypair.sign_string("Hello, World!")?;
```

### HTTP Signatures
```c
// C
SageHttpSigner* signer;
sage_http_signer_new(keypair, &signer);
SageHttpSignature* sig;
sage_http_signer_sign_request(signer, &request, &sig);
```

```javascript
// JavaScript
const signer = new WasmHttpSigner(keyPair);
const signedHeaders = signer.signSimpleRequest(request);
```

```rust
// Rust
let signer = HttpSigner::new(keypair);
let signature = signer.sign_request(&request)?;
```

## Error Handling

All APIs provide consistent error handling:

### C API
```c
SageResult result = sage_keypair_generate(SAGE_KEY_TYPE_ED25519, &keypair);
if (result != SAGE_SUCCESS) {
    const char* error = sage_get_last_error();
    // Handle error
}
```

### JavaScript API
```javascript
try {
    const keyPair = WasmKeyPair.generateEd25519();
} catch (error) {
    console.error('Key generation failed:', error.message);
}
```

### Rust API
```rust
match KeyPair::generate(KeyType::Ed25519) {
    Ok(keypair) => {
        // Use keypair
    }
    Err(error) => {
        // Handle error
    }
}
```

## Performance Considerations

### Benchmarks
- Ed25519 signing: ~10,000 ops/sec
- Ed25519 verification: ~5,000 ops/sec
- Secp256k1 signing: ~8,000 ops/sec
- Secp256k1 verification: ~3,000 ops/sec

### Memory Usage
- Key pair: ~64 bytes (Ed25519), ~96 bytes (Secp256k1)
- Signature: ~64 bytes (Ed25519), ~72 bytes (Secp256k1)
- HTTP signature context: ~1KB average

## Security Best Practices

1. **Key Management**
   - Always use secure random generation
   - Never log or expose private keys
   - Use appropriate key storage mechanisms

2. **Signature Verification**
   - Always verify signatures before trusting data
   - Use constant-time comparison functions
   - Implement proper replay protection

3. **HTTP Signatures**
   - Include timestamp in signed headers
   - Use appropriate signature expiration
   - Validate all required headers

## Building Documentation

To build the complete API documentation:

```bash
# Generate Rust documentation
cargo doc --all-features --no-deps

# Generate C documentation (requires Doxygen)
doxygen docs/api/c/Doxyfile

# Generate WASM documentation
npm run docs:wasm
```

## Contributing

When adding new APIs:

1. Update the appropriate language-specific documentation
2. Add examples to the examples directory
3. Update integration guides as needed
4. Run documentation tests to ensure accuracy

## Support

- [GitHub Issues](https://github.com/sage-x-project/rs-sage-core/issues)
- [Security Policy](https://github.com/sage-x-project/rs-sage-core/security/policy)
- [Contributing Guide](../../CONTRIBUTING.md)