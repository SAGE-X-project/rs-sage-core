# Copilot Code Review Instructions for SAGE Crypto Core

## Overview
This document provides custom instructions for GitHub Copilot when reviewing pull requests in the SAGE Crypto Core project. The project implements cryptographic operations and HTTP message signatures according to RFC 9421.

## Review Focus Areas

### 1. Security
- **Critical**: Check for any potential cryptographic vulnerabilities
- Verify proper handling of private keys (should never be exposed or logged)
- Ensure constant-time operations for cryptographic comparisons
- Check for proper random number generation
- Validate input sanitization and bounds checking
- Look for timing attack vulnerabilities

### 2. Rust Best Practices
- Ensure proper error handling with `Result<T, E>` types
- Check for appropriate use of `unsafe` blocks (should be minimal and well-justified)
- Verify proper lifetime annotations and borrowing patterns
- Ensure no unnecessary cloning or allocations
- Check for proper use of Rust idioms and patterns

### 3. RFC 9421 Compliance
- Verify HTTP signature components match RFC 9421 specification
- Check canonicalization follows the standard correctly
- Ensure signature parameters are properly validated
- Verify timestamp handling includes appropriate clock skew tolerance

### 4. Code Quality
- Check for comprehensive error messages that help debugging
- Ensure functions have single, clear responsibilities
- Verify consistent naming conventions (snake_case for functions/variables)
- Look for adequate test coverage, especially for edge cases
- Check for proper documentation on public APIs

### 5. Performance
- Look for unnecessary allocations or copies
- Check for efficient string operations
- Verify appropriate use of iterators vs loops
- Ensure cryptographic operations are not performed redundantly

## Specific Checks

### For Cryptographic Code
```rust
// BAD: Comparing secrets with == 
if signature == expected_signature { }

// GOOD: Using constant-time comparison
if signature.ct_eq(&expected_signature) { }
```

### For Error Handling
```rust
// BAD: Using unwrap() in library code
let key = KeyPair::from_bytes(&bytes).unwrap();

// GOOD: Propagating errors properly
let key = KeyPair::from_bytes(&bytes)?;
```

### For HTTP Signature Components
- Verify all derived components (@method, @path, etc.) are correctly implemented
- Check that signature-input and signature headers follow the correct format
- Ensure proper base64 encoding/decoding of signatures

## Review Priorities
1. **Security issues** - Always highest priority
2. **Correctness** - RFC compliance and logic errors
3. **API design** - Public interface usability and consistency
4. **Performance** - Only when it impacts usability
5. **Style** - Least priority, but maintain consistency

## Do NOT Flag
- Missing comments on private/internal functions (only public APIs need docs)
- Minor performance optimizations that don't impact real usage
- Style preferences that don't affect readability
- Test code that uses `unwrap()` (it's acceptable in tests)

## Additional Context
- This is a security-critical library used for cryptographic operations
- The library supports both Ed25519 and Secp256k1 algorithms
- FFI and WASM bindings are provided, so API stability is important
- Performance matters but not at the cost of security or correctness