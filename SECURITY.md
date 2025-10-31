# Security Policy

## Supported Versions

We take security seriously and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :x:                |
| 0.1.x   | :x:                |
| < 0.1   | :x:                |

## Known Security Issues

### ✅ Blockchain Feature Removed (RESOLVED in v0.3.0)

**Status**: RESOLVED
**Action Taken**: Blockchain feature completely removed
**Version**: v0.3.0+

The optional `blockchain` feature was **removed** in v0.3.0 to address critical security vulnerabilities:

- **RUSTSEC-2025-0009**: `ring` v0.16.20 via `ethers` (AES panic risk) - **FIXED**
- **Resolution**: Removed `ethers`, `futures`, and all blockchain dependencies

**Impact**:
- ✅ All core functionality remains intact
- ✅ No known vulnerabilities in default build
- ✅ All 260 tests passing

**Future Plans**:
- Blockchain integration will be re-implemented in Phase 7+ using the `alloy` crate
- The `alloy` crate is the actively maintained successor to `ethers`
- Timeline: Phase 7+ (post v1.0.0)

**For users who need blockchain integration**:
- Use v0.2.x with caution (has known vulnerabilities)
- Or wait for Phase 7+ implementation with alloy
- Or implement custom blockchain integration using alloy directly

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. Please follow these steps:

### 1. Do NOT Open a Public Issue

Please **do not** open a public GitHub issue for security vulnerabilities. This could put users at risk before a fix is available.

### 2. Report Privately

**Email**: [Your security email - TBD]
**Alternative**: Use GitHub Security Advisories (recommended)

To report via GitHub:
1. Go to: https://github.com/sage-x-project/rs-sage-core/security/advisories
2. Click "New draft security advisory"
3. Fill in the details

### 3. What to Include

Please provide as much information as possible:

- **Type of vulnerability**: (e.g., timing attack, memory leak, etc.)
- **Component affected**: Which module/function?
- **Attack scenario**: How could this be exploited?
- **Proof of concept**: Code or steps to reproduce
- **Impact assessment**: What's the potential impact?
- **Suggested fix**: (if you have one)

### 4. Response Timeline

We will acknowledge your report within:
- **24 hours**: Initial acknowledgment
- **72 hours**: Preliminary assessment
- **7 days**: Detailed response with fix timeline

### 5. Disclosure Timeline

We follow coordinated disclosure:
- **Day 0**: Vulnerability reported
- **Day 1-7**: Triage and fix development
- **Day 7-30**: Patch released (target)
- **Day 30+**: Public disclosure (after patch available)

We will work with you to determine an appropriate disclosure timeline.

## Security Best Practices

### For Users

1. **Keep dependencies updated**
   ```bash
   cargo update
   cargo audit
   ```

2. **Avoid optional features if not needed**
   ```toml
   # Minimal, secure build
   sage_crypto_core = "0.3"  # No optional features
   ```

3. **Use in production only after security review**
   - Review our security audit: `docs/security_audit_phase6_2.md`
   - Conduct your own security assessment
   - Consider external security audit for critical applications

4. **Monitor for security updates**
   - Watch this repository for security advisories
   - Subscribe to RustSec advisories
   - Run `cargo audit` regularly

### For Developers

1. **Constant-time operations**
   ```rust
   // ✅ Good: Constant-time comparison
   use subtle::ConstantTimeEq;
   let equal = secret1.ct_eq(secret2);

   // ❌ Bad: Timing leak
   if secret1 == secret2 { ... }
   ```

2. **Zeroize sensitive data**
   ```rust
   // ✅ Good: Zeroize secrets
   use zeroize::{Zeroize, Zeroizing};
   let mut secret = vec![0u8; 32];
   // ... use secret ...
   secret.zeroize();

   // Or use Zeroizing wrapper
   let secret = Zeroizing::new(vec![0u8; 32]);
   ```

3. **Use cryptographically secure RNG**
   ```rust
   // ✅ Good: OsRng (cryptographically secure)
   use rand::rngs::OsRng;
   let mut rng = OsRng;

   // ❌ Bad: thread_rng for key generation
   let mut rng = rand::thread_rng(); // Don't use for keys!
   ```

4. **Input validation**
   ```rust
   // ✅ Good: Validate input sizes
   if message.len() > MAX_MESSAGE_SIZE {
       return Err(Error::InvalidInput("Message too large"));
   }
   ```

## Security Audit Status

### Last Audit: 2025-10-13 (Phase 6.2)

**Summary**: Core cryptographic operations are secure. Optional blockchain dependencies have known vulnerabilities.

**Key Findings**:
- ✅ Core crypto: No vulnerabilities
- ✅ Constant-time operations: Properly implemented
- ✅ Memory safety: Zeroizing used correctly
- ✅ RNG: Cryptographically secure (OsRng)
- ⚠️ Blockchain feature: Dependency vulnerabilities

**Full Report**: `docs/security_audit_phase6_2.md`

### External Audits

**Status**: Not yet conducted
**Planned**: Before v1.0.0 release

We plan to conduct external security audits by professional cryptography experts before the v1.0.0 production release.

## Security Features

### Cryptographic Primitives

All cryptographic operations use industry-standard, audited libraries:

| Algorithm | Library | Standard |
|-----------|---------|----------|
| AES-256-GCM | `aes-gcm` 0.10 | NIST SP 800-38D, FIPS 197 |
| Ed25519 | `ed25519-dalek` 2.2 | RFC 8032 |
| ECDSA (secp256k1) | `k256` 0.11 | SEC 2 |
| X25519 | `x25519-dalek` 2.0 | RFC 7748 |
| HPKE | Custom | RFC 9180 |
| HTTP Signatures | Custom | RFC 9421 |
| HKDF | `hkdf` 0.12 | RFC 5869 |
| HMAC-SHA256 | `hmac` 0.12 | RFC 2104 |

### Security Properties

- **Authenticated Encryption**: AES-256-GCM (AEAD)
- **Forward Secrecy**: X25519 ephemeral keys
- **Replay Protection**: Nonce store with TTL
- **Timing Attack Resistance**: Constant-time comparisons
- **Memory Safety**: Rust memory safety + Zeroizing
- **Side-Channel Resistance**: AES-NI hardware acceleration

## Vulnerability Severity Levels

We use the following severity levels:

### Critical
- Remote code execution
- Private key extraction
- Bypass of all authentication

### High
- Authentication bypass
- Signature forgery
- Session hijacking

### Medium
- Denial of service
- Information disclosure
- Timing side-channels

### Low
- Unmaintained dependencies (no known exploits)
- Documentation issues
- Minor information leaks

## Hall of Fame

We would like to thank the following security researchers for responsibly disclosing vulnerabilities:

(None yet - be the first!)

---

## Additional Resources

- **Security Audit Report**: `docs/security_audit_phase6_2.md`
- **RustSec Advisory Database**: https://rustsec.org/
- **OWASP Cryptographic Failures**: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- **NIST Cryptographic Standards**: https://csrc.nist.gov/publications

## Contact

For security-related questions (non-vulnerability):
- **GitHub Discussions**: [Security Category]
- **Email**: [General contact - TBD]

For vulnerability reports, see "Reporting a Vulnerability" above.

---

**Last Updated**: 2025-10-14
**Version**: 0.3.0
**Status**: Active
