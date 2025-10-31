# P-256 (NIST P-256) Guide

## Overview

P-256 (NIST P-256 / secp256r1) ECDSA는 기업 환경에서 널리 사용되는 타원곡선 서명 알고리즘입니다.

**지원 기능:**
- FIPS 186-4 준수
- RFC 6979 (Deterministic ECDSA)
- JWK 및 PEM 직렬화
- 압축/비압축 공개키 지원

**상태:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. Setup

```toml
[dependencies]
sage_crypto_core = { version = "0.3" }
```

### 2. 키 생성 및 서명

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // P-256 키 생성
    let keypair = KeyPair::generate(KeyType::P256)?;
    println!("P-256 키 생성 완료");

    // 메시지 서명
    let message = b"Hello, SAGE!";
    let signature = keypair.sign(message)?;
    println!("서명 생성: {} bytes", signature.to_bytes().len());

    // 서명 검증
    keypair.verify(message, &signature)?;
    println!("서명 검증 성공!");

    Ok(())
}
```

---

## API Reference

### KeyType::P256

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};

// P-256 키 생성
let keypair = KeyPair::generate(KeyType::P256)?;
```

### P256KeyPair

직접 P256KeyPair를 사용할 수도 있습니다:

```rust
use sage_crypto_core::crypto::p256::P256KeyPair;

// 키 생성
let keypair = P256KeyPair::generate()?;

// 서명
let signature = keypair.sign(message)?;

// 검증
keypair.verify(message, &signature)?;

// 공개키 (압축, 33 bytes)
let pub_key = keypair.public_key_bytes();

// 공개키 (비압축, 65 bytes)
let pub_key_uncompressed = keypair.public_key_bytes_uncompressed();

// 개인키 (32 bytes)
let priv_key = keypair.private_key_bytes();

// 키 ID
let key_id = keypair.key_id();
```

---

## Examples

### Example 1: 기본 서명/검증

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate(KeyType::P256)?;
    let message = b"Important message";

    // 서명
    let signature = keypair.sign(message)?;

    // 검증
    keypair.verify(message, &signature)?;
    println!("✅ 서명 검증 성공");

    Ok(())
}
```

### Example 2: JWK Export/Import

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};
use sage_crypto_core::formats::KeyExporter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate(KeyType::P256)?;

    // JWK export
    let jwk = keypair.to_jwk()?;
    println!("JWK: {}", serde_json::to_string_pretty(&jwk)?);

    // JWK 형식:
    // {
    //   "kty": "EC",
    //   "crv": "P-256",
    //   "x": "<base64url>",
    //   "y": "<base64url>",
    //   "d": "<base64url>",  // private key only
    //   "kid": "<key_id>"
    // }

    Ok(())
}
```

### Example 3: PEM Export

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};
use sage_crypto_core::formats::KeyExporter;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate(KeyType::P256)?;

    // PEM export
    let priv_pem = keypair.private_key().to_pem()?;
    let pub_pem = keypair.public_key().to_pem()?;

    // 파일로 저장
    fs::write("p256_private.pem", priv_pem)?;
    fs::write("p256_public.pem", pub_pem)?;

    println!("PEM 파일 저장 완료");

    Ok(())
}
```

### Example 4: 개인키에서 복원

```rust
use sage_crypto_core::crypto::p256::P256KeyPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 원본 키 생성
    let keypair1 = P256KeyPair::generate()?;
    let priv_bytes = keypair1.private_key_bytes();

    // 개인키에서 복원
    let keypair2 = P256KeyPair::from_private_key_bytes(&priv_bytes)?;

    // 같은 공개키 확인
    assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    println!("✅ 키 복원 성공");

    Ok(())
}
```

### Example 5: RFC 9421 HTTP 서명

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};
use sage_crypto_core::rfc9421::{HttpSigner, SignatureComponent};
use http::Request;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate(KeyType::P256)?;
    let signer = HttpSigner::new(keypair);

    let request = Request::builder()
        .method("POST")
        .uri("/api/data")
        .body("request body")?;

    let components = vec![
        SignatureComponent::Method,
        SignatureComponent::Path,
        SignatureComponent::Authority,
    ];

    let signed_request = signer.sign_request(request, &components)?;
    println!("HTTP 요청 서명 완료");

    Ok(())
}
```

---

## Key Format Details

### Public Key

- **Compressed**: 33 bytes (0x02 or 0x03 prefix + 32 bytes x coordinate)
- **Uncompressed**: 65 bytes (0x04 prefix + 32 bytes x + 32 bytes y)

### Private Key

- **Size**: 32 bytes (scalar)

### Signature

- **Size**: 64 bytes (32 bytes r + 32 bytes s)
- **Format**: Deterministic ECDSA (RFC 6979)

---

## Standards Compliance

- **FIPS 186-4**: Digital Signature Standard (DSS)
- **SEC 2**: Recommended Elliptic Curve Domain Parameters (secp256r1)
- **RFC 6979**: Deterministic Usage of DSA and ECDSA
- **RFC 7517**: JSON Web Key (JWK) format
- **RFC 9421**: HTTP Message Signatures

---

## Performance

### Benchmarks (Apple M1)

| Operation | Time |
|-----------|------|
| Key Generation | ~50-80 μs |
| Sign | ~80-120 μs |
| Verify | ~150-200 μs |

### vs Other Algorithms

| Algorithm | Sign Speed | Verify Speed | Key Size | Sig Size |
|-----------|------------|--------------|----------|----------|
| Ed25519 | ✅ Fastest | ✅ Fastest | 32B | 64B |
| P-256 | Medium | Medium | 32B | 64B |
| Secp256k1 | Medium | Medium | 32B | 64B |
| RSA-2048 | Slowest | Fast | 256B | 256B |

**P-256 사용 권장:**
- 기업 환경 (FIPS 140-2 요구사항)
- NIST 표준 준수 필요
- 기존 시스템과의 호환성
- HSM 통합

**다른 알고리즘 고려:**
- **Ed25519**: 최고 성능, 단순성
- **Secp256k1**: Ethereum, Bitcoin 호환
- **RSA**: 레거시 시스템 호환

---

## Security Considerations

### Deterministic Signatures (RFC 6979)

P-256 구현은 RFC 6979를 따라 **결정론적 서명**을 생성합니다:

```rust
// 같은 키와 메시지는 항상 같은 서명 생성
let sig1 = keypair.sign(message)?;
let sig2 = keypair.sign(message)?;
assert_eq!(sig1.to_bytes(), sig2.to_bytes());
```

**장점:**
- Nonce 재사용 공격 방지
- 테스트 가능성 향상
- 재현 가능한 서명

### Side-Channel Attacks

- 상수 시간 연산 사용 (p256 crate)
- Timing attack 방어
- Cache attack 방어

### Best Practices

```rust
// ✅ Good: OS random 사용
let keypair = P256KeyPair::generate()?;

// ✅ Good: 개인키 즉시 zeroize
use zeroize::Zeroize;
let mut priv_bytes = keypair.private_key_bytes();
// ... use private key ...
priv_bytes.zeroize();

// ⚠️ 주의: 개인키를 로그에 출력하지 마세요
// println!("Private: {:?}", priv_bytes); // NEVER!
```

---

## Troubleshooting

### "Invalid P-256 private key"

**문제:** 개인키 형식 오류

**해결책:**
```rust
// 개인키는 정확히 32 bytes여야 함
let priv_bytes = vec![0u8; 32]; // ❌ 유효하지 않은 키

// 올바른 키 생성
let keypair = P256KeyPair::generate()?;
let valid_priv_bytes = keypair.private_key_bytes(); // ✅
```

### "Signature verification failed"

**문제:** 서명 검증 실패

**해결책:**
```rust
// 1. 같은 메시지 사용 확인
let message = b"test";
let signature = keypair.sign(message)?;
keypair.verify(message, &signature)?; // ✅

// 2. 서명 길이 확인 (64 bytes)
assert_eq!(signature.to_bytes().len(), 64);

// 3. 올바른 공개키 사용 확인
let pub_key_bytes = keypair.public_key_bytes();
```

---

## Related Documentation

- [Multi-Key Management Guide](MULTI_KEY_GUIDE.md)
- [Key Rotation Guide](KEY_ROTATION_GUIDE.md)
- [API Usage Guide](api_usage_guide.md)
- [RFC 6979](https://tools.ietf.org/html/rfc6979)
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/crypto/p256.rs`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-27
**Status**: Production Ready
