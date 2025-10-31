# RSA Signature Guide

## Overview

RSA 서명 기능은 SAGE 프로토콜에서 RSA-2048 및 RSA-4096 키를 사용한 디지털 서명을 지원합니다.

**지원 기능:**
- RSA-2048 및 RSA-4096 키 생성
- PKCS#1 v1.5 패딩 방식 (기본)
- PSS 패딩 방식 (더 안전함)
- DER/PEM 직렬화
- SHA-256 해싱

**상태:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. Setup

```toml
[dependencies]
sage_crypto_core = { version = "0.3" }
```

### 2. 키 생성

```rust
use sage_crypto_core::crypto::{RsaKeyPair, RsaKeySize};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // RSA-2048 키 생성
    let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
    println!("RSA-2048 키 생성 완료");

    // RSA-4096 키 생성 (더 안전하지만 느림)
    let keypair_4096 = RsaKeyPair::generate(RsaKeySize::Rsa4096)?;
    println!("RSA-4096 키 생성 완료");

    Ok(())
}
```

### 3. 서명 및 검증

```rust
use sage_crypto_core::crypto::{RsaKeyPair, RsaKeySize, PaddingScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
    let message = b"Hello, SAGE!";

    // 서명 생성 (PKCS#1 v1.5)
    let signature = keypair.sign(message, PaddingScheme::Pkcs1v15)?;
    println!("서명 생성: {} bytes", signature.len());

    // 서명 검증
    let is_valid = keypair.verify(message, &signature, PaddingScheme::Pkcs1v15)?;
    assert!(is_valid);
    println!("서명 검증 성공!");

    Ok(())
}
```

---

## API Reference

### RsaKeySize

RSA 키 크기 선택:

```rust
pub enum RsaKeySize {
    Rsa2048,  // 2048-bit (256 bytes)
    Rsa4096,  // 4096-bit (512 bytes)
}
```

### PaddingScheme

패딩 방식 선택:

```rust
pub enum PaddingScheme {
    Pkcs1v15,  // PKCS#1 v1.5 (전통적, 결정론적)
    Pss,       // PSS (확률적, 더 안전함)
}
```

### RsaKeyPair

주요 메서드:

```rust
// 키 생성
let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;

// 서명 생성
let signature = keypair.sign(message, PaddingScheme::Pkcs1v15)?;
let signature_pss = keypair.sign_pss(message)?;

// 서명 검증
let is_valid = keypair.verify(message, &signature, PaddingScheme::Pkcs1v15)?;
let is_valid_pss = keypair.verify_pss(message, &signature_pss)?;

// DER 직렬화
let private_der = keypair.private_key_to_der()?;
let public_der = keypair.public_key_to_der()?;

// PEM 직렬화
let private_pem = keypair.private_key_to_pem()?;
let public_pem = keypair.public_key_to_pem()?;
```

---

## Examples

### Example 1: 기본 서명/검증

```rust
use sage_crypto_core::crypto::{RsaKeyPair, RsaKeySize, PaddingScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 키 생성
    let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;

    // 메시지 서명
    let message = b"Important message";
    let signature = keypair.sign(message, PaddingScheme::Pkcs1v15)?;

    // 서명 검증
    let is_valid = keypair.verify(message, &signature, PaddingScheme::Pkcs1v15)?;

    if is_valid {
        println!("✅ 서명 검증 성공");
    } else {
        println!("❌ 서명 검증 실패");
    }

    Ok(())
}
```

### Example 2: PSS 패딩 사용

```rust
use sage_crypto_core::crypto::{RsaKeyPair, RsaKeySize, PaddingScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
    let message = b"Secure message with PSS";

    // PSS 패딩으로 서명
    let signature = keypair.sign(message, PaddingScheme::Pss)?;

    // PSS 패딩으로 검증
    let is_valid = keypair.verify(message, &signature, PaddingScheme::Pss)?;

    assert!(is_valid);
    println!("PSS 서명 검증 성공");

    Ok(())
}
```

### Example 3: 키 저장 및 로드 (PEM)

```rust
use sage_crypto_core::crypto::{RsaKeyPair, RsaKeySize, PaddingScheme};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 키 생성
    let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;

    // PEM으로 저장
    let private_pem = keypair.private_key_to_pem()?;
    let public_pem = keypair.public_key_to_pem()?;

    fs::write("private_key.pem", private_pem.as_bytes())?;
    fs::write("public_key.pem", public_pem.as_bytes())?;
    println!("키 저장 완료");

    // PEM에서 로드
    let loaded_pem = fs::read_to_string("private_key.pem")?;
    let keypair2 = RsaKeyPair::private_key_from_pem(&loaded_pem, RsaKeySize::Rsa2048)?;

    // 로드된 키로 서명
    let message = b"Test with loaded key";
    let signature = keypair2.sign(message, PaddingScheme::Pkcs1v15)?;

    // 원본 키로 검증
    assert!(keypair.verify(message, &signature, PaddingScheme::Pkcs1v15)?);
    println!("로드된 키 검증 성공");

    Ok(())
}
```

### Example 4: KeyPair 통합 사용

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType, Signer, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KeyPair로 RSA 키 생성
    let keypair = KeyPair::generate(KeyType::Rsa2048)?;

    println!("키 타입: {:?}", keypair.key_type());
    println!("키 ID: {}", keypair.key_id());

    // Signer 트레이트로 서명
    let message = b"Message to sign";
    let signature = keypair.sign(message)?;

    // Verifier 트레이트로 검증
    keypair.verify(message, &signature)?;
    println!("통합 서명/검증 성공");

    Ok(())
}
```

### Example 5: 멀티키 관리와 RSA

```rust
use sage_crypto_core::crypto::{
    MultiKeyManager, KeyPair, KeyType, Protocol,
};
use sage_crypto_core::storage::MemoryKeyStorage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryKeyStorage::new();
    let manager = MultiKeyManager::new(storage);

    let agent_id = "agent-rsa";

    // RSA와 다른 키 타입 함께 추가
    let rsa_key = KeyPair::generate(KeyType::Rsa2048)?;
    let ed25519_key = KeyPair::generate(KeyType::Ed25519)?;

    manager.add_key(agent_id, &rsa_key)?;
    manager.add_key(agent_id, &ed25519_key)?;

    println!("총 키 개수: {}", manager.count_keys(agent_id)?);

    // 모든 키 조회
    let all_keys = manager.get_all_keys(agent_id)?;
    for key in all_keys {
        println!("- 키 타입: {:?}", key.key_type());
    }

    Ok(())
}
```

---

## 성능 고려사항

### 키 생성 시간

| 키 크기 | 생성 시간 (대략) |
|---------|------------------|
| RSA-2048 | ~100-300ms |
| RSA-4096 | ~1-3초 |

### 서명/검증 시간

| 키 크기 | 서명 | 검증 |
|---------|------|------|
| RSA-2048 | ~1-2ms | ~0.1ms |
| RSA-4096 | ~5-10ms | ~0.2ms |

### 권장사항

1. **일반적인 사용**: RSA-2048 + PKCS#1 v1.5
2. **높은 보안**: RSA-4096 + PSS
3. **빠른 검증 필요**: Ed25519 사용 고려
4. **키 재사용**: 키를 파일에 저장하고 재사용

---

## 보안 고려사항

### 패딩 방식 선택

```rust
// ✅ Good: PSS 패딩 (더 안전함)
let sig = keypair.sign(message, PaddingScheme::Pss)?;

// ⚠️ OK: PKCS#1 v1.5 (호환성 좋음)
let sig = keypair.sign(message, PaddingScheme::Pkcs1v15)?;
```

### 키 크기 선택

```rust
// ✅ Good: RSA-2048 (2030년까지 안전)
let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;

// ✅ Better: RSA-4096 (장기 보안)
let keypair = RsaKeyPair::generate(RsaKeySize::Rsa4096)?;
```

### 키 저장

```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;

// ✅ Good: 안전한 권한으로 저장
let pem = keypair.private_key_to_pem()?;
fs::write("private_key.pem", pem.as_bytes())?;

#[cfg(unix)]
{
    let mut perms = fs::metadata("private_key.pem")?.permissions();
    perms.set_mode(0o600); // Owner만 읽기/쓰기
    fs::set_permissions("private_key.pem", perms)?;
}
```

---

## RFC 9421 HTTP 서명과 통합

### HTTP 메시지 서명

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};
use sage_crypto_core::rfc9421::{HttpSigner, SignatureComponent};
use http::Request;

fn sign_request() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate(KeyType::Rsa2048)?;
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

## Troubleshooting

### "RSA key generation failed"

**문제:** 키 생성 실패

**해결책:**
```rust
// 충분한 엔트로피 확보 후 재시도
use std::thread;
use std::time::Duration;

let result = RsaKeyPair::generate(RsaKeySize::Rsa2048);
if result.is_err() {
    thread::sleep(Duration::from_millis(100));
    let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
}
```

### "Invalid signature format"

**문제:** 서명 형식 불일치

**해결책:**
```rust
// 같은 패딩 방식으로 서명/검증
let signature = keypair.sign(message, PaddingScheme::Pkcs1v15)?;
let is_valid = keypair.verify(message, &signature, PaddingScheme::Pkcs1v15)?;

// ❌ 잘못된 예: 다른 패딩 방식 사용
// let signature = keypair.sign(message, PaddingScheme::Pkcs1v15)?;
// let is_valid = keypair.verify(message, &signature, PaddingScheme::Pss)?; // 실패!
```

### 느린 RSA-4096 키 생성

**문제:** RSA-4096 키 생성이 느림 (1-3초)

**해결책:**
```rust
// 1. 미리 키를 생성하고 캐싱
static CACHED_KEY: OnceCell<RsaKeyPair> = OnceCell::new();

fn get_or_create_key() -> &'static RsaKeyPair {
    CACHED_KEY.get_or_init(|| {
        RsaKeyPair::generate(RsaKeySize::Rsa4096).unwrap()
    })
}

// 2. 또는 파일에서 로드
let pem = fs::read_to_string("cached_key.pem")?;
let keypair = RsaKeyPair::private_key_from_pem(&pem, RsaKeySize::Rsa4096)?;
```

---

## 다른 알고리즘과 비교

| 알고리즘 | 키 크기 | 서명 크기 | 서명 속도 | 검증 속도 | 보안 수준 |
|----------|---------|-----------|-----------|-----------|-----------|
| Ed25519 | 32B | 64B | 매우 빠름 | 매우 빠름 | 높음 |
| RSA-2048 | 256B | 256B | 보통 | 빠름 | 높음 |
| RSA-4096 | 512B | 512B | 느림 | 빠름 | 매우 높음 |
| ECDSA P-256 | 32B | 64B | 빠름 | 빠름 | 높음 |

### 언제 RSA를 사용할까?

**RSA 사용이 적합한 경우:**
- 기존 시스템과의 호환성 필요
- 공개키 인프라(PKI)와 통합
- 장기 보안이 중요한 경우 (RSA-4096)
- 검증 성능이 중요한 경우

**다른 알고리즘 고려:**
- **Ed25519**: 빠른 서명/검증, 작은 키/서명
- **ECDSA**: 중간 수준의 성능, 업계 표준

---

## Related Documentation

- [Multi-Key Management Guide](MULTI_KEY_GUIDE.md)
- [Key Rotation Guide](KEY_ROTATION_GUIDE.md)
- [API Usage Guide](api_usage_guide.md)
- [RFC 9421 HTTP Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/crypto/rsa.rs`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-27
**Status**: Production Ready
