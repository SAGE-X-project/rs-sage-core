# X25519 (Curve25519) Key Exchange Guide

## Overview

X25519는 Curve25519 기반의 Diffie-Hellman 키 교환 알고리즘입니다. 빠르고 안전한 공유 비밀(shared secret) 생성을 제공합니다.

**핵심 특징:**
- 고성능 키 교환
- Ed25519와 키 변환 지원
- 32바이트 공개키/개인키
- RFC 7748 준수

**상태:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. Setup

```toml
[dependencies]
sage_crypto_core = { version = "0.3" }
```

### 2. 기본 키 교환

```rust
use sage_crypto_core::crypto::X25519KeyPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Alice와 Bob의 키 생성
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    // 공유 비밀 계산
    let alice_shared = alice.diffie_hellman(bob.public_key_bytes())?;
    let bob_shared = bob.diffie_hellman(alice.public_key_bytes())?;

    // 공유 비밀이 동일함
    assert_eq!(alice_shared, bob_shared);
    println!("✅ 공유 비밀 생성 성공!");

    Ok(())
}
```

---

## API Reference

### X25519KeyPair

```rust
use sage_crypto_core::crypto::X25519KeyPair;

// 키 생성
let keypair = X25519KeyPair::generate();

// 바이트에서 생성
let private_bytes = [0u8; 32];
let keypair = X25519KeyPair::from_bytes(&private_bytes)?;

// Diffie-Hellman 키 교환
let their_public = [0u8; 32];
let shared_secret = keypair.diffie_hellman(&their_public)?;

// 공개키 가져오기
let public_key = keypair.public_key_bytes();

// 개인키 가져오기 (⚠️ 주의: 안전하게 처리)
let private_key = keypair.private_key_bytes();

// 키 ID
let key_id = keypair.key_id();
```

---

## Examples

### Example 1: 기본 키 교환

```rust
use sage_crypto_core::crypto::X25519KeyPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Alice 키
    let alice = X25519KeyPair::generate();
    println!("Alice 공개키: {}", hex::encode(alice.public_key_bytes()));

    // Bob 키
    let bob = X25519KeyPair::generate();
    println!("Bob 공개키: {}", hex::encode(bob.public_key_bytes()));

    // Alice가 Bob과 공유 비밀 계산
    let alice_shared = alice.diffie_hellman(bob.public_key_bytes())?;
    println!("Alice 공유 비밀: {}", hex::encode(&alice_shared));

    // Bob이 Alice와 공유 비밀 계산
    let bob_shared = bob.diffie_hellman(alice.public_key_bytes())?;
    println!("Bob 공유 비밀: {}", hex::encode(&bob_shared));

    // 검증
    assert_eq!(alice_shared, bob_shared);
    println!("✅ 키 교환 성공!");

    Ok(())
}
```

### Example 2: Ed25519 → X25519 변환

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType, X25519KeyPair};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ed25519 키 생성 (서명용)
    let ed25519_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let ed25519_private = ed25519_keypair.private_key().to_bytes();
    let ed25519_public = ed25519_keypair.public_key().to_bytes();

    // X25519로 변환 (키 교환용)
    let x25519_keypair = X25519KeyPair::from_ed25519_private(&ed25519_private)?;
    let x25519_public = X25519KeyPair::ed25519_public_to_x25519(&ed25519_public)?;

    println!("Ed25519 개인키 → X25519 변환 완료");
    println!("Ed25519 공개키 → X25519 변환 완료");

    // 같은 키 쌍인지 확인
    assert_eq!(x25519_keypair.public_key_bytes(), x25519_public.as_slice());
    println!("✅ 키 변환 성공!");

    Ok(())
}
```

### Example 3: 키 저장 및 복원

```rust
use sage_crypto_core::crypto::X25519KeyPair;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 키 생성
    let keypair = X25519KeyPair::generate();

    // 개인키 저장 (⚠️ 실제로는 암호화해서 저장해야 함)
    let private_bytes = keypair.private_key_bytes();
    fs::write("x25519_private.bin", &private_bytes)?;
    println!("개인키 저장 완료");

    // 개인키 복원
    let loaded_private = fs::read("x25519_private.bin")?;
    let restored_keypair = X25519KeyPair::from_bytes(&loaded_private)?;

    // 같은 공개키인지 확인
    assert_eq!(
        keypair.public_key_bytes(),
        restored_keypair.public_key_bytes()
    );
    println!("✅ 키 복원 성공!");

    Ok(())
}
```

### Example 4: 암호화된 채널 설정

```rust
use sage_crypto_core::crypto::X25519KeyPair;
use sha2::{Sha256, Digest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 클라이언트와 서버 키 생성
    let client = X25519KeyPair::generate();
    let server = X25519KeyPair::generate();

    // 공유 비밀 계산
    let shared_secret = client.diffie_hellman(server.public_key_bytes())?;

    // 공유 비밀을 KDF로 처리 (실제 사용 시 HKDF 권장)
    let mut hasher = Sha256::new();
    hasher.update(&shared_secret);
    let encryption_key = hasher.finalize();

    println!("공유 비밀: {}", hex::encode(&shared_secret));
    println!("암호화 키: {}", hex::encode(&encryption_key));
    println!("✅ 암호화 채널 설정 완료!");

    Ok(())
}
```

---

## Ed25519 ↔ X25519 변환

하나의 키 쌍으로 서명(Ed25519)과 키 교환(X25519)을 모두 지원:

### 개인키 변환

```rust
use sage_crypto_core::crypto::X25519KeyPair;

// Ed25519 개인키 → X25519
let ed25519_private = [0u8; 32]; // 실제 Ed25519 개인키
let x25519_keypair = X25519KeyPair::from_ed25519_private(&ed25519_private)?;
```

### 공개키 변환

```rust
// Ed25519 공개키 → X25519
let ed25519_public = [0u8; 32]; // 실제 Ed25519 공개키
let x25519_public = X25519KeyPair::ed25519_public_to_x25519(&ed25519_public)?;
```

### 변환 원리

- **개인키**: SHA512(ed25519_private)[0..32] → X25519 scalar
- **공개키**: Edwards 점 → Montgomery 점 (RFC 7748)

---

## Key Format Details

### 개인키
- **크기**: 32 bytes
- **타입**: Scalar on Curve25519

### 공개키
- **크기**: 32 bytes
- **타입**: Montgomery u-coordinate

### 공유 비밀
- **크기**: 32 bytes
- **권장**: HKDF로 키 유도 후 사용

---

## Security Considerations

### 1. 공유 비밀 처리

```rust
// ❌ 나쁨: 공유 비밀 직접 사용
let shared = alice.diffie_hellman(bob.public_key_bytes())?;
let encryption_key = shared; // 위험!

// ✅ 좋음: HKDF로 키 유도
use hkdf::Hkdf;
use sha2::Sha256;

let shared = alice.diffie_hellman(bob.public_key_bytes())?;
let hkdf = Hkdf::<Sha256>::new(None, &shared);
let mut encryption_key = [0u8; 32];
hkdf.expand(b"encryption", &mut encryption_key)?;
```

### 2. 개인키 보안

```rust
use zeroize::Zeroize;

// 개인키 사용 후 메모리에서 삭제
let mut private_bytes = keypair.private_key_bytes();
// ... use private key ...
private_bytes.zeroize();
```

### 3. 공개키 검증

```rust
// 공개키 길이 확인
if public_key.len() != 32 {
    return Err(Error::InvalidInput("Invalid public key length"));
}
```

### Best Practices

1. **공유 비밀 → KDF**: 항상 HKDF/PBKDF2 사용
2. **Nonce 사용**: 재전송 공격 방지
3. **인증 추가**: MAC/서명으로 상대방 인증
4. **키 회전**: 주기적으로 키 변경

---

## Performance

### Benchmarks (Apple M1)

| Operation | Time |
|-----------|------|
| Key Generation | ~20 μs |
| Diffie-Hellman | ~30 μs |
| Ed25519 → X25519 | ~40 μs |

### vs Other Algorithms

| Algorithm | Speed | Key Size | Security |
|-----------|-------|----------|----------|
| X25519 | ✅ Fast | 32B | 128-bit |
| ECDH P-256 | Medium | 32B | 128-bit |
| RSA-2048 | Slow | 256B | 112-bit |
| RSA-4096 | Very Slow | 512B | 152-bit |

**X25519 사용 권장:**
- 고성능 키 교환 필요
- Signal, WireGuard 등 현대 프로토콜
- Ed25519와 함께 사용

---

## Standards Compliance

- **RFC 7748**: Elliptic Curves for Security
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
- **x25519-dalek**: Rust 구현 (dalek-cryptography)

---

## Integration Examples

### Signal Protocol Style

```rust
// 3-DH ratchet (초기화)
let alice_identity = X25519KeyPair::generate();
let alice_ephemeral = X25519KeyPair::generate();
let bob_identity = X25519KeyPair::generate();
let bob_ephemeral = X25519KeyPair::generate();

// DH1: Alice identity × Bob ephemeral
let dh1 = alice_identity.diffie_hellman(bob_ephemeral.public_key_bytes())?;

// DH2: Alice ephemeral × Bob identity
let dh2 = alice_ephemeral.diffie_hellman(bob_identity.public_key_bytes())?;

// DH3: Alice ephemeral × Bob ephemeral
let dh3 = alice_ephemeral.diffie_hellman(bob_ephemeral.public_key_bytes())?;

// 모든 DH 결과 결합
let mut master_secret = Vec::new();
master_secret.extend_from_slice(&dh1);
master_secret.extend_from_slice(&dh2);
master_secret.extend_from_slice(&dh3);
```

---

## Troubleshooting

### "Invalid X25519 private key"

**문제:** 개인키 형식 오류

**해결책:**
```rust
// 개인키는 정확히 32 bytes여야 함
let priv_bytes = vec![0u8; 32]; // 올바른 길이

let keypair = X25519KeyPair::from_bytes(&priv_bytes)?;
```

### "DH shared secrets don't match"

**문제:** 공유 비밀 불일치

**해결책:**
```rust
// 1. 공개키가 올바른지 확인
assert_eq!(alice.public_key_bytes().len(), 32);
assert_eq!(bob.public_key_bytes().len(), 32);

// 2. 같은 키 쌍 사용 확인
let alice_shared = alice.diffie_hellman(bob.public_key_bytes())?;
let bob_shared = bob.diffie_hellman(alice.public_key_bytes())?;
assert_eq!(alice_shared, bob_shared);
```

---

## Related Documentation

- [Multi-Key Management Guide](MULTI_KEY_GUIDE.md)
- [Key Rotation Guide](KEY_ROTATION_GUIDE.md)
- [Multi-Chain Manager Guide](MULTI_CHAIN_MANAGER_GUIDE.md)
- [RFC 7748](https://tools.ietf.org/html/rfc7748)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/crypto/x25519.rs`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-28
**Status**: Production Ready
