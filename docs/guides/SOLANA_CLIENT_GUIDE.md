# Solana Client Guide

## Overview

Solana 클라이언트는 SAGE 프로토콜에서 Solana 블록체인을 사용한 DID 등록 및 관리를 지원합니다.

**지원 기능:**
- Solana Agent Registry 프로그램과의 상호작용
- Ed25519 키만 지원 (Solana 네이티브)
- 멀티키 지원 (에이전트당 최대 5개 키)
- 키 관리 (추가, 회전, 취소)
- DID 해결 (resolution)
- PDA (Program Derived Address) 기반

**상태:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. Setup

```toml
[dependencies]
sage_crypto_core = { version = "0.3", features = ["blockchain"] }
```

### 2. 클라이언트 생성

```rust
use sage_crypto_core::blockchain::solana::SolanaClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Solana Devnet에 연결
    let client = SolanaClient::new(
        "https://api.devnet.solana.com",
        "YourProgramIDHere", // SAGE Registry 프로그램 ID
    )?;

    println!("Solana client created successfully!");
    Ok(())
}
```

### 3. DID 해결 (Resolve)

```rust
use sage_crypto_core::blockchain::solana::SolanaResolver;
use sage_crypto_core::blockchain::types::AgentDID;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SolanaClient::new(
        "https://api.devnet.solana.com",
        "YourProgramIDHere",
    )?;

    let resolver = SolanaResolver::new(client);

    // DID 해결
    let did = AgentDID::new("did:sage:solana:YourOwnerPublicKey")?;
    let metadata = resolver.resolve_did(&did).await?;

    println!("Agent name: {}", metadata.name);
    println!("Keys: {}", metadata.public_keys.len());

    Ok(())
}
```

---

## API Reference

### SolanaClient

주요 메서드:

```rust
// 클라이언트 생성
let client = SolanaClient::new(rpc_url, program_id)?;

// Fee payer 설정 (트랜잭션 서명용)
let client = client.with_fee_payer(keypair);

// Registry PDA 파생
let (registry_pda, bump) = client.derive_registry_pda();

// Agent PDA 파생
let (agent_pda, bump) = client.derive_agent_pda(&owner, &did);

// Registry 정보 조회
let registry = client.get_registry().await?;

// Agent 정보 조회
let agent = client.get_agent(&owner, &did).await?;

// Agent 활성 상태 확인
let is_active = client.is_agent_active(&owner, &did).await?;
```

### SolanaResolver

주요 메서드:

```rust
// Resolver 생성
let resolver = SolanaResolver::new(client);

// DID 해결
let metadata = resolver.resolve_did(&did).await?;

// DID 활성 상태 확인
let is_active = resolver.is_did_active(&did).await?;

// 배치 해결 (여러 DID 한번에)
let results = resolver.batch_resolve_dids(&dids).await;
```

### RegistrationParams

에이전트 등록 파라미터:

```rust
pub struct RegistrationParams {
    pub did: String,
    pub name: String,
    pub description: String,
    pub endpoint: String,
    pub capabilities: String,  // JSON 문자열
    pub public_keys: Vec<[u8; 32]>,
    pub key_types: Vec<u8>,    // 0 = Ed25519 only
    pub signatures: Vec<[u8; 64]>,
}
```

### 제약사항 (Constants)

```rust
pub const MAX_KEYS_PER_AGENT: usize = 5;
pub const MAX_DID_LEN: usize = 128;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DESCRIPTION_LEN: usize = 256;
pub const MAX_ENDPOINT_LEN: usize = 128;
pub const MAX_CAPABILITIES_LEN: usize = 256;
```

---

## Examples

### Example 1: 클라이언트 생성 및 PDA 파생

```rust
use sage_crypto_core::blockchain::solana::SolanaClient;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 클라이언트 생성
    let client = SolanaClient::new(
        "https://api.devnet.solana.com",
        "11111111111111111111111111111111", // 테스트 프로그램 ID
    )?;

    // Registry PDA 파생
    let (registry_pda, bump) = client.derive_registry_pda();
    println!("Registry PDA: {}, bump: {}", registry_pda, bump);

    // Agent PDA 파생
    let owner = Keypair::new();
    let did = "did:sage:solana:test-agent";
    let (agent_pda, bump) = client.derive_agent_pda(&owner.pubkey(), did);
    println!("Agent PDA: {}, bump: {}", agent_pda, bump);

    Ok(())
}
```

### Example 2: DID 해결

```rust
use sage_crypto_core::blockchain::solana::{SolanaClient, SolanaResolver};
use sage_crypto_core::blockchain::types::AgentDID;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SolanaClient::new(
        "https://api.devnet.solana.com",
        "YourProgramIDHere",
    )?;

    let resolver = SolanaResolver::new(client);

    // DID 생성
    let did = AgentDID::new("did:sage:solana:OwnerPublicKeyHere")?;

    // DID 해결
    match resolver.resolve_did(&did).await {
        Ok(metadata) => {
            println!("✅ DID 해결 성공");
            println!("Name: {}", metadata.name);
            println!("Description: {}", metadata.description);
            println!("Endpoint: {}", metadata.endpoint);
            println!("Keys: {}", metadata.public_keys.len());
            println!("Active: {}", metadata.is_active);
        }
        Err(e) => {
            println!("❌ DID 해결 실패: {}", e);
        }
    }

    Ok(())
}
```

### Example 3: 배치 DID 해결

```rust
use sage_crypto_core::blockchain::solana::{SolanaClient, SolanaResolver};
use sage_crypto_core::blockchain::types::AgentDID;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SolanaClient::new(
        "https://api.devnet.solana.com",
        "YourProgramIDHere",
    )?;

    let resolver = SolanaResolver::new(client);

    // 여러 DID 준비
    let dids = vec![
        AgentDID::new("did:sage:solana:owner1")?,
        AgentDID::new("did:sage:solana:owner2")?,
        AgentDID::new("did:sage:solana:owner3")?,
    ];

    // 배치 해결
    let results = resolver.batch_resolve_dids(&dids).await;

    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(metadata) => println!("DID {}: {}", i, metadata.name),
            Err(e) => println!("DID {}: Error - {}", i, e),
        }
    }

    Ok(())
}
```

### Example 4: 등록 파라미터 검증

```rust
use sage_crypto_core::blockchain::solana::{SolanaClient, RegistrationParams};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SolanaClient::new(
        "https://api.devnet.solana.com",
        "YourProgramIDHere",
    )?;

    // 유효한 파라미터
    let params = RegistrationParams {
        did: "did:sage:solana:test".to_string(),
        name: "Test Agent".to_string(),
        description: "A test agent".to_string(),
        endpoint: "https://example.com".to_string(),
        capabilities: r#"["messaging","storage"]"#.to_string(),
        public_keys: vec![[0u8; 32]],
        key_types: vec![0],  // Ed25519
        signatures: vec![[0u8; 64]],
    };

    // 파라미터 검증은 내부적으로 수행됨
    // 수동 검증도 가능:
    // client.validate_registration_params(&params)?;

    println!("✅ 파라미터 검증 성공");

    Ok(())
}
```

### Example 5: DID 형식 파싱

```rust
use sage_crypto_core::blockchain::types::AgentDID;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simple 형식
    let did1 = AgentDID::new("did:sage:solana:OwnerPublicKey")?;

    // Nonce 포함 형식
    let did2 = AgentDID::new("did:sage:solana:OwnerPublicKey:42")?;

    println!("DID 1: {}", did1.as_str());
    println!("DID 2: {}", did2.as_str());

    // DID 파싱 및 검증
    let chain = did1.chain()?;
    println!("Chain: {}", chain);  // "solana"

    Ok(())
}
```

---

## DID 형식

### 지원하는 DID 형식

1. **Simple 형식:**
   ```
   did:sage:solana:{owner_pubkey}
   ```

2. **Nonce 포함 형식:**
   ```
   did:sage:solana:{owner_pubkey}:{nonce}
   ```

### 예시

```
did:sage:solana:9fKTtFqv2WVyXbZqDr5Z7oJ3h3NvU8TZoFLhgYwqPvxj
did:sage:solana:9fKTtFqv2WVyXbZqDr5Z7oJ3h3NvU8TZoFLhgYwqPvxj:42
```

---

## 제약사항 및 제한

### Solana 고유 제약사항

1. **Ed25519만 지원**
   - Solana는 네이티브로 Ed25519 서명만 지원
   - 다른 키 타입 (Secp256k1, P256, RSA)은 사용 불가

2. **최대 키 개수**
   - 에이전트당 최대 5개 키 (Ethereum의 10개보다 적음)
   - 온체인 스토리지 비용 최적화를 위한 설계

3. **문자열 길이 제한**
   - DID: 128자
   - Name: 64자
   - Description: 256자
   - Endpoint: 128자
   - Capabilities: 256자

### 성능 고려사항

```rust
// ✅ Good: RPC endpoint 재사용
let client = Arc::new(SolanaClient::new(rpc_url, program_id)?);
let resolver1 = SolanaResolver::from_arc(client.clone());
let resolver2 = SolanaResolver::from_arc(client.clone());

// ⚠️ 주의: 과도한 배치 요청
// RPC rate limit 고려 필요
let dids = vec![/* 너무 많은 DID */];
let results = resolver.batch_resolve_dids(&dids).await;
```

---

## 트러블슈팅

### "Invalid program ID"

**문제:** 프로그램 ID 형식 오류

**해결책:**
```rust
// ❌ 잘못된 형식
let client = SolanaClient::new(url, "invalid-id");

// ✅ 올바른 형식 (Base58)
let client = SolanaClient::new(
    url,
    "11111111111111111111111111111111"
)?;
```

### "Failed to get agent"

**문제:** 에이전트가 존재하지 않음

**해결책:**
```rust
// 먼저 활성 상태 확인
if client.is_agent_active(&owner, &did).await? {
    let agent = client.get_agent(&owner, &did).await?;
} else {
    println!("Agent not found or inactive");
}
```

### "Too many keys"

**문제:** 최대 키 개수 초과

**해결책:**
```rust
use sage_crypto_core::blockchain::solana::MAX_KEYS_PER_AGENT;

let params = RegistrationParams {
    // ...
    public_keys: vec![/* 최대 5개 */],
    key_types: vec![0; MAX_KEYS_PER_AGENT.min(5)],
    // ...
};
```

### "Only Ed25519 keys supported"

**문제:** Ed25519가 아닌 키 타입 사용 시도

**해결책:**
```rust
// ❌ Solana에서는 불가능
let params = RegistrationParams {
    key_types: vec![1],  // Secp256k1 - 지원 안 됨!
    // ...
};

// ✅ Ed25519만 사용
let params = RegistrationParams {
    key_types: vec![0],  // Ed25519만 허용
    // ...
};
```

---

## Ethereum과의 차이점

| 기능 | Ethereum | Solana |
|-----|----------|--------|
| **지원 키 타입** | Ed25519, Secp256k1, P256, RSA | Ed25519만 |
| **최대 키 개수** | 10 | 5 |
| **트랜잭션 속도** | ~15초 (Sepolia) | ~400ms |
| **트랜잭션 비용** | 가변 (gas price) | 고정 (~0.000005 SOL) |
| **스마트 컨트랙트** | Solidity | Anchor (Rust) |
| **주소 형식** | 0x... (hex, 42자) | Base58 (32-44자) |
| **컨센서스** | PoS | PoH + PoS |

---

## 보안 고려사항

### 1. RPC Endpoint 보안

```rust
// ✅ Good: Trusted RPC endpoint 사용
let client = SolanaClient::new(
    "https://api.mainnet-beta.solana.com",  // Solana 공식
    program_id,
)?;

// ⚠️ 주의: 검증되지 않은 RPC
// 민감한 작업에는 사용 금지
```

### 2. Private Key 관리

```rust
// ✅ Good: 환경 변수 사용
let private_key = std::env::var("SOLANA_PRIVATE_KEY")?;

// ❌ 절대 금지: 하드코딩
// let private_key = "your-secret-key-here";
```

### 3. 트랜잭션 서명

```rust
// Fee payer 키페어는 안전하게 보관
let keypair = Keypair::from_bytes(&private_key_bytes)?;
let client = client.with_fee_payer(keypair);

// 사용 후 메모리에서 제거 (zeroize crate 사용 권장)
```

---

## 성능 최적화

### RPC 클라이언트 재사용

```rust
use std::sync::Arc;

// ✅ 클라이언트를 Arc로 공유
let client = Arc::new(SolanaClient::new(rpc_url, program_id)?);

// 여러 resolver가 같은 RPC 연결 공유
let resolver1 = SolanaResolver::from_arc(client.clone());
let resolver2 = SolanaResolver::from_arc(client.clone());
```

### 배치 처리

```rust
// ✅ 여러 DID를 한번에 해결
let dids = vec![did1, did2, did3];
let results = resolver.batch_resolve_dids(&dids).await;

// ⚠️ rate limit 고려
// 대량 요청 시 chunk로 나누기
for chunk in dids.chunks(10) {
    let results = resolver.batch_resolve_dids(chunk).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
}
```

---

## Related Documentation

- [Blockchain Types Reference](../src/blockchain/types.rs)
- [Multi-Key Management Guide](MULTI_KEY_GUIDE.md)
- [Solana Program Source](../../sage/contracts/solana/programs/sage-registry/)
- [Solana Documentation](https://docs.solana.com/)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/blockchain/solana/`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-27
**Status**: Production Ready
