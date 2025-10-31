# Multi-Chain Manager Guide

## Overview

Multi-Chain Manager는 여러 블록체인(Ethereum, Solana)을 통합 관리하는 시스템입니다. 단일 인터페이스로 여러 체인의 Agent 등록, 조회, 관리를 지원합니다.

**핵심 특징:**
- Ethereum & Solana 통합 지원
- 네트워크별 클라이언트 관리
- 통합 Agent 조회 API
- 기본 체인 설정

**상태:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. Setup

```toml
[dependencies]
sage_crypto_core = { version = "0.3", features = ["blockchain"] }
```

### 2. 기본 사용

```rust
use sage_crypto_core::blockchain::{MultiChainManager, Chain};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MultiChainManager::new();

    // Ethereum 클라이언트 추가
    manager.add_ethereum_client(
        "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
        "0x1234567890123456789012345678901234567890", // Registry address
        Some("sepolia"),
    ).await?;

    // Solana 클라이언트 추가
    manager.add_solana_client(
        "https://api.devnet.solana.com",
        "YourProgramID1111111111111111111111111111", // Program ID
        Some("devnet"),
    ).await?;

    // 등록된 체인 목록
    let chains = manager.list_chains();
    println!("등록된 체인: {:?}", chains);

    Ok(())
}
```

---

## API Reference

### MultiChainManager

```rust
use sage_crypto_core::blockchain::MultiChainManager;

// 매니저 생성
let mut manager = MultiChainManager::new();

// 기본 체인 설정
manager.set_default_chain(Chain::Ethereum);

// 기본 체인 조회
let chain = manager.default_chain();

// 클라이언트 개수
let count = manager.client_count();

// 체인 등록 여부
let has_eth = manager.has_chain(Chain::Ethereum);

// 체인 목록
let chains = manager.list_chains();
```

### Ethereum Operations

```rust
// Ethereum 클라이언트 추가
manager.add_ethereum_client(rpc_url, registry_address, network_name).await?;

// Ethereum Agent 조회
let metadata = manager.get_ethereum_agent(
    "did:sage:ethereum:0x...",
    Some("sepolia")
).await?;

// Ethereum Agent 활성화 상태 확인
let is_active = manager.is_ethereum_agent_active(
    "did:sage:ethereum:0x...",
    Some("sepolia")
).await?;

// Ethereum 클라이언트 가져오기
let client = manager.get_ethereum_client(Some("sepolia"))?;
```

### Solana Operations

```rust
// Solana 클라이언트 추가
manager.add_solana_client(rpc_url, program_id, network_name).await?;

// Solana Agent 조회
let account = manager.get_solana_agent(
    "owner_pubkey_string",
    "did:sage:solana:...",
    Some("devnet")
).await?;

// Solana Agent 활성화 상태 확인
let is_active = manager.is_solana_agent_active(
    "owner_pubkey_string",
    "did:sage:solana:...",
    Some("devnet")
).await?;

// Solana 클라이언트 가져오기
let client = manager.get_solana_client(Some("devnet"))?;
```

---

## Examples

### Example 1: 다중 네트워크 설정

```rust
use sage_crypto_core::blockchain::{MultiChainManager, Chain};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MultiChainManager::new();

    // Ethereum 메인넷 & 테스트넷
    manager.add_ethereum_client(
        "https://eth-mainnet.g.alchemy.com/v2/YOUR-KEY",
        "0xMainnetRegistryAddress",
        Some("mainnet"),
    ).await?;

    manager.add_ethereum_client(
        "https://eth-sepolia.g.alchemy.com/v2/YOUR-KEY",
        "0xSepoliaRegistryAddress",
        Some("sepolia"),
    ).await?;

    // Solana 메인넷 & 데브넷
    manager.add_solana_client(
        "https://api.mainnet-beta.solana.com",
        "MainnetProgramID",
        Some("mainnet"),
    ).await?;

    manager.add_solana_client(
        "https://api.devnet.solana.com",
        "DevnetProgramID",
        Some("devnet"),
    ).await?;

    // 기본 체인 설정
    manager.set_default_chain(Chain::Ethereum);

    println!("✅ 4개 네트워크 설정 완료!");
    println!("등록된 체인: {:?}", manager.list_chains());

    Ok(())
}
```

### Example 2: Agent 조회

```rust
use sage_crypto_core::blockchain::MultiChainManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MultiChainManager::new();

    // 클라이언트 설정
    manager.add_ethereum_client(
        "https://eth-sepolia.g.alchemy.com/v2/YOUR-KEY",
        "0xRegistryAddress",
        Some("sepolia"),
    ).await?;

    // Ethereum Agent 조회
    let did = "did:sage:ethereum:0x1234...";
    match manager.get_ethereum_agent(did, Some("sepolia")).await {
        Ok(metadata) => {
            println!("Agent DID: {:?}", metadata.did);
            println!("Name: {}", metadata.name);
            println!("Active: {}", metadata.is_active);
            println!("Public Keys: {}", metadata.public_keys.len());
        }
        Err(e) => {
            eprintln!("Agent 조회 실패: {}", e);
        }
    }

    Ok(())
}
```

### Example 3: 체인별 Agent 활성화 상태 확인

```rust
use sage_crypto_core::blockchain::MultiChainManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MultiChainManager::new();

    // 클라이언트 설정 (생략)
    // ...

    // Ethereum Agent 확인
    let eth_did = "did:sage:ethereum:0x1234...";
    let eth_active = manager.is_ethereum_agent_active(
        eth_did,
        Some("sepolia")
    ).await?;

    println!("Ethereum Agent {} 활성화: {}", eth_did, eth_active);

    // Solana Agent 확인
    let sol_owner = "YourOwnerPubkey";
    let sol_did = "did:sage:solana:...";
    let sol_active = manager.is_solana_agent_active(
        sol_owner,
        sol_did,
        Some("devnet")
    ).await?;

    println!("Solana Agent {} 활성화: {}", sol_did, sol_active);

    Ok(())
}
```

### Example 4: 동적 체인 관리

```rust
use sage_crypto_core::blockchain::{MultiChainManager, Chain};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MultiChainManager::new();

    // 초기 설정
    manager.add_ethereum_client(
        "https://eth-sepolia.g.alchemy.com/v2/KEY1",
        "0xAddress1",
        Some("sepolia"),
    ).await?;

    manager.add_ethereum_client(
        "https://eth-goerli.g.alchemy.com/v2/KEY2",
        "0xAddress2",
        Some("goerli"),
    ).await?;

    println!("초기 클라이언트 수: {}", manager.client_count());

    // 특정 네트워크 제거
    manager.remove_network(Chain::Ethereum, "goerli");
    println!("Goerli 제거 후: {}", manager.client_count());

    // 새 네트워크 추가
    manager.add_ethereum_client(
        "https://eth-holesky.g.alchemy.com/v2/KEY3",
        "0xAddress3",
        Some("holesky"),
    ).await?;

    println!("Holesky 추가 후: {}", manager.client_count());
    println!("등록된 체인: {:?}", manager.list_chains());

    Ok(())
}
```

### Example 5: 에러 처리

```rust
use sage_crypto_core::blockchain::MultiChainManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MultiChainManager::new();

    // 클라이언트 추가 (실패 가능)
    match manager.add_ethereum_client(
        "https://invalid-rpc-url",
        "0xInvalidAddress",
        Some("test"),
    ).await {
        Ok(_) => println!("클라이언트 추가 성공"),
        Err(e) => eprintln!("클라이언트 추가 실패: {}", e),
    }

    // 존재하지 않는 클라이언트 접근
    match manager.get_ethereum_client(Some("nonexistent")) {
        Ok(client) => println!("클라이언트 찾음"),
        Err(e) => eprintln!("클라이언트 없음: {}", e),
    }

    // Agent 조회 (실패 가능)
    match manager.get_ethereum_agent(
        "did:sage:ethereum:0xinvalid",
        Some("sepolia")
    ).await {
        Ok(metadata) => println!("Agent 찾음: {}", metadata.name),
        Err(e) => eprintln!("Agent 조회 실패: {}", e),
    }

    Ok(())
}
```

---

## Architecture

### 구조

```
MultiChainManager
├── ethereum_clients: HashMap<String, Arc<EthereumClient>>
├── solana_clients: HashMap<String, Arc<SolanaClient>>
└── default_chain: Option<Chain>
```

### 네트워크 식별자

- Ethereum: `"mainnet"`, `"sepolia"`, `"goerli"`, `"holesky"`
- Solana: `"mainnet"`, `"devnet"`, `"testnet"`
- Custom: 사용자 정의 문자열 가능

### 클라이언트 관리

```rust
// 네트워크별 클라이언트 저장
ethereum_clients.insert("sepolia", Arc::new(client));

// 네트워크별 조회
let client = ethereum_clients.get("sepolia")?;
```

---

## Integration Patterns

### Pattern 1: 멀티 체인 Agent 조회

```rust
async fn get_agent_from_any_chain(
    manager: &MultiChainManager,
    did: &str
) -> Result<()> {
    // Ethereum에서 시도
    if let Ok(metadata) = manager.get_ethereum_agent(did, None).await {
        println!("Found on Ethereum: {}", metadata.name);
        return Ok(());
    }

    // Solana에서 시도 (owner 필요)
    // ...

    Err(Error::NotFound)
}
```

### Pattern 2: 체인별 상태 모니터링

```rust
async fn monitor_agent_status(manager: &MultiChainManager) -> Result<()> {
    for (chain, networks) in manager.list_chains() {
        for network in networks {
            match chain {
                Chain::Ethereum => {
                    // Ethereum Agent 상태 확인
                    // ...
                }
                Chain::Solana => {
                    // Solana Agent 상태 확인
                    // ...
                }
            }
        }
    }
    Ok(())
}
```

### Pattern 3: 체인 선택 전략

```rust
fn select_chain(manager: &MultiChainManager, did: &str) -> Option<Chain> {
    // DID에서 체인 파싱
    if did.contains("ethereum") {
        return Some(Chain::Ethereum);
    }
    if did.contains("solana") {
        return Some(Chain::Solana);
    }

    // 기본 체인 사용
    manager.default_chain()
}
```

---

## Best Practices

### 1. 클라이언트 초기화

```rust
// ✅ 좋음: 초기화 시 모든 네트워크 설정
async fn setup_manager() -> Result<MultiChainManager> {
    let mut manager = MultiChainManager::new();

    manager.add_ethereum_client(rpc, addr, Some("mainnet")).await?;
    manager.add_solana_client(rpc, prog, Some("mainnet")).await?;

    manager.set_default_chain(Chain::Ethereum);

    Ok(manager)
}

// ❌ 나쁨: 매번 동적으로 추가
// async fn use_manager() {
//     manager.add_ethereum_client(...).await?; // 반복 호출
// }
```

### 2. 에러 처리

```rust
// ✅ 좋음: 구체적인 에러 처리
match manager.get_ethereum_agent(did, network).await {
    Ok(metadata) => { /* 성공 처리 */ },
    Err(Error::NotFound) => { /* Agent 없음 */ },
    Err(Error::NetworkError(_)) => { /* 네트워크 오류 */ },
    Err(e) => { /* 기타 오류 */ },
}

// ❌ 나쁨: 에러 무시
// let metadata = manager.get_ethereum_agent(did, network).await.ok();
```

### 3. 네트워크 명명

```rust
// ✅ 좋음: 명확한 네트워크 이름
manager.add_ethereum_client(rpc, addr, Some("ethereum-mainnet")).await?;
manager.add_solana_client(rpc, prog, Some("solana-devnet")).await?;

// ❌ 나쁨: 모호한 이름
// manager.add_ethereum_client(rpc, addr, Some("net1")).await?;
```

### 4. Arc<Client> 활용

```rust
// ✅ 좋음: 여러 곳에서 공유
let client = manager.get_ethereum_client(Some("mainnet"))?;
tokio::spawn(async move {
    // client 사용
});

// 다른 곳에서도 사용 가능
let client2 = manager.get_ethereum_client(Some("mainnet"))?;
```

---

## Performance Considerations

### 1. 클라이언트 재사용

```rust
// ✅ 좋음: 클라이언트 재사용
let client = manager.get_ethereum_client(Some("mainnet"))?;
for did in dids {
    let metadata = client.get_agent_by_did(&did).await?;
}

// ❌ 나쁨: 매번 클라이언트 조회
// for did in dids {
//     let client = manager.get_ethereum_client(Some("mainnet"))?;
//     let metadata = client.get_agent_by_did(&did).await?;
// }
```

### 2. 병렬 조회

```rust
use tokio::task::JoinSet;

// 여러 체인에서 병렬 조회
let mut set = JoinSet::new();

for (chain, networks) in manager.list_chains() {
    for network in networks {
        let manager_clone = Arc::new(manager.clone());
        set.spawn(async move {
            // 각 네트워크에서 조회
        });
    }
}

while let Some(result) = set.join_next().await {
    // 결과 처리
}
```

---

## Troubleshooting

### "Ethereum client not found for network"

**문제:** 네트워크가 등록되지 않음

**해결책:**
```rust
// 클라이언트 추가 확인
manager.add_ethereum_client(rpc, addr, Some("sepolia")).await?;

// 네트워크 이름 확인
let chains = manager.list_chains();
println!("등록된 네트워크: {:?}", chains);
```

### "Invalid Solana pubkey"

**문제:** Owner pubkey 형식 오류

**해결책:**
```rust
// 올바른 Base58 형식 사용
let owner = "YourBase58EncodedPubkey...";
let account = manager.get_solana_agent(owner, did, network).await?;
```

### 클라이언트 추가 실패

**문제:** RPC 연결 실패

**해결책:**
```rust
// RPC URL 확인
println!("RPC URL: {}", rpc_url);

// 재시도 로직
for attempt in 0..3 {
    match manager.add_ethereum_client(rpc, addr, network).await {
        Ok(_) => break,
        Err(e) if attempt < 2 => {
            eprintln!("재시도 {}: {}", attempt + 1, e);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(e) => return Err(e),
    }
}
```

---

## Related Documentation

- [Ethereum Integration Guide](ethereum_integration.md)
- [Solana Client Guide](SOLANA_CLIENT_GUIDE.md)
- [Blockchain Integration](blockchain_integration.md)
- [Multi-Key Management](MULTI_KEY_GUIDE.md)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/blockchain/manager.rs`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-28
**Status**: Production Ready
