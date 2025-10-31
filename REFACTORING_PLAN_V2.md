# rs-sage-core Refactoring Plan v2.0
## Based on sage v1.3.1 (Go) - 2025-10-26

이 문서는 sage v1.3.1 (Go)의 최신 코어 코드를 기반으로 rs-sage-core를 리팩토링하는 계획을 담고 있습니다.

---

## 📊 Current Status Comparison

### sage (Go) v1.3.1 Features
- ✅ Ed25519, Secp256k1, **P-256**, X25519, RSA256 지원
- ✅ Multi-key resolution (agent당 최대 10개 키)
- ✅ Key rotation with history tracking
- ✅ DID format with owner address validation
- ✅ Public key ownership verification
- ✅ Atomic key rotation
- ✅ Complete key revocation
- ✅ Smart contract (SageRegistryV4)
- ✅ RFC 9421 HTTP Message Signatures
- ✅ HPKE, Session, Handshake protocols
- ✅ Multi-chain support (Ethereum, Solana)

### rs-sage-core (Rust) v0.3.0 Features
- ✅ Ed25519, Secp256k1
- ❌ P-256, X25519, RSA256
- ✅ Basic key storage (File, Memory)
- ❌ Key rotation infrastructure
- ❌ Multi-key per agent
- ✅ RFC 9421 HTTP Message Signatures
- ✅ HPKE, Session, Handshake protocols (Phase 4 완료)
- ✅ Transport abstraction (Phase 5.1 완료)
- ✅ Input validation (Phase 6.3 완료)
- ❌ Blockchain/DID (보안 이슈로 v0.3.0에서 제거됨)

---

## 🎯 Refactoring Goals

### Primary Goals
1. **Crypto Parity**: sage v1.3.1과 동일한 암호화 알고리즘 지원
2. **Key Management**: Key rotation, multi-key support, ownership verification
3. **Blockchain Reintegration**: alloy 크레이트 기반 안전한 재구현
4. **DID Enhancement**: v1.3.1의 owner address 포함 DID 포맷 지원
5. **API Consistency**: sage의 interface 구조와 일관성 유지

### Secondary Goals
1. Performance optimization
2. Enhanced test coverage
3. Improved documentation
4. FFI/WASM enhancements

---

## 📋 Gap Analysis

### 1. Cryptographic Algorithms

| Algorithm | sage v1.3.1 | rs-sage-core v0.3.0 | Priority | Effort |
|-----------|-------------|---------------------|----------|--------|
| Ed25519 | ✅ | ✅ | - | - |
| Secp256k1 | ✅ | ✅ | - | - |
| **P-256** | ✅ | ❌ | **HIGH** | Medium |
| X25519 | ✅ | ❌ | **HIGH** | Low |
| RSA256 | ✅ | ❌ | MEDIUM | Medium |

**Gap**: rs-sage-core는 P-256, X25519, RSA256 미지원

**Impact**:
- P-256: NIST 표준 알고리즘, 많은 기업 환경에서 요구됨
- X25519: HPKE에서 이미 사용 중이지만, KeyPair로 노출되지 않음
- RSA256: JWT, legacy system 호환성

---

### 2. Key Management Infrastructure

#### 2.1 Key Rotation

**sage v1.3.1** (`pkg/agent/crypto/types.go:103-133`):
```go
type KeyRotationConfig struct {
    RotationInterval time.Duration
    MaxKeyAge        time.Duration
    KeepOldKeys      bool
}

type KeyRotator interface {
    Rotate(id string) (KeyPair, error)
    SetRotationConfig(config KeyRotationConfig)
    GetRotationHistory(id string) ([]KeyRotationEvent, error)
}

type KeyRotationEvent struct {
    Timestamp time.Time
    OldKeyID  string
    NewKeyID  string
    Reason    string
}
```

**rs-sage-core v0.3.0**: ❌ 미구현

**Required Implementation**:
- `src/crypto/rotation.rs` (새 파일)
  - `KeyRotationConfig` struct
  - `KeyRotator` trait
  - `DefaultKeyRotator` implementation
  - `KeyRotationEvent` struct
  - History tracking storage

**Estimated LOC**: ~300-400 lines

---

#### 2.2 Multi-Key Support

**sage v1.3.1 Changes** (CHANGELOG v1.1.0):
- Agent당 최대 10개의 공개키 지원
- `ResolveAllPublicKeys()`: 모든 검증된 공개키 조회
- `ResolvePublicKeyByType()`: 특정 키 타입 조회
- Protocol-specific key selection (ECDSA for Ethereum, Ed25519 for Solana)

**rs-sage-core v0.3.0**: ❌ 미구현

**Required Implementation**:
- `src/crypto/multi_key.rs` (새 파일)
  - `MultiKeyManager` struct
  - Key type filtering
  - Protocol-specific key selection
  - Max 10 keys per agent validation

**Estimated LOC**: ~250-350 lines

---

#### 2.3 Storage Enhancements

**sage v1.3.1** (`pkg/agent/crypto/types.go:85-101`):
```go
type KeyStorage interface {
    Store(id string, keyPair KeyPair) error
    Load(id string) (KeyPair, error)
    Delete(id string) error
    List() ([]string, error)
    Exists(id string) bool  // ← 새로 추가됨
}
```

**rs-sage-core v0.3.0** (`src/crypto/storage/mod.rs`):
```rust
pub trait KeyStorage: Send + Sync {
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()>;
    fn load(&self, id: &str) -> Result<KeyPair>;
    fn delete(&self, id: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
    // Exists() 메서드 없음
}
```

**Required Changes**:
- `Exists()` 메서드 추가
- FileKeyStorage, MemoryKeyStorage에 구현

**Estimated LOC**: ~20-30 lines

---

### 3. DID and Blockchain Integration

#### 3.1 Current Status

**sage v1.3.1**:
- SageRegistryV4 스마트 계약
- Enhanced DID format: `did:sage:ethereum:0x{address}` 또는 `did:sage:ethereum:0x{address}:{nonce}`
- Public key ownership verification via ecrecover
- Atomic key rotation on-chain
- Multi-chain support (Ethereum, Solana)

**rs-sage-core v0.3.0**:
- ❌ Blockchain 기능 완전 제거 (RUSTSEC-2025-0009 대응)
- `src/blockchain/` deprecated (컴파일 안됨)
- Phase 7+에서 alloy 크레이트로 재구현 예정

#### 3.2 Required Implementation

**Phase 7: Blockchain Reintegration**

새로운 의존성:
```toml
[dependencies]
alloy = { version = "0.1", features = ["contract", "providers", "signers"] }
alloy-sol-types = "0.1"
```

**파일 구조**:
```
src/blockchain/
├── mod.rs
├── types.rs                    # DID types, AgentMetadata
├── ethereum/
│   ├── mod.rs
│   ├── client.rs              # EthereumClient (alloy-based)
│   ├── registry.rs            # SageRegistryV4 contract bindings
│   └── resolver.rs            # Ethereum DID resolver
├── solana/
│   ├── mod.rs
│   ├── client.rs
│   └── resolver.rs
├── manager.rs                  # Multi-chain manager
└── ownership.rs                # Public key ownership verification
```

**새로운 기능**:
1. **Enhanced DID Format** (`types.rs`):
   ```rust
   pub enum DIDFormat {
       Simple,                         // did:sage:ethereum:0xABC...
       WithAddress(String),            // did:sage:ethereum:0x{owner}
       WithNonce(String, u64),         // did:sage:ethereum:0x{owner}:{nonce}
   }

   pub fn generate_agent_did_with_address(
       chain: Chain,
       owner_address: &str,
   ) -> Result<String>;

   pub fn derive_ethereum_address(
       public_key: &[u8],
   ) -> Result<String>;
   ```

2. **Public Key Ownership Verification** (`ownership.rs`):
   ```rust
   pub fn verify_ecdsa_ownership(
       public_key: &[u8],
       expected_address: &str,
   ) -> Result<bool>;
   ```

3. **Atomic Key Rotation** (`ethereum/registry.rs`):
   ```rust
   pub async fn rotate_key(
       &self,
       old_key_hash: [u8; 32],
       new_public_key: &[u8],
       signature: &[u8],
   ) -> Result<TransactionReceipt>;
   ```

4. **Multi-Key Resolution** (`ethereum/resolver.rs`):
   ```rust
   pub async fn resolve_all_public_keys(
       &self,
       did: &str,
   ) -> Result<Vec<PublicKey>>;

   pub async fn resolve_public_key_by_type(
       &self,
       did: &str,
       key_type: KeyType,
   ) -> Result<Option<PublicKey>>;
   ```

**Estimated LOC**: ~2,500-3,000 lines

**Timeline**: 2-3 weeks

---

### 4. RFC 9421 Enhancements

#### 4.1 Algorithm Registry

**sage v1.3.1** (`pkg/agent/core/rfc9421/types.go:91-101`):
```go
// GetSupportedAlgorithms returns a list of RFC 9421 supported algorithms
// This dynamically fetches from the centralized algorithm registry
func GetSupportedAlgorithms() []string {
    return sagecrypto.ListRFC9421SupportedAlgorithms()
}

// IsAlgorithmSupported checks if an RFC 9421 algorithm is supported
func IsAlgorithmSupported(algorithm string) bool {
    _, err := sagecrypto.GetKeyTypeFromRFC9421Algorithm(algorithm)
    return err == nil
}
```

**rs-sage-core v0.3.0** (`src/rfc9421/mod.rs:13-31`):
- 하드코딩된 `SignatureAlgorithm` enum
- Dynamic algorithm registry 없음

**Required Implementation**:
- `src/crypto/algorithm_registry.rs` (새 파일)
  - Algorithm registration system
  - RFC 9421 algorithm mapping
  - Dynamic algorithm support check

**Estimated LOC**: ~150-200 lines

---

## 🚀 Implementation Roadmap

### Phase 7: Cryptographic Algorithm Expansion (Week 1-2)

**Objective**: sage v1.3.1과 동일한 암호화 알고리즘 지원

#### Task 7.1: P-256 (NIST P-256) Support
**Priority**: HIGH
**Effort**: Medium (3-4 days)

**Files to Create/Modify**:
- `src/crypto/p256.rs` (새 파일, ~200 LOC)
- `src/crypto/keys.rs` (KeyType enum에 P256 추가)
- `src/crypto/mod.rs` (export 추가)

**Dependencies**:
```toml
p256 = { version = "0.13", features = ["ecdsa", "std"] }
```

**Implementation Details**:
```rust
// src/crypto/p256.rs
use p256::ecdsa::{SigningKey, VerifyingKey, Signature};
use p256::elliptic_curve::rand_core::OsRng;

pub struct P256KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl P256KeyPair {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::Signer;
        let signature: Signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        use p256::ecdsa::signature::Verifier;
        let sig = Signature::try_from(signature)?;
        Ok(self.verifying_key.verify(message, &sig).is_ok())
    }
}
```

**Tests**:
- Key generation
- Sign/verify roundtrip
- Interoperability with Go implementation
- RFC test vectors

---

#### Task 7.2: X25519 Key Agreement
**Priority**: HIGH
**Effort**: Low (1-2 days)

**Files to Modify**:
- `src/crypto/keys.rs` (KeyType::X25519 추가)
- HPKE에서 이미 x25519-dalek 사용 중이므로 통합만 필요

**Implementation**:
```rust
// src/crypto/keys.rs
pub enum KeyType {
    Ed25519,
    Secp256k1,
    P256,
    X25519,  // ← 추가
    RSA256,
}

// src/crypto/x25519.rs (새 파일)
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub struct X25519KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}
```

---

#### Task 7.3: RSA256 Support
**Priority**: MEDIUM
**Effort**: Medium (3-4 days)

**Dependencies**:
```toml
rsa = { version = "0.9", features = ["sha2"] }
sha2 = "0.10"
```

**Files to Create**:
- `src/crypto/rsa.rs` (~250 LOC)

**Implementation**:
```rust
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Signer, Verifier};
use sha2::Sha256;

pub struct RSA256KeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RSA256KeyPair {
    pub fn generate(bits: usize) -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self { private_key, public_key })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}
```

---

### Phase 8: Key Management Infrastructure (Week 2-3)

#### Task 8.1: Key Rotation
**Priority**: HIGH
**Effort**: High (5-6 days)

**Files to Create**:
- `src/crypto/rotation.rs` (~400 LOC)
- `tests/key_rotation_tests.rs` (~200 LOC)

**Implementation Structure**:
```rust
// src/crypto/rotation.rs
use std::time::Duration;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    pub rotation_interval: Duration,
    pub max_key_age: Duration,
    pub keep_old_keys: bool,
}

#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    pub timestamp: DateTime<Utc>,
    pub old_key_id: String,
    pub new_key_id: String,
    pub reason: String,
}

pub trait KeyRotator: Send + Sync {
    fn rotate(&self, id: &str) -> Result<KeyPair>;
    fn set_rotation_config(&mut self, config: KeyRotationConfig);
    fn get_rotation_history(&self, id: &str) -> Result<Vec<KeyRotationEvent>>;
}

pub struct DefaultKeyRotator {
    config: KeyRotationConfig,
    history: Arc<Mutex<HashMap<String, Vec<KeyRotationEvent>>>>,
    storage: Arc<dyn KeyStorage>,
}

impl DefaultKeyRotator {
    pub fn new(storage: Arc<dyn KeyStorage>) -> Self {
        Self {
            config: KeyRotationConfig::default(),
            history: Arc::new(Mutex::new(HashMap::new())),
            storage,
        }
    }
}

impl KeyRotator for DefaultKeyRotator {
    fn rotate(&self, id: &str) -> Result<KeyPair> {
        // 1. Load old key
        let old_key = self.storage.load(id)?;
        let old_key_id = old_key.id();

        // 2. Generate new key of same type
        let new_key = KeyPair::generate(old_key.key_type())?;
        let new_key_id = new_key.id();

        // 3. Store new key
        self.storage.store(id, &new_key)?;

        // 4. Handle old key
        if !self.config.keep_old_keys {
            self.storage.delete(&old_key_id)?;
        }

        // 5. Record rotation event
        let event = KeyRotationEvent {
            timestamp: Utc::now(),
            old_key_id: old_key_id.clone(),
            new_key_id: new_key_id.clone(),
            reason: "Manual rotation".to_string(),
        };

        let mut history = self.history.lock().unwrap();
        history.entry(id.to_string())
            .or_insert_with(Vec::new)
            .push(event);

        Ok(new_key)
    }

    fn set_rotation_config(&mut self, config: KeyRotationConfig) {
        self.config = config;
    }

    fn get_rotation_history(&self, id: &str) -> Result<Vec<KeyRotationEvent>> {
        let history = self.history.lock().unwrap();
        Ok(history.get(id).cloned().unwrap_or_default())
    }
}
```

**Auto-rotation support**:
```rust
impl DefaultKeyRotator {
    pub async fn start_auto_rotation(&self) -> JoinHandle<()> {
        let interval = self.config.rotation_interval;
        let max_age = self.config.max_key_age;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                // Check all keys and rotate if needed
                if let Ok(keys) = self.storage.list() {
                    for key_id in keys {
                        if let Ok(key) = self.storage.load(&key_id) {
                            let age = Utc::now() - key.created_at();
                            if age > max_age {
                                let _ = self.rotate(&key_id);
                            }
                        }
                    }
                }
            }
        })
    }
}
```

---

#### Task 8.2: Multi-Key Support
**Priority**: HIGH
**Effort**: Medium (4-5 days)

**Files to Create**:
- `src/crypto/multi_key.rs` (~350 LOC)

**Implementation**:
```rust
// src/crypto/multi_key.rs
const MAX_KEYS_PER_AGENT: usize = 10;

pub struct MultiKeyManager {
    storage: Arc<dyn KeyStorage>,
}

impl MultiKeyManager {
    pub fn new(storage: Arc<dyn KeyStorage>) -> Self {
        Self { storage }
    }

    /// Add a key for an agent
    pub fn add_key(&self, agent_id: &str, key: &KeyPair) -> Result<()> {
        let existing_keys = self.get_all_keys(agent_id)?;

        if existing_keys.len() >= MAX_KEYS_PER_AGENT {
            return Err(Error::TooManyKeys);
        }

        let key_id = format!("{}/{}", agent_id, key.id());
        self.storage.store(&key_id, key)
    }

    /// Get all keys for an agent
    pub fn get_all_keys(&self, agent_id: &str) -> Result<Vec<KeyPair>> {
        let all_keys = self.storage.list()?;
        let prefix = format!("{}/", agent_id);

        let mut keys = Vec::new();
        for key_id in all_keys {
            if key_id.starts_with(&prefix) {
                keys.push(self.storage.load(&key_id)?);
            }
        }

        Ok(keys)
    }

    /// Get keys by type
    pub fn get_keys_by_type(
        &self,
        agent_id: &str,
        key_type: KeyType,
    ) -> Result<Vec<KeyPair>> {
        let all_keys = self.get_all_keys(agent_id)?;
        Ok(all_keys
            .into_iter()
            .filter(|k| k.key_type() == key_type)
            .collect())
    }

    /// Get protocol-specific key (ECDSA for Ethereum, Ed25519 for Solana)
    pub fn get_protocol_key(
        &self,
        agent_id: &str,
        protocol: Protocol,
    ) -> Result<Option<KeyPair>> {
        let key_type = match protocol {
            Protocol::Ethereum => KeyType::Secp256k1,  // or P256
            Protocol::Solana => KeyType::Ed25519,
        };

        let keys = self.get_keys_by_type(agent_id, key_type)?;
        Ok(keys.into_iter().next())
    }
}

pub enum Protocol {
    Ethereum,
    Solana,
}
```

---

#### Task 8.3: Storage Enhancements
**Priority**: LOW
**Effort**: Low (1 day)

**Files to Modify**:
- `src/crypto/storage/mod.rs`
- `src/crypto/storage/file.rs`
- `src/crypto/storage/memory.rs`

**Changes**:
```rust
// src/crypto/storage/mod.rs
pub trait KeyStorage: Send + Sync {
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()>;
    fn load(&self, id: &str) -> Result<KeyPair>;
    fn delete(&self, id: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
    fn exists(&self, id: &str) -> bool;  // ← 새로 추가
}

// src/crypto/storage/memory.rs
impl KeyStorage for MemoryKeyStorage {
    fn exists(&self, id: &str) -> bool {
        self.keys.read().unwrap().contains_key(id)
    }
}

// src/crypto/storage/file.rs
impl KeyStorage for FileKeyStorage {
    fn exists(&self, id: &str) -> bool {
        let path = self.base_path.join(format!("{}.jwk", id));
        path.exists()
    }
}
```

---

### Phase 9: Blockchain Reintegration (Week 3-5)

#### Task 9.1: Project Setup and Dependencies
**Priority**: HIGH
**Effort**: Low (1 day)

**Cargo.toml updates**:
```toml
[dependencies]
# Ethereum
alloy = { version = "0.1", features = ["contract", "providers", "signers", "network"] }
alloy-sol-types = "0.1"
alloy-primitives = "0.1"

# Solana
solana-client = "1.18"
solana-sdk = "1.18"
bs58 = "0.5"

# Common
async-trait = "0.1"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

**Feature flag**:
```toml
[features]
default = []
blockchain = ["alloy", "solana-client"]
```

---

#### Task 9.2: Core Types and DID Format
**Priority**: HIGH
**Effort**: Medium (2-3 days)

**Files to Create**:
- `src/blockchain/mod.rs` (~100 LOC)
- `src/blockchain/types.rs` (~300 LOC)

**Implementation**:
```rust
// src/blockchain/types.rs
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported blockchain networks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chain {
    Ethereum,
    Solana,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Ethereum => write!(f, "ethereum"),
            Chain::Solana => write!(f, "solana"),
        }
    }
}

/// Network identifiers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    // Ethereum
    EthereumMainnet,
    EthereumSepolia,
    EthereumGoerli,
    // Solana
    SolanaMainnet,
    SolanaDevnet,
    SolanaTestnet,
}

/// Agent DID (Decentralized Identifier)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDID(String);

impl AgentDID {
    /// Parse a DID string
    pub fn parse(did: &str) -> Result<Self> {
        if !did.starts_with("did:sage:") {
            return Err(Error::InvalidDID("Missing 'did:sage:' prefix".into()));
        }
        Ok(Self(did.to_string()))
    }

    /// Extract chain from DID
    pub fn chain(&self) -> Result<Chain> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() < 3 {
            return Err(Error::InvalidDID("Invalid DID format".into()));
        }

        match parts[2] {
            "ethereum" => Ok(Chain::Ethereum),
            "solana" => Ok(Chain::Solana),
            _ => Err(Error::InvalidDID(format!("Unknown chain: {}", parts[2]))),
        }
    }

    /// Extract address from DID
    pub fn address(&self) -> Result<String> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() < 4 {
            return Err(Error::InvalidDID("Missing address".into()));
        }
        Ok(parts[3].to_string())
    }

    /// Extract nonce if present
    pub fn nonce(&self) -> Option<u64> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() >= 5 {
            parts[4].parse().ok()
        } else {
            None
        }
    }
}

/// DID format variants
#[derive(Debug, Clone)]
pub enum DIDFormat {
    /// Simple format: did:sage:{chain}:{identifier}
    Simple,
    /// With owner address: did:sage:{chain}:0x{address}
    WithAddress(String),
    /// With nonce: did:sage:{chain}:0x{address}:{nonce}
    WithNonce(String, u64),
}

/// Generate agent DID with owner address
pub fn generate_agent_did_with_address(
    chain: Chain,
    owner_address: &str,
) -> Result<String> {
    validate_address(chain, owner_address)?;
    Ok(format!("did:sage:{}:{}", chain, owner_address))
}

/// Generate agent DID with nonce
pub fn generate_agent_did_with_nonce(
    chain: Chain,
    owner_address: &str,
    nonce: u64,
) -> Result<String> {
    validate_address(chain, owner_address)?;
    Ok(format!("did:sage:{}:{}:{}", chain, owner_address, nonce))
}

/// Derive Ethereum address from secp256k1 public key
pub fn derive_ethereum_address(public_key: &[u8]) -> Result<String> {
    use tiny_keccak::{Hasher, Keccak};

    if public_key.len() != 65 {
        return Err(Error::InvalidPublicKey("Expected 65-byte uncompressed key".into()));
    }

    // Skip the 0x04 prefix
    let key_bytes = &public_key[1..];

    // Keccak256 hash
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(key_bytes);
    keccak.finalize(&mut hash);

    // Take last 20 bytes
    let address_bytes = &hash[12..];
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

fn validate_address(chain: Chain, address: &str) -> Result<()> {
    match chain {
        Chain::Ethereum => {
            if !address.starts_with("0x") || address.len() != 42 {
                return Err(Error::InvalidAddress("Invalid Ethereum address".into()));
            }
        }
        Chain::Solana => {
            // Base58 validation
            if bs58::decode(address).into_vec().is_err() {
                return Err(Error::InvalidAddress("Invalid Solana address".into()));
            }
        }
    }
    Ok(())
}

/// Agent metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub did: AgentDID,
    pub name: String,
    pub description: String,
    pub endpoint: String,
    pub public_keys: Vec<PublicKeyInfo>,
    pub capabilities: Vec<String>,
    pub owner: String,
    pub is_active: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub key_type: crate::crypto::KeyType,
    pub key_data: Vec<u8>,
    pub key_hash: [u8; 32],
    pub verified: bool,
}
```

---

#### Task 9.3: Ethereum Client (alloy-based)
**Priority**: HIGH
**Effort**: High (5-7 days)

**Files to Create**:
- `src/blockchain/ethereum/mod.rs`
- `src/blockchain/ethereum/client.rs` (~400 LOC)
- `src/blockchain/ethereum/registry.rs` (~300 LOC)
- `src/blockchain/ethereum/resolver.rs` (~250 LOC)

**Implementation**:
```rust
// src/blockchain/ethereum/client.rs
use alloy::providers::{Provider, ProviderBuilder};
use alloy::primitives::{Address, U256, Bytes};
use alloy::contract::Contract;
use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;

pub struct EthereumClient {
    provider: Box<dyn Provider>,
    signer: Option<PrivateKeySigner>,
    registry_address: Address,
    network: Network,
}

impl EthereumClient {
    pub async fn new(
        rpc_url: &str,
        registry_address: &str,
        network: Network,
    ) -> Result<Self> {
        let provider = ProviderBuilder::new()
            .on_http(rpc_url.parse()?);

        let registry_address = registry_address.parse()?;

        Ok(Self {
            provider: Box::new(provider),
            signer: None,
            registry_address,
            network,
        })
    }

    pub fn with_signer(mut self, private_key: &str) -> Result<Self> {
        let signer = private_key.parse::<PrivateKeySigner>()?;
        self.signer = Some(signer);
        Ok(self)
    }

    /// Register agent on-chain
    pub async fn register_agent(
        &self,
        did: &str,
        name: &str,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<TransactionReceipt> {
        let contract = self.get_registry_contract()?;

        // Prepare call data
        let call = contract.function("registerAgent")?
            .call((
                Bytes::from(did.as_bytes()),
                Bytes::from(name.as_bytes()),
                Bytes::from(public_key),
                Bytes::from(signature),
            ));

        // Send transaction
        let tx = call.send().await?;
        let receipt = tx.get_receipt().await?;

        Ok(receipt)
    }

    /// Rotate key atomically
    pub async fn rotate_key(
        &self,
        old_key_hash: [u8; 32],
        new_public_key: &[u8],
        signature: &[u8],
    ) -> Result<TransactionReceipt> {
        let contract = self.get_registry_contract()?;

        let call = contract.function("rotateKey")?
            .call((
                Bytes::from(old_key_hash),
                Bytes::from(new_public_key),
                Bytes::from(signature),
            ));

        let tx = call.send().await?;
        let receipt = tx.get_receipt().await?;

        Ok(receipt)
    }

    /// Revoke key completely
    pub async fn revoke_key(
        &self,
        key_hash: [u8; 32],
        signature: &[u8],
    ) -> Result<TransactionReceipt> {
        let contract = self.get_registry_contract()?;

        let call = contract.function("revokeKey")?
            .call((
                Bytes::from(key_hash),
                Bytes::from(signature),
            ));

        let tx = call.send().await?;
        let receipt = tx.get_receipt().await?;

        Ok(receipt)
    }

    fn get_registry_contract(&self) -> Result<Contract> {
        // Load ABI from embedded JSON
        let abi = include_str!("../../../contracts/SageRegistryV4.abi.json");
        let contract = Contract::new(
            self.registry_address,
            abi.parse()?,
            self.provider.clone(),
        );
        Ok(contract)
    }
}
```

**Resolver implementation**:
```rust
// src/blockchain/ethereum/resolver.rs
pub struct EthereumResolver {
    client: EthereumClient,
}

impl EthereumResolver {
    pub fn new(client: EthereumClient) -> Self {
        Self { client }
    }

    /// Resolve all public keys for an agent
    pub async fn resolve_all_public_keys(
        &self,
        did: &str,
    ) -> Result<Vec<PublicKeyInfo>> {
        let agent_did = AgentDID::parse(did)?;
        let address = agent_did.address()?;

        let contract = self.client.get_registry_contract()?;
        let result = contract.function("getAgentKeys")?
            .call((address.parse::<Address>()?))
            .await?;

        // Parse result
        let keys: Vec<PublicKeyInfo> = result.0
            .into_iter()
            .filter(|k| k.verified)  // Only verified keys
            .collect();

        Ok(keys)
    }

    /// Resolve public key by type
    pub async fn resolve_public_key_by_type(
        &self,
        did: &str,
        key_type: KeyType,
    ) -> Result<Option<PublicKeyInfo>> {
        let all_keys = self.resolve_all_public_keys(did).await?;
        Ok(all_keys
            .into_iter()
            .find(|k| k.key_type == key_type))
    }

    /// Resolve agent metadata
    pub async fn resolve_agent(
        &self,
        did: &str,
    ) -> Result<AgentMetadata> {
        let agent_did = AgentDID::parse(did)?;
        let address = agent_did.address()?;

        let contract = self.client.get_registry_contract()?;
        let result = contract.function("getAgent")?
            .call((address.parse::<Address>()?))
            .await?;

        Ok(AgentMetadata {
            did: agent_did,
            name: result.0,
            description: result.1,
            endpoint: result.2,
            public_keys: self.resolve_all_public_keys(did).await?,
            capabilities: result.3,
            owner: result.4,
            is_active: result.5,
            created_at: result.6.as_u64(),
            updated_at: result.7.as_u64(),
        })
    }
}
```

---

#### Task 9.4: Public Key Ownership Verification
**Priority**: HIGH (Security Critical)
**Effort**: Medium (2-3 days)

**Files to Create**:
- `src/blockchain/ownership.rs` (~200 LOC)

**Implementation**:
```rust
// src/blockchain/ownership.rs
use crate::crypto::secp256k1::Secp256k1KeyPair;
use tiny_keccak::{Hasher, Keccak};

/// Verify that an ECDSA public key is owned by the given address
pub fn verify_ecdsa_ownership(
    public_key: &[u8],
    expected_address: &str,
) -> Result<bool> {
    let derived_address = derive_ethereum_address(public_key)?;
    Ok(derived_address.to_lowercase() == expected_address.to_lowercase())
}

/// Verify ownership via signature
pub fn verify_ownership_signature(
    message: &[u8],
    signature: &[u8],
    expected_address: &str,
) -> Result<bool> {
    // Recover public key from signature
    let public_key = recover_public_key(message, signature)?;

    // Verify derived address matches
    verify_ecdsa_ownership(&public_key, expected_address)
}

/// Recover public key from ECDSA signature
pub fn recover_public_key(
    message: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    if signature.len() != 65 {
        return Err(Error::InvalidSignature("Expected 65-byte signature".into()));
    }

    // Parse signature (r, s, v)
    let r_s = &signature[..64];
    let v = signature[64];

    let sig = Signature::try_from(r_s)?;
    let recovery_id = RecoveryId::try_from(v % 27)?;

    // Hash message (Ethereum uses Keccak256)
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(message);
    keccak.finalize(&mut hash);

    // Recover public key
    let verifying_key = VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id)?;

    // Convert to uncompressed format (65 bytes)
    let public_key = verifying_key.to_encoded_point(false);
    Ok(public_key.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_ecdsa_ownership() {
        // Test vector from Go implementation
        let public_key = hex::decode(
            "04a1b2c3d4..."
        ).unwrap();
        let expected_address = "0x1234567890123456789012345678901234567890";

        assert!(verify_ecdsa_ownership(&public_key, expected_address).unwrap());
    }

    #[test]
    fn test_ownership_signature() {
        let message = b"test message";
        let signature = hex::decode("...").unwrap();
        let address = "0x...";

        assert!(verify_ownership_signature(message, &signature, address).unwrap());
    }
}
```

---

#### Task 9.5: Solana Client
**Priority**: MEDIUM
**Effort**: Medium (4-5 days)

**Files to Create**:
- `src/blockchain/solana/mod.rs`
- `src/blockchain/solana/client.rs` (~300 LOC)
- `src/blockchain/solana/resolver.rs` (~200 LOC)

**Implementation**:
```rust
// src/blockchain/solana/client.rs
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

pub struct SolanaClient {
    rpc_client: RpcClient,
    payer: Option<Keypair>,
    program_id: Pubkey,
}

impl SolanaClient {
    pub fn new(rpc_url: &str, program_id: &str) -> Result<Self> {
        let rpc_client = RpcClient::new(rpc_url.to_string());
        let program_id = program_id.parse()?;

        Ok(Self {
            rpc_client,
            payer: None,
            program_id,
        })
    }

    pub fn with_payer(mut self, keypair: Keypair) -> Self {
        self.payer = Some(keypair);
        self
    }

    pub async fn register_agent(
        &self,
        did: &str,
        name: &str,
        public_key: &[u8],
    ) -> Result<String> {
        // Solana program interaction
        // Implementation similar to Ethereum but using Solana SDK
        todo!("Implement Solana registration")
    }
}
```

---

#### Task 9.6: Multi-Chain Manager
**Priority**: HIGH
**Effort**: Medium (3-4 days)

**Files to Create**:
- `src/blockchain/manager.rs` (~350 LOC)

**Implementation**:
```rust
// src/blockchain/manager.rs
use std::collections::HashMap;
use async_trait::async_trait;

#[async_trait]
pub trait ChainClient: Send + Sync {
    async fn register_agent(
        &self,
        did: &str,
        name: &str,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<String>;

    async fn resolve_agent(&self, did: &str) -> Result<AgentMetadata>;
    async fn resolve_all_keys(&self, did: &str) -> Result<Vec<PublicKeyInfo>>;
}

pub struct MultiChainManager {
    clients: HashMap<Chain, Box<dyn ChainClient>>,
}

impl MultiChainManager {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    pub fn register_client(&mut self, chain: Chain, client: Box<dyn ChainClient>) {
        self.clients.insert(chain, client);
    }

    pub async fn register_agent(
        &self,
        chain: Chain,
        did: &str,
        name: &str,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<String> {
        let client = self.clients.get(&chain)
            .ok_or(Error::UnsupportedChain)?;

        client.register_agent(did, name, public_key, signature).await
    }

    pub async fn resolve_agent(&self, did: &str) -> Result<AgentMetadata> {
        let agent_did = AgentDID::parse(did)?;
        let chain = agent_did.chain()?;

        let client = self.clients.get(&chain)
            .ok_or(Error::UnsupportedChain)?;

        client.resolve_agent(did).await
    }

    pub async fn resolve_all_keys(&self, did: &str) -> Result<Vec<PublicKeyInfo>> {
        let agent_did = AgentDID::parse(did)?;
        let chain = agent_did.chain()?;

        let client = self.clients.get(&chain)
            .ok_or(Error::UnsupportedChain)?;

        client.resolve_all_keys(did).await
    }
}
```

---

### Phase 10: Testing and Documentation (Week 5-6)

#### Task 10.1: Comprehensive Tests
**Priority**: HIGH
**Effort**: High (5-6 days)

**Test Coverage Goals**:
- Unit tests: >85% coverage
- Integration tests: All major workflows
- Blockchain tests: Mock and testnet
- Interoperability tests: Go ↔ Rust

**Files to Create**:
- `tests/crypto_parity_tests.rs` (P-256, X25519, RSA)
- `tests/key_rotation_tests.rs`
- `tests/multi_key_tests.rs`
- `tests/blockchain_integration_tests.rs`
- `tests/ownership_verification_tests.rs`
- `tests/interop_tests.rs` (Go/Rust compatibility)

**Example**:
```rust
// tests/interop_tests.rs
#[tokio::test]
async fn test_signature_compatibility_with_go() {
    // Generate key in Rust
    let key = P256KeyPair::generate().unwrap();
    let message = b"test message";
    let signature = key.sign(message).unwrap();

    // Export public key
    let pub_key_bytes = key.public_key_bytes();

    // Verify in Go (via FFI or external process)
    let verified = verify_with_go_implementation(
        &pub_key_bytes,
        message,
        &signature,
    ).await;

    assert!(verified);
}
```

---

#### Task 10.2: Documentation
**Priority**: MEDIUM
**Effort**: Medium (3-4 days)

**Documentation Updates**:
1. **README.md**: Update feature list, version compatibility
2. **CHANGELOG.md**: Document all changes
3. **docs/MIGRATION_GUIDE.md**: Guide for upgrading from v0.3.0
4. **docs/BLOCKCHAIN_INTEGRATION.md**: Blockchain setup guide
5. **docs/KEY_ROTATION_GUIDE.md**: Key rotation best practices
6. **API documentation**: Rustdoc for all public APIs

**Example**:
```markdown
# Migration Guide: v0.3.0 → v0.4.0

## New Features

### 1. P-256 Support
```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};

let key = KeyPair::generate(KeyType::P256)?;
```

### 2. Key Rotation
```rust
use sage_crypto_core::crypto::rotation::{DefaultKeyRotator, KeyRotationConfig};

let rotator = DefaultKeyRotator::new(storage);
rotator.set_rotation_config(KeyRotationConfig {
    rotation_interval: Duration::from_secs(30 * 24 * 3600), // 30 days
    max_key_age: Duration::from_secs(90 * 24 * 3600), // 90 days
    keep_old_keys: true,
});

let new_key = rotator.rotate("my-key-id")?;
```

### 3. Blockchain Integration (Re-enabled)
```rust
use sage_crypto_core::blockchain::{EthereumClient, Network};

let client = EthereumClient::new(
    "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
    "0x1234...", // Registry contract address
    Network::EthereumSepolia,
).await?;

let receipt = client.register_agent(
    "did:sage:ethereum:0xABC...",
    "My Agent",
    &public_key,
    &signature,
).await?;
```

## Breaking Changes

1. `KeyStorage` trait now includes `exists()` method
2. Blockchain feature must be enabled: `features = ["blockchain"]`
3. DID format may include owner address (backward compatible)

## Deprecations

None in this release.
```

---

## 📦 Deliverables

### Phase 7 Deliverables
- [ ] P-256 implementation with tests
- [ ] X25519 KeyPair wrapper
- [ ] RSA256 implementation with tests
- [ ] Updated KeyType enum
- [ ] Interoperability tests with Go

### Phase 8 Deliverables
- [ ] Key rotation infrastructure
- [ ] Multi-key manager
- [ ] Storage enhancements (exists method)
- [ ] Rotation history tracking
- [ ] Auto-rotation support

### Phase 9 Deliverables
- [ ] Ethereum client (alloy-based)
- [ ] Solana client
- [ ] Multi-chain manager
- [ ] Public key ownership verification
- [ ] Enhanced DID format support
- [ ] SageRegistryV4 integration
- [ ] Contract ABI files

### Phase 10 Deliverables
- [ ] Comprehensive test suite (>85% coverage)
- [ ] Interoperability tests
- [ ] Updated documentation
- [ ] Migration guide
- [ ] API documentation (Rustdoc)
- [ ] Example applications

---

## 📈 Success Criteria

### Functional Requirements
- ✅ All cryptographic algorithms from sage v1.3.1 supported
- ✅ Key rotation with history tracking
- ✅ Multi-key support (max 10 per agent)
- ✅ Blockchain integration with Ethereum and Solana
- ✅ Public key ownership verification
- ✅ Atomic on-chain operations

### Non-Functional Requirements
- ✅ Performance: 2-4x faster than Go (maintain current benchmark)
- ✅ Test coverage: >85%
- ✅ Security: Pass audit with no HIGH/CRITICAL issues
- ✅ Documentation: Complete API docs and guides
- ✅ Interoperability: 100% compatible with sage v1.3.1

---

## ⚠️ Risk Assessment

### High Risk Areas

1. **Blockchain Reintegration**
   - **Risk**: New security vulnerabilities with alloy
   - **Mitigation**: Thorough security audit, dependency monitoring, testnet testing

2. **Interoperability**
   - **Risk**: Signature/encoding incompatibility with Go
   - **Mitigation**: Comprehensive cross-language tests, shared test vectors

3. **Key Rotation**
   - **Risk**: Race conditions, incomplete rotations
   - **Mitigation**: Atomic operations, comprehensive testing, transactional storage

### Medium Risk Areas

1. **Performance Regression**
   - **Risk**: New features slow down existing operations
   - **Mitigation**: Continuous benchmarking, profiling

2. **API Breaking Changes**
   - **Risk**: Breaking existing users
   - **Mitigation**: Semantic versioning, deprecation warnings, migration guide

---

## 📅 Timeline Estimate

| Phase | Duration | Dependencies | Completion Date |
|-------|----------|--------------|-----------------|
| Phase 7: Crypto Expansion | 1-2 weeks | None | Week 2 |
| Phase 8: Key Management | 1-2 weeks | Phase 7 | Week 4 |
| Phase 9: Blockchain | 2-3 weeks | Phase 7, 8 | Week 7 |
| Phase 10: Testing & Docs | 1-2 weeks | All previous | Week 9 |
| **Total** | **5-9 weeks** | - | **~2-2.5 months** |

---

## 🔄 Implementation Strategy

### Week-by-Week Plan

**Week 1-2**: Phase 7 (Crypto Algorithms)
- Days 1-4: P-256 implementation
- Days 5-6: X25519 wrapper
- Days 7-10: RSA256 implementation
- Days 11-14: Testing and interop validation

**Week 3-4**: Phase 8 (Key Management)
- Days 15-20: Key rotation infrastructure
- Days 21-25: Multi-key support
- Days 26-28: Storage enhancements and testing

**Week 5-7**: Phase 9 (Blockchain)
- Days 29-31: Project setup, types, DID format
- Days 32-38: Ethereum client (alloy)
- Days 39-43: Ownership verification
- Days 44-48: Solana client
- Days 49-52: Multi-chain manager

**Week 8-9**: Phase 10 (Testing & Docs)
- Days 53-58: Comprehensive testing
- Days 59-63: Documentation and examples

---

## 🛠️ Development Guidelines

### Code Quality Standards
- Follow Rust idioms and best practices
- Use `cargo clippy` and fix all warnings
- Format with `cargo fmt`
- Document all public APIs with Rustdoc
- Write tests for all new functionality

### Security Practices
- Use constant-time comparisons for crypto operations
- Zeroize sensitive data (use `zeroize` crate)
- Validate all inputs
- Use secure random number generators
- Regular dependency audits with `cargo audit`

### Testing Strategy
- Unit tests for all modules
- Integration tests for workflows
- Property-based testing for crypto (proptest)
- Fuzz testing for parsers
- Interoperability tests with Go implementation

---

## 📚 References

- sage v1.3.1 CHANGELOG: `/Users/kevin/work/github/sage-x-project/sage/CHANGELOG.md`
- sage crypto types: `/Users/kevin/work/github/sage-x-project/sage/pkg/agent/crypto/types.go`
- SageRegistryV4: `/Users/kevin/work/github/sage-x-project/sage/contracts/ethereum/contracts/SageRegistryV4.sol`
- rs-sage-core v0.3.0: Current implementation
- alloy documentation: https://alloy.rs
- Solana Rust SDK: https://docs.rs/solana-sdk

---

## ✅ Next Steps

1. **Review this plan** with stakeholders
2. **Set up development branch**: `feat/sage-v1.3.1-parity`
3. **Create GitHub project** for tracking
4. **Begin Phase 7**: P-256 implementation
5. **Set up CI/CD** for new tests
6. **Schedule weekly progress reviews**

---

**Document Version**: 2.0
**Created**: 2025-10-26
**Author**: Claude (AI Assistant)
**Status**: Draft - Awaiting Approval
