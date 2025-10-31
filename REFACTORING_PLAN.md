# rs-sage-core 리팩토링 계획서

**생성일**: 2025-10-12
**목표**: @sage/ (Go) 프로젝트의 v1.0.0 변경사항을 @rs-sage-core/ (Rust)에 반영

---

## 📊 현황 분석

### sage (Go) v1.0.0 - 2025-10-11 릴리스

**핵심 기능**:
1. ✅ **RFC 9421** HTTP Message Signatures
2. ✅ **RFC 9180 HPKE** - Hybrid Public Key Encryption
3. ✅ **4-Phase Handshake Protocol** - Invitation → Request → Response → Complete
4. ✅ **Session Management** - Session lifecycle, expiration, nonce cache
5. ✅ **Transport Layer Abstraction** - HTTP, WebSocket, MockTransport, A2A/gRPC
6. ✅ **Multi-Chain DID** - Ethereum, Solana, Kaia
7. ✅ **Smart Contracts** - SageRegistryV2, ERC-8004
8. ✅ **CLI Tools** - sage-crypto, sage-did, sage-verify
9. ✅ **85+ Tests** - 100% pass rate

**주요 컴포넌트**:
```
sage/pkg/agent/
├── core/             # Core types and interfaces
├── crypto/           # Ed25519, Secp256k1, X25519, RSA
├── did/              # Multi-chain DID (Ethereum, Solana, Kaia)
├── hpke/             # RFC 9180 HPKE implementation
│   ├── client.go     (9KB)
│   ├── server.go     (9KB)
│   └── common.go     (8KB)
├── handshake/        # 4-phase handshake protocol
│   ├── client.go     (6KB)
│   ├── server.go     (14KB)
│   └── types.go      (6KB)
├── session/          # Session management
│   ├── session.go    (22KB)
│   ├── manager.go    (12KB)
│   └── nonce.go      (2KB)
└── transport/        # Transport abstraction
    ├── http/         # HTTP/REST transport
    ├── websocket/    # WebSocket transport
    ├── a2a/          # A2A/gRPC transport
    └── interface.go  # Transport interface
```

---

### rs-sage-core (Rust) Phase 3 완료 - 2025-01-27

**현재 기능**:
1. ✅ **RFC 9421** HTTP Message Signatures
2. ✅ **Crypto** - Ed25519, Secp256k1
3. ✅ **DID** - DID document, resolver
4. ✅ **Blockchain** - Ethereum/EVM integration only
5. ✅ **77 Passing Tests**
6. ❌ **HPKE (RFC 9180)** - 없음
7. ❌ **Handshake Protocol** - 없음
8. ❌ **Session Management** - 없음
9. ❌ **Transport Layer** - 없음
10. ❌ **Multi-Chain** - Solana, Kaia 없음

**주요 컴포넌트**:
```
rs-sage-core/src/
├── core/                    # Message, VerificationService
├── crypto/                  # Ed25519, Secp256k1
├── did/                     # DID document, resolver
├── rfc9421/                 # RFC 9421 signatures
├── blockchain/ (optional)   # Ethereum only
│   ├── client.rs
│   ├── did_registry.rs
│   ├── nonce_tracker.rs
│   └── synchronizer.rs
├── ffi/ (optional)          # C FFI bindings
├── wasm/ (optional)         # WebAssembly bindings
└── formats/                 # Key import/export
```

---

## 🎯 리팩토링 목표

### Phase 4: HPKE & Handshake (우선순위: 높음)

**목표**: RFC 9180 HPKE 및 4-phase handshake 프로토콜 구현

**작업 내용**:

#### Task 4-1: HPKE (RFC 9180) 구현
- **파일**: `src/hpke/`
  - `mod.rs` - 모듈 진입점
  - `kem.rs` - X25519 Key Encapsulation Mechanism
  - `kdf.rs` - HKDF-SHA256 Key Derivation Function
  - `aead.rs` - ChaCha20-Poly1305 AEAD encryption
  - `types.rs` - HPKE types and constants
  - `client.rs` - HPKE client (sender)
  - `server.rs` - HPKE server (receiver)

- **Dependencies** 추가 (Cargo.toml):
```toml
# HPKE dependencies
x25519-dalek = "2.0"          # X25519 key exchange
chacha20poly1305 = "0.10"     # AEAD encryption
hkdf = "0.12"                 # Key derivation
```

- **API 설계**:
```rust
pub struct HpkeClient {
    ephemeral_key: X25519PrivateKey,
    shared_secret: [u8; 32],
}

impl HpkeClient {
    pub fn new() -> Self;
    pub fn encapsulate(&self, recipient_pk: &X25519PublicKey) -> (Vec<u8>, [u8; 32]);
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

pub struct HpkeServer {
    private_key: X25519PrivateKey,
    shared_secret: Option<[u8; 32]>,
}

impl HpkeServer {
    pub fn new(private_key: X25519PrivateKey) -> Self;
    pub fn decapsulate(&mut self, encapsulated_key: &[u8]) -> Result<[u8; 32]>;
    pub fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}
```

- **테스트**:
  - RFC 9180 test vectors
  - End-to-end encryption/decryption
  - Benchmarks for performance
  - Fuzzing for robustness

**예상 작업량**: 7개 파일, ~2,000 LOC

---

#### Task 4-2: Handshake Protocol 구현
- **파일**: `src/handshake/`
  - `mod.rs` - 모듈 진입점
  - `types.rs` - Handshake message types
  - `client.rs` - Handshake initiator
  - `server.rs` - Handshake responder
  - `state_machine.rs` - State transitions
  - `utils.rs` - Helper functions

- **4-Phase Protocol**:
```rust
pub enum HandshakePhase {
    Invitation,  // Phase 1: Service discovery
    Request,     // Phase 2: Ephemeral key exchange
    Response,    // Phase 3: Mutual authentication
    Complete,    // Phase 4: Session key derivation
}

pub struct HandshakeClient {
    did: String,
    private_key: PrivateKey,
    ephemeral_key: X25519PrivateKey,
    state: HandshakePhase,
}

impl HandshakeClient {
    pub fn new(did: String, private_key: PrivateKey) -> Self;
    pub fn create_invitation(&self) -> Result<InvitationMessage>;
    pub fn create_request(&mut self, invitation: InvitationMessage) -> Result<RequestMessage>;
    pub fn process_response(&mut self, response: ResponseMessage) -> Result<CompleteMessage>;
    pub fn derive_session_key(&self) -> Result<SessionKey>;
}

pub struct HandshakeServer {
    did: String,
    private_key: PrivateKey,
    state: HandshakePhase,
}

impl HandshakeServer {
    pub fn new(did: String, private_key: PrivateKey) -> Self;
    pub fn process_invitation(&self, invitation: InvitationMessage) -> Result<()>;
    pub fn process_request(&mut self, request: RequestMessage) -> Result<ResponseMessage>;
    pub fn finalize_handshake(&self, complete: CompleteMessage) -> Result<SessionKey>;
}
```

- **메시지 타입**:
```rust
#[derive(Serialize, Deserialize)]
pub struct InvitationMessage {
    pub from: String,              // Sender DID
    pub services: Vec<String>,     // Available services
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RequestMessage {
    pub from: String,
    pub to: String,
    pub ephemeral_public_key: Vec<u8>,  // X25519 public key
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseMessage {
    pub from: String,
    pub to: String,
    pub ephemeral_public_key: Vec<u8>,
    pub encapsulated_key: Vec<u8>,      // HPKE encapsulated key
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct CompleteMessage {
    pub session_id: String,
    pub encrypted_ack: Vec<u8>,         // HPKE encrypted
    pub timestamp: u64,
}
```

- **테스트**:
  - Full handshake flow tests
  - State machine transitions
  - Error handling (timeouts, invalid states)
  - Concurrent handshake tests

**예상 작업량**: 6개 파일, ~1,800 LOC

---

#### Task 4-3: Session Management 구현
- **파일**: `src/session/`
  - `mod.rs` - 모듈 진입점
  - `session.rs` - Session lifecycle
  - `manager.rs` - Session pool management
  - `nonce.rs` - Nonce cache for replay protection
  - `types.rs` - Session types

- **Session 구조**:
```rust
pub struct Session {
    id: String,
    local_did: String,
    remote_did: String,
    session_key: [u8; 32],
    created_at: SystemTime,
    expires_at: SystemTime,
    nonce_cache: HashSet<[u8; 32]>,
}

impl Session {
    pub fn new(local_did: String, remote_did: String, session_key: [u8; 32]) -> Self;
    pub fn is_expired(&self) -> bool;
    pub fn validate_nonce(&mut self, nonce: &[u8; 32]) -> Result<()>;
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub struct SessionManager {
    sessions: DashMap<String, Arc<RwLock<Session>>>,
    cleanup_interval: Duration,
}

impl SessionManager {
    pub fn new(cleanup_interval: Duration) -> Self;
    pub fn create_session(&self, local_did: String, remote_did: String, key: [u8; 32]) -> String;
    pub fn get_session(&self, session_id: &str) -> Option<Arc<RwLock<Session>>>;
    pub fn remove_session(&self, session_id: &str) -> Option<Arc<RwLock<Session>>>;
    pub fn cleanup_expired(&self);
    pub fn start_cleanup_task(&self) -> JoinHandle<()>;
}
```

- **Nonce Cache**:
```rust
pub struct NonceCache {
    cache: Arc<DashMap<String, HashSet<[u8; 32]>>>,  // DID -> nonces
    ttl: Duration,
}

impl NonceCache {
    pub fn new(ttl: Duration) -> Self;
    pub fn validate_and_mark(&self, did: &str, nonce: &[u8; 32]) -> Result<()>;
    pub fn clear_for_did(&self, did: &str);
    pub fn cleanup_expired(&self);
}
```

- **테스트**:
  - Session creation and expiration
  - Nonce replay protection
  - Concurrent session access
  - Session cleanup tests
  - Fuzzing for nonce cache

**예상 작업량**: 5개 파일, ~1,500 LOC

---

### Phase 5: Transport Layer (우선순위: 중간)

**목표**: 프로토콜에 독립적인 전송 레이어 추상화

**작업 내용**:

#### Task 5-1: Transport Abstraction 구현
- **파일**: `src/transport/`
  - `mod.rs` - 모듈 진입점
  - `interface.rs` - Transport trait 정의
  - `selector.rs` - URL 기반 자동 선택
  - `http/` - HTTP/REST transport
  - `websocket/` - WebSocket transport
  - `mock.rs` - MockTransport for testing

- **Transport Trait**:
```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, url: &str, message: &[u8]) -> Result<Vec<u8>>;
    async fn receive(&self) -> Result<Vec<u8>>;
    fn scheme(&self) -> &str;  // "http", "https", "ws", "wss"
}

pub struct TransportSelector;

impl TransportSelector {
    pub fn select(url: &str) -> Result<Box<dyn Transport>> {
        match url.split("://").next() {
            Some("http") | Some("https") => Ok(Box::new(HttpTransport::new())),
            Some("ws") | Some("wss") => Ok(Box::new(WebSocketTransport::new())),
            _ => Err(Error::UnsupportedScheme),
        }
    }
}
```

- **HTTP Transport**:
```rust
pub struct HttpTransport {
    client: reqwest::Client,
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send(&self, url: &str, message: &[u8]) -> Result<Vec<u8>> {
        let response = self.client
            .post(url)
            .body(message.to_vec())
            .send()
            .await?;
        Ok(response.bytes().await?.to_vec())
    }

    async fn receive(&self) -> Result<Vec<u8>> {
        // Not supported for HTTP (request-response only)
        Err(Error::NotSupported)
    }

    fn scheme(&self) -> &str { "http" }
}
```

- **WebSocket Transport**:
```rust
pub struct WebSocketTransport {
    connection: Arc<Mutex<Option<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&self, url: &str, message: &[u8]) -> Result<Vec<u8>> {
        // Send and wait for response
    }

    async fn receive(&self) -> Result<Vec<u8>> {
        // Receive messages
    }

    fn scheme(&self) -> &str { "ws" }
}
```

- **Dependencies** 추가:
```toml
# Transport dependencies
reqwest = { version = "0.12", features = ["json"], optional = true }
tokio-tungstenite = { version = "0.21", optional = true }
futures-util = { version = "0.3", optional = true }
```

- **Features**:
```toml
[features]
default = []
transport-http = ["reqwest"]
transport-websocket = ["tokio-tungstenite", "futures-util"]
transport-all = ["transport-http", "transport-websocket"]
```

- **테스트**:
  - HTTP transport tests
  - WebSocket transport tests
  - Transport selector tests
  - Mock transport tests

**예상 작업량**: 8개 파일, ~1,200 LOC

---

### Phase 6: Multi-Chain Support (우선순위: 낮음)

**목표**: Solana, Kaia 블록체인 지원 추가

**작업 내용**:

#### Task 6-1: Solana DID 클라이언트
- **파일**: `src/blockchain/solana/`
  - `mod.rs`
  - `client.rs` - Solana RPC client
  - `did_program.rs` - DID program interface
  - `transaction.rs` - Transaction helpers

- **Dependencies**:
```toml
solana-client = { version = "1.18", optional = true }
solana-sdk = { version = "1.18", optional = true }
```

- **Features**:
```toml
[features]
blockchain-solana = ["solana-client", "solana-sdk"]
```

**예상 작업량**: 4개 파일, ~800 LOC

---

#### Task 6-2: Kaia Network 지원
- **파일**: `src/blockchain/kaia/`
  - `mod.rs`
  - `provider.rs` - Kaia RPC provider
  - `did_registry.rs` - DID registry contract

- **참고**: Kaia는 Ethereum 호환이므로 ethers 사용 가능

**예상 작업량**: 3개 파일, ~500 LOC

---

#### Task 6-3: Multi-Chain DID Resolver
- **파일**: `src/did/multi_chain.rs`

- **API**:
```rust
pub enum ChainType {
    Ethereum,
    Solana,
    Kaia,
}

pub struct MultiChainDIDResolver {
    ethereum: Option<Arc<BlockchainDIDResolver<M>>>,
    solana: Option<Arc<SolanaDIDResolver>>,
    kaia: Option<Arc<KaiaDIDResolver>>,
}

impl MultiChainDIDResolver {
    pub async fn resolve(&self, did: &str) -> Result<DIDDocument> {
        // Parse DID method and route to appropriate resolver
        match did.split(':').nth(1) {
            Some("ethr") => self.ethereum.resolve(did).await,
            Some("sol") => self.solana.resolve(did).await,
            Some("kaia") => self.kaia.resolve(did).await,
            _ => Err(Error::UnsupportedMethod),
        }
    }
}
```

**예상 작업량**: 1개 파일, ~400 LOC

---

## 📋 전체 작업 요약

### Phase 4: HPKE & Handshake (필수)
| Task | 파일 수 | LOC | 우선순위 | 예상 기간 |
|------|---------|-----|----------|-----------|
| 4-1: HPKE 구현 | 7 | ~2,000 | 높음 | 5-7일 |
| 4-2: Handshake 구현 | 6 | ~1,800 | 높음 | 4-6일 |
| 4-3: Session 구현 | 5 | ~1,500 | 높음 | 3-5일 |
| **Phase 4 합계** | **18** | **~5,300** | - | **12-18일** |

### Phase 5: Transport Layer (권장)
| Task | 파일 수 | LOC | 우선순위 | 예상 기간 |
|------|---------|-----|----------|-----------|
| 5-1: Transport 구현 | 8 | ~1,200 | 중간 | 3-4일 |

### Phase 6: Multi-Chain (선택)
| Task | 파일 수 | LOC | 우선순위 | 예상 기간 |
|------|---------|-----|----------|-----------|
| 6-1: Solana 지원 | 4 | ~800 | 낮음 | 2-3일 |
| 6-2: Kaia 지원 | 3 | ~500 | 낮음 | 1-2일 |
| 6-3: Multi-Chain Resolver | 1 | ~400 | 낮음 | 1일 |
| **Phase 6 합계** | **8** | **~1,700** | - | **4-6일** |

### 전체 합계
- **총 파일 수**: 34개 신규/수정
- **총 코드량**: ~8,200 LOC
- **예상 기간**: 19-28일 (Phase 4-6 모두 포함 시)

---

## 🔧 기술 스택 추가 사항

### Cargo.toml 의존성 추가
```toml
[dependencies]
# 기존 dependencies...

# HPKE (RFC 9180)
x25519-dalek = { version = "2.0", optional = true }
chacha20poly1305 = { version = "0.10", optional = true }
hkdf = { version = "0.12", optional = true }

# Transport Layer
reqwest = { version = "0.12", features = ["json"], optional = true }
tokio-tungstenite = { version = "0.21", optional = true }
futures-util = { version = "0.3", optional = true }

# Multi-Chain
solana-client = { version = "1.18", optional = true }
solana-sdk = { version = "1.18", optional = true }

[features]
default = []

# HPKE support
hpke = ["x25519-dalek", "chacha20poly1305", "hkdf"]

# Handshake and Session (depends on HPKE)
handshake = ["hpke"]
session = ["hpke", "tokio"]

# Transport Layer
transport-http = ["reqwest"]
transport-websocket = ["tokio-tungstenite", "futures-util"]
transport-all = ["transport-http", "transport-websocket"]

# Multi-Chain Blockchain
blockchain-solana = ["solana-client", "solana-sdk"]
blockchain-kaia = ["ethers"]  # Reuse ethers
blockchain-all = ["blockchain", "blockchain-solana", "blockchain-kaia"]

# Full feature set
full = ["hpke", "handshake", "session", "transport-all", "blockchain-all", "ffi", "wasm"]
```

---

## ✅ 체크리스트

### Phase 4 (필수)
- [ ] Task 4-1: HPKE 구현
  - [ ] `src/hpke/kem.rs` - X25519 KEM
  - [ ] `src/hpke/kdf.rs` - HKDF
  - [ ] `src/hpke/aead.rs` - ChaCha20-Poly1305
  - [ ] `src/hpke/client.rs` - HPKE sender
  - [ ] `src/hpke/server.rs` - HPKE receiver
  - [ ] RFC 9180 test vectors
  - [ ] E2E HPKE tests
  - [ ] Benchmarks

- [ ] Task 4-2: Handshake 구현
  - [ ] `src/handshake/types.rs` - Message types
  - [ ] `src/handshake/client.rs` - Initiator
  - [ ] `src/handshake/server.rs` - Responder
  - [ ] `src/handshake/state_machine.rs` - State transitions
  - [ ] Full handshake tests
  - [ ] Error handling tests

- [ ] Task 4-3: Session 구현
  - [ ] `src/session/session.rs` - Session lifecycle
  - [ ] `src/session/manager.rs` - Session pool
  - [ ] `src/session/nonce.rs` - Nonce cache
  - [ ] Session expiration tests
  - [ ] Nonce replay protection tests
  - [ ] Concurrent access tests

### Phase 5 (권장)
- [ ] Task 5-1: Transport 구현
  - [ ] `src/transport/interface.rs` - Transport trait
  - [ ] `src/transport/http/` - HTTP transport
  - [ ] `src/transport/websocket/` - WebSocket transport
  - [ ] `src/transport/selector.rs` - Auto-selection
  - [ ] `src/transport/mock.rs` - Mock transport
  - [ ] HTTP tests
  - [ ] WebSocket tests

### Phase 6 (선택)
- [ ] Task 6-1: Solana 지원
  - [ ] `src/blockchain/solana/client.rs`
  - [ ] `src/blockchain/solana/did_program.rs`
  - [ ] Solana integration tests

- [ ] Task 6-2: Kaia 지원
  - [ ] `src/blockchain/kaia/provider.rs`
  - [ ] `src/blockchain/kaia/did_registry.rs`
  - [ ] Kaia integration tests

- [ ] Task 6-3: Multi-Chain Resolver
  - [ ] `src/did/multi_chain.rs`
  - [ ] Multi-chain routing tests

---

## 🚀 실행 계획

### 1단계: Phase 4-1 (HPKE) - Week 1
- HPKE 핵심 구현
- RFC 9180 compliance
- 테스트 및 벤치마크

### 2단계: Phase 4-2 (Handshake) - Week 2
- 4-phase handshake 프로토콜
- State machine 구현
- 통합 테스트

### 3단계: Phase 4-3 (Session) - Week 3
- Session management
- Nonce cache
- Cleanup automation

### 4단계: Phase 5 (Transport) - Week 4
- Transport abstraction
- HTTP/WebSocket 구현
- Integration with handshake

### 5단계: Phase 6 (Multi-Chain) - Week 5 (선택)
- Solana/Kaia 지원
- Multi-chain resolver
- 최종 통합 테스트

---

## 📝 참고 자료

### RFC 문서
- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 7748: Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748.html)

### sage (Go) 레퍼런스
- `sage/pkg/agent/hpke/` - HPKE 구현 참고
- `sage/pkg/agent/handshake/` - Handshake 프로토콜 참고
- `sage/pkg/agent/session/` - Session 관리 참고
- `sage/pkg/agent/transport/` - Transport 추상화 참고
- `sage/CHANGELOG.md` - v1.0.0 변경사항

### Rust Crates
- [x25519-dalek](https://docs.rs/x25519-dalek/) - X25519 key exchange
- [chacha20poly1305](https://docs.rs/chacha20poly1305/) - AEAD encryption
- [hkdf](https://docs.rs/hkdf/) - HMAC-based KDF
- [tokio-tungstenite](https://docs.rs/tokio-tungstenite/) - WebSocket
- [reqwest](https://docs.rs/reqwest/) - HTTP client

---

## 🔍 다음 단계

1. **우선순위 확정**: Phase 4 (필수), Phase 5 (권장), Phase 6 (선택)
2. **일정 조율**: 다른 세션의 sage 프로젝트 수정 완료 대기
3. **Task 시작**: Phase 4-1 (HPKE) 구현부터 시작
4. **진행 상황 추적**: 각 Task 완료 시 TODO 업데이트

---

**작성자**: Claude Code
**문서 버전**: 1.0
**최종 업데이트**: 2025-10-12
