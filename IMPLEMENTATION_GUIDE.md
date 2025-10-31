# rs-sage-core Phase 4 구현 가이드

**생성일**: 2025-10-12
**기반**: sage (Go) v1.0.0 코드 분석
**목표**: HPKE, Handshake, Session을 Rust로 포팅

---

## 📚 sage (Go) 코드 분석 완료

### 1. HPKE (RFC 9180) 분석

**파일 구조**:
```
sage/pkg/agent/hpke/
├── types.go       (36줄)  - 상수, InfoBuilder 인터페이스
├── common.go      (312줄) - 공통 유틸리티, nonce store, payload 파싱
├── client.go      (308줄) - HPKE sender (initiator)
└── server.go      (319줄) - HPKE receiver (responder)
```

**핵심 개념**:

#### 1.1 HPKE Suite
```go
const (
    hpkeSuiteID = "hpke-base+x25519+hkdf-sha256"
    combinerID  = "e2e-x25519-hkdf-v1"  // Combines HPKE + E2E ECDH
)
```

- **KEM**: X25519 (타원 곡선 키 교환)
- **KDF**: HKDF-SHA256 (키 유도)
- **AEAD**: 실제로는 HPKE Base만 사용 (암호화 없이 키 유도만)

#### 1.2 Info Builder 패턴
```go
type InfoBuilder interface {
    BuildInfo(ctxID, initDID, respDID string) []byte
    BuildExportContext(ctxID string) []byte
}

func (DefaultInfoBuilder) BuildInfo(ctxID, initDID, respDID string) []byte {
    return []byte(
        "sage/hpke-info|v1" +
        "|suite=" + hpkeSuiteID +
        "|combiner=" + combinerID +
        "|ctx=" + ctxID +
        "|init=" + initDID +
        "|resp=" + respDID,
    )
}
```

**Rust 구현 방향**:
```rust
pub trait InfoBuilder: Send + Sync {
    fn build_info(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> Vec<u8>;
    fn build_export_context(&self, ctx_id: &str) -> Vec<u8>;
}

pub struct DefaultInfoBuilder;

impl InfoBuilder for DefaultInfoBuilder {
    fn build_info(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> Vec<u8> {
        format!(
            "sage/hpke-info|v1|suite={}|combiner={}|ctx={}|init={}|resp={}",
            HPKE_SUITE_ID, COMBINER_ID, ctx_id, init_did, resp_did
        ).into_bytes()
    }

    fn build_export_context(&self, ctx_id: &str) -> Vec<u8> {
        format!(
            "sage/hpke-export|v1|suite={}|combiner={}|ctx={}",
            HPKE_SUITE_ID, COMBINER_ID, ctx_id
        ).into_bytes()
    }
}
```

#### 1.3 HPKE Client Flow

**Go 코드 분석**:
```go
// 1. Resolve peer KEM public key (X25519)
peerKEM, err := c.resolvePeerKEM(ctx, peerDID)

// 2. Build HPKE info/export contexts
info := c.info.BuildInfo(ctxID, initDID, peerDID)
exportCtx := c.info.BuildExportContext(ctxID)

// 3. HPKE sender derivation → (enc, exporterHPKE)
enc, exporterHPKE, err := keys.HPKEDeriveSharedSecretToPeer(peerKEM, info, exportCtx, 32)

// 4. Generate client ephemeral X25519 for E2E
ephCpriv, ephCPubBytes, err := genEphX25519()

// 5. Build and sign init message
msg, err := c.buildAndSignInitMsg(...)

// 6. Send and receive server response
resp, err := c.sendAndGetSignedMsg(ctx, msg)

// 7. Parse server response (kid, ackTag, ephS)
kid, ackTag, ephSbytes, err := parseServerFieldsFromJSON(resp.Data)

// 8. Compute E2E DH: ssE2E = X25519(ephCpriv, ephSPub)
ssE2E, err := computeE2ESecret(ephCpriv, ephSbytes)

// 9. Combine secrets: combined = HKDF(exporterHPKE || ssE2E, salt=exportCtx)
combined, err := CombineSecrets(exporterHPKE, ssE2E, exportCtx)

// 10. Verify server ack tag
err := verifyAckTag(combined, ctxID, nonce, kid, ..., ackTag)

// 11. Create session and bind key ID
err := c.createAndBindSession(combined, kid)
```

**Rust 구현**:
```rust
pub struct HpkeClient {
    transport: Arc<dyn MessageTransport>,
    resolver: Arc<dyn DIDResolver>,
    keypair: KeyPair,  // Ed25519 for signing
    did: String,
    info_builder: Arc<dyn InfoBuilder>,
    session_manager: Arc<SessionManager>,
}

impl HpkeClient {
    pub async fn initialize(
        &self,
        ctx: Context,
        ctx_id: &str,
        init_did: &str,
        peer_did: &str,
    ) -> Result<String> {
        // 1. Resolve peer KEM key
        let peer_kem = self.resolve_peer_kem(&ctx, peer_did).await?;

        // 2. Build info/export contexts
        let info = self.info_builder.build_info(ctx_id, init_did, peer_did);
        let export_ctx = self.info_builder.build_export_context(ctx_id);

        // 3. HPKE sender derivation
        let (enc, exporter_hpke) = hpke_derive_sender_secrets(&peer_kem, &info, &export_ctx)?;

        // 4. Generate ephemeral X25519
        let (eph_c_priv, eph_c_pub) = generate_ephemeral_x25519()?;

        // 5. Build and sign init message
        let msg = self.build_and_sign_init_msg(
            ctx_id, init_did, peer_did, &info, &export_ctx, &enc, &eph_c_pub
        )?;

        // 6. Send and receive response
        let resp = self.transport.send(&ctx, &msg).await?;

        // 7. Parse server response
        let (kid, ack_tag, eph_s) = parse_server_response(&resp.data)?;

        // 8. Compute E2E secret
        let ss_e2e = compute_e2e_secret(&eph_c_priv, &eph_s)?;

        // 9. Combine secrets
        let combined = combine_secrets(&exporter_hpke, &ss_e2e, &export_ctx)?;

        // 10. Verify ack tag
        verify_ack_tag(&combined, ctx_id, &nonce, &kid, &info, &export_ctx,
                       &enc, &eph_c_pub, &eph_s, init_did, peer_did, &ack_tag)?;

        // 11. Create session and bind key ID
        self.create_and_bind_session(&combined, &kid).await?;

        Ok(kid)
    }
}
```

#### 1.4 HPKE Server Flow

**Go 코드 분석**:
```go
// 1. Verify sender DID and signature
senderDID, _, err := s.verifySender(ctx, msg)

// 2. Parse HPKE init payload
pl, err := ParseHPKEInitPayloadWithEphCFromJSON(msg.Payload)

// 3. Validate envelope (DID, timestamp, nonce, info/exportCtx)
err := s.validateInitEnvelope(msg, pl, senderDID)

// 4. Reproduce HPKE exporter from server skR and sender enc
exporterHPKE, err := keys.HPKEOpenSharedSecretWithPriv(s.kem.PrivateKey(), pl.Enc, pl.Info, pl.ExportCtx, 32)

// 5. Generate server ephS and compute ssE2E
ephSPubBytes, ssE2E, err := generateSrvE2E(pl.EphC)

// 6. Combine secrets
combined, err := CombineSecrets(exporterHPKE, ssE2E, pl.ExportCtx)

// 7. Create session and bind key ID
kid, err := s.createSessionAndBindKid(msg.ContextID, combined)

// 8. Compute ack tag
ack := MakeAckTag(combined, msg.ContextID, pl.Nonce, kid, ...)

// 9. Build signed response
return s.signedResponse(msg, map[string]any{
    "kid": kid,
    "ephS": base64(ephSPubBytes),
    "ackTagB64": base64(ack),
})
```

**Rust 구현**:
```rust
pub struct HpkeServer {
    keypair: KeyPair,     // Ed25519 for signing
    kem_key: KeyPair,     // X25519 KEM static key
    did: String,
    resolver: Arc<dyn DIDResolver>,
    session_manager: Arc<SessionManager>,
    info_builder: Arc<dyn InfoBuilder>,
    max_skew: Duration,
    nonce_store: Arc<NonceStore>,
    key_id_binder: Option<Arc<dyn KeyIDBinder>>,
}

impl HpkeServer {
    pub async fn handle_message(
        &self,
        ctx: Context,
        msg: &SecureMessage,
    ) -> Result<Response> {
        // 1. Verify sender
        let (sender_did, sender_pub) = self.verify_sender(&ctx, msg).await?;

        // 2. Parse payload
        let payload = parse_hpke_init_payload(&msg.payload)?;

        // 3. Validate envelope
        self.validate_init_envelope(msg, &payload, &sender_did)?;

        // 4. Reproduce exporter
        let exporter_hpke = hpke_open_shared_secret(
            &self.kem_key.private_key(),
            &payload.enc,
            &payload.info,
            &payload.export_ctx,
        )?;

        // 5. Generate server eph and compute E2E
        let (eph_s_pub, ss_e2e) = generate_server_ephemeral(&payload.eph_c)?;

        // 6. Combine secrets
        let combined = combine_secrets(&exporter_hpke, &ss_e2e, &payload.export_ctx)?;

        // 7. Create session and bind key ID
        let kid = self.create_session_and_bind_kid(&msg.context_id, &combined).await?;

        // 8. Compute ack tag
        let ack = make_ack_tag(&combined, &msg.context_id, &payload.nonce, &kid, ...)?;

        // 9. Build signed response
        Ok(self.signed_response(msg, &kid, &eph_s_pub, &ack))
    }
}
```

#### 1.5 ACK Tag 생성 (Key Confirmation)

**Go 코드**:
```go
func MakeAckTag(seed []byte, ctxID, nonce, kid string, binds ...[]byte) []byte {
    // 1. Derive ack key
    ackKey := hkdfExpand(seed, "SAGE-ack-key-v1", 32)

    // 2. Compute transcript hash
    th := sha256.New()
    for _, b := range binds {
        th.Write([]byte{0})  // delimiter
        th.Write(b)
    }
    transcriptHash := th.Sum(nil)

    // 3. Compute HMAC
    mac := hmac.New(sha256.New, ackKey)
    mac.Write([]byte("SAGE-ack-msg|v1|"))
    writeStr(mac, ctxID)   // length-prefixed
    writeStr(mac, nonce)
    writeStr(mac, kid)
    mac.Write(transcriptHash)

    return mac.Sum(nil)
}
```

**Rust 구현**:
```rust
pub fn make_ack_tag(
    seed: &[u8],
    ctx_id: &str,
    nonce: &str,
    kid: &str,
    binds: &[&[u8]],
) -> Result<Vec<u8>> {
    // 1. Derive ack key using HKDF-Expand
    let ack_key = hkdf_expand(seed, b"SAGE-ack-key-v1", 32)?;

    // 2. Compute transcript hash
    let mut hasher = Sha256::new();
    for b in binds {
        hasher.update(&[0u8]); // delimiter
        hasher.update(b);
    }
    let transcript_hash = hasher.finalize();

    // 3. Compute HMAC
    let mut mac = HmacSha256::new_from_slice(&ack_key)?;
    mac.update(b"SAGE-ack-msg|v1|");

    // Length-prefixed strings
    write_length_prefixed(&mut mac, ctx_id.as_bytes());
    write_length_prefixed(&mut mac, nonce.as_bytes());
    write_length_prefixed(&mut mac, kid.as_bytes());
    mac.update(&transcript_hash);

    Ok(mac.finalize().into_bytes().to_vec())
}

fn write_length_prefixed(mac: &mut HmacSha256, data: &[u8]) {
    let len = data.len() as u16;
    mac.update(&len.to_be_bytes());
    mac.update(data);
}
```

#### 1.6 Secret Combination

**Go 코드**:
```go
func CombineSecrets(exporterHPKE, ssE2E, exportCtx []byte) ([]byte, error) {
    // 1. Concatenate secrets
    ikm := append(exporterHPKE, ssE2E...)

    // 2. HKDF-Extract with exportCtx as salt
    prk := hkdf.Extract(sha256.New, ikm, exportCtx)

    // 3. HKDF-Expand with info="SAGE-HPKE+E2E-Combiner"
    r := hkdf.Expand(sha256.New, prk, []byte("SAGE-HPKE+E2E-Combiner"))

    out := make([]byte, 32)
    io.ReadFull(r, out)
    return out, nil
}
```

**Rust 구현**:
```rust
pub fn combine_secrets(
    exporter_hpke: &[u8],
    ss_e2e: &[u8],
    export_ctx: &[u8],
) -> Result<Vec<u8>> {
    // 1. Concatenate secrets
    let mut ikm = Vec::with_capacity(exporter_hpke.len() + ss_e2e.len());
    ikm.extend_from_slice(exporter_hpke);
    ikm.extend_from_slice(ss_e2e);

    // 2. HKDF-Extract with exportCtx as salt
    let (prk, _) = Hkdf::<Sha256>::extract(Some(export_ctx), &ikm);

    // 3. HKDF-Expand
    let mut okm = vec![0u8; 32];
    prk.expand(b"SAGE-HPKE+E2E-Combiner", &mut okm)
        .map_err(|e| Error::HkdfExpand(e.to_string()))?;

    Ok(okm)
}
```

---

### 2. Handshake Protocol 분석

**파일 구조**:
```
sage/pkg/agent/handshake/
├── types.go       (191줄) - Phase enum, message types, Events interface
├── client.go      (6.7KB)  - Handshake initiator
├── server.go      (14KB)   - Handshake responder
└── utils.go       (1.4KB)  - Utility functions
```

**핵심 개념**:

#### 2.1 4-Phase Protocol

```go
type Phase int

const (
    Invitation Phase = iota + 1  // Phase 1: Service discovery
    Request                      // Phase 2: Ephemeral key exchange
    Response                     // Phase 3: Mutual authentication
    Complete                     // Phase 4: Session confirmation
)
```

#### 2.2 Message Types

**Invitation Message**:
```go
type InvitationMessage struct {
    message.BaseMessage
    message.MessageControlHeader
}

// BaseMessage contains:
// - SessionID string
// - From string (sender DID)
// - To string (receiver DID)

// MessageControlHeader contains:
// - Sequence uint64
// - Nonce string
// - Timestamp time.Time
```

**Request Message**:
```go
type RequestMessage struct {
    message.BaseMessage
    message.MessageControlHeader
    EphemeralPubKey json.RawMessage `json:"ephemeralPublicKey"` // JWK format
}
```

**Response Message**:
```go
type ResponseMessage struct {
    message.BaseMessage
    message.MessageControlHeader
    EphemeralPubKey json.RawMessage `json:"ephemeralPublicKey"` // JWK format
    KeyID           string          `json:"keyid,omitempty"`
    Ack             bool            `json:"ack"`
}
```

**Complete Message**:
```go
type CompleteMessage struct {
    message.BaseMessage
    message.MessageControlHeader
}
```

**Rust 구현**:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Invitation = 1,
    Request = 2,
    Response = 3,
    Complete = 4,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase::Invitation => write!(f, "invitation"),
            Phase::Request => write!(f, "request"),
            Phase::Response => write!(f, "response"),
            Phase::Complete => write!(f, "complete"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InvitationMessage {
    #[serde(flatten)]
    pub base: BaseMessage,
    #[serde(flatten)]
    pub control: MessageControlHeader,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestMessage {
    #[serde(flatten)]
    pub base: BaseMessage,
    #[serde(flatten)]
    pub control: MessageControlHeader,
    #[serde(rename = "ephemeralPublicKey")]
    pub ephemeral_pub_key: serde_json::Value, // JWK format
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResponseMessage {
    #[serde(flatten)]
    pub base: BaseMessage,
    #[serde(flatten)]
    pub control: MessageControlHeader,
    #[serde(rename = "ephemeralPublicKey")]
    pub ephemeral_pub_key: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    pub ack: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompleteMessage {
    #[serde(flatten)]
    pub base: BaseMessage,
    #[serde(flatten)]
    pub control: MessageControlHeader,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseMessage {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub from: String, // sender DID
    pub to: String,   // receiver DID
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageControlHeader {
    pub sequence: u64,
    pub nonce: String,
    pub timestamp: DateTime<Utc>,
}
```

#### 2.3 Events Interface

**Go 코드**:
```go
type Events interface {
    OnInvitation(ctx context.Context, ctxID string, inv InvitationMessage) error
    OnRequest(ctx context.Context, ctxID string, req RequestMessage, senderPub crypto.PublicKey) error
    OnResponse(ctx context.Context, ctxID string, res ResponseMessage, senderPub crypto.PublicKey) error
    OnComplete(ctx context.Context, ctxID string, comp CompleteMessage, sessParams session.Params) error

    // Ask app layer to mint ephemeral X25519 keypair
    AskEphemeral(ctx context.Context, ctxID string) (rawPub []byte, jwkPub json.RawMessage, err error)
}
```

**Rust 구현**:
```rust
#[async_trait]
pub trait HandshakeEvents: Send + Sync {
    async fn on_invitation(&self, ctx: &Context, ctx_id: &str, inv: InvitationMessage) -> Result<()>;

    async fn on_request(
        &self,
        ctx: &Context,
        ctx_id: &str,
        req: RequestMessage,
        sender_pub: PublicKey,
    ) -> Result<()>;

    async fn on_response(
        &self,
        ctx: &Context,
        ctx_id: &str,
        res: ResponseMessage,
        sender_pub: PublicKey,
    ) -> Result<()>;

    async fn on_complete(
        &self,
        ctx: &Context,
        ctx_id: &str,
        comp: CompleteMessage,
        sess_params: SessionParams,
    ) -> Result<()>;

    async fn ask_ephemeral(
        &self,
        ctx: &Context,
        ctx_id: &str,
    ) -> Result<(Vec<u8>, serde_json::Value)>; // (raw_pub, jwk_pub)
}

// Default no-op implementation
pub struct NoopEvents;

#[async_trait]
impl HandshakeEvents for NoopEvents {
    async fn on_invitation(&self, _: &Context, _: &str, _: InvitationMessage) -> Result<()> {
        Ok(())
    }

    async fn on_request(&self, _: &Context, _: &str, _: RequestMessage, _: PublicKey) -> Result<()> {
        Ok(())
    }

    async fn on_response(&self, _: &Context, _: &str, _: ResponseMessage, _: PublicKey) -> Result<()> {
        Ok(())
    }

    async fn on_complete(&self, _: &Context, _: &str, _: CompleteMessage, _: SessionParams) -> Result<()> {
        Ok(())
    }

    async fn ask_ephemeral(&self, _: &Context, _: &str) -> Result<(Vec<u8>, serde_json::Value)> {
        Err(Error::NotImplemented("ask_ephemeral not implemented".into()))
    }
}
```

---

### 3. Session Management 분석

**파일 구조**:
```
sage/pkg/agent/session/
├── types.go          (64줄)  - Session interface, Config, Status
├── session.go        (22KB)  - Session implementation
├── manager.go        (12KB)  - SessionManager
├── nonce.go          (2.5KB) - Nonce cache
└── metadata.go       (2.9KB) - Session metadata
```

**핵심 개념**:

#### 3.1 Session Interface

**Go 코드**:
```go
type Session interface {
    // Identification
    GetID() string
    GetCreatedAt() time.Time
    GetLastUsedAt() time.Time

    // Lifecycle
    IsExpired() bool
    UpdateLastUsed()
    Close() error

    // Cryptographic operations
    Encrypt(plaintext []byte) ([]byte, error)
    Decrypt(data []byte) ([]byte, error)
    EncryptAndSign(plaintext []byte, covered []byte) ([]byte, []byte, error)
    DecryptAndVerify(cipher []byte, covered []byte, mac []byte) ([]byte, error)
    SignCovered(covered []byte) []byte
    VerifyCovered(covered, sig []byte) error

    // Statistics
    GetMessageCount() int
    GetConfig() Config
}

type Config struct {
    MaxAge      time.Duration // absolute expiration
    IdleTimeout time.Duration // idle timeout
    MaxMessages int
}
```

**Rust 구현**:
```rust
#[async_trait]
pub trait Session: Send + Sync {
    // Identification
    fn get_id(&self) -> &str;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_last_used_at(&self) -> DateTime<Utc>;

    // Lifecycle
    fn is_expired(&self) -> bool;
    fn update_last_used(&mut self);
    async fn close(&mut self) -> Result<()>;

    // Cryptographic operations
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt_and_sign(
        &self,
        plaintext: &[u8],
        covered: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)>; // (ciphertext, mac)
    async fn decrypt_and_verify(
        &self,
        cipher: &[u8],
        covered: &[u8],
        mac: &[u8],
    ) -> Result<Vec<u8>>;
    fn sign_covered(&self, covered: &[u8]) -> Vec<u8>;
    fn verify_covered(&self, covered: &[u8], sig: &[u8]) -> Result<()>;

    // Statistics
    fn get_message_count(&self) -> usize;
    fn get_config(&self) -> &SessionConfig;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub max_age: Duration,      // absolute expiration (e.g., 1 hour)
    pub idle_timeout: Duration, // idle timeout (e.g., 10 minutes)
    pub max_messages: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(3600),       // 1 hour
            idle_timeout: Duration::from_secs(600),   // 10 minutes
            max_messages: 10_000,
        }
    }
}
```

#### 3.2 Session Manager

**Go 코드 핵심 메서드**:
```go
type Manager struct {
    sessions  sync.Map  // map[string]*SecureSession
    keyToSess sync.Map  // map[string]string (keyID -> sessionID)
    // ...
}

// Create session from combined secret
func (m *Manager) EnsureSessionFromExporterWithRole(
    exporter []byte,
    info string,
    initiator bool,
    opts *SessionOpts,
) (*SecureSession, string, []byte, error)

// Bind key ID to session
func (m *Manager) BindKeyID(keyID, sessionID string)

// Get session by key ID
func (m *Manager) GetByKeyID(keyID string) (*SecureSession, bool)
```

**Rust 구현**:
```rust
pub struct SessionManager {
    sessions: DashMap<String, Arc<RwLock<SecureSession>>>,
    key_to_session: DashMap<String, String>, // keyID -> sessionID
    config: SessionManagerConfig,
    cleanup_handle: Option<JoinHandle<()>>,
}

impl SessionManager {
    pub fn new(config: SessionManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            key_to_session: DashMap::new(),
            config,
            cleanup_handle: None,
        })
    }

    pub async fn ensure_session_from_exporter_with_role(
        &self,
        exporter: &[u8],
        info: &str,
        initiator: bool,
        opts: Option<SessionOpts>,
    ) -> Result<(Arc<RwLock<SecureSession>>, String, Vec<u8>)> {
        // Derive session key from exporter using HKDF
        // Create SecureSession
        // Store in sessions map
        // Return (session, session_id, derived_key)
    }

    pub fn bind_key_id(&self, key_id: &str, session_id: &str) {
        self.key_to_session.insert(key_id.to_string(), session_id.to_string());
    }

    pub fn get_by_key_id(&self, key_id: &str) -> Option<Arc<RwLock<SecureSession>>> {
        self.key_to_session
            .get(key_id)
            .and_then(|sid| self.sessions.get(sid.value()).map(|s| s.value().clone()))
    }

    pub fn start_cleanup_task(self: &Arc<Self>) -> JoinHandle<()> {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(mgr.config.cleanup_interval);
            loop {
                interval.tick().await;
                mgr.cleanup_expired();
            }
        })
    }

    fn cleanup_expired(&self) {
        self.sessions.retain(|_, session| {
            !session.read().unwrap().is_expired()
        });
    }
}
```

#### 3.3 Nonce Cache (Replay Protection)

**Go 코드**:
```go
type nonceStore struct {
    ttl     time.Duration
    mu      sync.Mutex
    entries map[string]time.Time
}

func (s *nonceStore) checkAndMark(key string) bool {
    now := time.Now()
    exp := now.Add(s.ttl)
    s.mu.Lock()
    defer s.mu.Unlock()

    // Cleanup expired
    for k, v := range s.entries {
        if now.After(v) {
            delete(s.entries, k)
        }
    }

    // Check replay
    if _, ok := s.entries[key]; ok {
        return false // replay!
    }

    // Mark as used
    s.entries[key] = exp
    return true
}
```

**Rust 구현**:
```rust
pub struct NonceStore {
    ttl: Duration,
    entries: Arc<DashMap<String, DateTime<Utc>>>,
}

impl NonceStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Arc::new(DashMap::new()),
        }
    }

    pub fn check_and_mark(&self, key: &str) -> bool {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(self.ttl).unwrap();

        // Cleanup expired (async background task would be better)
        self.entries.retain(|_, v| *v > now);

        // Check replay
        if self.entries.contains_key(key) {
            return false; // replay detected!
        }

        // Mark as used
        self.entries.insert(key.to_string(), exp);
        true
    }

    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        self.entries.retain(|_, v| *v > now);
    }

    pub fn clear_for_key(&self, key: &str) {
        self.entries.remove(key);
    }
}
```

---

### 4. Transport Layer 분석

**파일 구조**:
```
sage/pkg/agent/transport/
├── interface.go       (99줄)  - MessageTransport interface
├── selector.go        - URL 기반 자동 선택
├── mock.go            - MockTransport for testing
├── http/              - HTTP transport
├── websocket/         - WebSocket transport
└── a2a/               - A2A/gRPC transport (optional)
```

**핵심 인터페이스**:

**Go 코드**:
```go
type MessageTransport interface {
    Send(ctx context.Context, msg *SecureMessage) (*Response, error)
}

type SecureMessage struct {
    ID        string
    ContextID string
    TaskID    string
    Payload   []byte
    DID       string
    Signature []byte
    Metadata  map[string]string
    Role      string // "user" or "agent"
}

type Response struct {
    Success   bool
    MessageID string
    TaskID    string
    Data      []byte
    Error     error
}
```

**Rust 구현**:
```rust
#[async_trait]
pub trait MessageTransport: Send + Sync {
    async fn send(&self, ctx: &Context, msg: &SecureMessage) -> Result<Response>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    pub id: String,
    pub context_id: String,
    pub task_id: String,
    pub payload: Vec<u8>,
    pub did: String,
    pub signature: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub role: String, // "user" or "agent"
}

#[derive(Debug, Clone)]
pub struct Response {
    pub success: bool,
    pub message_id: String,
    pub task_id: String,
    pub data: Vec<u8>,
}
```

---

## 🎯 Phase 4-1: HPKE 구현 계획

### 파일 구조
```
rs-sage-core/src/hpke/
├── mod.rs          - 모듈 진입점, 재export
├── types.rs        - 상수, InfoBuilder trait, HPKEInitPayload 등
├── common.rs       - 공통 유틸리티 (ack_tag, combine_secrets)
├── nonce_store.rs  - NonceStore 구현
├── client.rs       - HpkeClient 구현
└── server.rs       - HpkeServer 구현
```

### 의존성 추가
```toml
[dependencies]
# X25519 key exchange
x25519-dalek = "2.0"

# HKDF for key derivation
hkdf = "0.12"

# SHA-256
sha2 = "0.10"

# HMAC
hmac = "0.12"

# Async runtime
tokio = { version = "1.0", features = ["full"] }
async-trait = "0.1"

# Concurrent collections
dashmap = "5.5"

# UUID
uuid = { version = "1.6", features = ["v4", "serde"] }

# JSON
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Base64
base64 = "0.21"

# DateTime
chrono = { version = "0.4", features = ["serde"] }
```

### 구현 우선순위
1. **types.rs** - InfoBuilder trait, 상수, payload types
2. **common.rs** - combine_secrets, make_ack_tag, HKDF 유틸리티
3. **nonce_store.rs** - NonceStore (replay protection)
4. **client.rs** - HpkeClient (sender)
5. **server.rs** - HpkeServer (receiver)

### 테스트 계획
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_builder() {
        let builder = DefaultInfoBuilder;
        let info = builder.build_info("ctx-1", "did:sage:init", "did:sage:resp");
        assert!(info.starts_with(b"sage/hpke-info|v1"));
    }

    #[test]
    fn test_combine_secrets() {
        let exporter = vec![0u8; 32];
        let ss_e2e = vec![1u8; 32];
        let export_ctx = b"test-context";

        let combined = combine_secrets(&exporter, &ss_e2e, export_ctx).unwrap();
        assert_eq!(combined.len(), 32);
    }

    #[tokio::test]
    async fn test_hpke_client_server_flow() {
        // Full integration test
        // 1. Setup client and server
        // 2. Client initiates HPKE
        // 3. Server responds
        // 4. Verify ack tag
        // 5. Both create matching sessions
    }
}
```

---

## 📝 다음 단계

1. **Phase 4-1 시작**: HPKE 구현
   - `src/hpke/types.rs` 작성
   - `src/hpke/common.rs` 작성
   - `src/hpke/nonce_store.rs` 작성
   - `src/hpke/client.rs` 작성
   - `src/hpke/server.rs` 작성
   - 테스트 작성 및 검증

2. **Phase 4-2**: Handshake 구현
3. **Phase 4-3**: Session 구현
4. **Phase 5**: Transport Layer
5. **Phase 6**: Multi-Chain (선택)

---

**작성자**: Claude Code
**문서 버전**: 1.0
**최종 업데이트**: 2025-10-12
