//! HPKE handshake types (sage-spec `04-hpke.md`).

use crate::error::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

/// Agent DID as a string (`did:sage:<chain>:<identifier>`).
pub type AgentDID = String;

/// HPKE suite identifier
pub const HPKE_SUITE_ID: &str = "hpke-base+x25519+hkdf-sha256";
/// Combiner identifier
pub const COMBINER_ID: &str = "e2e-x25519-hkdf-v1";
/// HPKE `info` label
pub const INFO_LABEL: &str = "sage/hpke-info|v1";
/// HPKE export-context label
pub const EXPORT_CTX_LABEL: &str = "sage/hpke-export|v1";
/// Task id of the handshake completion message
pub const TASK_HPKE_COMPLETE: &str = "hpke/complete@v1";
/// Envelope version
pub const ENVELOPE_VERSION: &str = "v1";
/// Label for ACK key derivation
pub const ACK_KEY_LABEL: &[u8] = b"SAGE-ack-key-v1";
/// Label for channel binding derivation
pub const CB_LABEL: &[u8] = b"SAGE-cb-v1";
/// Label for client-to-server key
pub const C2S_KEY_LABEL: &[u8] = b"SAGE-c2s:key";
/// Label for client-to-server IV
pub const C2S_IV_LABEL: &[u8] = b"SAGE-c2s:iv";
/// Label for server-to-client key
pub const S2C_KEY_LABEL: &[u8] = b"SAGE-s2c:key";
/// Label for server-to-client IV
pub const S2C_IV_LABEL: &[u8] = b"SAGE-s2c:iv";
/// HKDF-Expand info of the secret combiner
pub const COMBINER_LABEL: &[u8] = b"SAGE-HPKE+E2E-Combiner";
/// Prefix of the ACK message
pub const ACK_MSG_LABEL: &[u8] = b"SAGE-ack-msg|v1|";
/// Session label used for HPKE sessions
pub const SESSION_LABEL: &str = "sage/hpke+e2e v1";

/// Builds the HPKE `info` and export-context strings.
pub trait InfoBuilder: Send + Sync {
    /// `info` for `SetupBase`
    fn build_info(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> Vec<u8>;
    /// Export context (also the combiner salt)
    fn build_export_context(&self, ctx_id: &str) -> Vec<u8>;
}

/// The sage-spec strings (`04-hpke.md` §2).
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultInfoBuilder;

impl InfoBuilder for DefaultInfoBuilder {
    fn build_info(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> Vec<u8> {
        format!(
            "{INFO_LABEL}|suite={HPKE_SUITE_ID}|combiner={COMBINER_ID}|ctx={ctx_id}|init={init_did}|resp={resp_did}"
        )
        .into_bytes()
    }

    fn build_export_context(&self, ctx_id: &str) -> Vec<u8> {
        format!("{EXPORT_CTX_LABEL}|suite={HPKE_SUITE_ID}|combiner={COMBINER_ID}|ctx={ctx_id}")
            .into_bytes()
    }
}

/// Issues the session key id the responder returns (`kid-<uuid>` by default).
pub trait KeyIDBinder: Send + Sync {
    /// Returns `(kid, true)` to override the default.
    fn issue_key_id(&self, ctx_id: &str) -> (String, bool);
}

/// Verifies a denial-of-service cookie before any public-key work.
pub trait CookieVerifier: Send + Sync {
    /// Whether the cookie is acceptable for this handshake.
    fn verify(&self, cookie: &str, ctx_id: &str, init_did: &str, resp_did: &str) -> bool;
}

/// Supplies a denial-of-service cookie for a handshake.
pub trait CookieSource: Send + Sync {
    /// Returns `(cookie, true)` when a cookie should be attached.
    fn get_cookie(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> (String, bool);
}

/// Resolves the responder's static X25519 KEM key (`public_kem_key` of the
/// registry record).
pub trait KemKeyResolver: Send + Sync {
    /// The 32-byte X25519 public key of `did`.
    fn resolve_kem_key(&self, did: &str) -> Result<[u8; 32]>;
}

/// Resolves an agent's signing public key.
pub trait SigningKeyResolver: Send + Sync {
    /// The signing key of `did`.
    fn resolve_signing_key(&self, did: &str) -> Result<crate::crypto::PublicKey>;
}

/// Traffic keys derived from the session seed (`04-hpke.md` §4).
#[derive(Debug, Clone)]
pub struct TrafficKeys {
    /// Client-to-server key
    pub c2s_key: [u8; 32],
    /// Client-to-server IV
    pub c2s_iv: [u8; 12],
    /// Server-to-client key
    pub s2c_key: [u8; 32],
    /// Server-to-client IV
    pub s2c_iv: [u8; 12],
    /// Channel binding value
    pub channel_binding: [u8; 32],
}

/// The initiator's payload (`04-hpke.md` §6). `info` and `export_ctx` are
/// sent as JSON strings; `enc` and `eph_c` as base64url without padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeInitPayload {
    /// Initiator DID
    pub init_did: String,
    /// Responder DID
    pub resp_did: String,
    /// The `info` bytes (ASCII)
    pub info: Vec<u8>,
    /// The export context bytes (ASCII)
    pub export_ctx: Vec<u8>,
    /// Nonce, unique per context
    pub nonce: String,
    /// RFC 3339 timestamp with nanoseconds
    pub ts: String,
    /// HPKE encapsulated key (32 bytes)
    pub enc: Vec<u8>,
    /// Initiator ephemeral X25519 public key (32 bytes)
    pub eph_c: Vec<u8>,
    /// Optional denial-of-service cookie (carried in transport metadata by the Go core)
    pub cookie: Option<String>,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(v: &JsonValue, key: &str) -> Result<Vec<u8>> {
    let s = v
        .get(key)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::InvalidInput(format!("missing {key}")))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::InvalidInput(format!("{key} is not base64url")))
}

fn text(v: &JsonValue, key: &str) -> Result<String> {
    v.get(key)
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::InvalidInput(format!("missing {key}")))
}

impl HpkeInitPayload {
    /// Serialise as the JSON object the Go core sends.
    pub fn to_json(&self) -> JsonValue {
        let mut v = json!({
            "initDid": self.init_did,
            "respDid": self.resp_did,
            "info": String::from_utf8_lossy(&self.info),
            "exportCtx": String::from_utf8_lossy(&self.export_ctx),
            "nonce": self.nonce,
            "ts": self.ts,
            "enc": b64(&self.enc),
            "ephC": b64(&self.eph_c),
        });
        if let Some(c) = &self.cookie {
            v["cookie"] = JsonValue::String(c.clone());
        }
        v
    }

    /// Serialise to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.to_json()).unwrap_or_default()
    }

    /// Parse the JSON object; `enc` and `ephC` must be 32 bytes.
    pub fn from_json(v: &JsonValue) -> Result<Self> {
        let enc = unb64(v, "enc")?;
        let eph_c = unb64(v, "ephC")?;
        if enc.len() != 32 || eph_c.len() != 32 {
            return Err(Error::InvalidInput("enc and ephC must be 32 bytes".into()));
        }
        Ok(Self {
            init_did: text(v, "initDid")?,
            resp_did: text(v, "respDid")?,
            info: text(v, "info")?.into_bytes(),
            export_ctx: text(v, "exportCtx")?.into_bytes(),
            nonce: text(v, "nonce")?,
            ts: text(v, "ts")?,
            enc,
            eph_c,
            cookie: v
                .get("cookie")
                .and_then(JsonValue::as_str)
                .map(str::to_string),
        })
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let v: JsonValue = serde_json::from_slice(data)
            .map_err(|e| Error::InvalidInput(format!("payload: {e}")))?;
        Self::from_json(&v)
    }
}

/// The responder's signed envelope (`04-hpke.md` §6). Binary members are
/// base64url without padding; `sig_b64` is a detached signature over the
/// JCS form of the other members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSigEnvelope {
    /// `"v1"`
    pub v: String,
    /// `"hpke/complete@v1"`
    pub task: String,
    /// Context id
    pub ctx: String,
    /// Session key id
    pub kid: String,
    /// Responder ephemeral public key
    #[serde(rename = "ephS")]
    pub eph_s: String,
    /// ACK tag
    #[serde(rename = "ackTagB64")]
    pub ack_tag_b64: String,
    /// RFC 3339 timestamp
    pub ts: String,
    /// Responder DID
    pub did: String,
    /// SHA-256 of `info`
    #[serde(rename = "infoHash")]
    pub info_hash: String,
    /// SHA-256 of the export context
    #[serde(rename = "exportCtxHash")]
    pub export_ctx_hash: String,
    /// Echoed `enc`
    pub enc: String,
    /// Echoed `ephC`
    #[serde(rename = "ephC")]
    pub eph_c: String,
    /// Detached signature (absent while signing)
    #[serde(rename = "sigB64", skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
}

impl ServerSigEnvelope {
    /// JCS bytes of the envelope without `sigB64` (what is signed).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.sig_b64 = None;
        let json =
            serde_json::to_vec(&unsigned).map_err(|e| Error::Serialization(e.to_string()))?;
        crate::jcs::canonicalize(&json)
    }

    /// Decode a base64url member.
    pub fn decode(&self, member: &str) -> Result<Vec<u8>> {
        let s = match member {
            "ephS" => &self.eph_s,
            "ackTagB64" => &self.ack_tag_b64,
            "infoHash" => &self.info_hash,
            "exportCtxHash" => &self.export_ctx_hash,
            "enc" => &self.enc,
            "ephC" => &self.eph_c,
            "sigB64" => self.sig_b64.as_deref().unwrap_or(""),
            other => return Err(Error::InvalidInput(format!("unknown member {other}"))),
        };
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| Error::InvalidInput(format!("{member} is not base64url")))
    }

    /// Encode a base64url member.
    pub fn b64(bytes: &[u8]) -> String {
        b64(bytes)
    }
}

/// Verification reference in DID document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationReference {
    /// Reference to a verification method by ID
    Reference(String),
    /// Embedded verification method
    Embedded(VerificationMethod),
}

/// DID Document representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    /// DID subject
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// DID of the subject
    pub id: String,
    /// Verification methods
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication methods
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<VerificationReference>,
}

impl DIDDocument {
    /// Create a new DID document
    pub fn new(did: AgentDID) -> Self {
        let id = did;

        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
                "https://w3id.org/security/suites/secp256k1-2020/v1".to_string(),
            ],
            id,
            verification_method: Vec::new(),
            authentication: Vec::new(),
        }
    }

    /// Add a verification method
    pub fn add_verification_method(&mut self, vm: VerificationMethod) {
        self.verification_method.push(vm);
    }

    /// Add an authentication reference
    pub fn add_authentication(&mut self, auth: VerificationReference) {
        self.authentication.push(auth);
    }
}

/// Verification method in DID document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Verification method id (`<did>#<fragment>`)
    pub id: String,
    /// Verification method type (for example `Ed25519VerificationKey2020`)
    #[serde(rename = "type")]
    pub method_type: String,
    /// Controller DID
    pub controller: String,
    /// Public key in multibase encoding
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    /// Public key as a JWK
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<JsonValue>,
}

impl VerificationMethod {
    /// Create verification method from public key
    pub fn from_public_key(
        did: &AgentDID,
        key_id: &str,
        public_key: &crate::crypto::PublicKey,
    ) -> Self {
        use crate::crypto::PublicKey;

        let did_str = did.clone();

        let key_bytes = public_key.to_bytes();
        let key_multibase = format!("z{}", bs58::encode(&key_bytes).into_string());

        // Determine method type based on key type
        let method_type = match public_key {
            PublicKey::Ed25519(_) => "Ed25519VerificationKey2020",
            PublicKey::P256(_) => "JsonWebKey2020",
            PublicKey::Secp256k1(_) => "EcdsaSecp256k1VerificationKey2019",
        };

        Self {
            id: format!("{did_str}#{key_id}"),
            method_type: method_type.to_string(),
            controller: did_str,
            public_key_multibase: Some(key_multibase),
            public_key_jwk: None,
        }
    }
}

/// DID Resolution result
#[derive(Debug, Clone)]
pub struct DIDResolutionResult {
    /// Resolved DID document
    pub document: Option<DIDDocument>,
    /// Resolution metadata
    pub metadata: Option<JsonValue>,
}

/// DID Resolver trait for resolving DIDs to DID documents
///
/// This trait provides blockchain-based DID resolution for HPKE handshakes.
pub trait DIDResolver: Send + Sync {
    /// Resolve a DID to its DID document
    ///
    /// # Arguments
    /// * `did` - The DID to resolve
    ///
    /// # Returns
    /// DID resolution result containing the document and metadata
    fn resolve(&self, did: &AgentDID) -> Result<DIDResolutionResult>;
}
