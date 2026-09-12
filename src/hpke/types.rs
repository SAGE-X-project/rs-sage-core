//! HPKE Types and Constants
//!
//! This module defines the core types, traits, and constants for the HPKE implementation
//! based on RFC 9180 and sage (Go) v1.0.1.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Agent DID as a string (`did:sage:<chain>:<identifier>`).
pub type AgentDID = String;

/// HPKE suite identifier for X25519 + HKDF-SHA256
pub const HPKE_SUITE_ID: &str = "hpke-base+x25519+hkdf-sha256";

/// Combiner identifier for HPKE + E2E ECDH secret combination
pub const COMBINER_ID: &str = "e2e-x25519-hkdf-v1";

/// Label for ACK key derivation (sage v1.0.1)
pub const ACK_KEY_LABEL: &[u8] = b"SAGE-ack-key-v1";

/// Label for channel binding derivation (sage v1.0.1)
pub const CB_LABEL: &[u8] = b"SAGE-cb-v1";

/// Label for client-to-server encryption key derivation (sage v1.0.1)
pub const C2S_KEY_LABEL: &[u8] = b"SAGE-c2s:key";

/// Label for client-to-server IV derivation (sage v1.0.1)
pub const C2S_IV_LABEL: &[u8] = b"SAGE-c2s:iv";

/// Label for server-to-client encryption key derivation (sage v1.0.1)
pub const S2C_KEY_LABEL: &[u8] = b"SAGE-s2c:key";

/// Label for server-to-client IV derivation (sage v1.0.1)
pub const S2C_IV_LABEL: &[u8] = b"SAGE-s2c:iv";

/// Label for HPKE+E2E secret combiner
pub const COMBINER_LABEL: &[u8] = b"SAGE-HPKE+E2E-Combiner";

/// Label for ACK message HMAC
pub const ACK_MSG_LABEL: &[u8] = b"SAGE-ack-msg|v1|";

/// InfoBuilder trait for constructing HPKE info and export context strings
///
/// This trait allows customization of the HPKE context information strings
/// used during key derivation.
pub trait InfoBuilder: Send + Sync {
    /// Build the HPKE info string from context ID and participant DIDs
    ///
    /// # Arguments
    /// * `ctx_id` - Context identifier
    /// * `init_did` - Initiator's DID
    /// * `resp_did` - Responder's DID
    fn build_info(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> Vec<u8>;

    /// Build the HPKE export context string
    ///
    /// # Arguments
    /// * `ctx_id` - Context identifier
    fn build_export_context(&self, ctx_id: &str) -> Vec<u8>;
}

/// Default InfoBuilder implementation following sage v1.0.1 format
pub struct DefaultInfoBuilder;

impl InfoBuilder for DefaultInfoBuilder {
    fn build_info(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> Vec<u8> {
        format!(
            "sage/hpke-info|v1|suite={HPKE_SUITE_ID}|combiner={COMBINER_ID}|ctx={ctx_id}|init={init_did}|resp={resp_did}"
        )
        .into_bytes()
    }

    fn build_export_context(&self, ctx_id: &str) -> Vec<u8> {
        format!("sage/hpke-export|v1|suite={HPKE_SUITE_ID}|combiner={COMBINER_ID}|ctx={ctx_id}")
            .into_bytes()
    }
}

/// KeyIDBinder trait for issuing key IDs bound to context IDs (sage v1.0.1)
///
/// This trait provides a mechanism to create verifiable key IDs that are
/// bound to specific context IDs for additional security.
pub trait KeyIDBinder: Send + Sync {
    /// Issue a key ID for the given context ID
    ///
    /// # Arguments
    /// * `ctx_id` - Context identifier
    ///
    /// # Returns
    /// A tuple of (key_id, success flag)
    fn issue_key_id(&self, ctx_id: &str) -> (String, bool);
}

/// CookieVerifier trait for DoS protection (sage v1.0.1)
///
/// This trait provides cheap pre-validation of requests before expensive
/// HPKE operations are performed. Implementations can use proof-of-work,
/// rate limiting, or other DoS mitigation strategies.
pub trait CookieVerifier: Send + Sync {
    /// Verify a cookie before processing the HPKE request
    ///
    /// # Arguments
    /// * `cookie` - The cookie to verify
    /// * `ctx_id` - Context identifier
    /// * `init_did` - Initiator's DID
    /// * `resp_did` - Responder's DID
    ///
    /// # Returns
    /// `true` if the cookie is valid, `false` otherwise
    fn verify(&self, cookie: &str, ctx_id: &str, init_did: &str, resp_did: &str) -> bool;
}

/// CookieSource trait for client cookie attachment (sage v1.0.1)
///
/// This trait allows clients to attach cookies to HPKE requests for
/// DoS protection on the server side.
pub trait CookieSource: Send + Sync {
    /// Get a cookie for the given context
    ///
    /// # Arguments
    /// * `ctx_id` - Context identifier
    /// * `init_did` - Initiator's DID
    /// * `resp_did` - Responder's DID
    ///
    /// # Returns
    /// A tuple of (cookie, success flag)
    fn get_cookie(&self, ctx_id: &str, init_did: &str, resp_did: &str) -> (String, bool);
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
            PublicKey::Rsa(_, _) => "JsonWebKey2020",
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

/// HPKE initialization payload structure
///
/// This structure contains all the information needed for the HPKE handshake,
/// including ephemeral keys, nonces, and context information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeInitPayload {
    /// Encapsulated HPKE key (KEM output)
    pub enc: Vec<u8>,

    /// Client ephemeral X25519 public key for E2E secret
    #[serde(rename = "ephC")]
    pub eph_c: Vec<u8>,

    /// HPKE info string
    pub info: Vec<u8>,

    /// HPKE export context string
    #[serde(rename = "exportCtx")]
    pub export_ctx: Vec<u8>,

    /// Nonce for replay protection
    pub nonce: String,

    /// Optional cookie for DoS protection (sage v1.0.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie: Option<String>,
}

/// Traffic keys structure for bidirectional communication (sage v1.0.1)
///
/// This structure contains separate keys for client-to-server and
/// server-to-client communication, as well as a channel binding value.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct TrafficKeys {
    /// Client-to-server encryption key (32 bytes)
    pub c2s_key: [u8; 32],

    /// Client-to-server IV (12 bytes)
    pub c2s_iv: [u8; 12],

    /// Server-to-client encryption key (32 bytes)
    pub s2c_key: [u8; 32],

    /// Server-to-client IV (12 bytes)
    pub s2c_iv: [u8; 12],

    /// Channel binding value (32 bytes)
    pub channel_binding: [u8; 32],
}

/// Server signature envelope structure (sage v1.0.1)
///
/// This structure is signed by the server and returned to the client
/// to prove possession of the server's private key and bind all handshake
/// parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSigEnvelope {
    /// Version
    pub v: String,

    /// Task ID
    pub task: String,

    /// Context ID
    pub ctx: String,

    /// Key ID
    pub kid: String,

    /// Server ephemeral public key (base64)
    #[serde(rename = "ephS")]
    pub eph_s: String,

    /// ACK tag (base64)
    #[serde(rename = "ackTagB64")]
    pub ack_tag_b64: String,

    /// Timestamp
    pub ts: String,

    /// Server DID
    pub did: String,

    /// SHA256 hash of info (hex)
    #[serde(rename = "infoHash")]
    pub info_hash: String,

    /// SHA256 hash of exportCtx (hex)
    #[serde(rename = "exportCtxHash")]
    pub export_ctx_hash: String,

    /// Echoed client enc (base64)
    pub enc: String,

    /// Echoed client ephC (base64)
    #[serde(rename = "ephC")]
    pub eph_c: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_info_builder() {
        let builder = DefaultInfoBuilder;
        let info = builder.build_info("ctx-123", "did:sage:alice", "did:sage:bob");
        let info_str = String::from_utf8(info).unwrap();

        assert!(info_str.contains("sage/hpke-info|v1"));
        assert!(info_str.contains("suite=hpke-base+x25519+hkdf-sha256"));
        assert!(info_str.contains("combiner=e2e-x25519-hkdf-v1"));
        assert!(info_str.contains("ctx=ctx-123"));
        assert!(info_str.contains("init=did:sage:alice"));
        assert!(info_str.contains("resp=did:sage:bob"));
    }

    #[test]
    fn test_default_export_context() {
        let builder = DefaultInfoBuilder;
        let export_ctx = builder.build_export_context("ctx-456");
        let export_ctx_str = String::from_utf8(export_ctx).unwrap();

        assert!(export_ctx_str.contains("sage/hpke-export|v1"));
        assert!(export_ctx_str.contains("suite=hpke-base+x25519+hkdf-sha256"));
        assert!(export_ctx_str.contains("combiner=e2e-x25519-hkdf-v1"));
        assert!(export_ctx_str.contains("ctx=ctx-456"));
    }

    #[test]
    fn test_traffic_keys_zeroize() {
        let mut keys = TrafficKeys {
            c2s_key: [1u8; 32],
            c2s_iv: [2u8; 12],
            s2c_key: [3u8; 32],
            s2c_iv: [4u8; 12],
            channel_binding: [5u8; 32],
        };

        // Manually zeroize
        zeroize::Zeroize::zeroize(&mut keys);

        // Verify all fields are zeroed
        assert_eq!(keys.c2s_key, [0u8; 32]);
        assert_eq!(keys.c2s_iv, [0u8; 12]);
        assert_eq!(keys.s2c_key, [0u8; 32]);
        assert_eq!(keys.s2c_iv, [0u8; 12]);
        assert_eq!(keys.channel_binding, [0u8; 32]);
    }
}
