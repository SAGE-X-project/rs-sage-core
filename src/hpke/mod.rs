//! HPKE handshake (RFC 9180 base mode, X25519-HKDF-SHA256, HKDF-SHA256,
//! ChaCha20-Poly1305, export only) as profiled by sage-spec `04-hpke.md`:
//! the initiator encapsulates to the responder's static KEM key and both
//! sides combine the HPKE exporter with an ephemeral X25519 secret into the
//! session seed; the responder answers with a signed, JCS-canonicalised
//! envelope carrying an ACK tag over the whole transcript.
//!
//! ```no_run
//! use std::sync::Arc;
//! use sage_crypto_core::crypto::{KeyPair, KeyType, X25519KeyPair};
//! use sage_crypto_core::hpke::{HpkeClient, HpkeServer, MemoryKeyResolver};
//!
//! let a = KeyPair::generate(KeyType::Ed25519).unwrap();
//! let b = KeyPair::generate(KeyType::Ed25519).unwrap();
//! let kem = X25519KeyPair::generate();
//! let resolver = Arc::new(MemoryKeyResolver::new());
//! resolver.add_signing_key("did:sage:ethereum:0xb", b.public_key().clone());
//! resolver.add_kem_key("did:sage:ethereum:0xb", *kem.public_key_bytes());
//!
//! let client = HpkeClient::new("did:sage:ethereum:0xa", a, resolver.clone(), resolver);
//! let server = HpkeServer::new("did:sage:ethereum:0xb", b, kem.private_key_bytes());
//! let state = client.initialize("ctx-1", "did:sage:ethereum:0xb").unwrap();
//! let handled = server.handle_init("ctx-1", "did:sage:ethereum:0xa", state.payload()).unwrap();
//! let session = client.complete(state, &handled.envelope).unwrap();
//! assert_eq!(*session.seed, *handled.seed);
//! ```

pub mod client;
pub mod common;
pub mod nonce_store;
pub mod resolver;
pub mod server;
pub mod types;

pub use client::{HpkeClient, HpkeClientConfig, HpkeClientSession, HpkeClientState};
pub use common::{
    combine_secrets, derive_traffic_keys, hmac_expand, is_all_zero_32, kem_open, kem_seal,
    make_ack_tag, sha256_hash, sha256_hash_hex, verify_ack_tag, zero_bytes,
};
pub use nonce_store::NonceStore;
pub use resolver::{DidDocumentKemResolver, MemoryKeyResolver};
pub use server::{HpkeServer, HpkeServerConfig, HpkeServerSession};
pub use types::{
    CookieSource, CookieVerifier, DefaultInfoBuilder, HpkeInitPayload, InfoBuilder, KemKeyResolver,
    KeyIDBinder, ServerSigEnvelope, SigningKeyResolver, TrafficKeys, ACK_KEY_LABEL, ACK_MSG_LABEL,
    C2S_IV_LABEL, C2S_KEY_LABEL, CB_LABEL, COMBINER_ID, COMBINER_LABEL, ENVELOPE_VERSION,
    EXPORT_CTX_LABEL, HPKE_SUITE_ID, INFO_LABEL, S2C_IV_LABEL, S2C_KEY_LABEL, SESSION_LABEL,
    TASK_HPKE_COMPLETE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType, X25519KeyPair};
    use crate::session::{SecureSession, SessionConfig};
    use std::sync::Arc;

    fn setup() -> (HpkeClient, HpkeServer, Arc<MemoryKeyResolver>) {
        let a = KeyPair::generate(KeyType::Ed25519).unwrap();
        let b = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let kem = X25519KeyPair::generate();
        let resolver = Arc::new(MemoryKeyResolver::new());
        resolver.add_signing_key("did:sage:ethereum:0xb", b.public_key().clone());
        resolver.add_kem_key("did:sage:ethereum:0xb", *kem.public_key_bytes());
        let client = HpkeClient::new(
            "did:sage:ethereum:0xa",
            a,
            resolver.clone(),
            resolver.clone(),
        );
        let server = HpkeServer::new("did:sage:ethereum:0xb", b, kem.private_key_bytes());
        (client, server, resolver)
    }

    #[test]
    fn handshake_yields_a_shared_session() {
        let (client, server, _) = setup();
        let state = client.initialize("ctx-1", "did:sage:ethereum:0xb").unwrap();
        // the payload survives its JSON encoding
        let json = state.payload().to_bytes();
        let parsed = HpkeInitPayload::from_bytes(&json).unwrap();
        assert_eq!(&parsed, state.payload());
        let handled = server
            .handle_init_detailed("ctx-1", "did:sage:ethereum:0xa", &parsed)
            .unwrap();
        let env_json = serde_json::to_vec(&handled.envelope).unwrap();
        let envelope: ServerSigEnvelope = serde_json::from_slice(&env_json).unwrap();
        let session = client.complete(state, &envelope).unwrap();
        assert_eq!(*session.seed, *handled.seed);
        assert_eq!(session.kid, handled.kid);
        assert_eq!(session.session_id, handled.session_id);
        let init = SecureSession::with_role(
            session.session_id.clone(),
            &session.seed,
            true,
            SessionConfig::default(),
        )
        .unwrap();
        let resp = SecureSession::with_role(
            handled.session_id.clone(),
            &handled.seed,
            false,
            SessionConfig::default(),
        )
        .unwrap();
        let record = init.encrypt_outbound(b"hello").unwrap();
        assert_eq!(resp.decrypt_inbound(&record).unwrap(), b"hello");
    }

    #[test]
    fn responder_rejects_bad_payloads() {
        let (client, server, _) = setup();
        let state = client.initialize("ctx-1", "did:sage:ethereum:0xb").unwrap();
        let p = state.payload().clone();
        assert!(
            server
                .handle_init_detailed("ctx-1", "did:sage:ethereum:0xother", &p)
                .is_err(),
            "signer mismatch"
        );
        let mut wrong = p.clone();
        wrong.resp_did = "did:sage:ethereum:0xc".into();
        assert!(
            server
                .handle_init_detailed("ctx-1", "did:sage:ethereum:0xa", &wrong)
                .is_err(),
            "respDid"
        );
        let mut old = p.clone();
        old.ts = "2020-01-01T00:00:00Z".into();
        assert!(
            server
                .handle_init_detailed("ctx-1", "did:sage:ethereum:0xa", &old)
                .is_err(),
            "ts"
        );
        assert!(
            server
                .handle_init_detailed("ctx-2", "did:sage:ethereum:0xa", &p)
                .is_err(),
            "info for another ctx"
        );
        assert!(server
            .handle_init_detailed("ctx-1", "did:sage:ethereum:0xa", &p)
            .is_ok());
        assert!(
            server
                .handle_init_detailed("ctx-1", "did:sage:ethereum:0xa", &p)
                .is_err(),
            "replay"
        );
        // generic error hides the reason
        let err = server
            .handle_init("ctx-1", "did:sage:ethereum:0xa", &p)
            .err()
            .expect("replay must be rejected");
        assert!(
            matches!(err, crate::error::Error::Verification(ref m) if m == "authentication failed"),
            "{err}"
        );
    }

    #[test]
    fn initiator_rejects_tampered_envelopes() {
        let (client, server, _) = setup();
        let state = client.initialize("ctx-1", "did:sage:ethereum:0xb").unwrap();
        let handled = server
            .handle_init_detailed("ctx-1", "did:sage:ethereum:0xa", state.payload())
            .unwrap();
        let mut env = handled.envelope.clone();
        env.kid = "kid-other".into();
        assert!(
            client.complete(state, &env).is_err(),
            "signature no longer matches"
        );
        let state = client.initialize("ctx-1", "did:sage:ethereum:0xb").unwrap();
        let mut env = handled.envelope.clone();
        env.sig_b64 = None;
        assert!(client.complete(state, &env).is_err(), "unsigned");
    }
}
