//! HPKE handshake initiator (sage-spec `04-hpke.md`).

use crate::crypto::{KeyPair, Verifier as _};
use crate::error::{Error, Result};
use crate::hpke::common::{
    combine_secrets, is_all_zero_32, kem_seal, make_ack_tag, verify_ack_tag,
};
use crate::hpke::types::*;
use rand::RngCore;
use std::sync::Arc;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

/// Initiator configuration.
#[derive(Debug, Clone)]
pub struct HpkeClientConfig {
    /// Suite ids this initiator will use
    pub suite: String,
}

impl Default for HpkeClientConfig {
    fn default() -> Self {
        Self {
            suite: HPKE_SUITE_ID.to_string(),
        }
    }
}

/// State kept between `initialize` and `complete`.
pub struct HpkeClientState {
    ctx_id: String,
    peer_did: String,
    payload: HpkeInitPayload,
    eph_secret: Zeroizing<[u8; 32]>,
    exporter: Zeroizing<Vec<u8>>,
}

impl HpkeClientState {
    /// The payload that was sent.
    pub fn payload(&self) -> &HpkeInitPayload {
        &self.payload
    }
}

/// Result of a completed handshake on the initiator side.
pub struct HpkeClientSession {
    /// Session seed (the combined secret); feed it to
    /// `SecureSession::with_role(id, seed, true, cfg)` with the id from
    /// `session::compute_session_id(seed, SESSION_LABEL)`.
    pub seed: Zeroizing<Vec<u8>>,
    /// Session key id issued by the responder
    pub kid: String,
    /// Session id derived from the seed
    pub session_id: String,
}

/// The initiator.
pub struct HpkeClient {
    did: String,
    #[allow(dead_code)] // the transport signature of the init message is produced by the caller
    signing_keypair: KeyPair,
    kem_resolver: Arc<dyn KemKeyResolver>,
    signing_resolver: Arc<dyn SigningKeyResolver>,
    info_builder: Arc<dyn InfoBuilder>,
    cookie_source: Option<Arc<dyn CookieSource>>,
    config: HpkeClientConfig,
}

impl HpkeClient {
    /// Create an initiator. `kem_resolver` supplies responders' KEM keys and
    /// `signing_resolver` their signing keys (both may be the same object).
    pub fn new(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        kem_resolver: Arc<dyn KemKeyResolver>,
        signing_resolver: Arc<dyn SigningKeyResolver>,
    ) -> Self {
        Self {
            did: did.into(),
            signing_keypair,
            kem_resolver,
            signing_resolver,
            info_builder: Arc::new(DefaultInfoBuilder),
            cookie_source: None,
            config: HpkeClientConfig::default(),
        }
    }

    /// Attach a cookie source.
    pub fn with_cookie_source(mut self, source: Arc<dyn CookieSource>) -> Self {
        self.cookie_source = Some(source);
        self
    }

    /// Override the configuration.
    pub fn with_config(mut self, config: HpkeClientConfig) -> Self {
        self.config = config;
        self
    }

    /// This agent's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Build the init payload for `peer_did` under `ctx_id`.
    pub fn initialize(&self, ctx_id: &str, peer_did: &str) -> Result<HpkeClientState> {
        if self.config.suite != HPKE_SUITE_ID {
            return Err(Error::Unsupported(format!("suite {}", self.config.suite)));
        }
        let peer_kem = self.kem_resolver.resolve_kem_key(peer_did)?;
        let info = self.info_builder.build_info(ctx_id, &self.did, peer_did);
        let export_ctx = self.info_builder.build_export_context(ctx_id);
        let (enc, exporter) = kem_seal(&peer_kem, &info, &export_ctx)?;
        let mut eph_secret = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *eph_secret);
        let eph_c = x25519(*eph_secret, X25519_BASEPOINT_BYTES).to_vec();
        let cookie = self.cookie_source.as_ref().and_then(|s| {
            match s.get_cookie(ctx_id, &self.did, peer_did) {
                (c, true) => Some(c),
                _ => None,
            }
        });
        let payload = HpkeInitPayload {
            init_did: self.did.clone(),
            resp_did: peer_did.to_string(),
            info,
            export_ctx,
            nonce: uuid::Uuid::new_v4().to_string(),
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            enc,
            eph_c,
            cookie,
        };
        Ok(HpkeClientState {
            ctx_id: ctx_id.to_string(),
            peer_did: peer_did.to_string(),
            payload,
            eph_secret,
            exporter,
        })
    }

    /// Verify the responder's envelope and derive the session seed.
    pub fn complete(
        &self,
        state: HpkeClientState,
        envelope: &ServerSigEnvelope,
    ) -> Result<HpkeClientSession> {
        if envelope.v != ENVELOPE_VERSION || envelope.task != TASK_HPKE_COMPLETE {
            return Err(Error::Verification(format!(
                "unsupported version/task {}/{}",
                envelope.v, envelope.task
            )));
        }
        if envelope.ctx != state.ctx_id {
            return Err(Error::Verification("context id mismatch".into()));
        }
        if envelope.did != state.peer_did {
            return Err(Error::Verification("responder DID mismatch".into()));
        }
        // Signature over the JCS form of the envelope without sigB64.
        let sig_bytes = envelope.decode("sigB64")?;
        if sig_bytes.is_empty() {
            return Err(Error::Verification("envelope is not signed".into()));
        }
        let pub_key = self.signing_resolver.resolve_signing_key(&envelope.did)?;
        let signature = crate::crypto::Signature::from_bytes(pub_key.key_type(), &sig_bytes)?;
        pub_key.verify(&envelope.canonical_bytes()?, &signature)?;
        // Echoed members and hashes must match what was sent.
        let payload = &state.payload;
        if envelope.decode("enc")? != payload.enc || envelope.decode("ephC")? != payload.eph_c {
            return Err(Error::Verification("enc/ephC echo mismatch".into()));
        }
        if envelope.decode("infoHash")? != crate::hpke::common::sha256_hash(&payload.info)
            || envelope.decode("exportCtxHash")?
                != crate::hpke::common::sha256_hash(&payload.export_ctx)
        {
            return Err(Error::Verification("info/exportCtx hash mismatch".into()));
        }
        let eph_s = envelope.decode("ephS")?;
        let eph_s_arr: [u8; 32] = eph_s
            .as_slice()
            .try_into()
            .map_err(|_| Error::Verification("ephS must be 32 bytes".into()))?;
        if is_all_zero_32(&eph_s_arr) {
            return Err(Error::Verification("ephS is all zero".into()));
        }
        let ss = Zeroizing::new(x25519(*state.eph_secret, eph_s_arr));
        if is_all_zero_32(&*ss) {
            return Err(Error::Verification("E2E shared secret is all zero".into()));
        }
        let seed = combine_secrets(&state.exporter, &*ss, &payload.export_ctx)?;
        let expected = make_ack_tag(
            &seed,
            &state.ctx_id,
            &payload.nonce,
            &envelope.kid,
            &[
                &payload.info,
                &payload.export_ctx,
                &payload.enc,
                &payload.eph_c,
                &eph_s,
                payload.init_did.as_bytes(),
                payload.resp_did.as_bytes(),
            ],
        )?;
        verify_ack_tag(&expected, &envelope.decode("ackTagB64")?)?;
        let session_id = crate::session::compute_session_id(&seed, SESSION_LABEL)?;
        Ok(HpkeClientSession {
            seed,
            kid: envelope.kid.clone(),
            session_id,
        })
    }
}
