//! HPKE handshake responder (sage-spec `04-hpke.md`).

use crate::crypto::{KeyPair, Signer as _};
use crate::error::{Error, Result};
use crate::hpke::common::{combine_secrets, is_all_zero_32, kem_open, make_ack_tag, sha256_hash};
use crate::hpke::nonce_store::NonceStore;
use crate::hpke::types::*;
use rand::RngCore;
use std::sync::Arc;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

/// Responder configuration.
#[derive(Debug, Clone)]
pub struct HpkeServerConfig {
    /// Accepted clock skew of the init `ts` (default 2 minutes)
    pub max_time_skew_secs: i64,
    /// Replay window for `(ctx, nonce)` (default 10 minutes)
    pub nonce_ttl_secs: i64,
    /// Accepted suite ids
    pub allowed_suites: Vec<String>,
}

impl Default for HpkeServerConfig {
    fn default() -> Self {
        Self {
            max_time_skew_secs: 120,
            nonce_ttl_secs: 600,
            allowed_suites: vec![HPKE_SUITE_ID.to_string()],
        }
    }
}

/// Result of a handled init message.
pub struct HpkeServerSession {
    /// The signed envelope to return to the initiator
    pub envelope: ServerSigEnvelope,
    /// Session seed (the combined secret)
    pub seed: Zeroizing<Vec<u8>>,
    /// Session key id
    pub kid: String,
    /// Session id derived from the seed
    pub session_id: String,
}

/// The responder.
pub struct HpkeServer {
    did: String,
    signing_keypair: KeyPair,
    kem_secret: Zeroizing<[u8; 32]>,
    info_builder: Arc<dyn InfoBuilder>,
    binder: Option<Arc<dyn KeyIDBinder>>,
    cookie_verifier: Option<Arc<dyn CookieVerifier>>,
    replay: NonceStore,
    config: HpkeServerConfig,
}

impl HpkeServer {
    /// Create a responder from its signing key and static X25519 KEM secret.
    pub fn new(did: impl Into<String>, signing_keypair: KeyPair, kem_secret: [u8; 32]) -> Self {
        Self::with_config(
            did,
            signing_keypair,
            kem_secret,
            HpkeServerConfig::default(),
        )
    }

    /// Create a responder with a configuration.
    pub fn with_config(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        kem_secret: [u8; 32],
        config: HpkeServerConfig,
    ) -> Self {
        Self {
            did: did.into(),
            signing_keypair,
            kem_secret: Zeroizing::new(kem_secret),
            info_builder: Arc::new(DefaultInfoBuilder),
            binder: None,
            cookie_verifier: None,
            replay: NonceStore::new(chrono::Duration::seconds(config.nonce_ttl_secs)),
            config,
        }
    }

    /// Issue session key ids through a binder.
    pub fn with_key_id_binder(mut self, binder: Arc<dyn KeyIDBinder>) -> Self {
        self.binder = Some(binder);
        self
    }

    /// Require and verify a denial-of-service cookie before any public-key work.
    pub fn with_cookie_verifier(mut self, verifier: Arc<dyn CookieVerifier>) -> Self {
        self.cookie_verifier = Some(verifier);
        self
    }

    /// This agent's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The responder's KEM public key (what initiators resolve).
    pub fn kem_public_key(&self) -> [u8; 32] {
        x25519(*self.kem_secret, X25519_BASEPOINT_BYTES)
    }

    /// Handle an init payload whose transport message was signed by
    /// `sender_did`. Every rejection returns the same generic error; the
    /// detailed reason is available through [`HpkeServer::handle_init_detailed`].
    pub fn handle_init(
        &self,
        ctx_id: &str,
        sender_did: &str,
        payload: &HpkeInitPayload,
    ) -> Result<HpkeServerSession> {
        self.handle_init_detailed(ctx_id, sender_did, payload)
            .map_err(|_| Error::Verification("authentication failed".into()))
    }

    /// Like [`HpkeServer::handle_init`] but with the specific rejection reason.
    pub fn handle_init_detailed(
        &self,
        ctx_id: &str,
        sender_did: &str,
        payload: &HpkeInitPayload,
    ) -> Result<HpkeServerSession> {
        if let Some(v) = &self.cookie_verifier {
            let cookie = payload.cookie.as_deref().unwrap_or("");
            if !v.verify(cookie, ctx_id, &payload.init_did, &self.did) {
                return Err(Error::Verification("cookie rejected".into()));
            }
        }
        if payload.init_did != sender_did {
            return Err(Error::Verification(
                "initDid does not match the signer".into(),
            ));
        }
        if payload.resp_did != self.did {
            return Err(Error::Verification("respDid is not this agent".into()));
        }
        let ts = chrono::DateTime::parse_from_rfc3339(&payload.ts)
            .map_err(|_| Error::Verification("invalid ts".into()))?;
        let skew = (chrono::Utc::now() - ts.with_timezone(&chrono::Utc))
            .num_seconds()
            .abs();
        if skew > self.config.max_time_skew_secs {
            return Err(Error::Verification("ts outside the accepted skew".into()));
        }
        if !self
            .replay
            .check_and_mark(&format!("{ctx_id}|{}", payload.nonce))
        {
            return Err(Error::Verification("replayed nonce".into()));
        }
        if payload.info != self.info_builder.build_info(ctx_id, sender_did, &self.did) {
            return Err(Error::Verification("info mismatch".into()));
        }
        if payload.export_ctx != self.info_builder.build_export_context(ctx_id) {
            return Err(Error::Verification("exportCtx mismatch".into()));
        }
        if !self
            .config
            .allowed_suites
            .iter()
            .any(|s| s == HPKE_SUITE_ID)
        {
            return Err(Error::Unsupported("suite not allowed".into()));
        }
        let exporter = kem_open(
            &self.kem_secret,
            &payload.enc,
            &payload.info,
            &payload.export_ctx,
        )?;
        let eph_c_arr: [u8; 32] = payload
            .eph_c
            .as_slice()
            .try_into()
            .map_err(|_| Error::Verification("ephC must be 32 bytes".into()))?;
        let mut eph_s_secret = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *eph_s_secret);
        let eph_s = x25519(*eph_s_secret, X25519_BASEPOINT_BYTES);
        let ss = Zeroizing::new(x25519(*eph_s_secret, eph_c_arr));
        if is_all_zero_32(&*ss) {
            return Err(Error::Verification("E2E shared secret is all zero".into()));
        }
        let seed = combine_secrets(&exporter, &*ss, &payload.export_ctx)?;
        let kid = match &self.binder {
            Some(b) => match b.issue_key_id(ctx_id) {
                (k, true) if !k.is_empty() => k,
                _ => format!("kid-{}", uuid::Uuid::new_v4()),
            },
            None => format!("kid-{}", uuid::Uuid::new_v4()),
        };
        let ack = make_ack_tag(
            &seed,
            ctx_id,
            &payload.nonce,
            &kid,
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
        let mut envelope = ServerSigEnvelope {
            v: ENVELOPE_VERSION.into(),
            task: TASK_HPKE_COMPLETE.into(),
            ctx: ctx_id.to_string(),
            kid: kid.clone(),
            eph_s: ServerSigEnvelope::b64(&eph_s),
            ack_tag_b64: ServerSigEnvelope::b64(&ack),
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            did: self.did.clone(),
            info_hash: ServerSigEnvelope::b64(&sha256_hash(&payload.info)),
            export_ctx_hash: ServerSigEnvelope::b64(&sha256_hash(&payload.export_ctx)),
            enc: ServerSigEnvelope::b64(&payload.enc),
            eph_c: ServerSigEnvelope::b64(&payload.eph_c),
            sig_b64: None,
        };
        let signature = self.signing_keypair.sign(&envelope.canonical_bytes()?)?;
        envelope.sig_b64 = Some(ServerSigEnvelope::b64(&signature.to_bytes()));
        let session_id = crate::session::compute_session_id(&seed, SESSION_LABEL)?;
        Ok(HpkeServerSession {
            envelope,
            seed,
            kid,
            session_id,
        })
    }
}
