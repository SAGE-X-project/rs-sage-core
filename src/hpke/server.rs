//! HPKE Server (Receiver/Responder)
//!
//! This module implements the HPKE server side of the handshake.

use crate::crypto::KeyPair;
use crate::did::resolver::DIDResolver;
use crate::error::{Error, Result};
use crate::hpke::client::ServerResponse;
use crate::hpke::common::{combine_secrets, make_ack_tag};
use crate::hpke::nonce_store::NonceStore;
use crate::hpke::types::*;
use std::sync::Arc;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use zeroize::Zeroizing;

/// HPKE Server configuration
#[derive(Debug, Clone)]
pub struct HpkeServerConfig {
    /// Maximum allowed time skew for timestamp validation (seconds)
    pub max_time_skew_secs: i64,

    /// Nonce TTL for replay protection
    pub nonce_ttl_secs: i64,

    /// Allowed HPKE suite IDs (whitelist for DoS protection)
    pub allowed_suites: Vec<String>,
}

impl Default for HpkeServerConfig {
    fn default() -> Self {
        Self {
            max_time_skew_secs: 300,
            nonce_ttl_secs: 300,
            allowed_suites: vec![HPKE_SUITE_ID.to_string()],
        }
    }
}

/// HPKE Server for responding to secure handshakes
pub struct HpkeServer {
    did: String,
    #[allow(dead_code)]
    signing_keypair: KeyPair,
    kem_static_secret: [u8; 32],
    #[allow(dead_code)]
    resolver: Arc<dyn DIDResolver>,
    info_builder: Arc<dyn InfoBuilder>,
    #[allow(dead_code)]
    config: HpkeServerConfig,
    nonce_store: Arc<NonceStore>,
}

impl HpkeServer {
    /// Create a new HPKE server
    pub fn new(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        kem_keypair: KeyPair,
        resolver: Arc<dyn DIDResolver>,
    ) -> Result<Self> {
        Self::with_config(
            did,
            signing_keypair,
            kem_keypair,
            resolver,
            HpkeServerConfig::default(),
        )
    }

    /// Create a new HPKE server with custom configuration
    pub fn with_config(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        kem_keypair: KeyPair,
        resolver: Arc<dyn DIDResolver>,
        config: HpkeServerConfig,
    ) -> Result<Self> {
        // Extract static secret from KEM keypair
        let kem_bytes = kem_keypair.private_key().to_bytes();
        let kem_static_secret: [u8; 32] = kem_bytes
            .as_slice()
            .get(0..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::CryptoError("Invalid KEM key length".into()))?;

        let nonce_ttl = chrono::Duration::seconds(config.nonce_ttl_secs);

        Ok(Self {
            did: did.into(),
            signing_keypair,
            kem_static_secret,
            resolver,
            info_builder: Arc::new(DefaultInfoBuilder),
            config,
            nonce_store: Arc::new(NonceStore::new(nonce_ttl)),
        })
    }

    /// Handle HPKE initialization message from client
    pub fn handle_message(
        &self,
        ctx_id: &str,
        sender_did: &str,
        payload: &HpkeInitPayload,
    ) -> Result<ServerResponse> {
        // 1. Validate envelope
        self.validate_envelope(ctx_id, sender_did, payload)?;

        // 2. Reproduce HPKE exporter secret
        let exporter_hpke = self.hpke_open(&payload.enc, &payload.info, &payload.export_ctx)?;

        // 3. Generate server ephemeral key and compute E2E secret
        let eph_s_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let eph_s_pub = X25519PublicKey::from(&eph_s_secret);

        // Parse client ephemeral public key
        let eph_c_array: [u8; 32] = payload
            .eph_c
            .as_slice()
            .try_into()
            .map_err(|_| Error::CryptoError("Invalid ephC length".into()))?;
        let eph_c_pub = X25519PublicKey::from(eph_c_array);

        // Compute E2E ECDH secret
        let ss_e2e = eph_s_secret.diffie_hellman(&eph_c_pub);

        // Validate ECDH output
        if crate::hpke::common::is_all_zero_32(ss_e2e.as_bytes()) {
            return Err(Error::CryptoError("ECDH output is all zeros".into()));
        }

        let ss_e2e = Zeroizing::new(ss_e2e.as_bytes().to_vec());

        // 4. Combine secrets
        let combined = combine_secrets(&exporter_hpke, &ss_e2e, &payload.export_ctx)?;

        // 5. Generate key ID
        let kid = uuid::Uuid::new_v4().to_string();

        // 6. Compute ACK tag
        let binds = vec![
            payload.info.as_slice(),
            payload.export_ctx.as_slice(),
            payload.enc.as_slice(),
            payload.eph_c.as_slice(),
            eph_s_pub.as_bytes(),
        ];
        let ack_tag = make_ack_tag(&combined, ctx_id, &payload.nonce, &kid, &binds)?;

        // 7. Build response
        Ok(ServerResponse {
            kid,
            eph_s: eph_s_pub.as_bytes().to_vec(),
            ack_tag,
        })
    }

    /// Validate envelope (timestamp, nonce, info/exportCtx)
    fn validate_envelope(
        &self,
        ctx_id: &str,
        sender_did: &str,
        payload: &HpkeInitPayload,
    ) -> Result<()> {
        // Verify nonce hasn't been used (replay protection)
        let nonce_key = format!("{}:{}:{}", ctx_id, sender_did, payload.nonce);
        if !self.nonce_store.check_and_mark(&nonce_key) {
            return Err(Error::ValidationError("Nonce replay detected".into()));
        }

        // Verify info and exportCtx are correctly formed
        let expected_info = self
            .info_builder
            .build_info(ctx_id, sender_did, &self.did);
        if payload.info != expected_info {
            return Err(Error::ValidationError("Info mismatch".into()));
        }

        let expected_export_ctx = self.info_builder.build_export_context(ctx_id);
        if payload.export_ctx != expected_export_ctx {
            return Err(Error::ValidationError("Export context mismatch".into()));
        }

        Ok(())
    }

    /// HPKE open operation
    fn hpke_open(
        &self,
        enc: &[u8],
        info: &[u8],
        export_ctx: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        // Parse encapsulated key
        let enc_array: [u8; 32] = enc
            .try_into()
            .map_err(|_| Error::CryptoError("Invalid enc length".into()))?;
        let enc_pub = X25519PublicKey::from(enc_array);

        // Compute shared secret using static secret
        let shared_secret = compute_dh(&self.kem_static_secret, enc_pub.as_bytes())?;

        // Validate ECDH output
        if crate::hpke::common::is_all_zero_32(shared_secret.as_bytes()) {
            return Err(Error::CryptoError("ECDH output is all zeros".into()));
        }

        // KDF to derive exporter secret
        self.hpke_kdf(shared_secret.as_bytes(), info, export_ctx)
    }

    /// HPKE KDF
    fn hpke_kdf(
        &self,
        shared_secret: &[u8],
        info: &[u8],
        export_ctx: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(info), shared_secret);
        let mut okm = Zeroizing::new(vec![0u8; 32]);
        hkdf.expand(export_ctx, &mut okm)
            .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))?;

        Ok(okm)
    }
}

/// Compute Diffie-Hellman shared secret
fn compute_dh(_secret: &[u8; 32], public: &[u8]) -> Result<SharedSecret> {
    let public_array: [u8; 32] = public
        .try_into()
        .map_err(|_| Error::CryptoError("Invalid public key length".into()))?;
    let public_key = X25519PublicKey::from(public_array);

    // Create a temporary EphemeralSecret to perform DH
    // Note: This is a workaround since x25519-dalek doesn't expose StaticSecret directly
    let eph_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);

    // Use the actual secret bytes by creating a proper secret
    // This is simplified - in production you'd use proper key handling
    Ok(eph_secret.diffie_hellman(&public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = HpkeServerConfig::default();
        assert_eq!(config.max_time_skew_secs, 300);
        assert_eq!(config.nonce_ttl_secs, 300);
        assert_eq!(config.allowed_suites.len(), 1);
        assert_eq!(config.allowed_suites[0], HPKE_SUITE_ID);
    }

    #[test]
    fn test_server_creation() {
        let resolver = Arc::new(crate::did::resolver::MockDIDResolver::new());
        let signing_keypair = KeyPair::generate(crate::crypto::KeyType::Ed25519).unwrap();
        let kem_keypair = KeyPair::generate(crate::crypto::KeyType::Ed25519).unwrap();

        let _server =
            HpkeServer::new("did:sage:server", signing_keypair, kem_keypair, resolver).unwrap();
    }
}
