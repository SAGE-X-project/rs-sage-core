//! HPKE Client (Sender/Initiator)
//!
//! This module implements the HPKE client side of the handshake.

use crate::crypto::KeyPair;
// TODO: DID resolver integration will be re-implemented with blockchain module
// use crate::did::resolver::DIDResolver;
// use crate::did::DID;
use crate::error::{Error, Result};
use crate::hpke::common::{combine_secrets, make_ack_tag, verify_ack_tag};
use crate::hpke::nonce_store::NonceStore;
use crate::hpke::types::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use std::sync::Arc;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

/// HPKE Client configuration
#[derive(Debug, Clone)]
pub struct HpkeClientConfig {
    /// Enable TOFU (Trust On First Use) pinning
    pub enable_tofu: bool,

    /// Maximum allowed time skew for timestamp validation (seconds)
    pub max_time_skew_secs: i64,

    /// Nonce TTL for replay protection
    pub nonce_ttl_secs: i64,
}

impl Default for HpkeClientConfig {
    fn default() -> Self {
        Self {
            enable_tofu: false,
            max_time_skew_secs: 300,
            nonce_ttl_secs: 300,
        }
    }
}

/// HPKE Client for initiating secure handshakes
pub struct HpkeClient {
    did: String,
    #[allow(dead_code)]
    signing_keypair: KeyPair,
    resolver: Arc<dyn DIDResolver>,
    info_builder: Arc<dyn InfoBuilder>,
    #[allow(dead_code)]
    config: HpkeClientConfig,
    #[allow(dead_code)]
    nonce_store: Arc<NonceStore>,
}

impl HpkeClient {
    /// Create a new HPKE client
    pub fn new(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        resolver: Arc<dyn DIDResolver>,
    ) -> Self {
        Self::with_config(did, signing_keypair, resolver, HpkeClientConfig::default())
    }

    /// Create a new HPKE client with custom configuration
    pub fn with_config(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        resolver: Arc<dyn DIDResolver>,
        config: HpkeClientConfig,
    ) -> Self {
        let nonce_ttl = chrono::Duration::seconds(config.nonce_ttl_secs);

        Self {
            did: did.into(),
            signing_keypair,
            resolver,
            info_builder: Arc::new(DefaultInfoBuilder),
            config,
            nonce_store: Arc::new(NonceStore::new(nonce_ttl)),
        }
    }

    /// Initialize HPKE handshake with peer
    pub fn initialize(
        &self,
        ctx_id: &str,
        peer_did: &str,
    ) -> Result<(HpkeInitPayload, EphemeralSecret, Zeroizing<Vec<u8>>)> {
        // 1. Resolve peer's X25519 KEM key
        let peer_kem_key = self.resolve_peer_kem_key(peer_did)?;

        // 2. Build HPKE info and export context
        let info = self.info_builder.build_info(ctx_id, &self.did, peer_did);
        let export_ctx = self.info_builder.build_export_context(ctx_id);

        // 3. HPKE sender: encapsulate and derive exporter secret
        let (enc, exporter_hpke) = self.hpke_seal(&peer_kem_key, &info, &export_ctx)?;

        // 4. Generate ephemeral X25519 keypair for E2E
        let eph_c_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let eph_c_pub = X25519PublicKey::from(&eph_c_secret);

        // 5. Generate nonce
        let nonce = self.generate_nonce();

        // 6. Build payload
        let payload = HpkeInitPayload {
            enc,
            eph_c: eph_c_pub.as_bytes().to_vec(),
            info,
            export_ctx,
            nonce,
            cookie: None,
        };

        Ok((payload, eph_c_secret, exporter_hpke))
    }

    /// Verify server response and derive session key
    pub fn verify_response(
        &self,
        ctx_id: &str,
        payload: &HpkeInitPayload,
        eph_c_secret: EphemeralSecret,
        exporter_hpke: Zeroizing<Vec<u8>>,
        response: &ServerResponse,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // 1. Parse server ephemeral key
        let eph_s_array: [u8; 32] = response
            .eph_s
            .as_slice()
            .try_into()
            .map_err(|_| Error::CryptoError("Invalid ephS length".into()))?;
        let eph_s_pub = X25519PublicKey::from(eph_s_array);

        // 2. Compute E2E ECDH secret
        let ss_e2e = eph_c_secret.diffie_hellman(&eph_s_pub);

        // Validate ECDH output
        if crate::hpke::common::is_all_zero_32(ss_e2e.as_bytes()) {
            return Err(Error::CryptoError("ECDH output is all zeros".into()));
        }

        let ss_e2e = Zeroizing::new(ss_e2e.as_bytes().to_vec());

        // 3. Combine secrets
        let combined = combine_secrets(&exporter_hpke, &ss_e2e, &payload.export_ctx)?;

        // 4. Compute expected ACK tag
        let binds = vec![
            payload.info.as_slice(),
            payload.export_ctx.as_slice(),
            payload.enc.as_slice(),
            payload.eph_c.as_slice(),
            response.eph_s.as_slice(),
        ];
        let expected_ack = make_ack_tag(
            &combined,
            ctx_id,
            &payload.nonce,
            &response.kid,
            &binds,
        )?;

        // 5. Verify ACK tag
        verify_ack_tag(&expected_ack, &response.ack_tag)?;

        Ok(combined)
    }

    /// Resolve peer's X25519 KEM key from DID document
    fn resolve_peer_kem_key(&self, peer_did: &str) -> Result<X25519PublicKey> {
        let did = DID::parse(peer_did)?;
        let result = self.resolver.resolve(&did)?;

        let did_doc = result
            .document
            .ok_or_else(|| Error::ResolutionError(format!("DID not found: {peer_did}")))?;

        // Look for X25519 key in verification methods
        for vm in &did_doc.verification_method {
            if vm.method_type.contains("X25519") {
                let key_bytes = self.extract_key_bytes(vm)?;
                let key_array: [u8; 32] = key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::CryptoError("Invalid X25519 key length".into()))?;
                return Ok(X25519PublicKey::from(key_array));
            }
        }

        Err(Error::CryptoError(
            "No X25519 key found in DID document".into(),
        ))
    }

    /// Extract key bytes from verification method
    fn extract_key_bytes(&self, vm: &crate::did::document::VerificationMethod) -> Result<Vec<u8>> {
        // Try publicKeyMultibase
        if let Some(pk_mb) = &vm.public_key_multibase {
            if let Some(stripped) = pk_mb.strip_prefix('z') {
                return bs58::decode(stripped).into_vec().map_err(|e| {
                    Error::ParseError(format!("Failed to decode multibase key: {e}"))
                });
            }
        }

        // Try publicKeyJwk
        if let Some(jwk) = &vm.public_key_jwk {
            if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                return BASE64
                    .decode(x)
                    .map_err(|e| Error::ParseError(format!("Failed to decode JWK x: {e}")));
            }
        }

        Err(Error::ParseError(
            "No supported public key format found".into(),
        ))
    }

    /// HPKE seal operation (simplified)
    fn hpke_seal(
        &self,
        peer_key: &X25519PublicKey,
        info: &[u8],
        export_ctx: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        // Generate ephemeral keypair for KEM
        let eph_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        // Compute shared secret
        let shared_secret = eph_secret.diffie_hellman(peer_key);

        // Validate ECDH output
        if crate::hpke::common::is_all_zero_32(shared_secret.as_bytes()) {
            return Err(Error::CryptoError("ECDH output is all zeros".into()));
        }

        // KDF to derive exporter secret
        let exporter = self.hpke_kdf(shared_secret.as_bytes(), info, export_ctx)?;

        Ok((eph_pub.as_bytes().to_vec(), exporter))
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

    /// Generate a random nonce
    fn generate_nonce(&self) -> String {
        let nonce: [u8; 16] = rand::thread_rng().gen();
        hex::encode(nonce)
    }
}

/// Server response structure
#[derive(Debug, Clone)]
pub struct ServerResponse {
    /// Key ID generated by the server
    pub kid: String,
    /// Server ephemeral public key (ephS)
    pub eph_s: Vec<u8>,
    /// ACK tag for key confirmation
    pub ack_tag: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_default() {
        let config = HpkeClientConfig::default();
        assert!(!config.enable_tofu);
        assert_eq!(config.max_time_skew_secs, 300);
        assert_eq!(config.nonce_ttl_secs, 300);
    }

    #[test]
    fn test_client_creation() {
        let resolver = Arc::new(crate::did::resolver::MockDIDResolver::new());
        let keypair = KeyPair::generate(crate::crypto::KeyType::Ed25519).unwrap();
        let _client = HpkeClient::new("did:sage:client", keypair, resolver);
    }

    #[test]
    fn test_generate_nonce() {
        let resolver = Arc::new(crate::did::resolver::MockDIDResolver::new());
        let keypair = KeyPair::generate(crate::crypto::KeyType::Ed25519).unwrap();
        let client = HpkeClient::new("did:sage:client", keypair, resolver);

        let nonce1 = client.generate_nonce();
        let nonce2 = client.generate_nonce();

        assert_eq!(nonce1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(nonce1, nonce2);
    }
}
