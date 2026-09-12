//! Session seed and id derivation (sage-spec `05-session.md` §1).

use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Default derivation label when none is given (legacy handshake).
pub const DEFAULT_LABEL: &str = "a2a/handshake v1";
/// Label used by the HPKE handshake sessions.
pub const HPKE_E2E_LABEL: &str = "sage/hpke+e2e v1";
/// Label used by the session manager's HPKE path.
pub const HPKE_LABEL: &str = "sage/hpke v1";

/// Inputs to the seed derivation, identical on both peers.
#[derive(Debug, Clone)]
pub struct SessionParams {
    /// Context id shared by both peers
    pub context_id: String,
    /// This node's ephemeral public key bytes as sent on the wire
    pub self_eph: Vec<u8>,
    /// The peer's ephemeral public key bytes as received
    pub peer_eph: Vec<u8>,
    /// Derivation label (empty selects [`DEFAULT_LABEL`])
    pub label: String,
}

impl SessionParams {
    fn label(&self) -> &str {
        if self.label.is_empty() {
            DEFAULT_LABEL
        } else {
            &self.label
        }
    }
}

/// `seed = HKDF-Extract(SHA-256, sharedSecret, salt = SHA-256(label || ctx || lo || hi))`
/// with `(lo, hi)` the byte-sorted ephemeral public keys.
pub fn derive_session_seed(shared_secret: &[u8], params: &SessionParams) -> Result<Vec<u8>> {
    if shared_secret.is_empty() {
        return Err(Error::InvalidInput("empty shared secret".into()));
    }
    if params.context_id.is_empty() || params.self_eph.is_empty() || params.peer_eph.is_empty() {
        return Err(Error::InvalidInput("invalid session params".into()));
    }
    let (lo, hi) = if params.self_eph <= params.peer_eph {
        (&params.self_eph, &params.peer_eph)
    } else {
        (&params.peer_eph, &params.self_eph)
    };
    let mut h = Sha256::new();
    h.update(params.label().as_bytes());
    h.update(params.context_id.as_bytes());
    h.update(lo);
    h.update(hi);
    let salt = h.finalize();
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&salt), shared_secret);
    Ok(prk.to_vec())
}

/// `sid = base64url-raw(SHA-256(label || seed)[0:16])`
pub fn compute_session_id(seed: &[u8], label: &str) -> Result<String> {
    if seed.is_empty() {
        return Err(Error::InvalidInput("empty seed".into()));
    }
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update(seed);
    let full = h.finalize();
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(&full[..16]))
}
