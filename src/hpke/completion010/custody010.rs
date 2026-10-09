//! External custody for the completion endpoint's Ed25519 signing key and
//! X25519 KEM key. The endpoint never receives private bytes from custody.
use super::bad;
use crate::error::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::panic::{catch_unwind, AssertUnwindSafe};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Protected custody for one fixed registered Ed25519 signing key. `sign`
/// must sign the supplied bytes exactly; every result is verified under the
/// public key read at construction. Keep custody outside model/plugin reach.
pub trait Ed25519Custody010: Send {
    /// Return the custody's Ed25519 public key.
    fn public_key(&mut self) -> Result<[u8; 32]>;
    /// Sign the exact message bytes.
    fn sign(&mut self, message: &[u8]) -> Result<[u8; 64]>;
}

/// Protected custody for one fixed registered X25519 KEM key. `ecdh` returns
/// the raw X25519 shared value with the peer key and must refuse an all-zero
/// result. The shared value lets its holder derive that handshake's secrets,
/// so this protects the long-term key, not a compromised host's sessions.
pub trait X25519Custody010: Send {
    /// Return the custody's X25519 public key.
    fn public_key(&mut self) -> Result<[u8; 32]>;
    /// Return the X25519 shared value with `peer`.
    fn ecdh(&mut self, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>>;
}

/// The endpoint's signing source: a local key or external custody.
pub(crate) enum EndpointSigner {
    Local(SigningKey),
    Custody {
        public: VerifyingKey,
        custody: Box<dyn Ed25519Custody010>,
    },
}

impl EndpointSigner {
    pub(crate) fn public(&self) -> [u8; 32] {
        match self {
            Self::Local(k) => k.verifying_key().to_bytes(),
            Self::Custody { public, .. } => public.to_bytes(),
        }
    }

    /// Sign with the retained key. A custody signature is accepted only when
    /// it verifies strictly under the constructed public key.
    pub(crate) fn sign(&mut self, message: &[u8]) -> Result<[u8; 64]> {
        match self {
            Self::Local(k) => Ok(k.sign(message).to_bytes()),
            Self::Custody { public, custody } => {
                let owned = message.to_vec();
                let raw = catch_unwind(AssertUnwindSafe(|| custody.sign(&owned)))
                    .map_err(|_| bad())??;
                public
                    .verify_strict(message, &Signature::from_bytes(&raw))
                    .map_err(|_| bad())?;
                Ok(raw)
            }
        }
    }

    pub(crate) fn custody(mut custody: Box<dyn Ed25519Custody010>) -> Result<Self> {
        let raw = catch_unwind(AssertUnwindSafe(|| custody.public_key())).map_err(|_| bad())??;
        let public = VerifyingKey::from_bytes(&raw).map_err(|_| bad())?;
        Ok(Self::Custody { public, custody })
    }
}

/// The endpoint's optional KEM source.
pub(crate) enum EndpointKem {
    Local(Zeroizing<Vec<u8>>),
    Custody {
        public: [u8; 32],
        custody: Box<dyn X25519Custody010>,
    },
}

impl EndpointKem {
    pub(crate) fn ready(&self) -> bool {
        match self {
            Self::Local(k) => k.len() == 32,
            Self::Custody { .. } => true,
        }
    }

    pub(crate) fn custody(mut custody: Box<dyn X25519Custody010>) -> Result<Self> {
        let public =
            catch_unwind(AssertUnwindSafe(|| custody.public_key())).map_err(|_| bad())??;
        Ok(Self::Custody { public, custody })
    }
}

// RFC 9180 identifiers for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
// ChaCha20Poly1305, the only suite of the 0.10.0 handshake.
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0003;

fn suite_kem() -> Vec<u8> {
    [b"KEM".as_slice(), &KEM_ID.to_be_bytes()].concat()
}

fn suite_hpke() -> Vec<u8> {
    [
        b"HPKE".as_slice(),
        &KEM_ID.to_be_bytes(),
        &KDF_ID.to_be_bytes(),
        &AEAD_ID.to_be_bytes(),
    ]
    .concat()
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let input = [b"HPKE-v1".as_slice(), suite, label.as_bytes(), ikm].concat();
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    Zeroizing::new(prk.to_vec())
}

fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &str,
    info: &[u8],
    n: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let length = u16::try_from(n).map_err(|_| bad())?;
    let labeled = [
        length.to_be_bytes().as_slice(),
        b"HPKE-v1",
        suite,
        label.as_bytes(),
        info,
    ]
    .concat();
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| bad())?;
    let mut out = Zeroizing::new(vec![0; n]);
    hk.expand(&labeled, &mut out).map_err(|_| bad())?;
    Ok(out)
}

/// RFC 9180 base-mode receiver exporter with the KEM Diffie-Hellman delegated
/// to custody: Decap's DH(skR, pkE), ExtractAndExpand, KeySchedule, Export.
pub(crate) fn open_export(
    kem: &mut dyn X25519Custody010,
    pk_r: &[u8; 32],
    enc: &[u8],
    info: &[u8],
    exporter_context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let enc: &[u8; 32] = enc.try_into().map_err(|_| bad())?;
    let dh = catch_unwind(AssertUnwindSafe(|| kem.ecdh(enc))).map_err(|_| bad())??;
    if bool::from(dh.ct_eq(&[0; 32])) {
        return Err(bad());
    }
    let kem_suite = suite_kem();
    let prk = labeled_extract(&kem_suite, b"", "eae_prk", &*dh);
    let kem_context = [enc.as_slice(), pk_r].concat();
    let shared = labeled_expand(&kem_suite, &prk, "shared_secret", &kem_context, 32)?;
    let suite = suite_hpke();
    let psk_id_hash = labeled_extract(&suite, b"", "psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", "info_hash", info);
    let context = [[0u8].as_slice(), &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&suite, &shared, "secret", b"");
    let exporter = labeled_expand(&suite, &secret, "exp", &context, 32)?;
    labeled_expand(&suite, &exporter, "sec", exporter_context, 32)
}
