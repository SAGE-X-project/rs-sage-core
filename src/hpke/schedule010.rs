//! Transcript-bound 0.10.0 seed and ACK schedule, separate from the v1 handshake.
use crate::error::{Error, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

fn invalid() -> Error {
    Error::CryptoError("invalid 0.10.0 HPKE schedule input".into())
}

/// Derives the seed from a verified HPKE exporter, nonzero E2E X25519 result,
/// and SHA256(JCS(T)). All inputs are 32 bytes. Does not perform DH, authenticate
/// the transcript, verify current keys, or create a session. The caller must
/// reject invalid HPKE KEM results before obtaining the exporter.
pub fn combine_secrets_010(
    exporter: &[u8],
    shared: &[u8],
    th: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if exporter.len() != 32
        || shared.len() != 32
        || th.len() != 32
        || bool::from(shared.ct_eq(&[0u8; 32]))
    {
        return Err(invalid());
    }
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(exporter);
    ikm[32..].copy_from_slice(shared);
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(th), &*ikm);
    let result = expand(&prk, b"sage-hpke-combiner|0.10.0", th);
    // Best effort: HKDF/HMAC library internals may retain additional copies.
    use zeroize::Zeroize;
    prk.as_mut_slice().zeroize();
    result
}

fn expand(key: &[u8], label: &[u8], th: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut info = label.to_vec();
    info.extend_from_slice(th);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    Hkdf::<Sha256>::from_prk(key)
        .map_err(|_| invalid())?
        .expand(&info, &mut out)
        .map_err(|_| invalid())?;
    Ok(out)
}

/// Derives the ACK without exposing its key. The seed must come from the same
/// authenticated transcript's 0.10.0 combiner.
pub fn make_ack_tag_010(seed: &[u8], th: &[u8]) -> Result<[u8; 32]> {
    if seed.len() != 32 || th.len() != 32 {
        return Err(invalid());
    }
    let key = expand(seed, b"sage-hpke-ack|0.10.0", th)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| invalid())?;
    mac.update(th);
    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time comparison of a 32-byte ACK. Success is not evidence of
/// signatures, current key status, or a matching live pending handshake.
pub fn verify_ack_tag_010(seed: &[u8], th: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 32 {
        return false;
    }
    match make_ack_tag_010(seed, th) {
        Ok(expected) => bool::from(expected.ct_eq(tag)),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/hpke-schedule010.json"))
                .unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for c in cases {
            let decode = |k: &str| hex::decode(c[k].as_str().unwrap()).unwrap();
            let exporter = decode("exporter_hex");
            let shared = decode("ss_e2e_hex");
            let th = decode("th_hex");
            let seed = combine_secrets_010(&exporter, &shared, &th).unwrap();
            assert_eq!(*seed, decode("seed_hex"));
            let ack = make_ack_tag_010(&seed, &th).unwrap();
            assert_eq!(ack.as_slice(), decode("ack_tag_hex"));
            assert!(verify_ack_tag_010(&seed, &th, &ack));
            for i in 0..32 {
                let mut changed = ack;
                changed[i] ^= 1;
                assert!(!verify_ack_tag_010(&seed, &th, &changed));
            }
            let mut changed = th.clone();
            changed[0] ^= 1;
            assert!(!verify_ack_tag_010(&seed, &changed, &ack));
            assert_ne!(
                *seed,
                *combine_secrets_010(&exporter, &shared, &changed).unwrap()
            );
            assert_ne!(
                *seed,
                *crate::hpke::combine_secrets(&exporter, &shared, &th).unwrap()
            );
        }
    }
    #[test]
    fn rejects_invalid_inputs() {
        let good = [1u8; 32];
        for slot in 0..3 {
            for n in [0, 1, 31, 33, 64] {
                let bad = vec![1u8; n];
                let mut args: [&[u8]; 3] = [&good, &good, &good];
                args[slot] = &bad;
                assert!(combine_secrets_010(args[0], args[1], args[2]).is_err());
            }
        }
        assert!(combine_secrets_010(&good, &[0; 32], &good).is_err());
        for n in [0, 1, 31, 33, 64] {
            let bad = vec![0; n];
            assert!(make_ack_tag_010(&bad, &good).is_err());
            assert!(make_ack_tag_010(&good, &bad).is_err());
            assert!(!verify_ack_tag_010(&good, &good, &bad));
            assert!(!verify_ack_tag_010(&bad, &good, &good));
            assert!(!verify_ack_tag_010(&good, &bad, &good));
        }
    }
}
