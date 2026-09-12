//! Key proof of possession (`06-did-sage.md` §4):
//! `SHA-256("SAGE-PoP:" || DID || ":" || hex(key_data))` signed with the
//! key itself. Ed25519 signs the digest as its message; secp256k1 signs the
//! digest directly with RFC 6979 (low-S, `r || s || v`) and not the Keccak
//! convention used elsewhere.

use crate::crypto::{KeyPair, KeyType, PublicKey};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

/// The challenge string.
pub fn pop_challenge(did: &str, key_data: &[u8]) -> String {
    format!("SAGE-PoP:{did}:{}", hex::encode(key_data))
}

/// Sign the proof for `key_pair` (its public key bytes are `key_data`).
pub fn generate_key_pop(did: &str, key_pair: &KeyPair) -> Result<Vec<u8>> {
    let key_data = key_pair.public_key_bytes();
    let digest: [u8; 32] = Sha256::digest(pop_challenge(did, &key_data).as_bytes()).into();
    match key_pair.key_type() {
        KeyType::Ed25519 => {
            use ed25519_dalek::{Signer, SigningKey};
            let seed: [u8; 32] = key_pair.private_key_bytes().as_slice().try_into().unwrap();
            Ok(SigningKey::from_bytes(&seed)
                .sign(&digest)
                .to_bytes()
                .to_vec())
        }
        KeyType::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::from_slice(&key_pair.private_key_bytes())
                .map_err(|e| Error::CryptoError(format!("invalid secp256k1 key: {e}")))?;
            let (sig, recid) = sk
                .sign_prehash_recoverable(&digest)
                .map_err(|e| Error::CryptoError(format!("signing failed: {e}")))?;
            let (sig, recid) = match sig.normalize_s() {
                Some(low) => (
                    low,
                    k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1).unwrap(),
                ),
                None => (sig, recid),
            };
            let mut out = sig.to_bytes().to_vec();
            out.push(recid.to_byte());
            Ok(out)
        }
        KeyType::P256 => Err(Error::Unsupported(
            "P-256 keys are not registered on chain".into(),
        )),
    }
}

/// Verify a proof of possession for `key_data` of `key_type` under `did`.
pub fn verify_key_pop(did: &str, key_type: KeyType, key_data: &[u8], proof: &[u8]) -> Result<()> {
    let digest: [u8; 32] = Sha256::digest(pop_challenge(did, key_data).as_bytes()).into();
    let public = PublicKey::from_bytes(key_type, key_data)?;
    match (&public, key_type) {
        (PublicKey::Ed25519(pk), KeyType::Ed25519) => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = VerifyingKey::from_bytes(pk)
                .map_err(|_| Error::Verification("invalid Ed25519 key".into()))?;
            let sig_arr: [u8; 64] = proof
                .try_into()
                .map_err(|_| Error::Verification("Ed25519 proof must be 64 bytes".into()))?;
            vk.verify(&digest, &Signature::from_bytes(&sig_arr))
                .map_err(|_| Error::Verification("proof of possession failed".into()))
        }
        (PublicKey::Secp256k1(pk), KeyType::Secp256k1) => {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            if proof.len() != 64 && proof.len() != 65 {
                return Err(Error::Verification(
                    "secp256k1 proof must be 64 or 65 bytes".into(),
                ));
            }
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk)
                .map_err(|_| Error::Verification("invalid secp256k1 key".into()))?;
            let sig = k256::ecdsa::Signature::from_slice(&proof[..64])
                .map_err(|_| Error::Verification("invalid secp256k1 proof".into()))?;
            let sig = sig.normalize_s().unwrap_or(sig);
            vk.verify_prehash(&digest, &sig)
                .map_err(|_| Error::Verification("proof of possession failed".into()))
        }
        _ => Err(Error::Unsupported(
            "key type has no proof of possession".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_binding() {
        let did = "did:sage:ethereum:0xabc";
        for kt in [KeyType::Ed25519, KeyType::Secp256k1] {
            let kp = KeyPair::generate(kt).unwrap();
            let proof = generate_key_pop(did, &kp).unwrap();
            verify_key_pop(did, kt, &kp.public_key_bytes(), &proof).unwrap();
            assert!(verify_key_pop(
                "did:sage:ethereum:0xdef",
                kt,
                &kp.public_key_bytes(),
                &proof
            )
            .is_err());
            let other = KeyPair::generate(kt).unwrap();
            assert!(verify_key_pop(did, kt, &other.public_key_bytes(), &proof).is_err());
        }
        assert_eq!(pop_challenge("did:x", &[0xab]), "SAGE-PoP:did:x:ab");
    }
}
