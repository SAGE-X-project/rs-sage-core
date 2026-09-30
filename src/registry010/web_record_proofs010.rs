//! Cryptographic REG-04 proof checks over a structurally valid web record.

use crate::error::{Error, Result};
use crate::jcs::{self, Value};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use std::collections::BTreeMap;

use super::proof::pop_challenge010;
use super::web_record_shape010::{
    array, canonical_base64, check_web_registry_record_shape_010, field, object, string,
};

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

struct ProofKey {
    name: String,
    alg: String,
    material: Vec<u8>,
    signer: String,
    signature: Vec<u8>,
}

fn prime_ed_point(bytes: &[u8]) -> bool {
    let Ok(encoded) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    let Some(point) = CompressedEdwardsY(encoded).decompress() else {
        return false;
    };
    !point.is_identity() && point.is_torsion_free() && point.compress().to_bytes() == encoded
}

fn valid_signing_point(alg: &str, material: &[u8]) -> bool {
    match alg {
        "ed25519" => prime_ed_point(material),
        "ecdsa-p256-sha256" => p256::ecdsa::VerifyingKey::from_sec1_bytes(material).is_ok(),
        "sage-secp256k1-keccak256" => k256::ecdsa::VerifyingKey::from_sec1_bytes(material).is_ok(),
        _ => false,
    }
}

fn valid_x25519_point(material: &[u8]) -> bool {
    let Ok(public) = <[u8; 32]>::try_from(material) else {
        return false;
    };
    let mut private = [0u8; 32];
    private[0] = 1;
    x25519_dalek::x25519(private, public) != [0u8; 32]
}

fn verify(alg: &str, material: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
    match alg {
        "ed25519" => {
            if signature.len() != 64 || !prime_ed_point(&signature[..32]) {
                return false;
            }
            let Ok(key_bytes) = <[u8; 32]>::try_from(material) else {
                return false;
            };
            let Ok(key) = EdVerifyingKey::from_bytes(&key_bytes) else {
                return false;
            };
            let Ok(proof) = EdSignature::from_slice(signature) else {
                return false;
            };
            key.verify_strict(challenge, &proof).is_ok()
        }
        "ecdsa-p256-sha256" => {
            use p256::ecdsa::signature::Verifier;
            if signature.len() != 64 {
                return false;
            }
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(material) else {
                return false;
            };
            let Ok(proof) = p256::ecdsa::Signature::from_slice(signature) else {
                return false;
            };
            proof.normalize_s().is_none() && key.verify(challenge, &proof).is_ok()
        }
        "sage-secp256k1-keccak256" => {
            if signature.len() != 65 || signature[64] > 1 {
                return false;
            }
            let Ok(key) = k256::ecdsa::VerifyingKey::from_sec1_bytes(material) else {
                return false;
            };
            let Ok(proof) = k256::ecdsa::Signature::from_slice(&signature[..64]) else {
                return false;
            };
            if proof.normalize_s().is_some() {
                return false;
            }
            let Some(recovery) = k256::ecdsa::RecoveryId::from_byte(signature[64]) else {
                return false;
            };
            let digest = crate::crypto::keys::keccak256(challenge);
            let Ok(recovered) =
                k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &proof, recovery)
            else {
                return false;
            };
            recovered.to_encoded_point(false).as_bytes() == material
                && key.verify_prehash(&digest, &proof).is_ok()
        }
        _ => false,
    }
}

fn get_key(value: &Value) -> Result<ProofKey> {
    let fields = object(value)?;
    let proof = object(field(fields, "proof")?)?;
    let alg = string(field(fields, "alg")?)?.to_string();
    let material = canonical_base64(string(field(fields, "key")?)?, None).ok_or_else(invalid)?;
    let signature = canonical_base64(string(field(proof, "value")?)?, None).ok_or_else(invalid)?;
    Ok(ProofKey {
        name: string(field(fields, "name")?)?.to_string(),
        alg,
        material,
        signer: string(field(proof, "signer")?)?.to_string(),
        signature,
    })
}

/// Verify all REG-04 signing proofs and X25519 endorsements in a web record.
/// The trusted Source must still authenticate TLS origin, controller, mutation
/// history, and any retained historical KEM signer's earlier authority.
/// Success alone never authorizes a protected operation.
pub fn check_web_registry_proofs_010(raw: &[u8], expected_did: &str, now: i64) -> Result<()> {
    check_web_registry_record_shape_010(raw, expected_did, now)?;
    let wrapper: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(raw).map_err(|_| invalid())?;
    let record_raw = wrapper.get("record").ok_or_else(invalid)?.get();
    let record = jcs::parse(record_raw).map_err(|_| invalid())?;
    let keys = array(field(object(&record)?, "keys")?)?;
    let Some(rest) = expected_did.strip_prefix("did:sage:") else {
        return Err(invalid());
    };
    let Some((registry_id, agent_id)) = rest.rsplit_once(':') else {
        return Err(invalid());
    };
    let entries: Vec<ProofKey> = keys.iter().map(get_key).collect::<Result<_>>()?;
    let mut signing = BTreeMap::new();
    for key in &entries {
        if key.alg == "x25519" {
            continue;
        }
        if !valid_signing_point(&key.alg, &key.material) {
            return Err(invalid());
        }
        let challenge = pop_challenge010(registry_id, agent_id, &key.name, &key.alg, &key.material)
            .map_err(|_| invalid())?;
        if !verify(&key.alg, &key.material, &challenge, &key.signature) {
            return Err(invalid());
        }
        signing.insert(key.name.as_str(), key);
    }
    for key in &entries {
        if key.alg != "x25519" {
            continue;
        }
        if !valid_x25519_point(&key.material) {
            return Err(invalid());
        }
        let signer_name = key
            .signer
            .strip_prefix(&format!("{expected_did}#"))
            .ok_or_else(invalid)?;
        let signer = signing.get(signer_name).ok_or_else(invalid)?;
        let challenge = pop_challenge010(registry_id, agent_id, &key.name, &key.alg, &key.material)
            .map_err(|_| invalid())?;
        if !verify(&signer.alg, &signer.material, &challenge, &key.signature) {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::{json, Value as JsonValue};

    const DID: &str = "did:sage:web:agents.example.com:billing-bot";

    fn challenge(name: &str, alg: &str, material: &[u8]) -> Vec<u8> {
        pop_challenge010("web:agents.example.com", "billing-bot", name, alg, material).unwrap()
    }

    fn entry(name: &str, alg: &str, material: &[u8], signature: &[u8], signer: &str) -> JsonValue {
        json!({"name": name, "alg": alg, "key": URL_SAFE_NO_PAD.encode(material),
            "proof": {"signer": signer, "value": URL_SAFE_NO_PAD.encode(signature)},
            "state": "accepted"})
    }

    fn fixture() -> JsonValue {
        let ed_private = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let ed_public = ed_private.verifying_key().to_bytes();
        let ed_sig = ed_private.sign(&challenge("a-ed", "ed25519", &ed_public));
        let ed = entry(
            "a-ed",
            "ed25519",
            &ed_public,
            &ed_sig.to_bytes(),
            &format!("{DID}#a-ed"),
        );

        let kem_public = x25519_dalek::x25519([7u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let kem_sig = ed_private.sign(&challenge("b-kem", "x25519", &kem_public));
        let kem = entry(
            "b-kem",
            "x25519",
            &kem_public,
            &kem_sig.to_bytes(),
            &format!("{DID}#a-ed"),
        );

        use p256::ecdsa::signature::Signer;
        let p256_private = p256::ecdsa::SigningKey::from_slice(&[2u8; 32]).unwrap();
        let p256_public = p256_private.verifying_key().to_encoded_point(false);
        let p256_sig: p256::ecdsa::Signature = p256_private.sign(&challenge(
            "c-p256",
            "ecdsa-p256-sha256",
            p256_public.as_bytes(),
        ));
        let p256_sig = p256_sig.normalize_s().unwrap_or(p256_sig);
        let p256 = entry(
            "c-p256",
            "ecdsa-p256-sha256",
            p256_public.as_bytes(),
            &p256_sig.to_bytes(),
            &format!("{DID}#c-p256"),
        );

        let secp_private = k256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap();
        let secp_public = secp_private.verifying_key().to_encoded_point(false);
        let digest = crate::crypto::keys::keccak256(&challenge(
            "d-secp",
            "sage-secp256k1-keccak256",
            secp_public.as_bytes(),
        ));
        let (secp_sig, recovery) = secp_private.sign_prehash_recoverable(&digest).unwrap();
        let (secp_sig, recovery) = match secp_sig.normalize_s() {
            Some(low) => (
                low,
                k256::ecdsa::RecoveryId::from_byte(recovery.to_byte() ^ 1).unwrap(),
            ),
            None => (secp_sig, recovery),
        };
        let mut secp_bytes = secp_sig.to_bytes().to_vec();
        secp_bytes.push(recovery.to_byte());
        let secp = entry(
            "d-secp",
            "sage-secp256k1-keccak256",
            secp_public.as_bytes(),
            &secp_bytes,
            &format!("{DID}#d-secp"),
        );

        json!({"id": DID, "controller": "operator", "keys": [ed, kem, p256, secp],
            "services": [], "state": "active", "version": "1"})
    }

    fn check(record: &JsonValue) -> Result<()> {
        let body = json!({"record": record, "issued": 100, "expires": 105}).to_string();
        check_web_registry_proofs_010(body.as_bytes(), DID, 100)
    }

    fn flip_s(signature: &mut [u8], order_hex: &str) {
        let order = hex::decode(order_hex).unwrap();
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let difference = order[index] as i16 - signature[32 + index] as i16 - borrow;
            if difference < 0 {
                signature[32 + index] = (difference + 256) as u8;
                borrow = 1;
            } else {
                signature[32 + index] = difference as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0);
    }

    #[test]
    fn verifies_all_signing_suites_and_kem_endorsement() {
        assert!(check(&fixture()).is_ok());
        let mut record = fixture();
        record["keys"][0]["proof"]["value"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][1]["proof"]["signer"] = json!(format!("{DID}#missing"));
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][1]["key"] = json!(URL_SAFE_NO_PAD.encode([0u8; 32]));
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][0]["state"] = json!("revoked");
        assert!(check(&record).is_ok());
        let mut record = fixture();
        let mut signature = URL_SAFE_NO_PAD
            .decode(record["keys"][2]["proof"]["value"].as_str().unwrap())
            .unwrap();
        flip_s(
            &mut signature,
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        );
        record["keys"][2]["proof"]["value"] = json!(URL_SAFE_NO_PAD.encode(signature));
        assert!(check(&record).is_err());
        let mut record = fixture();
        let mut signature = URL_SAFE_NO_PAD
            .decode(record["keys"][3]["proof"]["value"].as_str().unwrap())
            .unwrap();
        signature[64] ^= 1;
        record["keys"][3]["proof"]["value"] = json!(URL_SAFE_NO_PAD.encode(signature));
        assert!(check(&record).is_err());
        let mut record = fixture();
        let mut signature = URL_SAFE_NO_PAD
            .decode(record["keys"][3]["proof"]["value"].as_str().unwrap())
            .unwrap();
        flip_s(
            &mut signature,
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        );
        signature[64] ^= 1;
        record["keys"][3]["proof"]["value"] = json!(URL_SAFE_NO_PAD.encode(signature));
        assert!(check(&record).is_err());
    }

    #[test]
    fn rejects_mixed_torsion_ed25519_point() {
        let base = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let mixed = base + curve25519_dalek::constants::EIGHT_TORSION[1];
        assert!(prime_ed_point(&base.compress().to_bytes()));
        assert!(!prime_ed_point(&mixed.compress().to_bytes()));
    }
}
