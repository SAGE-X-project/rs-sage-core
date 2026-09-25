//! Exact 0.10.0 REG-04 proof challenge bytes, separate from legacy DID proofs.
use super::rejected;
use crate::error::Result;

/// Construct REG-04 bytes for previously validated record components.
/// DID syntax, key encoding, signer authority, and proof signatures remain
/// the validating registry Source's responsibility.
pub fn pop_challenge010(
    registry_id: &str,
    agent_id: &str,
    name: &str,
    alg: &str,
    key_bytes: &[u8],
) -> Result<Vec<u8>> {
    let fields: [&[u8]; 5] = [
        registry_id.as_bytes(),
        agent_id.as_bytes(),
        name.as_bytes(),
        alg.as_bytes(),
        key_bytes,
    ];
    for (index, field) in fields.iter().enumerate() {
        if field.is_empty()
            || field.len() > u16::MAX as usize
            || (index < 4 && !field.iter().all(u8::is_ascii_graphic))
        {
            return Err(rejected());
        }
    }
    let mut challenge = b"sage-pop-0.10.0".to_vec();
    for field in fields {
        challenge.extend_from_slice(&(field.len() as u16).to_be_bytes());
        challenge.extend_from_slice(field);
    }
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    #[test]
    fn matches_both_specification_vectors() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/registry-proof-0.10.0.json"
        ))
        .unwrap();
        let vectors = fixture["challenge_vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 2);
        for vector in vectors {
            let value = |key| vector[key].as_str().unwrap();
            let key = hex::decode(value("public_key_hex")).unwrap();
            let challenge = pop_challenge010(
                value("registry_id"),
                value("agent_id"),
                value("name"),
                value("alg"),
                &key,
            )
            .unwrap();
            assert_eq!(hex::encode(&challenge), value("challenge_hex"));
            assert_eq!(
                hex::encode(Sha256::digest(&challenge)),
                value("challenge_sha256")
            );
        }
    }

    #[test]
    fn rejects_invalid_field_boundaries() {
        let valid = ("web:example.com", "agent", "key", "ed25519", &[1u8][..]);
        assert!(pop_challenge010("", valid.1, valid.2, valid.3, valid.4).is_err());
        assert!(pop_challenge010(valid.0, "agént", valid.2, valid.3, valid.4).is_err());
        assert!(pop_challenge010(valid.0, valid.1, "ke\ny", valid.3, valid.4).is_err());
        assert!(pop_challenge010(valid.0, valid.1, valid.2, valid.3, &[]).is_err());
        assert!(pop_challenge010(valid.0, valid.1, valid.2, valid.3, &vec![1; 65536]).is_err());
    }
}
