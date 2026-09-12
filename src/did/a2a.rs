//! A2A agent card and its proof (`07-a2a.md`).

use crate::crypto::{KeyPair, KeyType, PublicKey, Signature, Signer as _, Verifier as _};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A public key entry of the card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2APublicKey {
    /// `<DID>#key-<n>`
    pub id: String,
    /// `Ed25519VerificationKey2020`, `EcdsaSecp256k1VerificationKey2019` or `X25519KeyAgreementKey2019`
    #[serde(rename = "type")]
    pub key_type: String,
    /// The DID
    pub controller: String,
    /// Base58 of the raw key bytes
    #[serde(rename = "publicKeyBase58")]
    pub public_key_base58: String,
    /// Hex of the raw key bytes
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: String,
}

/// A service endpoint of the card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AEndpoint {
    /// Endpoint type (`MessageService`, ...)
    #[serde(rename = "type")]
    pub endpoint_type: String,
    /// Endpoint URI
    pub uri: String,
}

/// The proof member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AProof {
    /// `Ed25519Signature2020` or `EcdsaSecp256k1Signature2019`
    #[serde(rename = "type")]
    pub proof_type: String,
    /// RFC 3339 signing time
    pub created: String,
    /// `<DID>#key-<n>`
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// `assertionMethod`
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    /// Base58 of the raw signature
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// The agent card as exchanged on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AAgentCard {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID
    pub id: String,
    /// `["Agent", "AIAgent"]`
    #[serde(rename = "type")]
    pub card_type: Vec<String>,
    /// Name
    pub name: String,
    /// Description
    pub description: String,
    /// Registered keys in registry order
    #[serde(rename = "publicKey")]
    pub public_keys: Vec<A2APublicKey>,
    /// Service endpoints
    #[serde(rename = "service")]
    pub services: Vec<A2AEndpoint>,
    /// Capability names
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Creation time
    pub created: String,
    /// Update time
    pub updated: String,
    /// Proof (absent while building)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<A2AProof>,
}

/// What a card is built from.
#[derive(Debug, Clone)]
pub struct CardMetadata {
    /// The DID
    pub did: String,
    /// Name
    pub name: String,
    /// Description
    pub description: String,
    /// Service endpoint (`MessageService`)
    pub endpoint: String,
    /// Registered keys: `(key type, raw public key bytes)`; X25519 uses `None`
    pub keys: Vec<(Option<KeyType>, Vec<u8>)>,
    /// Capability names
    pub capabilities: Vec<String>,
    /// RFC 3339 timestamps
    pub created: String,
    /// RFC 3339 timestamps
    pub updated: String,
}

const CONTEXT: [&str; 3] = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/secp256k1-2019/v1",
];

fn method_type(kt: Option<KeyType>) -> &'static str {
    match kt {
        Some(KeyType::Ed25519) => "Ed25519VerificationKey2020",
        Some(KeyType::Secp256k1) => "EcdsaSecp256k1VerificationKey2019",
        Some(KeyType::P256) => "JsonWebKey2020",
        None => "X25519KeyAgreementKey2019",
    }
}

fn key_type_of(method: &str) -> Option<KeyType> {
    match method {
        "Ed25519VerificationKey2020" => Some(KeyType::Ed25519),
        "EcdsaSecp256k1VerificationKey2019" => Some(KeyType::Secp256k1),
        _ => None,
    }
}

impl A2AAgentCard {
    /// Build an unsigned card from metadata (`07-a2a.md` §1).
    pub fn from_metadata(meta: &CardMetadata) -> Self {
        let public_keys = meta
            .keys
            .iter()
            .enumerate()
            .map(|(i, (kt, bytes))| A2APublicKey {
                id: format!("{}#key-{}", meta.did, i + 1),
                key_type: method_type(*kt).to_string(),
                controller: meta.did.clone(),
                public_key_base58: bs58::encode(bytes).into_string(),
                public_key_hex: hex::encode(bytes),
            })
            .collect();
        Self {
            context: CONTEXT.iter().map(|s| s.to_string()).collect(),
            id: meta.did.clone(),
            card_type: vec!["Agent".into(), "AIAgent".into()],
            name: meta.name.clone(),
            description: meta.description.clone(),
            public_keys,
            services: if meta.endpoint.is_empty() {
                Vec::new()
            } else {
                vec![A2AEndpoint {
                    endpoint_type: "MessageService".into(),
                    uri: meta.endpoint.clone(),
                }]
            },
            capabilities: meta.capabilities.clone(),
            created: meta.created.clone(),
            updated: meta.updated.clone(),
            proof: None,
        }
    }

    /// Parse a card from JSON.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| Error::ParseError(format!("agent card: {e}")))
    }

    /// Serialise the card.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// JCS bytes of the card without `proof` (what is signed).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut v: Value =
            serde_json::to_value(self).map_err(|e| Error::Serialization(e.to_string()))?;
        if let Value::Object(m) = &mut v {
            m.remove("proof");
        }
        crate::jcs::canonicalize(
            &serde_json::to_vec(&v).map_err(|e| Error::Serialization(e.to_string()))?,
        )
    }

    /// Sign the card with `key_pair`, which must be the key at `key_index`
    /// (1-based) of `publicKey`.
    pub fn sign(&mut self, key_pair: &KeyPair, key_index: usize) -> Result<()> {
        let entry = self
            .public_keys
            .get(key_index.wrapping_sub(1))
            .ok_or_else(|| Error::InvalidInput("key index out of range".into()))?;
        if entry.public_key_hex != hex::encode(key_pair.public_key_bytes()) {
            return Err(Error::InvalidInput(
                "key pair does not match the card entry".into(),
            ));
        }
        let proof_type = match key_pair.key_type() {
            KeyType::Ed25519 => "Ed25519Signature2020",
            KeyType::Secp256k1 => "EcdsaSecp256k1Signature2019",
            KeyType::P256 => return Err(Error::Unsupported("P-256 proofs are not defined".into())),
        };
        self.proof = None;
        let sig = key_pair.sign(&self.canonical_bytes()?)?;
        self.proof = Some(A2AProof {
            proof_type: proof_type.into(),
            created: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            verification_method: entry.id.clone(),
            proof_purpose: "assertionMethod".into(),
            proof_value: bs58::encode(sig.to_bytes()).into_string(),
        });
        Ok(())
    }

    /// Structural checks (`07-a2a.md` §3 steps 2-3) without verifying the signature.
    pub fn validate(&self) -> Result<()> {
        if !self.id.starts_with("did:sage:") {
            return Err(Error::ValidationError(
                "id is not a did:sage identifier".into(),
            ));
        }
        for k in &self.public_keys {
            if !k.id.starts_with(&format!("{}#", self.id)) {
                return Err(Error::ValidationError(format!(
                    "key id {} does not belong to {}",
                    k.id, self.id
                )));
            }
            let hex_bytes = hex::decode(&k.public_key_hex)
                .map_err(|_| Error::ValidationError("publicKeyHex".into()))?;
            let b58 = bs58::decode(&k.public_key_base58)
                .into_vec()
                .map_err(|_| Error::ValidationError("publicKeyBase58".into()))?;
            if hex_bytes != b58 {
                return Err(Error::ValidationError(format!(
                    "{}: hex and base58 keys differ",
                    k.id
                )));
            }
        }
        if let Some(p) = &self.proof {
            if !p.verification_method.starts_with(&format!("{}#", self.id)) {
                return Err(Error::ValidationError(
                    "verificationMethod is not a key of this card".into(),
                ));
            }
            if p.proof_purpose != "assertionMethod" {
                return Err(Error::ValidationError(
                    "proofPurpose must be assertionMethod".into(),
                ));
            }
        }
        Ok(())
    }

    /// Verify the proof: JCS of the card without `proof`, signed by the key
    /// named in `verificationMethod` (`07-a2a.md` §2-§3).
    pub fn verify_proof(&self) -> Result<()> {
        self.validate()?;
        let proof = self
            .proof
            .as_ref()
            .ok_or_else(|| Error::Verification("no proof".into()))?;
        let entry = self
            .public_keys
            .iter()
            .find(|k| k.id == proof.verification_method)
            .ok_or_else(|| Error::Verification("verificationMethod not found".into()))?;
        let key_type = key_type_of(&entry.key_type)
            .ok_or_else(|| Error::Verification("key type cannot sign".into()))?;
        let expected_type = match key_type {
            KeyType::Ed25519 => "Ed25519Signature2020",
            KeyType::Secp256k1 => "EcdsaSecp256k1Signature2019",
            KeyType::P256 => unreachable!(),
        };
        if proof.proof_type != expected_type {
            return Err(Error::Verification(
                "proof type does not match the key".into(),
            ));
        }
        let key_bytes = hex::decode(&entry.public_key_hex)
            .map_err(|_| Error::Verification("publicKeyHex".into()))?;
        let public = PublicKey::from_bytes(key_type, &key_bytes)?;
        let sig_bytes = bs58::decode(&proof.proof_value)
            .into_vec()
            .map_err(|_| Error::Verification("proofValue".into()))?;
        let signature = Signature::from_bytes(key_type, &sig_bytes)?;
        public
            .verify(&self.canonical_bytes()?, &signature)
            .map_err(|_| Error::Verification("agent card proof failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(did: &str, kp: &KeyPair) -> CardMetadata {
        CardMetadata {
            did: did.into(),
            name: "a".into(),
            description: "d".into(),
            endpoint: "https://a.example/a2a".into(),
            keys: vec![
                (Some(kp.key_type()), kp.public_key_bytes()),
                (None, vec![7u8; 32]),
            ],
            capabilities: vec!["message-signing".into()],
            created: "2026-09-01T12:00:00Z".into(),
            updated: "2026-09-01T12:00:00Z".into(),
        }
    }

    #[test]
    fn sign_and_verify_both_key_types() {
        for kt in [KeyType::Ed25519, KeyType::Secp256k1] {
            let kp = KeyPair::generate(kt).unwrap();
            let did = crate::did::generate_did(crate::did::Chain::Ethereum, "0xabc");
            let mut card = A2AAgentCard::from_metadata(&meta(&did, &kp));
            card.sign(&kp, 1).unwrap();
            let json = card.to_json().unwrap();
            let parsed = A2AAgentCard::from_json(&json).unwrap();
            parsed.verify_proof().unwrap();
            let mut tampered = parsed.clone();
            tampered.name = "b".into();
            assert!(tampered.verify_proof().is_err());
            let mut wrong_key = parsed.clone();
            wrong_key.proof.as_mut().unwrap().verification_method = format!("{did}#key-2");
            assert!(wrong_key.verify_proof().is_err());
        }
    }
}
