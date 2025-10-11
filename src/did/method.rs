//! DID Method Implementations
//!
//! This module provides implementations for different DID methods supported by SAGE.

use crate::crypto::PublicKey;
use crate::error::{Error, Result};
use crate::did::DID;
use base58::ToBase58;
use sha2::{Digest, Sha256};

/// Supported DID methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DIDMethod {
    /// Key-based DID method (did:sage:key:)
    /// Uses base58-encoded public key fingerprint
    Key,
    /// Blockchain-based DID method (did:sage:chain:)
    /// Will be fully implemented with blockchain integration in Phase 3
    Chain,
}

impl DIDMethod {
    /// Returns the method identifier string
    pub fn as_str(&self) -> &'static str {
        match self {
            DIDMethod::Key => "key",
            DIDMethod::Chain => "chain",
        }
    }

    /// Parses a method identifier string
    pub fn parse(method: &str) -> Result<Self> {
        match method {
            "key" => Ok(DIDMethod::Key),
            "chain" => Ok(DIDMethod::Chain),
            _ => Err(Error::InvalidInput(format!(
                "Unknown DID method: {}",
                method
            ))),
        }
    }
}

impl std::fmt::Display for DIDMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Generates a DID from a public key using the specified method
///
/// # Arguments
///
/// * `public_key` - The public key to generate DID from
/// * `method` - The DID method to use
///
/// # Returns
///
/// A DID string in the format `did:sage:<method>:<identifier>`
pub fn generate_did_from_pubkey(public_key: &PublicKey, method: DIDMethod) -> Result<DID> {
    match method {
        DIDMethod::Key => generate_key_did(public_key),
        DIDMethod::Chain => generate_chain_did(public_key),
    }
}

/// Generates a key-based DID (did:sage:key:)
///
/// The identifier is a multibase-encoded (base58-btc) public key with:
/// - 'z' prefix for base58-btc multibase encoding
/// - Public key bytes encoded in base58
fn generate_key_did(public_key: &PublicKey) -> Result<DID> {
    // Get public key bytes
    let pub_key_bytes = public_key.to_bytes();

    // Encode as base58 with 'z' prefix (multibase base58-btc)
    let identifier = format!("z{}", pub_key_bytes.to_base58());

    Ok(DID::new("key", identifier))
}

/// Generates a blockchain-based DID (did:sage:chain:)
///
/// Uses SHA-256 hash of public key as the identifier
/// Full blockchain integration will be implemented in Phase 3
fn generate_chain_did(public_key: &PublicKey) -> Result<DID> {
    // Hash the public key
    let mut hasher = Sha256::new();
    hasher.update(public_key.to_bytes());
    let hash = hasher.finalize();

    // Take first 20 bytes and encode as hex (similar to Ethereum addresses)
    let identifier = hex::encode(&hash[..20]);

    Ok(DID::new("chain", identifier))
}

/// Parses a DID string into a DID struct
///
/// Expected format: `did:sage:<method>:<identifier>`
pub fn parse_did(did: &str) -> Result<DID> {
    let parts: Vec<&str> = did.split(':').collect();

    if parts.len() != 4 {
        return Err(Error::InvalidInput(format!(
            "Invalid DID format: {}. Expected 'did:sage:<method>:<identifier>'",
            did
        )));
    }

    if parts[0] != "did" {
        return Err(Error::InvalidInput(format!(
            "Invalid DID scheme: {}. Expected 'did'",
            parts[0]
        )));
    }

    if parts[1] != "sage" {
        return Err(Error::InvalidInput(format!(
            "Invalid DID namespace: {}. Expected 'sage'",
            parts[1]
        )));
    }

    let method = parts[2];
    let identifier = parts[3];

    // Validate method
    DIDMethod::parse(method)?;

    Ok(DID::new(method, identifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType};

    #[test]
    fn test_did_method_parse() {
        assert_eq!(DIDMethod::parse("key").unwrap(), DIDMethod::Key);
        assert_eq!(DIDMethod::parse("chain").unwrap(), DIDMethod::Chain);
        assert!(DIDMethod::parse("invalid").is_err());
    }

    #[test]
    fn test_generate_key_did() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

        assert!(did.as_str().starts_with("did:sage:key:z"));
        assert_eq!(did.method(), "key");
    }

    #[test]
    fn test_generate_chain_did() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Chain).unwrap();

        assert!(did.as_str().starts_with("did:sage:chain:"));
        assert_eq!(did.method(), "chain");
        // Chain DID should have 40 hex characters (20 bytes)
        assert_eq!(did.identifier().len(), 40);
    }

    #[test]
    fn test_parse_did() {
        let did_str = "did:sage:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let did = parse_did(did_str).unwrap();

        assert_eq!(did.as_str(), did_str);
        assert_eq!(did.method(), "key");
        assert_eq!(did.identifier(), "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    }

    #[test]
    fn test_parse_did_invalid_format() {
        assert!(parse_did("not:a:did").is_err());
        assert!(parse_did("did:other:key:abc").is_err());
        assert!(parse_did("did:sage:invalid:abc").is_err());
    }

    #[test]
    fn test_did_from_pubkey_deterministic() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did1 = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let did2 = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

        assert_eq!(did1.as_str(), did2.as_str());
    }
}
