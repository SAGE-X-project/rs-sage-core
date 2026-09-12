//! DID (Decentralized Identifier) Module
//!
//! This module provides DID types and resolution functionality.

pub mod resolver;

use crate::crypto::PublicKey;
use crate::error::Result;

// Re-export main types for convenience
pub use crate::hpke::types::{
    AgentDID as DID, DIDDocument, DIDResolutionResult, VerificationMethod, VerificationReference,
};
pub use resolver::{DIDResolver, MemoryDIDResolver, MockDIDResolver};

/// DID generation methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DIDMethod {
    /// Key-based DID (did:sage:key:...)
    Key,
    /// Chain-based DID (did:sage:chain:...)
    Chain,
}

/// Generate DID from public key using specified method
///
/// # Arguments
/// * `public_key` - The public key to generate DID from
/// * `method` - The DID method to use (Key or Chain)
///
/// # Returns
/// DID string in the format `did:sage:{method}:{identifier}`
pub fn generate_did_from_pubkey(public_key: &PublicKey, method: DIDMethod) -> Result<DID> {
    use sha2::{Digest, Sha256};

    let key_bytes = public_key.to_bytes();

    match method {
        DIDMethod::Key => {
            // For key-based DID, use multibase encoding of the key
            let multibase = format!("z{}", bs58::encode(&key_bytes).into_string());

            Ok(format!("did:sage:key:{multibase}"))
        }
        DIDMethod::Chain => {
            // For chain-based DID, use hash of the key (Ethereum-style address)
            let mut hasher = Sha256::new();
            hasher.update(&key_bytes);
            let hash = hasher.finalize();

            // Take last 20 bytes and encode as hex (like Ethereum address)
            let identifier = hex::encode(&hash[12..]);

            Ok(format!("did:sage:chain:{identifier}"))
        }
    }
}

/// Extension methods for DID strings
pub trait DIDExt {
    /// Identifier part after `did:sage:<method>:`
    fn identifier(&self) -> String;
    /// The DID as a string slice
    fn as_str(&self) -> &str;
}

impl DIDExt for DID {
    fn identifier(&self) -> String {
        self.strip_prefix("did:sage:")
            .and_then(|s| s.split(':').nth(1))
            .unwrap_or("")
            .to_string()
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}
