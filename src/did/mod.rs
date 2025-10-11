//! Decentralized Identifier (DID) Module
//!
//! This module provides DID functionality for SAGE, including:
//! - DID Document representation
//! - DID generation from cryptographic keys
//! - DID method implementations
//! - DID resolution (basic, will be enhanced with blockchain integration in Phase 3)
//!
//! ## DID Format
//!
//! SAGE uses the following DID format:
//! ```text
//! did:sage:<method>:<identifier>
//! ```
//!
//! Where:
//! - `method` is the DID method (e.g., "key" for key-based, "chain" for blockchain-based)
//! - `identifier` is the method-specific identifier (e.g., public key fingerprint)

pub mod document;
pub mod method;
pub mod resolver;

pub use document::{DIDDocument, ServiceEndpoint, ServiceEndpointValue, VerificationMethod, VerificationReference};
pub use method::{DIDMethod, generate_did_from_pubkey, parse_did};
pub use resolver::{BlockchainDIDResolver, DIDResolver, MemoryDIDResolver, ResolutionMetadata, ResolutionResult};

use crate::error::{Error, Result};

/// Represents a Decentralized Identifier (DID)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DID {
    /// The complete DID string (e.g., "did:sage:key:z6Mk...")
    pub did: String,
    /// The DID method (e.g., "key", "chain")
    pub method: String,
    /// The method-specific identifier
    pub identifier: String,
}

impl DID {
    /// Creates a new DID from components
    pub fn new(method: impl Into<String>, identifier: impl Into<String>) -> Self {
        let method = method.into();
        let identifier = identifier.into();
        let did = format!("did:sage:{}:{}", method, identifier);

        Self {
            did,
            method,
            identifier,
        }
    }

    /// Parses a DID string into components
    pub fn parse(did: &str) -> Result<Self> {
        parse_did(did)
    }

    /// Returns the complete DID string
    pub fn as_str(&self) -> &str {
        &self.did
    }

    /// Returns the DID method
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the method-specific identifier
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl std::fmt::Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

impl std::str::FromStr for DID {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_new() {
        let did = DID::new("key", "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(
            did.as_str(),
            "did:sage:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert_eq!(did.method(), "key");
        assert_eq!(did.identifier(), "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    }

    #[test]
    fn test_did_display() {
        let did = DID::new("key", "abc123");
        assert_eq!(format!("{}", did), "did:sage:key:abc123");
    }

    #[test]
    fn test_did_parse() {
        let did = DID::parse("did:sage:key:abc123").unwrap();
        assert_eq!(did.method(), "key");
        assert_eq!(did.identifier(), "abc123");
    }
}
