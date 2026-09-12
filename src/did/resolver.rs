//! DID Resolver Implementation
//!
//! This module provides DID resolution functionality integrating with blockchain.

use crate::error::{Error, Result};
pub use crate::hpke::types::{AgentDID, DIDResolver};
use crate::hpke::types::{DIDDocument, DIDResolutionResult, VerificationMethod};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Blockchain-based DID Resolver
///
/// Resolves DIDs by querying blockchain registries (Ethereum, Solana, etc.)
pub struct BlockchainDIDResolver {}

impl BlockchainDIDResolver {
    /// Create a new blockchain DID resolver
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for BlockchainDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for BlockchainDIDResolver {
    fn resolve(&self, _did: &AgentDID) -> Result<DIDResolutionResult> {
        {
            Err(Error::Unsupported("Blockchain feature not enabled".into()))
        }
    }
}

/// Memory-based DID Resolver for testing
///
/// In-memory DID document storage for testing and development
#[derive(Clone)]
pub struct MemoryDIDResolver {
    documents: Arc<RwLock<HashMap<String, DIDDocument>>>,
}

impl MemoryDIDResolver {
    /// Create a new memory resolver
    pub fn new() -> Self {
        Self {
            documents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a DID document
    pub fn register(&self, did: AgentDID, document: DIDDocument) -> Result<()> {
        let key = did;

        let mut docs = self.documents.write().unwrap();
        docs.insert(key, document);
        Ok(())
    }

    /// Get the number of registered DIDs
    pub fn len(&self) -> usize {
        self.documents.read().unwrap().len()
    }

    /// Check if the resolver is empty
    pub fn is_empty(&self) -> bool {
        self.documents.read().unwrap().is_empty()
    }
}

impl Default for MemoryDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for MemoryDIDResolver {
    fn resolve(&self, did: &AgentDID) -> Result<DIDResolutionResult> {
        let key = did.clone();

        let docs = self.documents.read().unwrap();

        if let Some(document) = docs.get(&key) {
            Ok(DIDResolutionResult {
                document: Some(document.clone()),
                metadata: Some(json!({
                    "contentType": "application/did+ld+json"
                })),
            })
        } else {
            // Return not found result with error metadata
            Ok(DIDResolutionResult {
                document: None,
                metadata: Some(json!({
                    "error": format!("DID {} not found", key)
                })),
            })
        }
    }
}

/// Mock DID Resolver for testing
///
/// Returns pre-configured DID documents for testing purposes
pub struct MockDIDResolver {
    /// Optional pre-configured document to return
    document: Option<DIDDocument>,
}

impl MockDIDResolver {
    /// Create a new mock resolver
    pub fn new() -> Self {
        Self { document: None }
    }

    /// Create a new mock resolver with a specific document
    pub fn with_document(document: DIDDocument) -> Self {
        Self {
            document: Some(document),
        }
    }

    /// Create a mock resolver with a default X25519 key for testing
    pub fn with_x25519_key(did: &str, public_key: &[u8]) -> Self {
        let key_multibase = format!("z{}", bs58::encode(public_key).into_string());

        let verification_method = VerificationMethod {
            id: format!("{did}#key-1"),
            method_type: "X25519KeyAgreementKey2020".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(key_multibase),
            public_key_jwk: None,
        };

        let document = DIDDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/x25519-2020/v1".to_string(),
            ],
            id: did.to_string(),
            verification_method: vec![verification_method],
            authentication: Vec::new(),
        };

        Self::with_document(document)
    }
}

impl Default for MockDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for MockDIDResolver {
    fn resolve(&self, did: &AgentDID) -> Result<DIDResolutionResult> {
        let did_str = did.clone();

        if let Some(doc) = &self.document {
            return Ok(DIDResolutionResult {
                document: Some(doc.clone()),
                metadata: Some(json!({
                    "contentType": "application/did+ld+json"
                })),
            });
        }

        // Generate a default mock document with a dummy X25519 key
        let dummy_key = vec![0u8; 32]; // Dummy key for testing
        let key_multibase = format!("z{}", bs58::encode(&dummy_key).into_string());

        let verification_method = VerificationMethod {
            id: format!("{did_str}#key-1"),
            method_type: "X25519KeyAgreementKey2020".to_string(),
            controller: did_str.clone(),
            public_key_multibase: Some(key_multibase),
            public_key_jwk: None,
        };

        let document = DIDDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/x25519-2020/v1".to_string(),
            ],
            id: did_str.clone(),
            verification_method: vec![verification_method],
            authentication: Vec::new(),
        };

        Ok(DIDResolutionResult {
            document: Some(document),
            metadata: Some(json!({
                "contentType": "application/did+ld+json"
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_resolver_creation() {
        let _resolver = MockDIDResolver::new();
    }

    #[test]
    fn test_mock_resolver_resolve() {
        let resolver = MockDIDResolver::new();
        let did = "did:sage:ethereum:0x1234567890123456789012345678901234567890".to_string();
        let result = resolver.resolve(&did).unwrap();

        assert!(result.document.is_some());
        let doc = result.document.unwrap();
        assert_eq!(doc.id, did);
        assert!(!doc.verification_method.is_empty());
    }

    #[test]
    fn test_mock_resolver_with_x25519_key() {
        let did = "did:sage:ethereum:0x1234567890123456789012345678901234567890";
        let public_key = [1u8; 32];
        let resolver = MockDIDResolver::with_x25519_key(did, &public_key);

        let result = resolver.resolve(&did.to_string()).unwrap();

        assert!(result.document.is_some());
        let doc = result.document.unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert!(doc.verification_method[0].method_type.contains("X25519"));
    }

    #[test]
    fn test_blockchain_resolver_creation() {
        let _resolver = BlockchainDIDResolver::new();
    }

    #[test]
    fn test_blockchain_resolver_default() {
        let _resolver = BlockchainDIDResolver::default();
    }
}
