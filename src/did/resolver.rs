//! DID Resolution
//!
//! This module provides DID resolution functionality. The current implementation
//! is basic and will be enhanced with blockchain integration in Phase 3.

use crate::did::{DIDDocument, DIDMethod, DID};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Result of DID resolution
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// The resolved DID Document
    pub document: Option<DIDDocument>,
    /// Resolution metadata
    pub metadata: ResolutionMetadata,
}

/// Metadata about the resolution process
#[derive(Debug, Clone, Default)]
pub struct ResolutionMetadata {
    /// Content type of the resolved document
    pub content_type: Option<String>,
    /// Error message if resolution failed
    pub error: Option<String>,
}

impl ResolutionResult {
    /// Creates a successful resolution result
    pub fn success(document: DIDDocument) -> Self {
        Self {
            document: Some(document),
            metadata: ResolutionMetadata {
                content_type: Some("application/did+ld+json".to_string()),
                error: None,
            },
        }
    }

    /// Creates a failed resolution result
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            document: None,
            metadata: ResolutionMetadata {
                content_type: None,
                error: Some(error.into()),
            },
        }
    }
}

/// DID Resolver trait
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to a DID Document
    fn resolve(&self, did: &DID) -> Result<ResolutionResult>;

    /// Registers a DID Document (for testing and local resolution)
    fn register(&self, did: DID, document: DIDDocument) -> Result<()>;
}

/// In-memory DID Resolver
///
/// This resolver stores DID Documents in memory for testing and development.
/// In Phase 3, this will be replaced/augmented with blockchain-based resolution.
pub struct MemoryDIDResolver {
    /// Storage for DID Documents
    storage: Arc<RwLock<HashMap<String, DIDDocument>>>,
}

impl MemoryDIDResolver {
    /// Creates a new memory-based DID resolver
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the number of registered DIDs
    pub fn len(&self) -> usize {
        self.storage.read().unwrap().len()
    }

    /// Returns true if no DIDs are registered
    pub fn is_empty(&self) -> bool {
        self.storage.read().unwrap().is_empty()
    }

    /// Clears all registered DIDs
    pub fn clear(&self) {
        self.storage.write().unwrap().clear();
    }
}

impl Default for MemoryDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDResolver for MemoryDIDResolver {
    fn resolve(&self, did: &DID) -> Result<ResolutionResult> {
        let storage = self.storage.read().unwrap();

        match storage.get(did.as_str()) {
            Some(document) => Ok(ResolutionResult::success(document.clone())),
            None => Ok(ResolutionResult::error(format!(
                "DID not found: {}",
                did.as_str()
            ))),
        }
    }

    fn register(&self, did: DID, document: DIDDocument) -> Result<()> {
        let mut storage = self.storage.write().unwrap();

        if storage.contains_key(did.as_str()) {
            return Err(Error::InvalidInput(format!(
                "DID already registered: {}",
                did.as_str()
            )));
        }

        storage.insert(did.to_string(), document);
        Ok(())
    }
}

/// Blockchain DID Resolver (Placeholder)
///
/// This resolver will query blockchain smart contracts for DID Documents.
/// Full implementation will be in Phase 3.
pub struct BlockchainDIDResolver {
    /// RPC endpoint for blockchain queries
    _rpc_endpoint: String,
}

impl BlockchainDIDResolver {
    /// Creates a new blockchain-based DID resolver
    pub fn new(rpc_endpoint: impl Into<String>) -> Self {
        Self {
            _rpc_endpoint: rpc_endpoint.into(),
        }
    }
}

impl DIDResolver for BlockchainDIDResolver {
    fn resolve(&self, did: &DID) -> Result<ResolutionResult> {
        // Placeholder: will be implemented in Phase 3 with actual blockchain queries
        if did.method() != DIDMethod::Chain.as_str() {
            return Ok(ResolutionResult::error(format!(
                "Blockchain resolver only supports chain method, got: {}",
                did.method()
            )));
        }

        Ok(ResolutionResult::error(
            "Blockchain resolution not yet implemented (Phase 3)".to_string(),
        ))
    }

    fn register(&self, _did: DID, _document: DIDDocument) -> Result<()> {
        Err(Error::Other(
            "Blockchain registration not yet implemented (Phase 3)".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType};
    use crate::did::method::{generate_did_from_pubkey, DIDMethod};

    #[test]
    fn test_memory_resolver_new() {
        let resolver = MemoryDIDResolver::new();
        assert!(resolver.is_empty());
    }

    #[test]
    fn test_memory_resolver_register_and_resolve() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let document = DIDDocument::new(did.clone());

        // Register
        resolver.register(did.clone(), document.clone()).unwrap();
        assert_eq!(resolver.len(), 1);

        // Resolve
        let result = resolver.resolve(&did).unwrap();
        assert!(result.document.is_some());
        assert_eq!(result.document.unwrap().id, did.to_string());
    }

    #[test]
    fn test_memory_resolver_resolve_not_found() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

        let result = resolver.resolve(&did).unwrap();
        assert!(result.document.is_none());
        assert!(result.metadata.error.is_some());
        assert!(result.metadata.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_memory_resolver_duplicate_registration() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let document = DIDDocument::new(did.clone());

        resolver.register(did.clone(), document.clone()).unwrap();
        let result = resolver.register(did, document);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_resolver_clear() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let document = DIDDocument::new(did.clone());

        resolver.register(did, document).unwrap();
        assert_eq!(resolver.len(), 1);

        resolver.clear();
        assert!(resolver.is_empty());
    }

    #[test]
    fn test_blockchain_resolver_placeholder() {
        let resolver = BlockchainDIDResolver::new("http://localhost:8545");
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Chain).unwrap();

        let result = resolver.resolve(&did).unwrap();
        assert!(result.document.is_none());
        assert!(result.metadata.error.is_some());
        assert!(result
            .metadata
            .error
            .unwrap()
            .contains("not yet implemented"));
    }
}
