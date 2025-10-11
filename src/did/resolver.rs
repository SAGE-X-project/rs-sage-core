//! DID Resolution
//!
//! This module provides DID resolution functionality with both memory-based
//! and blockchain-based resolvers.

use crate::did::{DIDDocument, DIDMethod, DID};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[cfg(feature = "blockchain")]
use crate::blockchain::DIDRegistry;
#[cfg(feature = "blockchain")]
use std::time::{Duration, Instant};

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
#[cfg(not(feature = "blockchain"))]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to a DID Document
    fn resolve(&self, did: &DID) -> Result<ResolutionResult>;

    /// Registers a DID Document (for testing and local resolution)
    fn register(&self, did: DID, document: DIDDocument) -> Result<()>;
}

/// DID Resolver trait with async support (blockchain feature)
#[cfg(feature = "blockchain")]
#[async_trait::async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to a DID Document
    async fn resolve(&self, did: &DID) -> Result<ResolutionResult>;

    /// Registers a DID Document (for testing and local resolution)
    async fn register(&self, did: DID, document: DIDDocument) -> Result<()>;
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

#[cfg(not(feature = "blockchain"))]
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

#[cfg(feature = "blockchain")]
#[async_trait::async_trait]
impl DIDResolver for MemoryDIDResolver {
    async fn resolve(&self, did: &DID) -> Result<ResolutionResult> {
        let storage = self.storage.read().unwrap();

        match storage.get(did.as_str()) {
            Some(document) => Ok(ResolutionResult::success(document.clone())),
            None => Ok(ResolutionResult::error(format!(
                "DID not found: {}",
                did.as_str()
            ))),
        }
    }

    async fn register(&self, did: DID, document: DIDDocument) -> Result<()> {
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

/// Cache entry for DID Documents
#[cfg(feature = "blockchain")]
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached DID Document
    document: DIDDocument,
    /// Timestamp when cached
    cached_at: Instant,
}

/// Blockchain DID Resolver with caching
///
/// This resolver queries blockchain smart contracts for DID Documents
/// and caches results to improve performance.
#[cfg(feature = "blockchain")]
pub struct BlockchainDIDResolver<M: ethers::providers::Middleware> {
    /// DID Registry contract
    registry: Arc<DIDRegistry<M>>,
    /// In-memory cache for resolved DIDs
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache TTL (time-to-live)
    cache_ttl: Duration,
}

#[cfg(feature = "blockchain")]
impl<M: ethers::providers::Middleware + 'static> BlockchainDIDResolver<M> {
    /// Creates a new blockchain-based DID resolver
    pub fn new(registry: Arc<DIDRegistry<M>>) -> Self {
        Self::with_cache_ttl(registry, Duration::from_secs(300)) // 5 minutes default
    }

    /// Creates a new blockchain-based DID resolver with custom cache TTL
    pub fn with_cache_ttl(registry: Arc<DIDRegistry<M>>, cache_ttl: Duration) -> Self {
        Self {
            registry,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
        }
    }

    /// Creates a resolver from a blockchain client and contract address
    pub fn from_client(
        client: Arc<M>,
        contract_address: ethers::types::Address,
    ) -> Self {
        let registry = Arc::new(DIDRegistry::new(contract_address, client));
        Self::new(registry)
    }

    /// Clears the cache
    pub fn clear_cache(&self) {
        self.cache.write().unwrap().clear();
    }

    /// Returns the number of cached entries
    pub fn cache_len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Checks if a cache entry is still valid
    fn is_cache_valid(&self, entry: &CacheEntry) -> bool {
        entry.cached_at.elapsed() < self.cache_ttl
    }

    /// Gets a DID Document from cache if available and valid
    fn get_from_cache(&self, did: &DID) -> Option<DIDDocument> {
        let cache = self.cache.read().unwrap();

        if let Some(entry) = cache.get(did.as_str()) {
            if self.is_cache_valid(entry) {
                return Some(entry.document.clone());
            }
        }

        None
    }

    /// Stores a DID Document in cache
    fn store_in_cache(&self, did: &DID, document: DIDDocument) {
        let mut cache = self.cache.write().unwrap();

        cache.insert(
            did.to_string(),
            CacheEntry {
                document,
                cached_at: Instant::now(),
            },
        );
    }

    /// Removes a DID from cache
    fn invalidate_cache(&self, did: &DID) {
        let mut cache = self.cache.write().unwrap();
        cache.remove(did.as_str());
    }
}

#[cfg(feature = "blockchain")]
#[async_trait::async_trait]
impl<M: ethers::providers::Middleware + 'static> DIDResolver for BlockchainDIDResolver<M> {
    async fn resolve(&self, did: &DID) -> Result<ResolutionResult> {
        // Only support chain method
        if did.method() != DIDMethod::Chain.as_str() {
            return Ok(ResolutionResult::error(format!(
                "Blockchain resolver only supports chain method, got: {}",
                did.method()
            )));
        }

        // Check cache first
        if let Some(document) = self.get_from_cache(did) {
            return Ok(ResolutionResult::success(document));
        }

        // Query blockchain
        match self.registry.get_did_document(did).await {
            Ok(Some(document)) => {
                // Store in cache
                self.store_in_cache(did, document.clone());
                Ok(ResolutionResult::success(document))
            }
            Ok(None) => Ok(ResolutionResult::error(format!(
                "DID not found on blockchain: {}",
                did.as_str()
            ))),
            Err(e) => Ok(ResolutionResult::error(format!(
                "Failed to query blockchain: {}",
                e
            ))),
        }
    }

    async fn register(&self, did: DID, document: DIDDocument) -> Result<()> {
        // Only support chain method
        if did.method() != DIDMethod::Chain.as_str() {
            return Err(Error::InvalidInput(format!(
                "Blockchain resolver only supports chain method, got: {}",
                did.method()
            )));
        }

        // Register on blockchain
        self.registry
            .register_did(&did, &document)
            .await
            .map_err(|e| Error::Other(format!("Failed to register DID on blockchain: {}", e)))?;

        // Invalidate cache for this DID
        self.invalidate_cache(&did);

        Ok(())
    }
}

/// Placeholder BlockchainDIDResolver for non-blockchain builds
#[cfg(not(feature = "blockchain"))]
pub struct BlockchainDIDResolver {
    _rpc_endpoint: String,
}

#[cfg(not(feature = "blockchain"))]
impl BlockchainDIDResolver {
    pub fn new(rpc_endpoint: impl Into<String>) -> Self {
        Self {
            _rpc_endpoint: rpc_endpoint.into(),
        }
    }
}

#[cfg(not(feature = "blockchain"))]
impl DIDResolver for BlockchainDIDResolver {
    fn resolve(&self, did: &DID) -> Result<ResolutionResult> {
        if did.method() != DIDMethod::Chain.as_str() {
            return Ok(ResolutionResult::error(format!(
                "Blockchain resolver only supports chain method, got: {}",
                did.method()
            )));
        }

        Ok(ResolutionResult::error(
            "Blockchain feature not enabled".to_string(),
        ))
    }

    fn register(&self, _did: DID, _document: DIDDocument) -> Result<()> {
        Err(Error::Other(
            "Blockchain feature not enabled".to_string(),
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

    #[cfg(not(feature = "blockchain"))]
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

    #[cfg(feature = "blockchain")]
    #[tokio::test]
    async fn test_memory_resolver_register_and_resolve() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let document = DIDDocument::new(did.clone());

        // Register
        resolver.register(did.clone(), document.clone()).await.unwrap();
        assert_eq!(resolver.len(), 1);

        // Resolve
        let result = resolver.resolve(&did).await.unwrap();
        assert!(result.document.is_some());
        assert_eq!(result.document.unwrap().id, did.to_string());
    }

    #[cfg(not(feature = "blockchain"))]
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

    #[cfg(feature = "blockchain")]
    #[tokio::test]
    async fn test_memory_resolver_resolve_not_found() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

        let result = resolver.resolve(&did).await.unwrap();
        assert!(result.document.is_none());
        assert!(result.metadata.error.is_some());
        assert!(result.metadata.error.unwrap().contains("not found"));
    }

    #[cfg(not(feature = "blockchain"))]
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

    #[cfg(feature = "blockchain")]
    #[tokio::test]
    async fn test_memory_resolver_duplicate_registration() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let document = DIDDocument::new(did.clone());

        resolver.register(did.clone(), document.clone()).await.unwrap();
        let result = resolver.register(did, document).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_resolver_clear() {
        let resolver = MemoryDIDResolver::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let document = DIDDocument::new(did.clone());

        #[cfg(not(feature = "blockchain"))]
        {
            resolver.register(did, document).unwrap();
            assert_eq!(resolver.len(), 1);

            resolver.clear();
            assert!(resolver.is_empty());
        }

        #[cfg(feature = "blockchain")]
        {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                resolver.register(did, document).await.unwrap();
                assert_eq!(resolver.len(), 1);

                resolver.clear();
                assert!(resolver.is_empty());
            });
        }
    }

    #[cfg(not(feature = "blockchain"))]
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
            .contains("not enabled"));
    }
}
