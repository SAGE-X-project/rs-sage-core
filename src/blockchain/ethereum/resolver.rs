//! Ethereum DID Resolver
//!
//! This module provides DID resolution functionality for agents registered
//! on the AgentCardRegistry contract.
//!
//! # Features
//!
//! - Resolve agent metadata by DID
//! - Query public keys with filtering
//! - Check agent activation status
//! - Optional caching for performance
//!
//! # Example
//!
//! ```ignore
//! use sage_crypto_core::blockchain::ethereum::{EthereumClient, EthereumResolver};
//!
//! let client = EthereumClient::new(
//!     "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
//!     "0x1234567890123456789012345678901234567890",
//! ).await?;
//!
//! let resolver = EthereumResolver::new(client);
//!
//! // Resolve agent by DID
//! let agent = resolver.resolve_agent("did:sage:ethereum:0xabcd...").await?;
//! println!("Agent name: {}", agent.name);
//!
//! // Get all public keys
//! let keys = resolver.resolve_all_public_keys("did:sage:ethereum:0xabcd...").await?;
//! println!("Found {} keys", keys.len());
//! ```

use crate::blockchain::types::{AgentDID, AgentMetadata, PublicKeyInfo};
use crate::crypto::KeyType;
use crate::error::Result;
use super::client::EthereumClient;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cache entry with expiration
#[derive(Clone)]
struct CacheEntry<T> {
    /// Cached data
    data: T,
    /// When this entry was cached
    cached_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            cached_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }
}

/// Ethereum DID resolver with optional caching
pub struct EthereumResolver {
    /// Ethereum client for blockchain queries
    client: Arc<EthereumClient>,

    /// Cache for agent metadata (DID -> AgentMetadata)
    agent_cache: DashMap<String, CacheEntry<AgentMetadata>>,

    /// Cache for public keys (DID -> Vec<PublicKeyInfo>)
    keys_cache: DashMap<String, CacheEntry<Vec<PublicKeyInfo>>>,

    /// Cache TTL (time-to-live)
    cache_ttl: Duration,

    /// Whether caching is enabled
    caching_enabled: bool,
}

impl EthereumResolver {
    /// Create a new resolver with caching enabled
    ///
    /// # Arguments
    ///
    /// * `client` - Ethereum client for blockchain queries
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = EthereumClient::new(rpc_url, registry_address).await?;
    /// let resolver = EthereumResolver::new(client);
    /// ```
    pub fn new(client: EthereumClient) -> Self {
        Self {
            client: Arc::new(client),
            agent_cache: DashMap::new(),
            keys_cache: DashMap::new(),
            cache_ttl: Duration::from_secs(300), // 5 minutes default
            caching_enabled: true,
        }
    }

    /// Create a new resolver with custom cache TTL
    ///
    /// # Arguments
    ///
    /// * `client` - Ethereum client
    /// * `cache_ttl` - Cache time-to-live duration
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    ///
    /// let resolver = EthereumResolver::with_cache_ttl(
    ///     client,
    ///     Duration::from_secs(600), // 10 minutes
    /// );
    /// ```
    pub fn with_cache_ttl(client: EthereumClient, cache_ttl: Duration) -> Self {
        Self {
            client: Arc::new(client),
            agent_cache: DashMap::new(),
            keys_cache: DashMap::new(),
            cache_ttl,
            caching_enabled: true,
        }
    }

    /// Create a new resolver without caching
    ///
    /// # Arguments
    ///
    /// * `client` - Ethereum client
    ///
    /// # Example
    ///
    /// ```ignore
    /// let resolver = EthereumResolver::without_cache(client);
    /// ```
    pub fn without_cache(client: EthereumClient) -> Self {
        Self {
            client: Arc::new(client),
            agent_cache: DashMap::new(),
            keys_cache: DashMap::new(),
            cache_ttl: Duration::from_secs(0),
            caching_enabled: false,
        }
    }

    /// Enable or disable caching
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable caching
    pub fn set_caching(&mut self, enabled: bool) {
        self.caching_enabled = enabled;
        if !enabled {
            self.clear_cache();
        }
    }

    /// Clear all cached data
    pub fn clear_cache(&self) {
        self.agent_cache.clear();
        self.keys_cache.clear();
    }

    /// Get cache statistics
    ///
    /// # Returns
    ///
    /// Tuple of (agent_cache_size, keys_cache_size)
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.agent_cache.len(), self.keys_cache.len())
    }

    /// Resolve agent metadata by DID
    ///
    /// This retrieves the full agent metadata including name, description,
    /// endpoint, public keys, and capabilities.
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string (e.g., "did:sage:ethereum:0x1234...")
    ///
    /// # Returns
    ///
    /// Complete agent metadata
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` if agent doesn't exist
    /// - `Error::InvalidInput` if DID format is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// let agent = resolver.resolve_agent("did:sage:ethereum:0xabcd...").await?;
    /// println!("Agent: {} ({})", agent.name, agent.description);
    /// println!("Owner: {}", agent.owner);
    /// println!("Active: {}", agent.is_active);
    /// ```
    pub async fn resolve_agent(&self, did: &str) -> Result<AgentMetadata> {
        // Validate DID format
        let _agent_did = AgentDID::parse(did)?;

        // Check cache first
        if self.caching_enabled {
            if let Some(entry) = self.agent_cache.get(did) {
                if !entry.is_expired(self.cache_ttl) {
                    return Ok(entry.data.clone());
                }
            }
        }

        // Query from blockchain
        let metadata = self.client.get_agent_by_did(did).await?;

        // Cache the result
        if self.caching_enabled {
            self.agent_cache
                .insert(did.to_string(), CacheEntry::new(metadata.clone()));
        }

        Ok(metadata)
    }

    /// Resolve all public keys for an agent
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string
    ///
    /// # Returns
    ///
    /// Vector of all public keys associated with the agent
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keys = resolver.resolve_all_public_keys("did:sage:ethereum:0xabcd...").await?;
    /// for key in keys {
    ///     println!("Key type: {:?}, verified: {}", key.key_type, key.verified);
    /// }
    /// ```
    pub async fn resolve_all_public_keys(&self, did: &str) -> Result<Vec<PublicKeyInfo>> {
        // Check cache first
        if self.caching_enabled {
            if let Some(entry) = self.keys_cache.get(did) {
                if !entry.is_expired(self.cache_ttl) {
                    return Ok(entry.data.clone());
                }
            }
        }

        // Get agent metadata (which includes public keys)
        let agent = self.resolve_agent(did).await?;
        let keys = agent.public_keys;

        // Cache the keys
        if self.caching_enabled {
            self.keys_cache
                .insert(did.to_string(), CacheEntry::new(keys.clone()));
        }

        Ok(keys)
    }

    /// Resolve public keys filtered by key type
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string
    /// * `key_type` - Key type to filter by (Ed25519, Secp256k1, P256)
    ///
    /// # Returns
    ///
    /// Vector of public keys matching the specified type
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sage_crypto_core::crypto::KeyType;
    ///
    /// // Get only Ed25519 keys
    /// let ed25519_keys = resolver
    ///     .resolve_public_key_by_type("did:sage:ethereum:0xabcd...", KeyType::Ed25519)
    ///     .await?;
    /// ```
    pub async fn resolve_public_key_by_type(
        &self,
        did: &str,
        key_type: KeyType,
    ) -> Result<Vec<PublicKeyInfo>> {
        let all_keys = self.resolve_all_public_keys(did).await?;

        let filtered_keys = all_keys
            .into_iter()
            .filter(|key| key.key_type == key_type)
            .collect();

        Ok(filtered_keys)
    }

    /// Check if an agent is active
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string
    ///
    /// # Returns
    ///
    /// `true` if the agent is active and can be used for interactions
    ///
    /// # Example
    ///
    /// ```ignore
    /// if resolver.is_agent_active("did:sage:ethereum:0xabcd...").await? {
    ///     println!("Agent is active and ready to use");
    /// } else {
    ///     println!("Agent is inactive or deactivated");
    /// }
    /// ```
    pub async fn is_agent_active(&self, did: &str) -> Result<bool> {
        let agent = self.resolve_agent(did).await?;
        Ok(agent.is_active)
    }

    /// Get only verified public keys
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string
    ///
    /// # Returns
    ///
    /// Vector of verified public keys only
    ///
    /// # Example
    ///
    /// ```ignore
    /// let verified_keys = resolver
    ///     .resolve_verified_keys("did:sage:ethereum:0xabcd...")
    ///     .await?;
    /// ```
    pub async fn resolve_verified_keys(&self, did: &str) -> Result<Vec<PublicKeyInfo>> {
        let all_keys = self.resolve_all_public_keys(did).await?;

        let verified_keys = all_keys
            .into_iter()
            .filter(|key| key.verified)
            .collect();

        Ok(verified_keys)
    }

    /// Get agent owner address
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string
    ///
    /// # Returns
    ///
    /// Owner's Ethereum address (0x-prefixed)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let owner = resolver.resolve_owner("did:sage:ethereum:0xabcd...").await?;
    /// println!("Agent owner: {}", owner);
    /// ```
    pub async fn resolve_owner(&self, did: &str) -> Result<String> {
        let agent = self.resolve_agent(did).await?;
        Ok(agent.owner)
    }

    /// Get agent capabilities
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string
    ///
    /// # Returns
    ///
    /// Vector of capability strings
    ///
    /// # Example
    ///
    /// ```ignore
    /// let capabilities = resolver.resolve_capabilities("did:sage:ethereum:0xabcd...").await?;
    /// for cap in capabilities {
    ///     println!("Capability: {}", cap);
    /// }
    /// ```
    pub async fn resolve_capabilities(&self, did: &str) -> Result<Vec<String>> {
        let agent = self.resolve_agent(did).await?;
        Ok(agent.capabilities)
    }

    /// Batch resolve multiple agents
    ///
    /// # Arguments
    ///
    /// * `dids` - Vector of agent DIDs
    ///
    /// # Returns
    ///
    /// Vector of tuples (DID, Result<AgentMetadata>)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let dids = vec![
    ///     "did:sage:ethereum:0x1111...",
    ///     "did:sage:ethereum:0x2222...",
    ///     "did:sage:ethereum:0x3333...",
    /// ];
    ///
    /// let results = resolver.batch_resolve(&dids).await;
    /// for (did, result) in results {
    ///     match result {
    ///         Ok(agent) => println!("{}: {}", did, agent.name),
    ///         Err(e) => println!("{}: Error - {}", did, e),
    ///     }
    /// }
    /// ```
    pub async fn batch_resolve(&self, dids: &[&str]) -> Vec<(String, Result<AgentMetadata>)> {
        let mut results = Vec::new();

        for did in dids {
            let result = self.resolve_agent(did).await;
            results.push((did.to_string(), result));
        }

        results
    }

    /// Get the underlying Ethereum client
    ///
    /// # Returns
    ///
    /// Reference to the Ethereum client
    pub fn client(&self) -> &EthereumClient {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry::new(42);
        assert!(!entry.is_expired(Duration::from_secs(1)));

        let expired_entry = CacheEntry {
            data: 42,
            cached_at: Instant::now() - Duration::from_secs(10),
        };
        assert!(expired_entry.is_expired(Duration::from_secs(5)));
    }

    #[tokio::test]
    #[ignore] // Requires network connection and valid contract
    async fn test_resolver_creation() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);
        assert!(resolver.caching_enabled);

        let (agent_cache, keys_cache) = resolver.cache_stats();
        assert_eq!(agent_cache, 0);
        assert_eq!(keys_cache, 0);
    }

    #[tokio::test]
    #[ignore] // Requires network connection
    async fn test_cache_operations() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);

        // Clear cache
        resolver.clear_cache();
        let (agent_cache, keys_cache) = resolver.cache_stats();
        assert_eq!(agent_cache, 0);
        assert_eq!(keys_cache, 0);
    }

    #[test]
    fn test_cache_ttl() {
        let entry = CacheEntry::new("test_data".to_string());

        // Should not be expired immediately
        assert!(!entry.is_expired(Duration::from_secs(60)));

        // Simulate old entry
        let old_entry = CacheEntry {
            data: "old_data".to_string(),
            cached_at: Instant::now() - Duration::from_secs(120),
        };

        // Should be expired with 60 second TTL
        assert!(old_entry.is_expired(Duration::from_secs(60)));
    }

    // ===== EthereumResolver Creation Tests =====

    #[tokio::test]
    async fn test_resolver_new() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);
        assert!(resolver.caching_enabled);
        assert_eq!(resolver.cache_ttl, Duration::from_secs(300)); // 5 minutes default

        let (agent_cache, keys_cache) = resolver.cache_stats();
        assert_eq!(agent_cache, 0);
        assert_eq!(keys_cache, 0);
    }

    #[tokio::test]
    async fn test_resolver_with_cache_ttl() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let custom_ttl = Duration::from_secs(600);
        let resolver = EthereumResolver::with_cache_ttl(client, custom_ttl);

        assert!(resolver.caching_enabled);
        assert_eq!(resolver.cache_ttl, custom_ttl);
    }

    #[tokio::test]
    async fn test_resolver_without_cache() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::without_cache(client);

        assert!(!resolver.caching_enabled);
        assert_eq!(resolver.cache_ttl, Duration::from_secs(0));
    }

    #[tokio::test]
    async fn test_resolver_client_getter() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);
        let client_ref = resolver.client();

        // Verify we can access the client
        assert_eq!(
            format!("{:?}", client_ref.registry_address()),
            "0x0000000000000000000000000000000000000001"
        );
    }

    // ===== Cache Management Tests =====

    #[tokio::test]
    async fn test_set_caching_disable() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let mut resolver = EthereumResolver::new(client);
        assert!(resolver.caching_enabled);

        // Disable caching
        resolver.set_caching(false);
        assert!(!resolver.caching_enabled);
    }

    #[tokio::test]
    async fn test_set_caching_enable() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let mut resolver = EthereumResolver::without_cache(client);
        assert!(!resolver.caching_enabled);

        // Enable caching
        resolver.set_caching(true);
        assert!(resolver.caching_enabled);
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);

        // Clear empty cache
        resolver.clear_cache();
        let (agent_cache, keys_cache) = resolver.cache_stats();
        assert_eq!(agent_cache, 0);
        assert_eq!(keys_cache, 0);
    }

    #[tokio::test]
    async fn test_cache_stats_empty() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);
        let (agent_cache, keys_cache) = resolver.cache_stats();

        assert_eq!(agent_cache, 0);
        assert_eq!(keys_cache, 0);
    }

    // ===== CacheEntry Tests =====

    #[test]
    fn test_cache_entry_new() {
        let data = "test_data".to_string();
        let entry = CacheEntry::new(data.clone());

        assert_eq!(entry.data, data);
    }

    #[test]
    fn test_cache_entry_not_expired() {
        let entry = CacheEntry::new(42);

        // Fresh entry should not be expired
        assert!(!entry.is_expired(Duration::from_secs(1)));
        assert!(!entry.is_expired(Duration::from_secs(60)));
        assert!(!entry.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn test_cache_entry_expired() {
        let old_entry = CacheEntry {
            data: "old".to_string(),
            cached_at: Instant::now() - Duration::from_secs(100),
        };

        // Should be expired with shorter TTL
        assert!(old_entry.is_expired(Duration::from_secs(50)));
        assert!(old_entry.is_expired(Duration::from_secs(10)));
        assert!(old_entry.is_expired(Duration::from_secs(1)));
    }

    #[test]
    fn test_cache_entry_clone() {
        let entry = CacheEntry::new(vec![1, 2, 3]);
        let cloned = entry.clone();

        assert_eq!(entry.data, cloned.data);
    }

    #[test]
    fn test_cache_entry_zero_ttl() {
        // Create an old entry to test zero TTL
        let old_entry = CacheEntry {
            data: 100,
            cached_at: Instant::now() - Duration::from_millis(1),
        };

        // With zero TTL, any elapsed time should be expired
        assert!(old_entry.is_expired(Duration::from_secs(0)));
    }

    // ===== Default Configuration Tests =====

    #[tokio::test]
    async fn test_default_cache_ttl() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let resolver = EthereumResolver::new(client);

        // Default TTL should be 5 minutes (300 seconds)
        assert_eq!(resolver.cache_ttl, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_custom_cache_ttl_values() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        // Test various TTL values
        let ttl_1min = Duration::from_secs(60);
        let resolver1 = EthereumResolver::with_cache_ttl(client, ttl_1min);
        assert_eq!(resolver1.cache_ttl, ttl_1min);
    }

    #[tokio::test]
    async fn test_resolver_multiple_instances() {
        let client1 = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let client2 = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000002",
        )
        .await
        .unwrap();

        let resolver1 = EthereumResolver::new(client1);
        let resolver2 = EthereumResolver::new(client2);

        // Each resolver should have independent caches
        let (a1, k1) = resolver1.cache_stats();
        let (a2, k2) = resolver2.cache_stats();

        assert_eq!(a1, 0);
        assert_eq!(k1, 0);
        assert_eq!(a2, 0);
        assert_eq!(k2, 0);
    }
}
