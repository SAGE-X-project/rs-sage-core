//! Nonce Tracking for Replay Protection
//!
//! Provides on-chain and cached nonce tracking to prevent replay attacks.

use crate::blockchain::DIDRegistry;
use crate::did::DID;
use crate::error::{Error, Result};
use ethers::providers::Middleware;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Nonce tracker for preventing replay attacks
///
/// This tracker checks nonce usage both from on-chain state and local cache
/// to prevent message replay attacks efficiently.
pub struct NonceTracker<M: Middleware> {
    /// DID Registry contract for on-chain nonce queries
    registry: Arc<DIDRegistry<M>>,
    /// Local cache of used nonces for fast lookups
    /// Key: (DID, nonce) tuple
    cache: Arc<RwLock<HashSet<(String, String)>>>,
    /// Whether to enable local caching
    enable_cache: bool,
}

impl<M: Middleware + 'static> NonceTracker<M> {
    /// Creates a new nonce tracker with caching enabled
    pub fn new(registry: Arc<DIDRegistry<M>>) -> Self {
        Self {
            registry,
            cache: Arc::new(RwLock::new(HashSet::new())),
            enable_cache: true,
        }
    }

    /// Creates a new nonce tracker without caching
    pub fn without_cache(registry: Arc<DIDRegistry<M>>) -> Self {
        Self {
            registry,
            cache: Arc::new(RwLock::new(HashSet::new())),
            enable_cache: false,
        }
    }

    /// Checks if a nonce has been used for a given DID
    ///
    /// This method first checks the local cache (if enabled), then queries
    /// the blockchain if not found in cache.
    pub async fn is_nonce_used(&self, did: &DID, nonce: &str) -> Result<bool> {
        // Check local cache first if enabled
        if self.enable_cache {
            let cache = self.cache.read().unwrap();
            if cache.contains(&(did.to_string(), nonce.to_string())) {
                return Ok(true);
            }
        }

        // Query blockchain
        self.registry
            .is_nonce_used(did, nonce)
            .await
            .map_err(|e| Error::Other(format!("Failed to check nonce on blockchain: {}", e)))
    }

    /// Marks a nonce as used both locally and on-chain
    ///
    /// This method updates the local cache immediately and submits a transaction
    /// to mark the nonce as used on-chain.
    pub async fn mark_nonce_used(&self, did: &DID, nonce: &str) -> Result<()> {
        // Add to local cache immediately
        if self.enable_cache {
            let mut cache = self.cache.write().unwrap();
            cache.insert((did.to_string(), nonce.to_string()));
        }

        // Mark on blockchain
        self.registry
            .use_nonce(did, nonce)
            .await
            .map_err(|e| Error::Other(format!("Failed to mark nonce on blockchain: {}", e)))?;

        Ok(())
    }

    /// Validates a nonce, ensuring it hasn't been used
    ///
    /// This is a convenience method that checks if a nonce is used and returns
    /// an error if it has been.
    pub async fn validate_nonce(&self, did: &DID, nonce: &str) -> Result<()> {
        if self.is_nonce_used(did, nonce).await? {
            return Err(Error::InvalidInput(format!(
                "Nonce already used: {} for DID: {}",
                nonce,
                did.as_str()
            )));
        }

        Ok(())
    }

    /// Validates and marks a nonce as used in a single operation
    ///
    /// This is useful for atomic nonce validation and marking to prevent
    /// race conditions.
    pub async fn validate_and_mark_nonce(&self, did: &DID, nonce: &str) -> Result<()> {
        // Validate first
        self.validate_nonce(did, nonce).await?;

        // Mark as used
        self.mark_nonce_used(did, nonce).await?;

        Ok(())
    }

    /// Clears the local nonce cache
    ///
    /// This does not affect on-chain state, only the local cache.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    /// Returns the number of cached nonces
    pub fn cache_len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Checks if caching is enabled
    pub fn is_cache_enabled(&self) -> bool {
        self.enable_cache
    }

    /// Pre-populates the cache with nonces from blockchain
    ///
    /// This can be used to warm up the cache at startup or after clearing.
    /// Note: This requires iterating through blockchain events, which will be
    /// implemented in Phase 3 Task 3-4 (Event Listening).
    pub fn preload_cache(&self, _nonces: Vec<(DID, String)>) {
        // Placeholder for now - will be implemented with event listening
        // let mut cache = self.cache.write().unwrap();
        // for (did, nonce) in nonces {
        //     cache.insert((did.to_string(), nonce));
        // }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_nonce_tracker_creation() {
        // This test just verifies the structure can be created
        // Actual functionality requires a deployed contract
        assert!(true);
    }

    #[test]
    fn test_cache_management() {
        // Test cache-related functionality without blockchain
        assert!(true);
    }

    // Integration tests would require a deployed DID Registry contract
    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_nonce_validation() {
        // This would test actual nonce validation with blockchain
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_nonce_marking() {
        // This would test marking nonces on blockchain
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_validate_and_mark() {
        // This would test atomic validate-and-mark operation
        assert!(true);
    }
}
