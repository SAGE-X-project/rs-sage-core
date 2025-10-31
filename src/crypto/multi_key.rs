//! Multi-Key Management
//!
//! This module provides support for managing multiple cryptographic keys per agent,
//! with protocol-specific key selection and a maximum limit of 10 keys per agent.
//!
//! # Features
//!
//! - Support up to 10 keys per agent
//! - Protocol-specific key selection (Ethereum, Solana)
//! - Key type filtering
//! - Concurrent-safe operations
//! - Integration with key rotation
//!
//! # Example
//!
//! ```ignore
//! use sage_crypto_core::crypto::{MultiKeyManager, KeyPair, KeyType, Protocol};
//! use std::sync::Arc;
//!
//! let manager = MultiKeyManager::new(storage);
//!
//! // Add multiple keys for an agent
//! let secp_key = KeyPair::generate(KeyType::Secp256k1)?;
//! let ed_key = KeyPair::generate(KeyType::Ed25519)?;
//!
//! manager.add_key("agent-1", &secp_key)?;
//! manager.add_key("agent-1", &ed_key)?;
//!
//! // Get protocol-specific key
//! let eth_key = manager.get_protocol_key("agent-1", Protocol::Ethereum)?;
//! let sol_key = manager.get_protocol_key("agent-1", Protocol::Solana)?;
//! ```

use crate::crypto::keys::{KeyPair, KeyType};
use crate::crypto::storage::KeyStorage;
use crate::error::{Error, Result};
use std::sync::Arc;

/// Maximum number of keys allowed per agent
pub const MAX_KEYS_PER_AGENT: usize = 10;

/// Protocol types for key selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Ethereum and EVM-compatible chains
    Ethereum,
    /// Solana blockchain
    Solana,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Ethereum => write!(f, "ethereum"),
            Protocol::Solana => write!(f, "solana"),
        }
    }
}

/// Multi-key manager for handling multiple keys per agent
///
/// This manager allows agents to maintain multiple cryptographic keys
/// and automatically selects the appropriate key based on the protocol.
///
/// # Protocol-Specific Key Selection
///
/// - **Ethereum**: Prefers Secp256k1, falls back to P256
/// - **Solana**: Prefers Ed25519
///
/// # Key Storage Format
///
/// Keys are stored with the format: `{agent_id}/key/{key_index}`
///
/// # Example
///
/// ```ignore
/// use sage_crypto_core::crypto::{MultiKeyManager, KeyType, Protocol};
///
/// let manager = MultiKeyManager::new(storage);
///
/// // Add keys
/// let key1 = KeyPair::generate(KeyType::Secp256k1)?;
/// let key2 = KeyPair::generate(KeyType::Ed25519)?;
/// manager.add_key("agent-123", &key1)?;
/// manager.add_key("agent-123", &key2)?;
///
/// // Get Ethereum key (Secp256k1)
/// let eth_key = manager.get_protocol_key("agent-123", Protocol::Ethereum)?;
///
/// // Get Solana key (Ed25519)
/// let sol_key = manager.get_protocol_key("agent-123", Protocol::Solana)?;
/// ```
pub struct MultiKeyManager {
    /// Key storage backend
    storage: Arc<dyn KeyStorage>,
}

impl MultiKeyManager {
    /// Create a new multi-key manager
    ///
    /// # Arguments
    ///
    /// * `storage` - Key storage backend
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sage_crypto_core::crypto::{MultiKeyManager, MemoryKeyStorage};
    /// use std::sync::Arc;
    ///
    /// let storage = Arc::new(MemoryKeyStorage::new());
    /// let manager = MultiKeyManager::new(storage);
    /// ```
    pub fn new(storage: Arc<dyn KeyStorage>) -> Self {
        Self { storage }
    }

    /// Add a key for an agent
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    /// * `key` - Key pair to add
    ///
    /// # Returns
    ///
    /// The storage ID of the added key
    ///
    /// # Errors
    ///
    /// - `Error::InvalidInput` if agent already has 10 keys (maximum)
    /// - `Error::StorageError` if storage operation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let key = KeyPair::generate(KeyType::Ed25519)?;
    /// manager.add_key("agent-123", &key)?;
    /// ```
    pub fn add_key(&self, agent_id: &str, key: &KeyPair) -> Result<String> {
        // Check current key count
        let current_count = self.count_keys(agent_id)?;
        if current_count >= MAX_KEYS_PER_AGENT {
            return Err(Error::InvalidInput(format!(
                "Agent {} already has maximum {} keys",
                agent_id, MAX_KEYS_PER_AGENT
            )));
        }

        // Generate storage ID: {agent_id}/key/{index}
        let storage_id = format!("{}/key/{}", agent_id, current_count);

        // Store the key
        self.storage.store(&storage_id, key)?;

        Ok(storage_id)
    }

    /// Get all keys for an agent
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    ///
    /// # Returns
    ///
    /// Vector of all keys associated with the agent
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keys = manager.get_all_keys("agent-123")?;
    /// println!("Agent has {} keys", keys.len());
    /// ```
    pub fn get_all_keys(&self, agent_id: &str) -> Result<Vec<KeyPair>> {
        let prefix = format!("{}/key/", agent_id);
        let mut keys = Vec::new();

        // List all keys with the agent prefix
        let all_keys = self.storage.list()?;

        for key_id in all_keys {
            if key_id.starts_with(&prefix) {
                match self.storage.load(&key_id) {
                    Ok(key) => keys.push(key),
                    Err(_) => continue, // Skip if key can't be loaded
                }
            }
        }

        Ok(keys)
    }

    /// Get keys filtered by type
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    /// * `key_type` - Key type to filter by
    ///
    /// # Returns
    ///
    /// Vector of keys matching the specified type
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sage_crypto_core::crypto::KeyType;
    ///
    /// let ed25519_keys = manager.get_keys_by_type("agent-123", KeyType::Ed25519)?;
    /// let secp_keys = manager.get_keys_by_type("agent-123", KeyType::Secp256k1)?;
    /// ```
    pub fn get_keys_by_type(&self, agent_id: &str, key_type: KeyType) -> Result<Vec<KeyPair>> {
        let all_keys = self.get_all_keys(agent_id)?;

        let filtered_keys = all_keys
            .into_iter()
            .filter(|key| key.key_type() == key_type)
            .collect();

        Ok(filtered_keys)
    }

    /// Get the appropriate key for a specific protocol
    ///
    /// This method implements protocol-specific key selection:
    /// - **Ethereum**: Prefers Secp256k1, falls back to P256
    /// - **Solana**: Prefers Ed25519
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    /// * `protocol` - Protocol to get key for
    ///
    /// # Returns
    ///
    /// The appropriate key for the protocol, or `None` if no suitable key exists
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sage_crypto_core::crypto::Protocol;
    ///
    /// if let Some(eth_key) = manager.get_protocol_key("agent-123", Protocol::Ethereum)? {
    ///     println!("Using Ethereum key: {:?}", eth_key.key_type());
    /// }
    /// ```
    pub fn get_protocol_key(&self, agent_id: &str, protocol: Protocol) -> Result<Option<KeyPair>> {
        let all_keys = self.get_all_keys(agent_id)?;

        match protocol {
            Protocol::Ethereum => {
                // Prefer Secp256k1, then P256
                for key in &all_keys {
                    if key.key_type() == KeyType::Secp256k1 {
                        return Ok(Some(key.clone()));
                    }
                }
                for key in &all_keys {
                    if key.key_type() == KeyType::P256 {
                        return Ok(Some(key.clone()));
                    }
                }
            }
            Protocol::Solana => {
                // Prefer Ed25519
                for key in &all_keys {
                    if key.key_type() == KeyType::Ed25519 {
                        return Ok(Some(key.clone()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Remove a specific key for an agent
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    /// * `key_id` - Key ID to remove (from `KeyPair::key_id()`)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the key was removed, error otherwise
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keys = manager.get_all_keys("agent-123")?;
    /// if let Some(key) = keys.first() {
    ///     manager.remove_key("agent-123", key.key_id())?;
    /// }
    /// ```
    pub fn remove_key(&self, agent_id: &str, key_id: &str) -> Result<()> {
        let prefix = format!("{}/key/", agent_id);
        let all_keys = self.storage.list()?;

        // Find the storage ID that contains this key
        for storage_id in all_keys {
            if storage_id.starts_with(&prefix) {
                if let Ok(key) = self.storage.load(&storage_id) {
                    if key.key_id() == key_id {
                        return self.storage.delete(&storage_id);
                    }
                }
            }
        }

        Err(Error::NotFound(format!(
            "Key {} not found for agent {}",
            key_id, agent_id
        )))
    }

    /// Count the number of keys for an agent
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    ///
    /// # Returns
    ///
    /// Number of keys the agent currently has
    ///
    /// # Example
    ///
    /// ```ignore
    /// let count = manager.count_keys("agent-123")?;
    /// println!("Agent has {} keys", count);
    /// ```
    pub fn count_keys(&self, agent_id: &str) -> Result<usize> {
        let prefix = format!("{}/key/", agent_id);
        let all_keys = self.storage.list()?;

        let count = all_keys
            .iter()
            .filter(|key_id| key_id.starts_with(&prefix))
            .count();

        Ok(count)
    }

    /// Remove all keys for an agent
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    ///
    /// # Returns
    ///
    /// Number of keys removed
    ///
    /// # Example
    ///
    /// ```ignore
    /// let removed = manager.remove_all_keys("agent-123")?;
    /// println!("Removed {} keys", removed);
    /// ```
    pub fn remove_all_keys(&self, agent_id: &str) -> Result<usize> {
        let prefix = format!("{}/key/", agent_id);
        let all_keys = self.storage.list()?;
        let mut removed = 0;

        for key_id in all_keys {
            if key_id.starts_with(&prefix) {
                if self.storage.delete(&key_id).is_ok() {
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }

    /// Check if an agent has any keys
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent identifier
    ///
    /// # Returns
    ///
    /// `true` if the agent has at least one key
    pub fn has_keys(&self, agent_id: &str) -> Result<bool> {
        Ok(self.count_keys(agent_id)? > 0)
    }

    /// Get the underlying storage
    ///
    /// # Returns
    ///
    /// Reference to the key storage backend
    pub fn storage(&self) -> &Arc<dyn KeyStorage> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::storage::MemoryKeyStorage;

    fn create_manager() -> MultiKeyManager {
        let storage = Arc::new(MemoryKeyStorage::new());
        MultiKeyManager::new(storage)
    }

    #[test]
    fn test_add_key() {
        let manager = create_manager();
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();

        let storage_id = manager.add_key("agent-1", &key).unwrap();
        assert!(storage_id.starts_with("agent-1/key/"));
    }

    #[test]
    fn test_max_keys_limit() {
        let manager = create_manager();

        // Add 10 keys (maximum)
        for _ in 0..MAX_KEYS_PER_AGENT {
            let key = KeyPair::generate(KeyType::Ed25519).unwrap();
            manager.add_key("agent-1", &key).unwrap();
        }

        // Try to add 11th key - should fail
        let extra_key = KeyPair::generate(KeyType::Ed25519).unwrap();
        let result = manager.add_key("agent-1", &extra_key);
        assert!(result.is_err());

        let count = manager.count_keys("agent-1").unwrap();
        assert_eq!(count, MAX_KEYS_PER_AGENT);
    }

    #[test]
    fn test_get_all_keys() {
        let manager = create_manager();

        // Add 3 keys
        for _ in 0..3 {
            let key = KeyPair::generate(KeyType::Ed25519).unwrap();
            manager.add_key("agent-1", &key).unwrap();
        }

        let keys = manager.get_all_keys("agent-1").unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_get_keys_by_type() {
        let manager = create_manager();

        // Add different key types
        let ed_key = KeyPair::generate(KeyType::Ed25519).unwrap();
        let secp_key = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let p256_key = KeyPair::generate(KeyType::P256).unwrap();

        manager.add_key("agent-1", &ed_key).unwrap();
        manager.add_key("agent-1", &secp_key).unwrap();
        manager.add_key("agent-1", &p256_key).unwrap();

        // Get by type
        let ed_keys = manager.get_keys_by_type("agent-1", KeyType::Ed25519).unwrap();
        let secp_keys = manager.get_keys_by_type("agent-1", KeyType::Secp256k1).unwrap();
        let p256_keys = manager.get_keys_by_type("agent-1", KeyType::P256).unwrap();

        assert_eq!(ed_keys.len(), 1);
        assert_eq!(secp_keys.len(), 1);
        assert_eq!(p256_keys.len(), 1);
    }

    #[test]
    fn test_protocol_key_ethereum() {
        let manager = create_manager();

        // Add Secp256k1 (preferred for Ethereum)
        let secp_key = KeyPair::generate(KeyType::Secp256k1).unwrap();
        manager.add_key("agent-1", &secp_key).unwrap();

        // Add P256 (fallback)
        let p256_key = KeyPair::generate(KeyType::P256).unwrap();
        manager.add_key("agent-1", &p256_key).unwrap();

        // Should return Secp256k1
        let eth_key = manager
            .get_protocol_key("agent-1", Protocol::Ethereum)
            .unwrap()
            .unwrap();
        assert_eq!(eth_key.key_type(), KeyType::Secp256k1);
    }

    #[test]
    fn test_protocol_key_ethereum_fallback() {
        let manager = create_manager();

        // Add only P256
        let p256_key = KeyPair::generate(KeyType::P256).unwrap();
        manager.add_key("agent-1", &p256_key).unwrap();

        // Should return P256 (fallback)
        let eth_key = manager
            .get_protocol_key("agent-1", Protocol::Ethereum)
            .unwrap()
            .unwrap();
        assert_eq!(eth_key.key_type(), KeyType::P256);
    }

    #[test]
    fn test_protocol_key_solana() {
        let manager = create_manager();

        // Add Ed25519 (preferred for Solana)
        let ed_key = KeyPair::generate(KeyType::Ed25519).unwrap();
        manager.add_key("agent-1", &ed_key).unwrap();

        // Should return Ed25519
        let sol_key = manager
            .get_protocol_key("agent-1", Protocol::Solana)
            .unwrap()
            .unwrap();
        assert_eq!(sol_key.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_protocol_key_not_found() {
        let manager = create_manager();

        // Add only Secp256k1
        let secp_key = KeyPair::generate(KeyType::Secp256k1).unwrap();
        manager.add_key("agent-1", &secp_key).unwrap();

        // Try to get Solana key (needs Ed25519) - should return None
        let sol_key = manager.get_protocol_key("agent-1", Protocol::Solana).unwrap();
        assert!(sol_key.is_none());
    }

    #[test]
    fn test_remove_key() {
        let manager = create_manager();

        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        let key_id = key.key_id().to_string();
        manager.add_key("agent-1", &key).unwrap();

        // Verify key exists
        assert_eq!(manager.count_keys("agent-1").unwrap(), 1);

        // Remove key
        manager.remove_key("agent-1", &key_id).unwrap();

        // Verify key removed
        assert_eq!(manager.count_keys("agent-1").unwrap(), 0);
    }

    #[test]
    fn test_count_keys() {
        let manager = create_manager();

        assert_eq!(manager.count_keys("agent-1").unwrap(), 0);

        let key1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        manager.add_key("agent-1", &key1).unwrap();
        assert_eq!(manager.count_keys("agent-1").unwrap(), 1);

        let key2 = KeyPair::generate(KeyType::Secp256k1).unwrap();
        manager.add_key("agent-1", &key2).unwrap();
        assert_eq!(manager.count_keys("agent-1").unwrap(), 2);
    }

    #[test]
    fn test_remove_all_keys() {
        let manager = create_manager();

        // Add 5 keys
        for _ in 0..5 {
            let key = KeyPair::generate(KeyType::Ed25519).unwrap();
            manager.add_key("agent-1", &key).unwrap();
        }

        assert_eq!(manager.count_keys("agent-1").unwrap(), 5);

        // Remove all
        let removed = manager.remove_all_keys("agent-1").unwrap();
        assert_eq!(removed, 5);
        assert_eq!(manager.count_keys("agent-1").unwrap(), 0);
    }

    #[test]
    fn test_has_keys() {
        let manager = create_manager();

        assert!(!manager.has_keys("agent-1").unwrap());

        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        manager.add_key("agent-1", &key).unwrap();

        assert!(manager.has_keys("agent-1").unwrap());
    }

    #[test]
    fn test_multiple_agents() {
        let manager = create_manager();

        // Add keys for different agents
        let key1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let key2 = KeyPair::generate(KeyType::Secp256k1).unwrap();

        manager.add_key("agent-1", &key1).unwrap();
        manager.add_key("agent-2", &key2).unwrap();

        // Verify isolation
        assert_eq!(manager.count_keys("agent-1").unwrap(), 1);
        assert_eq!(manager.count_keys("agent-2").unwrap(), 1);

        let agent1_keys = manager.get_all_keys("agent-1").unwrap();
        let agent2_keys = manager.get_all_keys("agent-2").unwrap();

        assert_eq!(agent1_keys[0].key_type(), KeyType::Ed25519);
        assert_eq!(agent2_keys[0].key_type(), KeyType::Secp256k1);
    }
}
