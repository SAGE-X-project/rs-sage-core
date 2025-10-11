//! Crypto manager for key management operations
//!
//! This module provides the CryptoManager for high-level cryptographic operations
//! including key generation, storage, and retrieval.

use std::sync::Arc;

use crate::crypto::keys::{KeyPair, KeyType};
use crate::crypto::storage::KeyStorage;
use crate::error::Result;

/// High-level crypto manager
pub struct CryptoManager {
    storage: Arc<dyn KeyStorage>,
}

impl CryptoManager {
    /// Creates a new CryptoManager with the given storage backend
    pub fn new(storage: Arc<dyn KeyStorage>) -> Self {
        Self { storage }
    }

    /// Generates a new key pair of the specified type
    pub fn generate_keypair(&self, key_type: KeyType) -> Result<KeyPair> {
        KeyPair::generate(key_type)
    }

    /// Stores a key pair with the given ID
    pub fn store_keypair(&self, id: &str, keypair: &KeyPair) -> Result<()> {
        self.storage.store(id, keypair)
    }

    /// Loads a key pair by ID
    pub fn load_keypair(&self, id: &str) -> Result<KeyPair> {
        self.storage.load(id)
    }

    /// Deletes a key pair by ID
    pub fn delete_keypair(&self, id: &str) -> Result<()> {
        self.storage.delete(id)
    }

    /// Lists all stored key IDs
    pub fn list_keys(&self) -> Result<Vec<String>> {
        self.storage.list()
    }

    /// Checks if a key exists
    pub fn key_exists(&self, id: &str) -> bool {
        self.storage.exists(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::storage::MemoryKeyStorage;

    #[test]
    fn test_generate_keypair() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let manager = CryptoManager::new(storage);

        let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_store_and_load() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let manager = CryptoManager::new(storage);

        let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();
        let id = "test-key";

        manager.store_keypair(id, &keypair).unwrap();
        assert!(manager.key_exists(id));

        let loaded = manager.load_keypair(id).unwrap();
        assert_eq!(loaded.public_key().key_id(), keypair.public_key().key_id());
    }

    #[test]
    fn test_delete() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let manager = CryptoManager::new(storage);

        let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();
        let id = "test-key";

        manager.store_keypair(id, &keypair).unwrap();
        assert!(manager.key_exists(id));

        manager.delete_keypair(id).unwrap();
        assert!(!manager.key_exists(id));
    }

    #[test]
    fn test_list_keys() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let manager = CryptoManager::new(storage);

        let kp1 = manager.generate_keypair(KeyType::Ed25519).unwrap();
        let kp2 = manager.generate_keypair(KeyType::Secp256k1).unwrap();

        manager.store_keypair("key1", &kp1).unwrap();
        manager.store_keypair("key2", &kp2).unwrap();

        let keys = manager.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }
}
