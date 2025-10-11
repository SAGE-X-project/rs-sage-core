//! In-memory key storage implementation
//!
//! This module provides a thread-safe in-memory key storage using DashMap.

use dashmap::DashMap;
use std::sync::Arc;

use crate::crypto::keys::KeyPair;
use crate::crypto::storage::KeyStorage;
use crate::error::{Error, Result};

/// In-memory key storage using DashMap for thread-safe concurrent access
pub struct MemoryKeyStorage {
    store: Arc<DashMap<String, KeyPair>>,
}

impl MemoryKeyStorage {
    /// Creates a new MemoryKeyStorage
    pub fn new() -> Self {
        Self {
            store: Arc::new(DashMap::new()),
        }
    }

    /// Returns the number of keys stored
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns true if storage is empty
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Clears all stored keys
    pub fn clear(&self) {
        self.store.clear();
    }
}

impl KeyStorage for MemoryKeyStorage {
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()> {
        self.store.insert(id.to_string(), keypair.clone());
        Ok(())
    }

    fn load(&self, id: &str) -> Result<KeyPair> {
        self.store
            .get(id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| Error::InvalidInput(format!("Key not found: {id}")))
    }

    fn delete(&self, id: &str) -> Result<()> {
        self.store
            .remove(id)
            .ok_or_else(|| Error::InvalidInput(format!("Key not found: {id}")))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.store.iter().map(|entry| entry.key().clone()).collect())
    }

    fn exists(&self, id: &str) -> bool {
        self.store.contains_key(id)
    }
}

impl Default for MemoryKeyStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyType;

    #[test]
    fn test_memory_storage_new() {
        let storage = MemoryKeyStorage::new();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_store_and_load() {
        let storage = MemoryKeyStorage::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = "test-key";

        storage.store(id, &keypair).unwrap();
        assert_eq!(storage.len(), 1);
        assert!(storage.exists(id));

        let loaded = storage.load(id).unwrap();
        assert_eq!(loaded.public_key().key_id(), keypair.public_key().key_id());
    }

    #[test]
    fn test_delete() {
        let storage = MemoryKeyStorage::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = "test-key";

        storage.store(id, &keypair).unwrap();
        assert!(storage.exists(id));

        storage.delete(id).unwrap();
        assert!(!storage.exists(id));
        assert!(storage.is_empty());
    }

    #[test]
    fn test_list() {
        let storage = MemoryKeyStorage::new();
        let kp1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let kp2 = KeyPair::generate(KeyType::Secp256k1).unwrap();

        storage.store("key1", &kp1).unwrap();
        storage.store("key2", &kp2).unwrap();

        let keys = storage.list().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_clear() {
        let storage = MemoryKeyStorage::new();
        let kp1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let kp2 = KeyPair::generate(KeyType::Secp256k1).unwrap();

        storage.store("key1", &kp1).unwrap();
        storage.store("key2", &kp2).unwrap();
        assert_eq!(storage.len(), 2);

        storage.clear();
        assert!(storage.is_empty());
    }

    #[test]
    fn test_load_nonexistent() {
        let storage = MemoryKeyStorage::new();
        let result = storage.load("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_nonexistent() {
        let storage = MemoryKeyStorage::new();
        let result = storage.delete("nonexistent");
        assert!(result.is_err());
    }
}
