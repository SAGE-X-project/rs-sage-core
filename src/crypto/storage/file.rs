//! File-based key storage implementation
//!
//! This module provides persistent key storage using the filesystem.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::crypto::keys::{KeyPair, KeyType};
use crate::crypto::storage::KeyStorage;
use crate::error::{Error, Result};
use crate::formats::KeyExporter;

/// File-based key storage with in-memory cache
pub struct FileKeyStorage {
    base_dir: PathBuf,
    cache: Arc<RwLock<HashMap<String, KeyPair>>>,
}

impl FileKeyStorage {
    /// Creates a new FileKeyStorage with the specified base directory
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .map_err(|e| Error::Other(format!("Failed to create storage directory: {e}")))?;
        }

        Ok(Self {
            base_dir,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns the file path for a given key ID
    fn key_path(&self, id: &str) -> PathBuf {
        self.base_dir.join(format!("{id}.pem"))
    }

    /// Parses PEM data and returns a KeyPair
    fn parse_pem(pem_data: &str) -> Result<KeyPair> {
        let pem = pem::parse(pem_data)
            .map_err(|e| Error::Other(format!("Failed to parse PEM: {e}")))?;

        // Determine key type from PEM tag
        let key_type = match pem.tag.as_str() {
            "PRIVATE KEY" => KeyType::Ed25519,
            "EC PRIVATE KEY" => KeyType::Secp256k1,
            _ => return Err(Error::InvalidInput(format!("Unknown PEM tag: {}", pem.tag))),
        };

        // Create keypair from private key bytes
        KeyPair::from_private_key_bytes(key_type, &pem.contents)
    }

    /// Loads all keys from disk into cache
    fn load_cache(&self) -> Result<()> {
        let mut cache = self.cache.write();
        cache.clear();

        if !self.base_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.base_dir)
            .map_err(|e| Error::Other(format!("Failed to read storage directory: {e}")))?
        {
            let entry = entry.map_err(|e| Error::Other(format!("Failed to read entry: {e}")))?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                if let Some(id) = path.file_stem().and_then(|s| s.to_str()) {
                    let pem_data = fs::read_to_string(&path)
                        .map_err(|e| Error::Other(format!("Failed to read key file: {e}")))?;

                    let keypair = Self::parse_pem(&pem_data)?;
                    cache.insert(id.to_string(), keypair);
                }
            }
        }

        Ok(())
    }
}

impl KeyStorage for FileKeyStorage {
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()> {
        // Export keypair to PEM format
        let pem_data = keypair.to_pem()?;

        // Write to file
        let path = self.key_path(id);
        fs::write(&path, pem_data)
            .map_err(|e| Error::Other(format!("Failed to write key file: {e}")))?;

        // Update cache
        let mut cache = self.cache.write();
        cache.insert(id.to_string(), keypair.clone());

        Ok(())
    }

    fn load(&self, id: &str) -> Result<KeyPair> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(keypair) = cache.get(id) {
                return Ok(keypair.clone());
            }
        }

        // Load from file
        let path = self.key_path(id);
        if !path.exists() {
            return Err(Error::InvalidInput(format!("Key not found: {id}")));
        }

        let pem_data = fs::read_to_string(&path)
            .map_err(|e| Error::Other(format!("Failed to read key file: {e}")))?;

        let keypair = Self::parse_pem(&pem_data)?;

        // Update cache
        let mut cache = self.cache.write();
        cache.insert(id.to_string(), keypair.clone());

        Ok(keypair)
    }

    fn delete(&self, id: &str) -> Result<()> {
        let path = self.key_path(id);

        if !path.exists() {
            return Err(Error::InvalidInput(format!("Key not found: {id}")));
        }

        // Delete file
        fs::remove_file(&path)
            .map_err(|e| Error::Other(format!("Failed to delete key file: {e}")))?;

        // Remove from cache
        let mut cache = self.cache.write();
        cache.remove(id);

        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        // Reload cache to ensure we have latest keys
        self.load_cache()?;

        let cache = self.cache.read();
        Ok(cache.keys().cloned().collect())
    }

    fn exists(&self, id: &str) -> bool {
        self.key_path(id).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyType;
    use tempfile::TempDir;

    #[test]
    fn test_file_storage_new() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        assert!(storage.base_dir.exists());
    }

    #[test]
    fn test_store_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = "test-key";

        storage.store(id, &keypair).unwrap();
        assert!(storage.exists(id));

        let loaded = storage.load(id).unwrap();
        assert_eq!(loaded.public_key().key_id(), keypair.public_key().key_id());
    }

    #[test]
    fn test_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = "test-key";

        storage.store(id, &keypair).unwrap();
        assert!(storage.exists(id));

        storage.delete(id).unwrap();
        assert!(!storage.exists(id));
    }

    #[test]
    fn test_list() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
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
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = "test-key";

        // Store with first storage instance
        {
            let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
            storage.store(id, &keypair).unwrap();
        }

        // Load with second storage instance
        {
            let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
            let loaded = storage.load(id).unwrap();
            assert_eq!(loaded.public_key().key_id(), keypair.public_key().key_id());
        }
    }

    #[test]
    fn test_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        let result = storage.load("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        let result = storage.delete("nonexistent");
        assert!(result.is_err());
    }
}
