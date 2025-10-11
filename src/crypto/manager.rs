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

    // TODO: Add tests after implementing storage backends in Task 1-3
}
