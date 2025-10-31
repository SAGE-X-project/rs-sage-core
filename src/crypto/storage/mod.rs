//! Key storage abstraction and implementations
//!
//! This module provides traits and implementations for storing and retrieving
//! cryptographic key pairs.

pub mod file;
pub mod memory;

use std::sync::Arc;

use crate::crypto::keys::KeyPair;
use crate::error::Result;

pub use file::FileKeyStorage;
pub use memory::MemoryKeyStorage;

/// Trait for key storage backends
pub trait KeyStorage: Send + Sync {
    /// Store a key pair with the given ID
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()>;

    /// Load a key pair by ID
    fn load(&self, id: &str) -> Result<KeyPair>;

    /// Delete a key pair by ID
    fn delete(&self, id: &str) -> Result<()>;

    /// List all stored key IDs
    fn list(&self) -> Result<Vec<String>>;

    /// Check if a key exists
    fn exists(&self, id: &str) -> bool;
}

/// Type alias for boxed KeyStorage trait objects
pub type DynKeyStorage = Arc<dyn KeyStorage>;
