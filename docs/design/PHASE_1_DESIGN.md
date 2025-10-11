# Phase 1: 핵심 인프라 구축 상세 설계

> **기간**: 5-7일
> **목표**: Core 모듈 구조 확립 및 Crypto 레이어 확장

## 📋 작업 개요

Phase 1에서는 전체 시스템의 기반이 되는 핵심 인프라를 구축합니다:

1. ✅ 프로젝트 모듈 구조 재설계
2. ✅ Core 통합 레이어 스캐폴딩
3. ✅ CryptoManager + KeyStorage 시스템
4. ✅ RFC 9421 고수준 API (MessageBuilder)
5. ✅ 기본 테스트 프레임워크

## 🎯 Task 1: 프로젝트 구조 재설계 (Day 1)

### 1.1 디렉토리 구조 생성

```bash
# 새 모듈 디렉토리 생성
mkdir -p src/core
mkdir -p src/crypto/storage
mkdir -p src/did
mkdir -p src/message
mkdir -p tests/integration
mkdir -p docs/design
```

### 1.2 모듈 파일 스캐폴딩

**생성할 파일 목록**:
```
src/
├── core/
│   ├── mod.rs           # 🆕
│   ├── message.rs       # 🆕
│   ├── verification_service.rs  # 🆕
│   └── types.rs         # 🆕
├── crypto/
│   ├── manager.rs       # 🆕
│   └── storage/
│       ├── mod.rs       # 🆕
│       ├── memory.rs    # 🆕
│       └── file.rs      # 🆕
└── rfc9421/
    ├── message_builder.rs  # 🆕
    └── validator.rs     # 🆕
```

### 1.3 lib.rs 업데이트

```rust
// src/lib.rs
#![warn(missing_docs)]
#![cfg_attr(not(feature = "ffi"), deny(unsafe_code))]

//! SAGE Crypto Core Library
//!
//! Comprehensive cryptographic library for SAGE with:
//! - Ed25519 and Secp256k1 signatures
//! - RFC 9421 HTTP Message Signatures
//! - DID (Decentralized Identifier) management
//! - Secure key storage and rotation

pub mod core;      // 🆕 통합 레이어
pub mod crypto;
pub mod error;
pub mod formats;
pub mod rfc9421;

// 🆕 새 모듈 (Phase 2-3에서 구현)
#[cfg(feature = "did")]
pub mod did;

#[cfg(feature = "message")]
pub mod message;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export main types
pub use core::Core;
pub use crypto::{KeyPair, KeyType, PrivateKey, PublicKey, Signature};
pub use error::{Error, Result};
pub use formats::{KeyExporter, KeyFormat, KeyImporter};

#[cfg(feature = "did")]
pub use did::{AgentDID, AgentMetadata, DIDManager};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

## 🎯 Task 2: Core 모듈 구현 (Day 2-3)

### 2.1 Message 타입 정의

**파일**: `src/core/message.rs`

```rust
//! Core message types for SAGE agent communication

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RFC 9421 compliant message with metadata for signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Agent DID (Decentralized Identifier)
    pub agent_did: String,

    /// Unique message identifier
    pub message_id: String,

    /// Unix timestamp (seconds since epoch)
    pub timestamp: i64,

    /// Nonce for replay protection
    pub nonce: String,

    /// HTTP headers
    pub headers: HashMap<String, String>,

    /// Message body
    pub body: Vec<u8>,

    /// Signature algorithm (e.g., "ed25519", "ecdsa-secp256k1-sha256")
    pub algorithm: String,

    /// Public key identifier
    pub key_id: String,

    /// Signature bytes
    pub signature: Vec<u8>,

    /// Fields included in signature
    pub signed_fields: Vec<String>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Message {
    /// Create a new message builder
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }

    /// Get the agent DID
    pub fn agent_did(&self) -> &str {
        &self.agent_did
    }

    /// Get the message ID
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Check if message has expired
    pub fn is_expired(&self, max_age_seconds: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        now - self.timestamp > max_age_seconds
    }
}

/// Builder for creating Message instances
#[derive(Debug, Default)]
pub struct MessageBuilder {
    agent_did: Option<String>,
    message_id: Option<String>,
    timestamp: Option<i64>,
    nonce: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    algorithm: Option<String>,
    key_id: Option<String>,
    signature: Option<Vec<u8>>,
    signed_fields: Vec<String>,
    metadata: HashMap<String, serde_json::Value>,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set agent DID
    pub fn agent_did(mut self, did: impl Into<String>) -> Self {
        self.agent_did = Some(did.into());
        self
    }

    /// Set message ID
    pub fn message_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }

    /// Set timestamp (defaults to current time)
    pub fn timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Set nonce
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Add a header
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set headers
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Set body
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Set algorithm
    pub fn algorithm(mut self, alg: impl Into<String>) -> Self {
        self.algorithm = Some(alg.into());
        self
    }

    /// Set key ID
    pub fn key_id(mut self, id: impl Into<String>) -> Self {
        self.key_id = Some(id.into());
        self
    }

    /// Set signature
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.signature = Some(sig);
        self
    }

    /// Add signed field
    pub fn signed_field(mut self, field: impl Into<String>) -> Self {
        self.signed_fields.push(field.into());
        self
    }

    /// Set signed fields
    pub fn signed_fields(mut self, fields: Vec<String>) -> Self {
        self.signed_fields = fields;
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Build the message
    pub fn build(self) -> Result<Message> {
        // Generate defaults
        let message_id = self.message_id.unwrap_or_else(|| {
            uuid::Uuid::new_v4().to_string()
        });

        let timestamp = self.timestamp.unwrap_or_else(|| {
            chrono::Utc::now().timestamp()
        });

        let nonce = self.nonce.unwrap_or_else(|| {
            use rand::Rng;
            let random_bytes: [u8; 16] = rand::thread_rng().gen();
            hex::encode(random_bytes)
        });

        Ok(Message {
            agent_did: self.agent_did.ok_or_else(|| {
                crate::error::Error::InvalidInput("agent_did is required".to_string())
            })?,
            message_id,
            timestamp,
            nonce,
            headers: self.headers,
            body: self.body,
            algorithm: self.algorithm.ok_or_else(|| {
                crate::error::Error::InvalidInput("algorithm is required".to_string())
            })?,
            key_id: self.key_id.ok_or_else(|| {
                crate::error::Error::InvalidInput("key_id is required".to_string())
            })?,
            signature: self.signature.ok_or_else(|| {
                crate::error::Error::InvalidInput("signature is required".to_string())
            })?,
            signed_fields: self.signed_fields,
            metadata: self.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_builder() {
        let msg = Message::builder()
            .agent_did("did:sage:eth:0x123")
            .algorithm("ed25519")
            .key_id("test-key")
            .signature(vec![0u8; 64])
            .body(b"test body".to_vec())
            .build()
            .unwrap();

        assert_eq!(msg.agent_did, "did:sage:eth:0x123");
        assert_eq!(msg.body, b"test body");
    }
}
```

### 2.2 VerificationOptions 및 Result

**파일**: `src/core/types.rs`

```rust
//! Core types used across the library

use std::time::Duration;

/// Options for signature verification
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    /// Require agent to be active
    pub require_active_agent: bool,

    /// Maximum allowed time difference
    pub max_clock_skew: Duration,

    /// Required capabilities
    pub required_capabilities: Vec<String>,

    /// Verify metadata matches expected values
    pub verify_metadata: bool,

    /// Maximum message age
    pub max_message_age: Option<Duration>,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            require_active_agent: true,
            max_clock_skew: Duration::from_secs(300), // 5 minutes
            required_capabilities: Vec::new(),
            verify_metadata: true,
            max_message_age: Some(Duration::from_secs(3600)), // 1 hour
        }
    }
}

/// Result of signature verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether signature is valid
    pub valid: bool,

    /// Error message if invalid
    pub error: Option<String>,

    /// When verification was performed
    pub verified_at: i64,

    /// Agent metadata (if resolved)
    #[cfg(feature = "did")]
    pub agent_metadata: Option<crate::did::AgentMetadata>,
}

impl VerificationResult {
    /// Create a successful verification result
    pub fn success() -> Self {
        Self {
            valid: true,
            error: None,
            verified_at: chrono::Utc::now().timestamp(),
            #[cfg(feature = "did")]
            agent_metadata: None,
        }
    }

    /// Create a failed verification result
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            error: Some(error.into()),
            verified_at: chrono::Utc::now().timestamp(),
            #[cfg(feature = "did")]
            agent_metadata: None,
        }
    }
}
```

### 2.3 VerificationService 스캐폴딩

**파일**: `src/core/verification_service.rs`

```rust
//! Verification service for agent messages

use crate::core::{Message, VerificationOptions, VerificationResult};
use crate::error::Result;

/// Service for verifying agent messages
pub struct VerificationService {
    // Phase 2에서 DIDManager 추가
    // Phase 3에서 NonceManager, DedupeDetector 추가
}

impl VerificationService {
    /// Create a new verification service
    pub fn new() -> Self {
        Self {}
    }

    /// Verify an agent message
    pub async fn verify_agent_message(
        &self,
        _message: &Message,
        _opts: &VerificationOptions,
    ) -> Result<VerificationResult> {
        // Phase 1: 기본 구조만
        // Phase 2: DID 검증 추가
        // Phase 3: Nonce, Dedupe 검증 추가
        todo!("Implement in Phase 2-3")
    }
}

impl Default for VerificationService {
    fn default() -> Self {
        Self::new()
    }
}
```

### 2.4 Core 통합 모듈

**파일**: `src/core/mod.rs`

```rust
//! Core integration layer for SAGE

pub mod message;
pub mod types;
pub mod verification_service;

pub use message::{Message, MessageBuilder};
pub use types::{VerificationOptions, VerificationResult};
pub use verification_service::VerificationService;

use crate::crypto::manager::CryptoManager;
use crate::crypto::KeyType;
use crate::error::Result;

/// Main entry point for SAGE core functionality
pub struct Core {
    crypto_manager: CryptoManager,
    verification_service: VerificationService,
}

impl Core {
    /// Create a new Core instance
    pub fn new() -> Self {
        Self {
            crypto_manager: CryptoManager::new(),
            verification_service: VerificationService::new(),
        }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self, key_type: KeyType) -> Result<crate::crypto::KeyPair> {
        self.crypto_manager.generate_keypair(key_type)
    }

    /// Store a key pair
    pub fn store_keypair(&self, keypair: &crate::crypto::KeyPair) -> Result<()> {
        self.crypto_manager.store_keypair(keypair)
    }

    /// Load a key pair by ID
    pub fn load_keypair(&self, id: &str) -> Result<crate::crypto::KeyPair> {
        self.crypto_manager.load_keypair(id)
    }

    /// Create a message builder
    pub fn message_builder(&self) -> MessageBuilder {
        Message::builder()
    }

    /// Get the crypto manager
    pub fn crypto_manager(&self) -> &CryptoManager {
        &self.crypto_manager
    }
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_creation() {
        let core = Core::new();
        assert!(core.generate_keypair(KeyType::Ed25519).is_ok());
    }
}
```

## 🎯 Task 3: CryptoManager + KeyStorage (Day 3-4)

### 3.1 KeyStorage Trait

**파일**: `src/crypto/storage/mod.rs`

```rust
//! Key storage abstraction

use crate::crypto::KeyPair;
use crate::error::Result;

pub mod memory;
pub mod file;

pub use memory::MemoryKeyStorage;
pub use file::FileKeyStorage;

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
```

### 3.2 MemoryKeyStorage 구현

**파일**: `src/crypto/storage/memory.rs`

```rust
//! In-memory key storage implementation

use super::KeyStorage;
use crate::crypto::KeyPair;
use crate::error::{Error, Result};
use dashmap::DashMap;
use std::sync::Arc;

/// In-memory key storage using DashMap for thread-safety
#[derive(Clone)]
pub struct MemoryKeyStorage {
    keys: Arc<DashMap<String, KeyPair>>,
}

impl MemoryKeyStorage {
    /// Create a new memory key storage
    pub fn new() -> Self {
        Self {
            keys: Arc::new(DashMap::new()),
        }
    }
}

impl Default for MemoryKeyStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStorage for MemoryKeyStorage {
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()> {
        self.keys.insert(id.to_string(), keypair.clone());
        Ok(())
    }

    fn load(&self, id: &str) -> Result<KeyPair> {
        self.keys
            .get(id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| Error::KeyNotFound(id.to_string()))
    }

    fn delete(&self, id: &str) -> Result<()> {
        self.keys
            .remove(id)
            .ok_or_else(|| Error::KeyNotFound(id.to_string()))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.keys.iter().map(|entry| entry.key().clone()).collect())
    }

    fn exists(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;

    #[test]
    fn test_memory_storage() {
        let storage = MemoryKeyStorage::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = keypair.key_id().to_string();

        // Store
        storage.store(&id, &keypair).unwrap();

        // Exists
        assert!(storage.exists(&id));

        // Load
        let loaded = storage.load(&id).unwrap();
        assert_eq!(loaded.key_id(), keypair.key_id());

        // Delete
        storage.delete(&id).unwrap();
        assert!(!storage.exists(&id));
    }
}
```

### 3.3 FileKeyStorage 구현

**파일**: `src/crypto/storage/file.rs`

```rust
//! File-based key storage implementation

use super::KeyStorage;
use crate::crypto::KeyPair;
use crate::error::{Error, Result};
use crate::formats::{KeyExporter, KeyFormat, KeyImporter};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

/// File-based key storage
pub struct FileKeyStorage {
    base_path: PathBuf,
    cache: Arc<RwLock<HashMap<String, KeyPair>>>,
}

impl FileKeyStorage {
    /// Create a new file key storage
    pub fn new(base_path: impl Into<PathBuf>) -> Result<Self> {
        let base_path = base_path.into();
        fs::create_dir_all(&base_path).map_err(|e| {
            Error::StorageError(format!("Failed to create storage directory: {}", e))
        })?;

        Ok(Self {
            base_path,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn key_path(&self, id: &str) -> PathBuf {
        self.base_path.join(format!("{}.pem", id))
    }
}

impl KeyStorage for FileKeyStorage {
    fn store(&self, id: &str, keypair: &KeyPair) -> Result<()> {
        // Export to PEM format
        let pem_data = crate::formats::pem::export_keypair(keypair)?;

        // Write to file
        let path = self.key_path(id);
        fs::write(&path, pem_data).map_err(|e| {
            Error::StorageError(format!("Failed to write key file: {}", e))
        })?;

        // Update cache
        self.cache.write().insert(id.to_string(), keypair.clone());

        Ok(())
    }

    fn load(&self, id: &str) -> Result<KeyPair> {
        // Check cache first
        if let Some(keypair) = self.cache.read().get(id) {
            return Ok(keypair.clone());
        }

        // Read from file
        let path = self.key_path(id);
        if !path.exists() {
            return Err(Error::KeyNotFound(id.to_string()));
        }

        let pem_data = fs::read(&path).map_err(|e| {
            Error::StorageError(format!("Failed to read key file: {}", e))
        })?;

        // Import from PEM
        let keypair = crate::formats::pem::import_keypair(&pem_data)?;

        // Update cache
        self.cache.write().insert(id.to_string(), keypair.clone());

        Ok(keypair)
    }

    fn delete(&self, id: &str) -> Result<()> {
        let path = self.key_path(id);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                Error::StorageError(format!("Failed to delete key file: {}", e))
            })?;
        }

        self.cache.write().remove(id);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();

        for entry in fs::read_dir(&self.base_path).map_err(|e| {
            Error::StorageError(format!("Failed to read directory: {}", e))
        })? {
            let entry = entry.map_err(|e| {
                Error::StorageError(format!("Failed to read entry: {}", e))
            })?;

            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".pem") {
                    keys.push(name.trim_end_matches(".pem").to_string());
                }
            }
        }

        Ok(keys)
    }

    fn exists(&self, id: &str) -> bool {
        self.key_path(id).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;
    use tempfile::tempdir;

    #[test]
    fn test_file_storage() {
        let temp_dir = tempdir().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path()).unwrap();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let id = keypair.key_id().to_string();

        // Store
        storage.store(&id, &keypair).unwrap();

        // Exists
        assert!(storage.exists(&id));

        // Load
        let loaded = storage.load(&id).unwrap();
        assert_eq!(loaded.key_id(), keypair.key_id());

        // Delete
        storage.delete(&id).unwrap();
        assert!(!storage.exists(&id));
    }
}
```

### 3.4 CryptoManager 구현

**파일**: `src/crypto/manager.rs`

```rust
//! Cryptographic operations manager

use super::storage::{KeyStorage, MemoryKeyStorage};
use super::{KeyPair, KeyType};
use crate::error::Result;
use std::sync::Arc;

/// Manager for cryptographic operations
pub struct CryptoManager {
    storage: Arc<dyn KeyStorage>,
}

impl CryptoManager {
    /// Create a new crypto manager with default memory storage
    pub fn new() -> Self {
        Self {
            storage: Arc::new(MemoryKeyStorage::new()),
        }
    }

    /// Create a crypto manager with custom storage
    pub fn with_storage(storage: Arc<dyn KeyStorage>) -> Self {
        Self { storage }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self, key_type: KeyType) -> Result<KeyPair> {
        KeyPair::generate(key_type)
    }

    /// Store a key pair
    pub fn store_keypair(&self, keypair: &KeyPair) -> Result<()> {
        self.storage.store(keypair.key_id(), keypair)
    }

    /// Load a key pair by ID
    pub fn load_keypair(&self, id: &str) -> Result<KeyPair> {
        self.storage.load(id)
    }

    /// Delete a key pair
    pub fn delete_keypair(&self, id: &str) -> Result<()> {
        self.storage.delete(id)
    }

    /// List all key pair IDs
    pub fn list_keypairs(&self) -> Result<Vec<String>> {
        self.storage.list()
    }

    /// Check if a key pair exists
    pub fn keypair_exists(&self, id: &str) -> bool {
        self.storage.exists(id)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_manager() {
        let manager = CryptoManager::new();
        let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();
        let id = keypair.key_id().to_string();

        manager.store_keypair(&keypair).unwrap();
        assert!(manager.keypair_exists(&id));

        let loaded = manager.load_keypair(&id).unwrap();
        assert_eq!(loaded.key_id(), keypair.key_id());
    }
}
```

### 3.5 Error 타입 업데이트

**파일**: `src/error.rs` (기존 파일 수정)

```rust
// 기존 코드에 추가
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ... 기존 에러들 ...

    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),
}
```

## 🎯 Task 4: RFC 9421 확장 (Day 5)

### 4.1 MessageBuilder 통합

**파일**: `src/rfc9421/message_builder.rs`

```rust
//! High-level message builder for RFC 9421

use crate::core::Message;
use crate::crypto::{KeyPair, Signer};
use crate::error::Result;
use crate::rfc9421::{HttpSigner, SignatureComponent};

/// Builder for creating signed messages
pub struct MessageBuilder {
    agent_did: String,
    body: Vec<u8>,
    keypair: Option<KeyPair>,
    components: Vec<SignatureComponent>,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new(agent_did: impl Into<String>) -> Self {
        Self {
            agent_did: agent_did.into(),
            body: Vec::new(),
            keypair: None,
            components: vec![
                SignatureComponent::Method,
                SignatureComponent::Path,
                SignatureComponent::Authority,
            ],
        }
    }

    /// Set body
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Set keypair for signing
    pub fn keypair(mut self, keypair: KeyPair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set components to sign
    pub fn components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.components = components;
        self
    }

    /// Build and sign the message
    pub fn build(self) -> Result<Message> {
        let keypair = self.keypair.ok_or_else(|| {
            crate::error::Error::InvalidInput("keypair is required".to_string())
        })?;

        // Create message base
        let message_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = {
            use rand::Rng;
            let random_bytes: [u8; 16] = rand::thread_rng().gen();
            hex::encode(random_bytes)
        };

        // Create signature base
        let mut signature_base = String::new();
        signature_base.push_str(&format!("agent_did: {}\n", self.agent_did));
        signature_base.push_str(&format!("message_id: {}\n", message_id));
        signature_base.push_str(&format!("timestamp: {}\n", timestamp));
        signature_base.push_str(&format!("nonce: {}\n", nonce));
        signature_base.push_str(&format!("body: {}", String::from_utf8_lossy(&self.body)));

        // Sign
        let signature = keypair.sign(signature_base.as_bytes())?;

        // Build message
        Ok(Message {
            agent_did: self.agent_did,
            message_id,
            timestamp,
            nonce,
            headers: std::collections::HashMap::new(),
            body: self.body,
            algorithm: match keypair.key_type() {
                crate::crypto::KeyType::Ed25519 => "ed25519".to_string(),
                crate::crypto::KeyType::Secp256k1 => "ecdsa-secp256k1-sha256".to_string(),
            },
            key_id: keypair.key_id().to_string(),
            signature: signature.to_bytes(),
            signed_fields: vec![
                "agent_did".to_string(),
                "message_id".to_string(),
                "timestamp".to_string(),
                "nonce".to_string(),
                "body".to_string(),
            ],
            metadata: std::collections::HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;

    #[test]
    fn test_message_builder() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let message = MessageBuilder::new("did:sage:eth:0x123")
            .body(b"Hello, SAGE!")
            .keypair(keypair)
            .build()
            .unwrap();

        assert_eq!(message.agent_did, "did:sage:eth:0x123");
        assert_eq!(message.body, b"Hello, SAGE!");
        assert!(!message.signature.is_empty());
    }
}
```

## 📝 Phase 1 완료 체크리스트

### Day 1: 구조 설계
- [ ] 디렉토리 구조 생성
- [ ] 모듈 스캐폴딩
- [ ] lib.rs 업데이트
- [ ] Cargo.toml 의존성 추가

### Day 2-3: Core 모듈
- [ ] Message 타입 구현
- [ ] MessageBuilder 구현
- [ ] VerificationOptions/Result 구현
- [ ] VerificationService 스캐폴딩
- [ ] Core 통합 모듈

### Day 3-4: Crypto 확장
- [ ] KeyStorage trait
- [ ] MemoryKeyStorage 구현
- [ ] FileKeyStorage 구현
- [ ] CryptoManager 구현
- [ ] Error 타입 업데이트

### Day 5: RFC 9421 확장
- [ ] MessageBuilder 고수준 API
- [ ] 통합 테스트

### Day 6-7: 테스트 및 문서화
- [ ] 유닛 테스트 작성
- [ ] 통합 테스트 작성
- [ ] 문서 작성
- [ ] 코드 리뷰

## 🧪 테스트 전략

### 유닛 테스트
- 각 모듈의 `#[cfg(test)] mod tests` 섹션
- 기본 기능 검증

### 통합 테스트
**파일**: `tests/integration/phase1_tests.rs`

```rust
use sage_crypto_core::*;

#[test]
fn test_end_to_end_workflow() {
    // Core 생성
    let core = Core::new();

    // 키 생성
    let keypair = core.generate_keypair(KeyType::Ed25519).unwrap();
    let key_id = keypair.key_id().to_string();

    // 키 저장
    core.store_keypair(&keypair).unwrap();

    // 키 로드
    let loaded = core.load_keypair(&key_id).unwrap();
    assert_eq!(loaded.key_id(), keypair.key_id());

    // 메시지 생성
    let message = core.message_builder()
        .agent_did("did:sage:eth:0x123")
        .body(b"test")
        .keypair(loaded)
        .build()
        .unwrap();

    assert!(!message.signature.is_empty());
}
```

## 🎓 Phase 1 학습 목표

1. Rust 모듈 시스템 이해
2. Trait 기반 추상화
3. Arc + RwLock vs DashMap 성능 차이
4. 파일 I/O 및 에러 처리
5. Builder 패턴 구현

## 다음 단계

Phase 1 완료 후 → **Phase 2: DID 시스템** 구현으로 진행

---

**작성일**: 2025-01-27
**버전**: 1.0
