//! Phase 1 Integration Tests
//!
//! Tests the complete integration of Phase 1 components:
//! - CryptoManager for key lifecycle management
//! - KeyStorage backends (Memory and File)
//! - MessageBuilder with signing integration
//! - VerificationService for message verification

use sage_crypto_core::core::{MessageBuilder, VerificationOptions, VerificationService};
use sage_crypto_core::crypto::{CryptoManager, FileKeyStorage, MemoryKeyStorage};
use sage_crypto_core::{KeyPair, KeyType};
use std::sync::Arc;
use tempfile::TempDir;

/// Test complete signed message flow: generate → sign → verify
#[test]
fn test_end_to_end_signed_message_flow_ed25519() {
    // Generate keypair using CryptoManager
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);
    let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();

    // Build and sign message using MessageBuilder
    let message = MessageBuilder::new()
        .agent_did("did:sage:test-agent")
        .body(b"Integration test message".to_vec())
        .keypair(keypair.clone())
        .build()
        .expect("Failed to build signed message");

    // Verify the message was signed
    assert!(!message.signature.is_empty());
    assert_eq!(message.algorithm, "ed25519");
    assert_eq!(message.key_id, keypair.public_key().key_id());
    assert!(!message.signed_fields.is_empty());

    // Verify message using VerificationService
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
    assert!(result.signature_valid);
}

/// Test complete signed message flow with Secp256k1
#[test]
fn test_end_to_end_signed_message_flow_secp256k1() {
    // Generate keypair using CryptoManager
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);
    let keypair = manager.generate_keypair(KeyType::Secp256k1).unwrap();

    // Build and sign message
    let message = MessageBuilder::new()
        .agent_did("did:sage:secp256k1-agent")
        .body(b"Secp256k1 test message".to_vec())
        .keypair(keypair.clone())
        .build()
        .expect("Failed to build signed message");

    // Verify the message was signed
    assert!(!message.signature.is_empty());
    assert_eq!(message.algorithm, "es256k");
    assert_eq!(message.key_id, keypair.public_key().key_id());

    // Verify message using VerificationService
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
    assert!(result.signature_valid);
}

/// Test KeyStorage persistence with FileKeyStorage
#[test]
fn test_file_key_storage_integration() {
    let temp_dir = TempDir::new().unwrap();
    let key_id = "test-persistent-key";

    // Store a key using FileKeyStorage
    let keypair = {
        let storage = Arc::new(FileKeyStorage::new(temp_dir.path()).unwrap());
        let manager = CryptoManager::new(storage);
        let kp = manager.generate_keypair(KeyType::Ed25519).unwrap();
        manager.store_keypair(key_id, &kp).unwrap();
        kp
    };

    // Load the key in a new manager instance (simulating restart)
    let loaded_keypair = {
        let storage = Arc::new(FileKeyStorage::new(temp_dir.path()).unwrap());
        let manager = CryptoManager::new(storage);
        manager.load_keypair(key_id).unwrap()
    };

    // Verify loaded keypair matches original
    assert_eq!(
        loaded_keypair.public_key().key_id(),
        keypair.public_key().key_id()
    );

    // Sign message with loaded keypair
    let message = MessageBuilder::new()
        .agent_did("did:sage:persistent-agent")
        .body(b"Persistence test".to_vec())
        .keypair(loaded_keypair.clone())
        .build()
        .unwrap();

    // Verify with original public key
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
}

/// Test MemoryKeyStorage integration
#[test]
fn test_memory_key_storage_integration() {
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);

    // Generate and store multiple keys
    let key1 = manager.generate_keypair(KeyType::Ed25519).unwrap();
    let key2 = manager.generate_keypair(KeyType::Secp256k1).unwrap();

    manager.store_keypair("key1", &key1).unwrap();
    manager.store_keypair("key2", &key2).unwrap();

    // List stored keys
    let keys = manager.list_keys().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"key1".to_string()));
    assert!(keys.contains(&"key2".to_string()));

    // Load and use keys
    let loaded_key1 = manager.load_keypair("key1").unwrap();
    let message = MessageBuilder::new()
        .agent_did("did:sage:memory-test")
        .keypair(loaded_key1)
        .build()
        .unwrap();

    assert!(!message.signature.is_empty());
}

/// Test unsigned message creation
#[test]
fn test_unsigned_message_creation() {
    // Build message without keypair
    let message = MessageBuilder::new()
        .agent_did("did:sage:unsigned")
        .message_id("msg-001")
        .timestamp(1234567890)
        .nonce("test-nonce")
        .body(b"Unsigned message".to_vec())
        .build()
        .unwrap();

    // Verify message is unsigned
    assert!(message.signature.is_empty());
    assert!(message.algorithm.is_empty());
    assert!(message.key_id.is_empty());
    assert!(message.signed_fields.is_empty());

    // Verification should fail for unsigned message
    let service = VerificationService::new();
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(!result.verified);
    assert!(!result.signature_valid);
}

/// Test auto-generation of message fields
#[test]
fn test_message_auto_generation() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    // Build message without explicit message_id, timestamp, nonce
    let message = MessageBuilder::new()
        .agent_did("did:sage:auto-gen")
        .keypair(keypair)
        .build()
        .unwrap();

    // Verify fields were auto-generated
    assert!(!message.message_id.is_empty());
    assert!(message.timestamp > 0);
    assert!(!message.nonce.is_empty());
    assert!(!message.signature.is_empty());
}

/// Test timestamp verification
#[test]
fn test_timestamp_verification() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let service = VerificationService::new();
    let now = chrono::Utc::now().timestamp();

    // Create message with current timestamp
    let valid_message = MessageBuilder::new()
        .agent_did("did:sage:timestamp-test")
        .timestamp(now)
        .keypair(keypair.clone())
        .build()
        .unwrap();

    // Verify with timestamp checking enabled
    let options = VerificationOptions {
        check_timestamp: true,
        max_age_secs: Some(3600), // 1 hour
        ..Default::default()
    };

    let result = service
        .verify(&valid_message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
    assert!(result.timestamp_valid);

    // Create message with expired timestamp (2 hours old)
    let expired_message = MessageBuilder::new()
        .agent_did("did:sage:expired")
        .timestamp(now - 7200)
        .keypair(keypair.clone())
        .build()
        .unwrap();

    let result = service
        .verify(&expired_message, keypair.public_key(), &options)
        .unwrap();

    assert!(!result.verified);
    assert!(!result.timestamp_valid);
}

/// Test cross-key-type verification fails
///
/// Verifies that a message signed with one key type (Ed25519) cannot be verified
/// with a different key type (Secp256k1). This ensures proper cryptographic isolation.
#[test]
fn test_cross_key_type_verification_fails() {
    let ed25519_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let secp256k1_keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();

    // Sign message with Ed25519
    let message = MessageBuilder::new()
        .agent_did("did:sage:cross-key-test")
        .keypair(ed25519_keypair)
        .build()
        .unwrap();

    // Try to verify with Secp256k1 public key (should fail)
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, secp256k1_keypair.public_key(), &options)
        .unwrap();

    assert!(!result.verified);
    assert!(!result.signature_valid);
}

/// Test CryptoManager key deletion
#[test]
fn test_crypto_manager_key_deletion() {
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);
    let key_id = "deletable-key";

    // Generate and store key
    let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();
    manager.store_keypair(key_id, &keypair).unwrap();

    // Verify key exists
    assert!(manager.list_keys().unwrap().contains(&key_id.to_string()));

    // Delete key
    manager.delete_keypair(key_id).unwrap();

    // Verify key no longer exists
    assert!(!manager.list_keys().unwrap().contains(&key_id.to_string()));

    // Loading deleted key should fail
    assert!(manager.load_keypair(key_id).is_err());
}

/// Test message with custom headers
#[test]
fn test_message_with_custom_headers() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    let message = MessageBuilder::new()
        .agent_did("did:sage:custom-headers")
        .header("x-custom-header", "custom-value")
        .header("x-request-id", "req-12345")
        .keypair(keypair.clone())
        .build()
        .unwrap();

    // Verify custom headers are preserved
    assert_eq!(
        message.headers.get("x-custom-header").unwrap(),
        "custom-value"
    );
    assert_eq!(message.headers.get("x-request-id").unwrap(), "req-12345");

    // Verify message is still properly signed
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
}

/// Test message with metadata
#[test]
fn test_message_with_metadata() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    let message = MessageBuilder::new()
        .agent_did("did:sage:metadata-test")
        .metadata("version", serde_json::json!("1.0"))
        .metadata("type", serde_json::json!("test"))
        .keypair(keypair)
        .build()
        .unwrap();

    // Verify metadata is preserved
    assert_eq!(message.metadata.get("version").unwrap(), "1.0");
    assert_eq!(message.metadata.get("type").unwrap(), "test");
}

/// Test multiple messages with same keypair
#[test]
fn test_multiple_messages_same_keypair() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let service = VerificationService::new();
    let options = VerificationOptions::default();

    // Create multiple messages with same keypair
    for i in 0..5 {
        let message = MessageBuilder::new()
            .agent_did(format!("did:sage:agent-{i}"))
            .body(format!("Message {i}").into_bytes())
            .keypair(keypair.clone())
            .build()
            .unwrap();

        // Each message should have unique nonce and message_id
        assert!(!message.nonce.is_empty());
        assert!(!message.message_id.is_empty());

        // Each message should verify correctly
        let result = service
            .verify(&message, keypair.public_key(), &options)
            .unwrap();
        assert!(result.verified);
    }
}
