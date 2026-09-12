//! Phase 2 Integration Tests
//!
//! Tests the complete integration of Phase 2 components:
//! - Actual signature verification with HttpVerifier
//! - DID module integration with verification
//! - End-to-end flow: DID generation → signing → resolution → verification

use sage_crypto_core::core::{MessageBuilder, VerificationOptions, VerificationService};
use sage_crypto_core::crypto::{CryptoManager, MemoryKeyStorage};
use sage_crypto_core::did::{
    generate_did_from_pubkey, DIDDocument, DIDMethod, DIDResolver, MemoryDIDResolver,
    VerificationMethod, VerificationReference,
};
use sage_crypto_core::{KeyPair, KeyType};
use std::sync::Arc;

use sage_crypto_core::did::DIDExt;

/// Test end-to-end flow with DID integration
#[test]
fn test_end_to_end_with_did_ed25519() {
    // 1. Generate keypair
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);
    let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();

    // 2. Generate DID from public key
    let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
    assert!(did.as_str().starts_with("did:sage:key:"));

    // 3. Create DID Document with verification method
    let mut did_doc = DIDDocument::new(did.clone());
    let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
    let vm_id = vm.id.clone();
    did_doc.add_verification_method(vm);
    did_doc.add_authentication(VerificationReference::Reference(vm_id));

    // 4. Register DID Document in resolver
    let resolver = MemoryDIDResolver::new();
    resolver.register(did.clone(), did_doc).unwrap();

    // 5. Sign a message
    let message = MessageBuilder::new()
        .agent_did(did.as_str())
        .body(b"Phase 2 integration test".to_vec())
        .keypair(keypair.clone())
        .build()
        .expect("Failed to build signed message");

    // 6. Resolve DID Document
    let resolution_result = resolver.resolve(&did).unwrap();
    assert!(resolution_result.document.is_some());

    // 7. Verify message signature
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
    assert!(result.signature_valid);
}

/// Test end-to-end flow with Secp256k1
#[test]
fn test_end_to_end_with_did_secp256k1() {
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);
    let keypair = manager.generate_keypair(KeyType::Secp256k1).unwrap();

    let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

    let mut did_doc = DIDDocument::new(did.clone());
    let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
    did_doc.add_verification_method(vm);

    let resolver = MemoryDIDResolver::new();
    resolver.register(did.clone(), did_doc).unwrap();

    let message = MessageBuilder::new()
        .agent_did(did.as_str())
        .body(b"Secp256k1 integration test".to_vec())
        .keypair(keypair.clone())
        .build()
        .unwrap();

    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
    assert!(result.signature_valid);
    assert_eq!(message.algorithm, "es256k");
}

/// Test chain-based DID with verification
#[test]
fn test_chain_did_integration() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    // Generate chain-based DID
    let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Chain).unwrap();
    assert!(did.as_str().starts_with("did:sage:chain:"));
    assert_eq!(did.identifier().len(), 40); // 20 bytes as hex

    let mut did_doc = DIDDocument::new(did.clone());
    let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
    did_doc.add_verification_method(vm);

    let resolver = MemoryDIDResolver::new();
    resolver.register(did.clone(), did_doc.clone()).unwrap();

    // Verify document can be resolved
    let resolution = resolver.resolve(&did).unwrap();
    assert!(resolution.document.is_some());
    assert_eq!(resolution.document.unwrap().id, did.to_string());
}

/// Test signature verification failure with wrong key
#[test]
fn test_verification_failure_wrong_key() {
    let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
    let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap();

    let did = generate_did_from_pubkey(keypair1.public_key(), DIDMethod::Key).unwrap();

    // Sign with keypair1
    let message = MessageBuilder::new()
        .agent_did(did.as_str())
        .body(b"Test message".to_vec())
        .keypair(keypair1)
        .build()
        .unwrap();

    // Try to verify with keypair2 (should fail)
    let service = VerificationService::new();
    let options = VerificationOptions::default();
    let result = service
        .verify(&message, keypair2.public_key(), &options)
        .unwrap();

    assert!(!result.verified);
    assert!(!result.signature_valid);
}

/// Test verification with timestamp and nonce checking
#[test]
fn test_verification_with_all_checks() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

    let now = chrono::Utc::now().timestamp();
    let message = MessageBuilder::new()
        .agent_did(did.as_str())
        .timestamp(now)
        .nonce("unique-nonce-12345")
        .body(b"Test with checks".to_vec())
        .keypair(keypair.clone())
        .build()
        .unwrap();

    let service = VerificationService::new();
    let options = VerificationOptions {
        check_timestamp: true,
        check_nonce: true,
        max_age_secs: Some(3600),
        ..Default::default()
    };

    let result = service
        .verify(&message, keypair.public_key(), &options)
        .unwrap();

    assert!(result.verified);
    assert!(result.signature_valid);
    assert!(result.timestamp_valid);
    assert!(result.nonce_valid);
}

/// Test DID Document serialization and deserialization
#[test]
fn test_did_document_json_roundtrip() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

    let mut did_doc = DIDDocument::new(did.clone());
    let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
    did_doc.add_verification_method(vm);
    did_doc.add_authentication(VerificationReference::Reference(format!("{did}#key-1")));

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&did_doc).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"verificationMethod\""));
    assert!(json.contains("\"authentication\""));

    // Deserialize back
    let deserialized: DIDDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, did_doc.id);
    assert_eq!(
        deserialized.verification_method.len(),
        did_doc.verification_method.len()
    );
    assert_eq!(
        deserialized.authentication.len(),
        did_doc.authentication.len()
    );
}

/// Test multiple agents with different DIDs
#[test]
fn test_multiple_agents_different_dids() {
    let storage = Arc::new(MemoryKeyStorage::new());
    let manager = CryptoManager::new(storage);
    let resolver = MemoryDIDResolver::new();
    let service = VerificationService::new();

    // Create 3 different agents
    for i in 0..3 {
        let keypair = manager.generate_keypair(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

        let mut did_doc = DIDDocument::new(did.clone());
        let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
        did_doc.add_verification_method(vm);

        resolver.register(did.clone(), did_doc).unwrap();

        // Each agent signs a message
        let message = MessageBuilder::new()
            .agent_did(did.as_str())
            .body(format!("Message from agent {i}").into_bytes())
            .keypair(keypair.clone())
            .build()
            .unwrap();

        // Verify each message
        let result = service
            .verify(
                &message,
                keypair.public_key(),
                &VerificationOptions::default(),
            )
            .unwrap();

        assert!(result.verified);
    }

    // Verify all DIDs are registered
    assert_eq!(resolver.len(), 3);
}

/// Test DID resolution failure
#[test]
fn test_did_resolution_not_found() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();

    let resolver = MemoryDIDResolver::new();

    // Try to resolve non-existent DID
    let result = resolver.resolve(&did).unwrap();
    assert!(result.document.is_none());

    // Check metadata contains error
    let metadata = result.metadata.unwrap();
    let error = metadata.get("error").and_then(|v| v.as_str());
    assert!(error.is_some());
    assert!(error.unwrap().contains("not found"));
}

/// Test verification method type correctness
#[test]
fn test_verification_method_types() {
    // Ed25519
    let ed_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let ed_did = generate_did_from_pubkey(ed_keypair.public_key(), DIDMethod::Key).unwrap();
    let ed_vm = VerificationMethod::from_public_key(&ed_did, "key-1", ed_keypair.public_key());
    assert_eq!(ed_vm.method_type, "Ed25519VerificationKey2020");

    // Secp256k1
    let secp_keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let secp_did = generate_did_from_pubkey(secp_keypair.public_key(), DIDMethod::Key).unwrap();
    let secp_vm =
        VerificationMethod::from_public_key(&secp_did, "key-1", secp_keypair.public_key());
    assert_eq!(secp_vm.method_type, "EcdsaSecp256k1VerificationKey2019");
}
