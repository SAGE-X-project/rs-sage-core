//! Integration tests for SAGE Crypto Core

use http::{Request, Response};
use sage_crypto_core::crypto::{Signer, Verifier};
use sage_crypto_core::formats::{KeyExporter, KeyFormat};
use sage_crypto_core::rfc9421::{HttpSigner, HttpVerifier};
use sage_crypto_core::{KeyPair, KeyType};

#[test]
fn test_ed25519_full_cycle() {
    // Generate key pair
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let message = b"Test message for Ed25519";

    // Sign and verify
    let signature = keypair.sign(message).unwrap();
    assert!(keypair.verify(message, &signature).is_ok());

    // Export and verify public key
    let public_key = keypair.public_key();
    assert!(public_key.verify(message, &signature).is_ok());

    // Wrong message should fail
    assert!(public_key.verify(b"Wrong message", &signature).is_err());
}

#[test]
fn test_secp256k1_full_cycle() {
    // Generate key pair
    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let message = b"Test message for Secp256k1";

    // Sign and verify
    let signature = keypair.sign(message).unwrap();
    assert!(keypair.verify(message, &signature).is_ok());

    // Export and verify public key
    let public_key = keypair.public_key();
    assert!(public_key.verify(message, &signature).is_ok());

    // Wrong message should fail
    assert!(public_key.verify(b"Wrong message", &signature).is_err());
}

#[test]
fn test_cross_algorithm_verification_fails() {
    let ed25519_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let secp256k1_keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let message = b"Test message";

    // Sign with Ed25519
    let ed_signature = ed25519_keypair.sign(message).unwrap();

    // Try to verify Ed25519 signature with Secp256k1 key (should fail)
    assert!(secp256k1_keypair.verify(message, &ed_signature).is_err());
}

#[test]
fn test_key_export_formats() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    // Test PEM export
    let pem = keypair.to_pem().unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

    // Test raw export
    let raw_bytes = keypair.export(KeyFormat::Raw).unwrap();
    assert_eq!(raw_bytes.len(), 32); // Ed25519 private key is 32 bytes

    // Test public key export
    let public_pem = keypair.public_key().to_pem().unwrap();
    assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
}

#[test]
fn test_http_message_signing() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let signer = HttpSigner::new(keypair.clone());

    // Create a test request
    let request = Request::builder()
        .method("POST")
        .uri("https://example.com/api/test")
        .header("content-type", "application/json")
        .body(b"test body".to_vec())
        .unwrap();

    // Sign the request
    let signed_request = signer.sign_request(request).unwrap();

    // Verify signatures were added
    assert!(signed_request.headers().contains_key("signature"));
    assert!(signed_request.headers().contains_key("signature-input"));

    // Verify the signature
    let verifier = HttpVerifier::new(keypair.public_key().clone());
    assert!(verifier.verify_request(&signed_request).is_ok());
}

#[test]
fn test_http_response_signing() {
    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let signer = HttpSigner::new(keypair.clone());

    // Create a test response
    let response = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(b"response body".to_vec())
        .unwrap();

    // Sign the response
    let signed_response = signer.sign_response(response).unwrap();

    // Verify signatures were added
    assert!(signed_response.headers().contains_key("signature"));
    assert!(signed_response.headers().contains_key("signature-input"));

    // Verify the signature
    let verifier = HttpVerifier::new(keypair.public_key().clone());
    assert!(verifier.verify_response(&signed_response).is_ok());
}

#[test]
fn test_signature_expiration() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let signer = HttpSigner::new(keypair.clone());

    // Create and sign a request
    let request = Request::builder()
        .method("GET")
        .uri("https://example.com/test")
        .body(())
        .unwrap();

    let signed_request = signer.sign_request(request).unwrap();

    // Extract signature-input header
    let sig_input = signed_request
        .headers()
        .get("signature-input")
        .unwrap()
        .to_str()
        .unwrap();

    // Verify it contains created and expires parameters
    assert!(sig_input.contains("created="));
    assert!(sig_input.contains("expires="));
}

#[test]
fn test_empty_message_signing() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let empty_message = b"";

    // Should be able to sign empty message
    let signature = keypair.sign(empty_message).unwrap();
    assert!(keypair.verify(empty_message, &signature).is_ok());
}

#[test]
fn test_large_message_signing() {
    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let large_message = vec![0u8; 1_000_000]; // 1MB message

    // Should be able to sign large message
    let signature = keypair.sign(&large_message).unwrap();
    assert!(keypair.verify(&large_message, &signature).is_ok());
}

#[test]
fn test_key_id_consistency() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let key_id1 = keypair.key_id();
    let key_id2 = keypair.public_key().key_id();

    // Key ID should be consistent between keypair and public key
    assert_eq!(key_id1, key_id2);

    // Key ID should be hex encoded and 16 characters (8 bytes)
    assert_eq!(key_id1.len(), 16);
    assert!(key_id1.chars().all(|c| c.is_ascii_hexdigit()));
}
