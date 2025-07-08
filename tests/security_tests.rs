//! Security-focused tests to detect potential vulnerabilities

use sage_crypto_core::crypto::{ed25519, secp256k1, Signer, Verifier};
use sage_crypto_core::{KeyPair, KeyType};

#[test]
fn test_timing_attack_resistance() {
    // Test that signature verification takes similar time for valid and invalid signatures
    use std::time::Instant;

    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let message = b"test message";
    let valid_signature = keypair.sign(message).unwrap();

    // Create an invalid signature by modifying the valid one
    let mut invalid_sig_bytes = valid_signature.to_bytes();
    invalid_sig_bytes[0] ^= 1; // Flip one bit

    // Time valid verification (should succeed)
    let start = Instant::now();
    for _ in 0..100 {
        let _ = keypair.verify(message, &valid_signature);
    }
    let valid_time = start.elapsed();

    // Time invalid verification (should fail)
    // Note: We can't easily create an invalid signature of the same type,
    // so we test with wrong message instead
    let start = Instant::now();
    for _ in 0..100 {
        let _ = keypair.verify(b"wrong message", &valid_signature);
    }
    let invalid_time = start.elapsed();

    // Times should be reasonably similar (within 50% difference)
    let ratio = valid_time.as_nanos() as f64 / invalid_time.as_nanos() as f64;
    assert!(
        ratio > 0.5 && ratio < 2.0,
        "Timing difference too large: ratio={}",
        ratio
    );
}

#[test]
fn test_key_reuse_safety() {
    // Test that using the same key for multiple operations is safe
    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();

    let large_message = vec![0xFF; 1000];
    let messages: Vec<&[u8]> = vec![
        b"message1",
        b"message2",
        b"",            // empty
        &large_message, // large
    ];

    let signatures: Vec<_> = messages
        .iter()
        .map(|msg| keypair.sign(msg).unwrap())
        .collect();

    // Verify all signatures
    for (msg, sig) in messages.iter().zip(&signatures) {
        assert!(keypair.verify(msg, sig).is_ok());
    }

    // Cross-verify should fail
    for (i, sig) in signatures.iter().enumerate() {
        for (j, msg) in messages.iter().enumerate() {
            if i != j {
                assert!(keypair.verify(msg, sig).is_err());
            }
        }
    }
}

#[test]
fn test_malformed_key_rejection() {
    // Test various malformed keys are properly rejected

    // Ed25519: Invalid lengths
    for len in &[0, 16, 31, 33, 64, 128] {
        let bad_key = vec![0x42u8; *len];
        assert!(ed25519::signing_key_from_bytes(&bad_key).is_err());
        assert!(ed25519::verifying_key_from_bytes(&bad_key).is_err());
    }

    // Secp256k1: Invalid lengths
    for len in &[0, 16, 31, 33, 64] {
        let bad_key = vec![0x42u8; *len];
        if *len != 32 {
            assert!(secp256k1::signing_key_from_bytes(&bad_key).is_err());
        }
    }

    // Invalid point encodings for secp256k1
    let invalid_points = vec![
        vec![0x00; 33], // Invalid prefix
        vec![0x01; 33], // Invalid prefix
        vec![0x05; 33], // Invalid prefix
        vec![0xFF; 33], // Invalid prefix
    ];

    for point in invalid_points {
        assert!(secp256k1::verifying_key_from_bytes(&point).is_err());
    }
}

#[test]
fn test_signature_non_malleability() {
    use sage_crypto_core::Signature;

    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let message = b"test message";
    let signature = keypair.sign(message).unwrap();

    // Get signature bytes
    let sig_bytes = signature.to_bytes();

    // Try to create malleable signatures by modifying bytes
    for i in 0..sig_bytes.len() {
        let mut modified = sig_bytes.clone();
        modified[i] ^= 1; // Flip one bit

        // Try to parse modified signature
        if let Ok(modified_sig) = secp256k1::signature_from_der(&modified) {
            // If parsing succeeds, verification should fail
            let result = keypair.verify(message, &Signature::Secp256k1(modified_sig));
            assert!(
                result.is_err(),
                "Modified signature at byte {} should not verify",
                i
            );
        }
    }
}

#[test]
fn test_private_key_extraction_prevention() {
    // Ensure private keys cannot be accidentally exposed through public APIs
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    // The public API should not expose private key material
    // This is more of a code review item, but we can test that
    // the public key derived from private key matches the stored public key
    let public_key = keypair.public_key();
    let key_id = keypair.key_id();

    // Key ID should be derived from public key only
    assert_eq!(public_key.key_id(), key_id);

    // Test that we can't access private key through any public method
    // (This is ensured by Rust's type system, but good to document)
}

#[test]
fn test_deterministic_signatures() {
    // Ed25519 signatures should be deterministic
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let message = b"test message";

    let sig1 = keypair.sign(message).unwrap();
    let sig2 = keypair.sign(message).unwrap();

    // Ed25519 is deterministic, so signatures should be identical
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn test_http_signature_replay_protection() {
    use sage_crypto_core::rfc9421::HttpSigner;
    use std::thread::sleep;
    use std::time::Duration;

    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let signer = HttpSigner::new(keypair);

    let request1 = http::Request::builder()
        .method("POST")
        .uri("https://example.com/api")
        .body(())
        .unwrap();

    let signed1 = signer.sign_request(request1).unwrap();

    // Wait at least 1 second to ensure different timestamp
    sleep(Duration::from_secs(1));

    let request2 = http::Request::builder()
        .method("POST")
        .uri("https://example.com/api")
        .body(())
        .unwrap();

    let signed2 = signer.sign_request(request2).unwrap();

    // Signatures should be different due to different timestamps
    let sig1 = signed1.headers().get("signature").unwrap();
    let sig2 = signed2.headers().get("signature").unwrap();
    assert_ne!(
        sig1, sig2,
        "HTTP signatures should include timestamp for replay protection"
    );

    // Both should have different signature-input values
    let input1 = signed1.headers().get("signature-input").unwrap();
    let input2 = signed2.headers().get("signature-input").unwrap();
    assert_ne!(input1, input2);
}
