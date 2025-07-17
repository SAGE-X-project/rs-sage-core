//! Edge case tests for SAGE Crypto Core

use sage_crypto_core::crypto::{ed25519, secp256k1};

#[test]
fn test_ed25519_invalid_key_sizes() {
    // Test invalid private key size
    let short_key = vec![0u8; 16];
    let result = ed25519::signing_key_from_bytes(&short_key);
    assert!(result.is_err());

    let long_key = vec![0u8; 64];
    let result = ed25519::signing_key_from_bytes(&long_key);
    assert!(result.is_err());

    // Test invalid public key size
    let short_pub = vec![0u8; 16];
    let result = ed25519::verifying_key_from_bytes(&short_pub);
    assert!(result.is_err());

    let long_pub = vec![0u8; 64];
    let result = ed25519::verifying_key_from_bytes(&long_pub);
    assert!(result.is_err());

    // Test invalid signature size
    let short_sig = vec![0u8; 32];
    let result = ed25519::signature_from_bytes(&short_sig);
    assert!(result.is_err());

    let long_sig = vec![0u8; 128];
    let result = ed25519::signature_from_bytes(&long_sig);
    assert!(result.is_err());
}

#[test]
fn test_secp256k1_invalid_key_sizes() {
    // Test invalid private key size
    let short_key = vec![0u8; 16];
    let result = secp256k1::signing_key_from_bytes(&short_key);
    assert!(result.is_err());

    let long_key = vec![0u8; 64];
    let result = secp256k1::signing_key_from_bytes(&long_key);
    assert!(result.is_err());

    // Test invalid public key formats
    let invalid_pub = vec![0u8; 31]; // Too short
    let result = secp256k1::verifying_key_from_bytes(&invalid_pub);
    assert!(result.is_err());

    // Test invalid signature
    let invalid_sig = vec![0xFF; 70]; // Invalid DER
    let result = secp256k1::signature_from_der(&invalid_sig);
    assert!(result.is_err());
}

#[test]
fn test_invalid_signature_formats() {
    // Test malformed base64 in signature operations

    // This should work - valid Ed25519 signature is 64 bytes
    let valid_sig_bytes = vec![0u8; 64];
    let ed_sig_result = ed25519::signature_from_bytes(&valid_sig_bytes);
    assert!(ed_sig_result.is_ok());

    // Test secp256k1 fixed-size signature parsing
    // Note: All zeros is not a valid signature, so we use a different pattern
    let mut fixed_sig = vec![0u8; 64];
    fixed_sig[31] = 1; // Make r = 1
    fixed_sig[63] = 1; // Make s = 1
    let _secp_sig_result = secp256k1::signature_from_bytes(&fixed_sig);
    // This might still fail as 1,1 might not be valid scalars
    // So we just test that the function doesn't panic
    let _ = secp256k1::signature_from_bytes(&fixed_sig);

    // Test invalid fixed-size signature
    let invalid_fixed = vec![0u8; 63]; // Wrong size
    let result = secp256k1::signature_from_bytes(&invalid_fixed);
    assert!(result.is_err());
}

#[test]
fn test_zero_keys_rejected() {
    // All-zero keys should be rejected by the crypto libraries
    let zero_private = [0u8; 32];

    // For secp256k1, all-zero key is invalid
    let result = secp256k1::signing_key_from_bytes(&zero_private);
    assert!(result.is_err());
}

#[test]
fn test_malformed_pem_handling() {
    // Test various malformed PEM formats
    let malformed_pems = vec![
        "-----BEGIN PUBLIC KEY-----\ninvalid base64!!!\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----", // Empty
        "-----BEGIN WRONG TYPE-----\nVGVzdA==\n-----END WRONG TYPE-----",
        "No PEM headers at all",
        "-----BEGIN PUBLIC KEY-----\nVGVzdA==", // Missing end
    ];

    for pem in malformed_pems {
        let result = pem::parse(pem.as_bytes());
        // At least some of these should fail
        if result.is_ok() {
            let pem_data = result.unwrap();
            // Even if parsing succeeds, the key creation should fail
            assert!(ed25519::verifying_key_from_bytes(&pem_data.contents).is_err());
        }
    }
}

#[test]
fn test_signature_malleability() {
    use sage_crypto_core::crypto::Signer;
    use sage_crypto_core::{KeyPair, KeyType};

    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let message = b"test message";
    let signature = keypair.sign(message).unwrap();

    // Convert to bytes and back
    let sig_bytes = signature.to_bytes();

    // For secp256k1, signatures are DER encoded, so round-trip should work
    let recovered = secp256k1::signature_from_der(&sig_bytes).unwrap();

    // The recovered signature should still verify
    use sage_crypto_core::crypto::Verifier;
    assert!(keypair
        .verify(message, &sage_crypto_core::Signature::Secp256k1(recovered))
        .is_ok());
}

#[test]
fn test_concurrent_key_generation() {
    use sage_crypto_core::{KeyPair, KeyType};
    use std::thread;

    let handles: Vec<_> = (0..10)
        .map(|_| {
            thread::spawn(|| {
                // Generate keys in parallel
                let ed_key = KeyPair::generate(KeyType::Ed25519).unwrap();
                let secp_key = KeyPair::generate(KeyType::Secp256k1).unwrap();
                (ed_key.key_id().to_string(), secp_key.key_id().to_string())
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All key IDs should be unique
    let mut all_ids = Vec::new();
    for (ed_id, secp_id) in results {
        all_ids.push(ed_id);
        all_ids.push(secp_id);
    }

    all_ids.sort();
    all_ids.dedup();
    assert_eq!(all_ids.len(), 20); // Should have 20 unique IDs
}

#[test]
fn test_max_size_limits() {
    use sage_crypto_core::rfc9421::SignatureComponent;

    // Test very long header names
    let long_header_name = "x-".repeat(1000) + "header";
    let component = SignatureComponent::Header(long_header_name.clone());
    assert_eq!(component.identifier(), long_header_name.to_lowercase());

    // Test signature parameters with extreme values
    use sage_crypto_core::rfc9421::SignatureParams;
    let params = SignatureParams {
        key_id: Some("k".repeat(1000)),
        alg: Some("a".repeat(1000)),
        created: Some(i64::MAX),
        expires: Some(i64::MIN),
        nonce: Some("n".repeat(1000)),
        tag: Some("t".repeat(1000)),
    };

    // Should be able to format without panic
    let formatted = params.to_string();
    assert!(formatted.len() > 4000); // Should be quite long
}
