//! Phase 4 HPKE Integration Tests
//!
//! Tests the HPKE utility functions and secret derivation:
//! - Secret combination (HPKE + E2E ECDH)
//! - Traffic key derivation (C2S, S2C, Channel Binding)
//! - ACK tag generation and verification
//! - Info builder implementations
//!
//! Note: Full HPKE client/server flow is tested in handshake integration tests

use sage_crypto_core::hpke::common::{
    combine_secrets, derive_traffic_keys, is_all_zero_32, make_ack_tag, sha256_hash,
    sha256_hash_hex, verify_ack_tag,
};
use sage_crypto_core::hpke::types::{DefaultInfoBuilder, InfoBuilder};

/// Test secret combination with different inputs
#[test]
fn test_secret_combination() {
    let exporter_hpke = vec![0x11u8; 32];
    let ss_e2e = vec![0x22u8; 32];
    let export_ctx = b"test-export-context";

    let combined = combine_secrets(&exporter_hpke, &ss_e2e, export_ctx).unwrap();

    // Verify combined secret properties
    assert_eq!(combined.len(), 32);
    assert!(combined.iter().any(|&b| b != 0)); // Not all zeros

    // Verify determinism
    let combined2 = combine_secrets(&exporter_hpke, &ss_e2e, export_ctx).unwrap();
    assert_eq!(*combined, *combined2);

    // Verify different inputs produce different outputs
    let exporter_hpke2 = vec![0x33u8; 32];
    let combined3 = combine_secrets(&exporter_hpke2, &ss_e2e, export_ctx).unwrap();
    assert_ne!(*combined, *combined3);

    // Different export context
    let export_ctx2 = b"different-export-context";
    let combined4 = combine_secrets(&exporter_hpke, &ss_e2e, export_ctx2).unwrap();
    assert_ne!(*combined, *combined4);
}

/// Test traffic key derivation produces unique keys
#[test]
fn test_traffic_key_derivation() {
    let seed = vec![0x42u8; 32];
    let keys = derive_traffic_keys(&seed).unwrap();

    // Verify key sizes
    assert_eq!(keys.c2s_key.len(), 32);
    assert_eq!(keys.c2s_iv.len(), 12);
    assert_eq!(keys.s2c_key.len(), 32);
    assert_eq!(keys.s2c_iv.len(), 12);
    assert_eq!(keys.channel_binding.len(), 32);

    // Verify all keys are different
    assert_ne!(&keys.c2s_key[..], &keys.s2c_key[..]);
    assert_ne!(&keys.c2s_key[..], &keys.channel_binding[..]);
    assert_ne!(&keys.s2c_key[..], &keys.channel_binding[..]);

    // Verify IVs are different
    assert_ne!(&keys.c2s_iv[..], &keys.s2c_iv[..]);

    // Verify keys are deterministic
    let keys2 = derive_traffic_keys(&seed).unwrap();
    assert_eq!(keys.c2s_key, keys2.c2s_key);
    assert_eq!(keys.c2s_iv, keys2.c2s_iv);
    assert_eq!(keys.s2c_key, keys2.s2c_key);
    assert_eq!(keys.s2c_iv, keys2.s2c_iv);
    assert_eq!(keys.channel_binding, keys2.channel_binding);
}

/// Test traffic keys with different seeds produce different keys
#[test]
fn test_traffic_keys_different_seeds() {
    let seed1 = vec![0x01u8; 32];
    let seed2 = vec![0x02u8; 32];

    let keys1 = derive_traffic_keys(&seed1).unwrap();
    let keys2 = derive_traffic_keys(&seed2).unwrap();

    // All keys should be different
    assert_ne!(keys1.c2s_key, keys2.c2s_key);
    assert_ne!(keys1.c2s_iv, keys2.c2s_iv);
    assert_ne!(keys1.s2c_key, keys2.s2c_key);
    assert_ne!(keys1.s2c_iv, keys2.s2c_iv);
    assert_ne!(keys1.channel_binding, keys2.channel_binding);
}

/// Test ACK tag generation with various inputs
#[test]
fn test_ack_tag_generation() {
    let seed = vec![0x42u8; 32];
    let ctx_id = "ctx-123";
    let nonce = "nonce-456";
    let kid = "kid-789";
    let binds = vec![b"bind1".as_ref(), b"bind2".as_ref(), b"bind3".as_ref()];

    let tag = make_ack_tag(&seed, ctx_id, nonce, kid, &binds).unwrap();

    // Verify tag properties
    assert_eq!(tag.len(), 32); // HMAC-SHA256 output

    // Verify determinism
    let tag2 = make_ack_tag(&seed, ctx_id, nonce, kid, &binds).unwrap();
    assert_eq!(tag, tag2);

    // Verify different inputs produce different tags
    let tag3 = make_ack_tag(&seed, "different-ctx", nonce, kid, &binds).unwrap();
    assert_ne!(tag, tag3);

    let tag4 = make_ack_tag(&seed, ctx_id, "different-nonce", kid, &binds).unwrap();
    assert_ne!(tag, tag4);

    let tag5 = make_ack_tag(&seed, ctx_id, nonce, "different-kid", &binds).unwrap();
    assert_ne!(tag, tag5);

    // Different bindings
    let binds2 = vec![b"bind1".as_ref(), b"bind2-modified".as_ref()];
    let tag6 = make_ack_tag(&seed, ctx_id, nonce, kid, &binds2).unwrap();
    assert_ne!(tag, tag6);
}

/// Test ACK tag verification
#[test]
fn test_ack_tag_verification() {
    let tag1 = vec![0x42u8; 32];
    let tag2 = vec![0x42u8; 32];
    let tag3 = vec![0x43u8; 32];

    // Matching tags should verify
    assert!(verify_ack_tag(&tag1, &tag2).is_ok());

    // Different tags should fail
    assert!(verify_ack_tag(&tag1, &tag3).is_err());

    // Different lengths should fail
    let tag_short = vec![0x42u8; 16];
    assert!(verify_ack_tag(&tag1, &tag_short).is_err());
}

/// Test InfoBuilder implementation
#[test]
fn test_info_builder() {
    let builder = DefaultInfoBuilder;
    let ctx_id = "test-ctx";
    let init_did = "did:sage:alice";
    let resp_did = "did:sage:bob";

    // Test info building
    let info = builder.build_info(ctx_id, init_did, resp_did);
    let info_str = String::from_utf8(info.clone()).unwrap();

    assert!(info_str.contains("sage/hpke-info"));
    assert!(info_str.contains("v1"));
    assert!(info_str.contains("suite=hpke-base+x25519+hkdf-sha256"));
    assert!(info_str.contains("combiner=e2e-x25519-hkdf-v1"));
    assert!(info_str.contains(&format!("ctx={ctx_id}")));
    assert!(info_str.contains(&format!("init={init_did}")));
    assert!(info_str.contains(&format!("resp={resp_did}")));

    // Different DIDs should produce different info
    let info2 = builder.build_info(ctx_id, "did:sage:charlie", resp_did);
    assert_ne!(info, info2);

    // Test export context building
    let export_ctx = builder.build_export_context(ctx_id);
    let export_str = String::from_utf8(export_ctx.clone()).unwrap();

    assert!(export_str.contains("sage/hpke-export"));
    assert!(export_str.contains("v1"));
    assert!(export_str.contains(&format!("ctx={ctx_id}")));

    // Different context should produce different export context
    let export_ctx2 = builder.build_export_context("different-ctx");
    assert_ne!(export_ctx, export_ctx2);
}

/// Test is_all_zero_32 utility
#[test]
fn test_is_all_zero_32() {
    let zero = [0u8; 32];
    let non_zero1 = {
        let mut arr = [0u8; 32];
        arr[0] = 1;
        arr
    };
    let non_zero2 = {
        let mut arr = [0u8; 32];
        arr[31] = 1;
        arr
    };

    assert!(is_all_zero_32(&zero));
    assert!(!is_all_zero_32(&non_zero1));
    assert!(!is_all_zero_32(&non_zero2));
}

/// Test SHA256 hashing utilities
#[test]
fn test_sha256_utilities() {
    let data = b"hello world";

    // Test hash function
    let hash = sha256_hash(data);
    assert_eq!(hash.len(), 32);

    // Test hex encoding
    let hash_hex = sha256_hash_hex(data);
    assert_eq!(hash_hex.len(), 64); // 32 bytes = 64 hex chars
    assert_eq!(
        hash_hex,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    // Verify determinism
    let hash2 = sha256_hash(data);
    assert_eq!(hash, hash2);

    // Different data should produce different hash
    let hash3 = sha256_hash(b"different data");
    assert_ne!(hash, hash3);
}

/// Test traffic keys with edge case seeds
#[test]
fn test_traffic_keys_edge_cases() {
    // All zeros seed
    let zero_seed = vec![0u8; 32];
    let keys1 = derive_traffic_keys(&zero_seed).unwrap();
    assert_eq!(keys1.c2s_key.len(), 32);

    // All ones seed
    let ones_seed = vec![0xFFu8; 32];
    let keys2 = derive_traffic_keys(&ones_seed).unwrap();
    assert_eq!(keys2.c2s_key.len(), 32);

    // Keys should be different even for edge cases
    assert_ne!(keys1.c2s_key, keys2.c2s_key);
}

/// Test ACK tag with empty bindings
#[test]
fn test_ack_tag_empty_bindings() {
    let seed = vec![0x42u8; 32];
    let ctx_id = "ctx";
    let nonce = "nonce";
    let kid = "kid";

    // Empty bindings
    let binds_empty: Vec<&[u8]> = vec![];
    let tag1 = make_ack_tag(&seed, ctx_id, nonce, kid, &binds_empty).unwrap();
    assert_eq!(tag1.len(), 32);

    // Non-empty bindings should produce different tag
    let binds = vec![b"bind".as_ref()];
    let tag2 = make_ack_tag(&seed, ctx_id, nonce, kid, &binds).unwrap();
    assert_ne!(tag1, tag2);
}

/// Test combine_secrets with different context lengths
#[test]
fn test_combine_secrets_various_contexts() {
    let exporter = vec![0x11u8; 32];
    let ss_e2e = vec![0x22u8; 32];

    // Short context
    let ctx1 = b"short";
    let combined1 = combine_secrets(&exporter, &ss_e2e, ctx1).unwrap();

    // Long context
    let ctx2 = b"this is a much longer export context string with more data";
    let combined2 = combine_secrets(&exporter, &ss_e2e, ctx2).unwrap();

    // Both should succeed and produce different results
    assert_eq!(combined1.len(), 32);
    assert_eq!(combined2.len(), 32);
    assert_ne!(*combined1, *combined2);
}

/// Test multiple ACK tag verifications in sequence
#[test]
fn test_ack_tag_multiple_verifications() {
    let seed = vec![0x42u8; 32];
    let binds = vec![b"bind1".as_ref()];

    // Generate multiple tags
    let tag1 = make_ack_tag(&seed, "ctx1", "nonce1", "kid1", &binds).unwrap();
    let tag2 = make_ack_tag(&seed, "ctx2", "nonce2", "kid2", &binds).unwrap();
    let tag3 = make_ack_tag(&seed, "ctx3", "nonce3", "kid3", &binds).unwrap();

    // Each tag is unique
    assert_ne!(tag1, tag2);
    assert_ne!(tag2, tag3);
    assert_ne!(tag1, tag3);

    // Regenerate and verify
    let tag1_again = make_ack_tag(&seed, "ctx1", "nonce1", "kid1", &binds).unwrap();
    assert!(verify_ack_tag(&tag1, &tag1_again).is_ok());
}
