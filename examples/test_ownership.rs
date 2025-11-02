//! Test ownership verification functions
//!
//! This example demonstrates the blockchain ownership verification functionality.
//!
//! **Note**: This example requires the `blockchain` feature to be enabled.
//! Run with: `cargo run --example test_ownership --features blockchain`

// When blockchain feature is NOT enabled, show helpful message
#[cfg(not(feature = "blockchain"))]
fn main() {
    println!("❌ This example requires the 'blockchain' feature to be enabled.");
    println!();
    println!("Run with:");
    println!("  cargo run --example test_ownership --features blockchain");
}

// When blockchain feature IS enabled, run the actual tests
#[cfg(feature = "blockchain")]
fn main() {
    use sage_crypto_core::blockchain::{derive_ethereum_address, keccak256, verify_ecdsa_ownership};

    println!("Testing ownership verification...\n");

    // Test 1: Keccak256 hash
    println!("Test 1: Keccak256 hash");
    let empty_hash = keccak256(b"");
    println!("  keccak256(''): {}", hex::encode(empty_hash));
    let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    assert_eq!(hex::encode(empty_hash), expected);
    println!("  ✓ Passed\n");

    // Test 2: Derive Ethereum address from uncompressed public key (65 bytes with 0x04 prefix)
    println!("Test 2: Derive Ethereum address (65-byte uncompressed key)");
    let pub_key_hex = "04\
        79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
        483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let pub_key_bytes = hex::decode(pub_key_hex.replace('\n', "").replace(' ', "")).unwrap();
    assert_eq!(pub_key_bytes.len(), 65);
    assert_eq!(pub_key_bytes[0], 0x04);

    let address = derive_ethereum_address(&pub_key_bytes).unwrap();
    println!("  Derived address: {}", address);
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);
    println!("  ✓ Passed\n");

    // Test 3: Derive address from raw 64-byte key (add 0x04 prefix first)
    println!("Test 3: Convert 64-byte raw key to Ethereum address");
    let raw_key_hex = "\
        79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
        483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let raw_key_bytes = hex::decode(raw_key_hex.replace('\n', "").replace(' ', "")).unwrap();
    assert_eq!(raw_key_bytes.len(), 64);

    // Prepend 0x04 uncompressed marker
    let mut uncompressed_key = vec![0x04];
    uncompressed_key.extend_from_slice(&raw_key_bytes);
    assert_eq!(uncompressed_key.len(), 65);

    let address2 = derive_ethereum_address(&uncompressed_key).unwrap();
    println!("  Derived address: {}", address2);
    assert_eq!(address, address2); // Should match Test 2
    println!("  ✓ Passed\n");

    // Test 4: Verify ownership - correct address
    println!("Test 4: Verify ownership (correct address)");
    let is_owner = verify_ecdsa_ownership(&pub_key_bytes, &address).unwrap();
    println!("  Ownership verified: {}", is_owner);
    assert!(is_owner);
    println!("  ✓ Passed\n");

    // Test 5: Verify ownership - incorrect address
    println!("Test 5: Verify ownership (incorrect address)");
    let wrong_address = "0x0000000000000000000000000000000000000000";
    let is_not_owner = verify_ecdsa_ownership(&pub_key_bytes, wrong_address).unwrap();
    println!("  Ownership verified: {}", is_not_owner);
    assert!(!is_not_owner); // Should NOT be owner
    println!("  ✓ Passed\n");

    // Test 6: Invalid inputs should return errors
    println!("Test 6: Invalid inputs");

    // Invalid key length (too short)
    let invalid_key = vec![0u8; 32];
    assert!(derive_ethereum_address(&invalid_key).is_err());
    println!("  ✓ Invalid key length (32 bytes) rejected");

    // Invalid key prefix (should be 0x04 for uncompressed)
    let mut invalid_prefix_key = vec![0x03]; // Wrong prefix
    invalid_prefix_key.extend_from_slice(&raw_key_bytes);
    assert!(derive_ethereum_address(&invalid_prefix_key).is_err());
    println!("  ✓ Invalid key prefix (0x03) rejected");

    println!("  ✓ All invalid inputs properly rejected\n");

    println!("All tests passed! ✓");
}
