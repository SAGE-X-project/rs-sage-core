//! Test ownership verification functions

use sage_crypto_core::blockchain::ownership::*;

fn main() {
    println!("Testing ownership verification...\n");

    // Test 1: Keccak256
    println!("Test 1: Keccak256 hash");
    let empty_hash = keccak256(b"");
    println!("  keccak256(''): {}", hex::encode(empty_hash));
    let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    assert_eq!(hex::encode(empty_hash), expected);
    println!("  ✓ Passed\n");

    // Test 2: Derive Ethereum address (65-byte key with 0x04 prefix)
    println!("Test 2: Derive Ethereum address (65-byte)");
    let pub_key_hex = "04\
        79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
        483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let pub_key_bytes = hex::decode(pub_key_hex.replace("\n", "").replace(" ", "")).unwrap();
    let address = derive_ethereum_address(&pub_key_bytes).unwrap();
    println!("  Derived address: {}", address);
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42);
    println!("  ✓ Passed\n");

    // Test 3: Derive Ethereum address (64-byte raw key)
    println!("Test 3: Derive Ethereum address (64-byte)");
    let pub_key_hex = "\
        79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
        483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let pub_key_bytes = hex::decode(pub_key_hex.replace("\n", "").replace(" ", "")).unwrap();
    let address2 = derive_ethereum_address(&pub_key_bytes).unwrap();
    println!("  Derived address: {}", address2);
    assert_eq!(address, address2); // Should be same as 65-byte version
    println!("  ✓ Passed\n");

    // Test 4: Verify ownership
    println!("Test 4: Verify ownership");
    let pub_key_hex = "04\
        79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
        483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let pub_key_bytes = hex::decode(pub_key_hex.replace("\n", "").replace(" ", "")).unwrap();
    let address = derive_ethereum_address(&pub_key_bytes).unwrap();

    let is_owner = verify_ecdsa_ownership(&pub_key_bytes, &address).unwrap();
    println!("  Ownership verified: {}", is_owner);
    assert!(is_owner);

    let is_not_owner = verify_ecdsa_ownership(
        &pub_key_bytes,
        "0x0000000000000000000000000000000000000000"
    ).unwrap();
    println!("  Non-ownership verified: {}", !is_not_owner);
    assert!(!is_not_owner);
    println!("  ✓ Passed\n");

    // Test 5: Invalid inputs
    println!("Test 5: Invalid inputs");
    let invalid_key = vec![0u8; 32];
    assert!(derive_ethereum_address(&invalid_key).is_err());
    println!("  ✓ Invalid key length rejected\n");

    println!("All tests passed! ✓");
}
