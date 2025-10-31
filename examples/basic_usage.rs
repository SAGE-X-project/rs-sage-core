//! Basic Usage Example
//!
//! This example demonstrates the fundamental operations of sage_crypto_core:
//! - Key generation
//! - Message signing
//! - Signature verification
//! - Key export/import
//!
//! Run with: cargo run --example basic_usage

use sage_crypto_core::{KeyPair, KeyType, Result};
use sage_crypto_core::crypto::{Signer, Verifier};
use sage_crypto_core::formats::{KeyExporter, KeyFormat};

fn main() -> Result<()> {
    println!("=== SAGE Crypto Core - Basic Usage Example ===\n");

    // 1. Generate Ed25519 key pair
    println!("1. Generating Ed25519 key pair...");
    let keypair = KeyPair::generate(KeyType::Ed25519)?;
    println!("   ✓ Key pair generated");
    println!("   Public key: {}\n", hex::encode(keypair.public_key().to_bytes()));

    // 2. Sign a message
    let message = b"Hello, SAGE! This is a test message.";
    println!("2. Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = keypair.sign(message)?;
    println!("   ✓ Message signed");
    println!("   Signature: {}\n", hex::encode(&signature.to_bytes()));

    // 3. Verify signature
    println!("3. Verifying signature...");
    let is_valid = keypair.verify(message, &signature).is_ok();
    println!("   ✓ Signature verification: {}\n", if is_valid { "VALID ✓" } else { "INVALID ✗" });

    // 4. Test with wrong message
    let wrong_message = b"This is a different message";
    println!("4. Testing with wrong message...");
    let is_valid_wrong = keypair.verify(wrong_message, &signature).is_ok();
    println!("   ✓ Wrong message verification: {}\n", if is_valid_wrong { "VALID ✓" } else { "INVALID ✗" });

    // 5. Export public key in different formats
    println!("5. Exporting public key...");

    // JWK format
    let jwk = keypair.public_key().export(KeyFormat::Jwk)?;
    println!("   JWK: {}", String::from_utf8_lossy(&jwk));

    // Raw bytes
    let raw = keypair.public_key().export(KeyFormat::Raw)?;
    println!("   Raw (hex): {}\n", hex::encode(&raw));

    // 6. Generate Secp256k1 key pair
    println!("6. Generating Secp256k1 key pair...");
    let secp_keypair = KeyPair::generate(KeyType::Secp256k1)?;
    println!("   ✓ Secp256k1 key pair generated");
    println!("   Public key: {}\n", hex::encode(secp_keypair.public_key().to_bytes()));

    // 7. Sign with Secp256k1
    println!("7. Signing with Secp256k1...");
    let secp_signature = secp_keypair.sign(message)?;
    println!("   ✓ Message signed with Secp256k1");
    println!("   Signature: {}\n", hex::encode(&secp_signature.to_bytes()));

    // 8. Verify Secp256k1 signature
    println!("8. Verifying Secp256k1 signature...");
    let secp_valid = secp_keypair.verify(message, &secp_signature).is_ok();
    println!("   ✓ Signature verification: {}\n", if secp_valid { "VALID ✓" } else { "INVALID ✗" });

    println!("=== Example completed successfully! ===");
    Ok(())
}
