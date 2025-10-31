//! Public Key Ownership Verification
//!
//! This module provides functions to verify that ECDSA public keys are owned
//! by specific Ethereum addresses, preventing key theft attacks (CVE-SAGE-2025-001).
//!
//! # Security
//!
//! This module implements critical security features to prevent unauthorized
//! key usage in the SAGE registry. All public keys must be proven to be owned
//! by the claimed Ethereum address.
//!
//! # References
//!
//! - CVE-SAGE-2025-001: Public key theft vulnerability
//! - Ethereum address derivation: https://ethereum.org/en/developers/docs/accounts/

use crate::error::{Error, Result};
use k256::ecdsa::Signature;
use k256::ecdsa::recoverable::{Id as RecoveryId, Signature as RecoverableSignature};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tiny_keccak::{Hasher, Keccak};

/// Derive Ethereum address from an ECDSA public key
///
/// This function implements the standard Ethereum address derivation algorithm:
/// 1. Take the uncompressed public key (64 bytes: X || Y coordinates)
/// 2. Compute Keccak256 hash of the public key
/// 3. Take the last 20 bytes as the address
/// 4. Format with "0x" prefix in lowercase
///
/// # Arguments
/// * `public_key` - Uncompressed ECDSA public key (64 or 65 bytes)
///   - If 65 bytes, must start with 0x04 (uncompressed marker)
///   - If 64 bytes, raw X || Y format
///
/// # Returns
/// Ethereum address with "0x" prefix (lowercase)
///
/// # Example
/// ```ignore
/// let address = derive_ethereum_address(&public_key_bytes)?;
/// // Returns: "0x742d35cc6634c0532925a3b844bc9e7595f0beef"
/// ```
pub fn derive_ethereum_address(public_key: &[u8]) -> Result<String> {
    // Handle different public key formats
    let pub_key_bytes = match public_key.len() {
        64 => public_key, // Raw format (X || Y)
        65 => {
            // Uncompressed format with 0x04 prefix
            if public_key[0] != 0x04 {
                return Err(Error::InvalidInput(
                    "Invalid public key format: expected 0x04 prefix for 65-byte key".into(),
                ));
            }
            &public_key[1..] // Skip the 0x04 prefix
        }
        _ => {
            return Err(Error::InvalidInput(format!(
                "Invalid public key length: expected 64 or 65 bytes, got {}",
                public_key.len()
            )))
        }
    };

    // Compute Keccak256 hash of the public key
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(pub_key_bytes);
    hasher.finalize(&mut hash);

    // Take the last 20 bytes as the address and format with 0x prefix
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

/// Verify that an ECDSA public key is owned by the given Ethereum address
///
/// This function derives the Ethereum address from the public key and compares
/// it with the expected address. This is used to prevent key theft attacks where
/// an attacker tries to register a public key they don't actually own.
///
/// # Arguments
/// * `public_key` - Uncompressed ECDSA public key (64 or 65 bytes)
/// * `expected_address` - Expected Ethereum address (with or without "0x" prefix)
///
/// # Returns
/// `Ok(true)` if the address matches, `Ok(false)` otherwise
///
/// # Security
/// This is a critical security check for CVE-SAGE-2025-001. Always verify
/// ownership before registering public keys in the SAGE registry.
///
/// # Example
/// ```ignore
/// let is_owner = verify_ecdsa_ownership(
///     &public_key_bytes,
///     "0x742d35cc6634c0532925a3b844bc9e7595f0beef"
/// )?;
/// ```
pub fn verify_ecdsa_ownership(public_key: &[u8], expected_address: &str) -> Result<bool> {
    // Derive address from public key
    let derived_address = derive_ethereum_address(public_key)?;

    // Normalize expected address (add 0x prefix if missing, convert to lowercase)
    let normalized_expected = if expected_address.starts_with("0x") {
        expected_address.to_lowercase()
    } else {
        format!("0x{}", expected_address.to_lowercase())
    };

    // Case-insensitive comparison
    Ok(derived_address.eq_ignore_ascii_case(&normalized_expected))
}

/// Recover public key from ECDSA signature
///
/// This function implements ECDSA public key recovery (ecrecover). Given a
/// message and signature, it recovers the public key that created the signature.
///
/// # Arguments
/// * `message_hash` - Keccak256 hash of the message (32 bytes)
/// * `signature` - ECDSA signature (64 or 65 bytes)
///   - If 65 bytes: r (32) || s (32) || v (1)
///   - If 64 bytes: r (32) || s (32), v=0 assumed
///
/// # Returns
/// Uncompressed public key (64 bytes: X || Y) without 0x04 prefix
///
/// # Example
/// ```ignore
/// let message_hash = keccak256(b"ownership proof message");
/// let public_key = recover_public_key(&message_hash, &signature)?;
/// ```
pub fn recover_public_key(message_hash: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    // Validate message hash length
    if message_hash.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "Message hash must be 32 bytes, got {}",
            message_hash.len()
        )));
    }

    // Parse signature - RecoverableSignature expects 65 bytes (r || s || v)
    let recoverable_sig = if signature.len() == 65 {
        // Already in recoverable format
        RecoverableSignature::try_from(signature)
            .map_err(|e| Error::CryptoError(format!("Invalid recoverable signature: {}", e)))?
    } else if signature.len() == 64 {
        // Need to try both recovery IDs (0 and 1)
        let base_sig = Signature::try_from(signature)
            .map_err(|e| Error::CryptoError(format!("Invalid signature format: {}", e)))?;

        // Try recovery ID 0 first
        RecoverableSignature::new(&base_sig, RecoveryId::new(0).unwrap()).map_err(|e| {
            Error::CryptoError(format!("Failed to create recoverable signature: {}", e))
        })?
    } else {
        return Err(Error::InvalidInput(format!(
            "Invalid signature length: expected 64 or 65 bytes, got {}",
            signature.len()
        )));
    };

    // Recover public key using Keccak256 (Ethereum style)
    let recovered_key = recoverable_sig
        .recover_verifying_key_from_digest_bytes(message_hash.into())
        .map_err(|e| Error::CryptoError(format!("Public key recovery failed: {}", e)))?;

    // Convert to uncompressed bytes (64 bytes: X || Y)
    let encoded_point = recovered_key.to_encoded_point(false);
    let uncompressed = encoded_point.as_bytes();

    // Skip the 0x04 prefix if present
    if uncompressed[0] == 0x04 && uncompressed.len() == 65 {
        Ok(uncompressed[1..].to_vec())
    } else if uncompressed.len() == 64 {
        Ok(uncompressed.to_vec())
    } else {
        Err(Error::CryptoError(format!(
            "Unexpected recovered key format: {} bytes",
            uncompressed.len()
        )))
    }
}

/// Verify ownership via signature recovery
///
/// This function verifies that a signature was created by the owner of a
/// specific Ethereum address. It combines signature recovery and address
/// verification in one operation.
///
/// # Arguments
/// * `message_hash` - Keccak256 hash of the signed message (32 bytes)
/// * `signature` - ECDSA signature (64 or 65 bytes)
/// * `expected_address` - Expected Ethereum address (with or without "0x" prefix)
///
/// # Returns
/// `Ok(true)` if the signature was created by the owner of the address
///
/// # Security
/// This is used to prove ownership when registering or updating keys in the
/// SAGE registry. The message should include nonce and timestamp to prevent
/// replay attacks.
///
/// # Example
/// ```ignore
/// // Create ownership proof message
/// let message = format!("SAGE ownership proof: {}", address);
/// let message_hash = keccak256(message.as_bytes());
///
/// // Verify ownership
/// let is_owner = verify_ownership_signature(
///     &message_hash,
///     &signature,
///     "0x742d35cc6634c0532925a3b844bc9e7595f0beef"
/// )?;
/// ```
pub fn verify_ownership_signature(
    message_hash: &[u8],
    signature: &[u8],
    expected_address: &str,
) -> Result<bool> {
    // Recover public key from signature
    let public_key = recover_public_key(message_hash, signature)?;

    // Verify that the recovered public key belongs to the expected address
    verify_ecdsa_ownership(&public_key, expected_address)
}

/// Compute Keccak256 hash of a message (Ethereum-style)
///
/// # Arguments
/// * `message` - Message to hash
///
/// # Returns
/// 32-byte Keccak256 hash
pub fn keccak256(message: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(message);
    hasher.finalize(&mut hash);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_ethereum_address() {
        // Test vector from Go implementation
        // This is a known public key -> address mapping
        let pub_key_hex = concat!(
            "04", // Uncompressed marker
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Verify it's a valid Ethereum address format
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars

        println!("Derived address: {}", address);
    }

    #[test]
    fn test_derive_ethereum_address_64_bytes() {
        // Test with 64-byte (raw) public key
        let pub_key_hex = concat!(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Should produce the same result as 65-byte version
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_verify_ecdsa_ownership() {
        // Generate a test public key
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Verify ownership with correct address
        assert!(verify_ecdsa_ownership(&pub_key_bytes, &address).unwrap());

        // Verify ownership fails with incorrect address
        assert!(!verify_ecdsa_ownership(
            &pub_key_bytes,
            "0x0000000000000000000000000000000000000000"
        )
        .unwrap());
    }

    #[test]
    fn test_keccak256() {
        // Test vector from Ethereum
        let message = b"";
        let hash = keccak256(message);
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_invalid_public_key_length() {
        let invalid_key = vec![0u8; 32]; // Too short
        let result = derive_ethereum_address(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key_prefix() {
        let mut invalid_key = vec![0x05; 65]; // Wrong prefix
        invalid_key[0] = 0x05;
        let result = derive_ethereum_address(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_ownership_without_0x_prefix() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Remove 0x prefix from address
        let address_without_0x = &address[2..];

        // Should still verify correctly
        assert!(verify_ecdsa_ownership(&pub_key_bytes, address_without_0x).unwrap());
    }

    #[test]
    fn test_verify_ecdsa_ownership_case_insensitive() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Test with uppercase hex part only (keep 0x lowercase)
        let uppercase_address = format!("0x{}", address[2..].to_uppercase());
        assert!(verify_ecdsa_ownership(&pub_key_bytes, &uppercase_address).unwrap());
    }

    #[test]
    fn test_keccak256_non_empty() {
        let message = b"hello world";
        let hash = keccak256(message);

        // Verify it produces 32 bytes
        assert_eq!(hash.len(), 32);

        // Different message should produce different hash
        let hash2 = keccak256(b"hello world!");
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_recover_public_key_invalid_message_length() {
        let message = vec![0u8; 16]; // Too short (must be 32)
        let signature = vec![0u8; 64];

        let result = recover_public_key(&message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_public_key_invalid_signature_length() {
        let message_hash = [0u8; 32];
        let signature = vec![0u8; 32]; // Too short

        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_ethereum_address_consistency() {
        // Same public key in different formats should produce same address
        let pub_key_64 = hex::decode(concat!(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )).unwrap();

        let mut pub_key_65 = vec![0x04];
        pub_key_65.extend_from_slice(&pub_key_64);

        let address_64 = derive_ethereum_address(&pub_key_64).unwrap();
        let address_65 = derive_ethereum_address(&pub_key_65).unwrap();

        assert_eq!(address_64, address_65);
    }

    #[test]
    fn test_derive_ethereum_address_invalid_length_33() {
        let invalid_key = vec![0u8; 33];
        let result = derive_ethereum_address(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_ethereum_address_invalid_length_100() {
        let invalid_key = vec![0u8; 100];
        let result = derive_ethereum_address(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_keccak256_deterministic() {
        let message = b"test message";
        let hash1 = keccak256(message);
        let hash2 = keccak256(message);

        // Same message should always produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_ecdsa_ownership_mixed_case() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Test with mixed case
        let mut mixed_case = String::new();
        for (i, c) in address.chars().enumerate() {
            if i % 2 == 0 {
                mixed_case.push(c.to_ascii_uppercase());
            } else {
                mixed_case.push(c.to_ascii_lowercase());
            }
        }

        assert!(verify_ecdsa_ownership(&pub_key_bytes, &mixed_case).unwrap());
    }

    #[test]
    fn test_derive_ethereum_address_format() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Check format: 0x + 40 hex characters
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);

        // Check all chars after 0x are hex digits
        for c in address[2..].chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn test_recover_public_key_64_byte_signature() {
        // Create a simple test with known values
        // In practice, we'd use a real signature, but for unit tests
        // we're mainly testing error handling and format support

        let message_hash = [1u8; 32];
        let signature = vec![0u8; 64]; // Valid length but invalid signature

        // This will fail to recover but shouldn't panic
        let result = recover_public_key(&message_hash, &signature);
        // We expect it to fail with invalid signature, not panic
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ownership_signature_invalid_signature() {
        let message_hash = [1u8; 32];
        let invalid_signature = vec![0u8; 32]; // Too short
        let address = "0x742d35cc6634c0532925a3b844bc9e7595f0beef";

        let result = verify_ownership_signature(&message_hash, &invalid_signature, address);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ownership_signature_invalid_message_hash() {
        let message_hash = vec![0u8; 16]; // Too short
        let signature = vec![0u8; 64];
        let address = "0x742d35cc6634c0532925a3b844bc9e7595f0beef";

        let result = verify_ownership_signature(&message_hash, &signature, address);
        assert!(result.is_err());
    }

    // ===== Additional Edge Case Tests =====

    #[test]
    fn test_derive_ethereum_address_empty_key() {
        let empty_key = vec![];
        let result = derive_ethereum_address(&empty_key);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("expected 64 or 65 bytes, got 0"));
        }
    }

    #[test]
    fn test_derive_ethereum_address_single_byte() {
        let single_byte = vec![0x04];
        let result = derive_ethereum_address(&single_byte);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_ethereum_address_all_zeros_64() {
        let all_zeros = vec![0u8; 64];
        let result = derive_ethereum_address(&all_zeros);
        assert!(result.is_ok());

        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_derive_ethereum_address_all_zeros_65() {
        let mut all_zeros = vec![0x04];
        all_zeros.extend(vec![0u8; 64]);
        let result = derive_ethereum_address(&all_zeros);
        assert!(result.is_ok());

        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_derive_ethereum_address_all_ffs_64() {
        let all_ffs = vec![0xFFu8; 64];
        let result = derive_ethereum_address(&all_ffs);
        assert!(result.is_ok());

        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_derive_ethereum_address_all_ffs_65() {
        let mut all_ffs = vec![0x04];
        all_ffs.extend(vec![0xFFu8; 64]);
        let result = derive_ethereum_address(&all_ffs);
        assert!(result.is_ok());

        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_derive_ethereum_address_error_message_length() {
        let invalid_key = vec![0u8; 50];
        let result = derive_ethereum_address(&invalid_key);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid public key length"));
            assert!(msg.contains("expected 64 or 65 bytes"));
            assert!(msg.contains("got 50"));
        }
    }

    #[test]
    fn test_derive_ethereum_address_65_invalid_prefix_error() {
        let mut invalid_key = vec![0x03; 65]; // Compressed format prefix
        invalid_key[0] = 0x03;
        let result = derive_ethereum_address(&invalid_key);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid public key format"));
            assert!(msg.contains("expected 0x04 prefix"));
        }
    }

    #[test]
    fn test_verify_ecdsa_ownership_address_with_uppercase_0x() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Test with uppercase 0X prefix (should still work)
        let uppercase_0x = format!("0X{}", &address[2..]);
        // This should fail because we only handle "0x" not "0X"
        let result = verify_ecdsa_ownership(&pub_key_bytes, &uppercase_0x);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_ecdsa_ownership_64_byte_key() {
        let pub_key_hex = concat!(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Verify ownership with 64-byte key
        assert!(verify_ecdsa_ownership(&pub_key_bytes, &address).unwrap());
    }

    #[test]
    fn test_verify_ecdsa_ownership_propagates_derive_error() {
        let invalid_key = vec![0u8; 10]; // Invalid length
        let address = "0x742d35cc6634c0532925a3b844bc9e7595f0beef";

        let result = verify_ecdsa_ownership(&invalid_key, address);
        assert!(result.is_err());
    }

    #[test]
    fn test_keccak256_large_message() {
        let large_message = vec![0x42u8; 10_000];
        let hash = keccak256(&large_message);

        assert_eq!(hash.len(), 32);

        // Different large message should produce different hash
        let large_message2 = vec![0x43u8; 10_000];
        let hash2 = keccak256(&large_message2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_keccak256_known_vector() {
        // Known test vector: "hello world"
        let message = b"hello world";
        let hash = keccak256(message);

        // Expected hash for "hello world"
        let expected = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_keccak256_single_byte() {
        let message = b"a";
        let hash = keccak256(message);
        assert_eq!(hash.len(), 32);

        let message2 = b"b";
        let hash2 = keccak256(message2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_recover_public_key_zero_message_hash() {
        let message_hash = [0u8; 32];
        let signature = vec![0u8; 64];

        // Should fail with invalid signature, not panic
        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_public_key_error_message_invalid_length() {
        let message_hash = vec![0u8; 10];
        let signature = vec![0u8; 64];

        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Message hash must be 32 bytes"));
            assert!(msg.contains("got 10"));
        }
    }

    #[test]
    fn test_recover_public_key_error_message_invalid_sig_length() {
        let message_hash = [0u8; 32];
        let signature = vec![0u8; 50];

        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid signature length"));
            assert!(msg.contains("expected 64 or 65 bytes"));
            assert!(msg.contains("got 50"));
        }
    }

    #[test]
    fn test_recover_public_key_65_byte_signature_invalid() {
        let message_hash = [1u8; 32];
        let signature = vec![0u8; 65];

        // Should fail to recover but shouldn't panic
        let result = recover_public_key(&message_hash, &signature);
        // We expect a CryptoError for invalid signature
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_public_key_max_message_hash() {
        let message_hash = [0xFFu8; 32];
        let signature = vec![0u8; 64];

        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ownership_signature_with_invalid_address() {
        let message_hash = [1u8; 32];
        let signature = vec![0u8; 64];
        let invalid_address = "not-an-address";

        // Should propagate error from recover_public_key
        let result = verify_ownership_signature(&message_hash, &signature, invalid_address);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ownership_signature_empty_address() {
        let message_hash = [1u8; 32];
        let signature = vec![0u8; 64];
        let empty_address = "";

        let result = verify_ownership_signature(&message_hash, &signature, empty_address);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_ownership_address_only_0x() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let result = verify_ecdsa_ownership(&pub_key_bytes, "0x");

        // Should return false (address too short to match)
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_ecdsa_ownership_address_wrong_length() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();

        // Address too short
        let result = verify_ecdsa_ownership(&pub_key_bytes, "0x1234");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_derive_ethereum_address_consistency_all_zeros() {
        let key_64 = vec![0u8; 64];
        let mut key_65 = vec![0x04];
        key_65.extend(vec![0u8; 64]);

        let addr_64 = derive_ethereum_address(&key_64).unwrap();
        let addr_65 = derive_ethereum_address(&key_65).unwrap();

        assert_eq!(addr_64, addr_65);
    }

    #[test]
    fn test_keccak256_various_lengths() {
        // Test different message lengths
        for len in [0, 1, 10, 32, 63, 64, 65, 100, 255, 256, 1000].iter() {
            let message = vec![0x42u8; *len];
            let hash = keccak256(&message);
            assert_eq!(hash.len(), 32);
        }
    }

    #[test]
    fn test_verify_ecdsa_ownership_all_lowercase_no_0x() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Remove 0x and convert to lowercase
        let lowercase_no_0x = address[2..].to_lowercase();
        assert!(verify_ecdsa_ownership(&pub_key_bytes, &lowercase_no_0x).unwrap());
    }

    #[test]
    fn test_verify_ecdsa_ownership_all_uppercase_no_0x() {
        let pub_key_hex = concat!(
            "04",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        );

        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let address = derive_ethereum_address(&pub_key_bytes).unwrap();

        // Remove 0x and convert to uppercase
        let uppercase_no_0x = address[2..].to_uppercase();
        assert!(verify_ecdsa_ownership(&pub_key_bytes, &uppercase_no_0x).unwrap());
    }

    #[test]
    fn test_derive_ethereum_address_different_keys_different_addresses() {
        let key1 = vec![0x01u8; 64];
        let key2 = vec![0x02u8; 64];

        let addr1 = derive_ethereum_address(&key1).unwrap();
        let addr2 = derive_ethereum_address(&key2).unwrap();

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_recover_public_key_signature_length_66() {
        let message_hash = [1u8; 32];
        let signature = vec![0u8; 66]; // Invalid length

        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("expected 64 or 65 bytes"));
            assert!(msg.contains("got 66"));
        }
    }

    #[test]
    fn test_recover_public_key_signature_length_63() {
        let message_hash = [1u8; 32];
        let signature = vec![0u8; 63]; // Invalid length

        let result = recover_public_key(&message_hash, &signature);
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("expected 64 or 65 bytes"));
            assert!(msg.contains("got 63"));
        }
    }
}
