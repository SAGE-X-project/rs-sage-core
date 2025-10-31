//! X25519 Key Exchange
//!
//! This module provides X25519 (Curve25519) Diffie-Hellman key exchange functionality.
//!
//! # Features
//!
//! - X25519 key pair generation
//! - Diffie-Hellman shared secret computation
//! - Conversion between Ed25519 and X25519 keys
//! - Key serialization and deserialization
//!
//! # Example
//!
//! ```
//! use sage_crypto_core::crypto::X25519KeyPair;
//!
//! // Generate key pairs for Alice and Bob
//! let alice = X25519KeyPair::generate();
//! let bob = X25519KeyPair::generate();
//!
//! // Compute shared secrets
//! let alice_shared = alice.diffie_hellman(bob.public_key_bytes());
//! let bob_shared = bob.diffie_hellman(alice.public_key_bytes());
//!
//! // Shared secrets should be equal
//! assert_eq!(alice_shared, bob_shared);
//! ```

use crate::error::{Error, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// X25519 key pair for Diffie-Hellman key exchange
///
/// X25519 is based on Curve25519 and provides fast, secure key exchange.
/// It's commonly used for establishing shared secrets in encrypted communications.
#[derive(Clone)]
pub struct X25519KeyPair {
    /// Private key (32 bytes)
    secret: [u8; 32],
    /// Public key (32 bytes)
    public: [u8; 32],
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate();
    /// println!("Public key: {:?}", keypair.public_key_bytes());
    /// ```
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);

        // Compute public key using x25519 with base point
        let public = x25519(secret, X25519_BASEPOINT_BYTES);

        Self { secret, public }
    }

    /// Create X25519 key pair from raw private key bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte private key
    ///
    /// # Errors
    ///
    /// Returns error if the key length is not 32 bytes
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::X25519KeyPair;
    ///
    /// let private_key = [0u8; 32]; // Example key (don't use in production!)
    /// let keypair = X25519KeyPair::from_bytes(&private_key)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidInput(format!(
                "X25519 private key must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(bytes);

        // Compute public key using x25519 with base point
        let public = x25519(secret, X25519_BASEPOINT_BYTES);

        Ok(Self { secret, public })
    }

    /// Convert Ed25519 private key to X25519 private key
    ///
    /// This allows using the same key material for both signing (Ed25519)
    /// and key exchange (X25519).
    ///
    /// # Arguments
    ///
    /// * `ed25519_private` - 32-byte Ed25519 private key
    ///
    /// # Returns
    ///
    /// X25519 key pair derived from the Ed25519 key
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{X25519KeyPair, KeyPair, KeyType};
    ///
    /// // Generate Ed25519 key
    /// let ed25519 = KeyPair::generate(KeyType::Ed25519)?;
    /// let ed25519_private = ed25519.private_key().to_bytes();
    ///
    /// // Convert to X25519
    /// let x25519 = X25519KeyPair::from_ed25519_private(&ed25519_private)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_ed25519_private(ed25519_private: &[u8]) -> Result<Self> {
        if ed25519_private.len() != 32 {
            return Err(Error::InvalidInput(format!(
                "Ed25519 private key must be 32 bytes, got {}",
                ed25519_private.len()
            )));
        }

        // Ed25519 private key to signing key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(ed25519_private);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Convert Ed25519 to X25519
        // The private key is SHA512(ed25519_private)[0..32]
        let secret = signing_key.to_scalar_bytes();

        // Compute public key using x25519 with base point
        let public = x25519(secret, X25519_BASEPOINT_BYTES);

        Ok(Self { secret, public })
    }

    /// Convert Ed25519 public key to X25519 public key
    ///
    /// # Arguments
    ///
    /// * `ed25519_public` - 32-byte Ed25519 public key
    ///
    /// # Returns
    ///
    /// 32-byte X25519 public key
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{X25519KeyPair, KeyPair, KeyType};
    ///
    /// let ed25519 = KeyPair::generate(KeyType::Ed25519)?;
    /// let ed25519_public = ed25519.public_key().to_bytes();
    ///
    /// let x25519_public = X25519KeyPair::ed25519_public_to_x25519(&ed25519_public)?;
    /// assert_eq!(x25519_public.len(), 32);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<Vec<u8>> {
        if ed25519_public.len() != 32 {
            return Err(Error::InvalidInput(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                ed25519_public.len()
            )));
        }

        // Convert Edwards point to Montgomery point
        // This uses the standard conversion formula from RFC 7748
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(ed25519_public);

        // Create verifying key from bytes
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Error::InvalidInput(format!("Invalid Ed25519 public key: {}", e)))?;

        // Convert to Montgomery (X25519) format
        let montgomery_bytes = verifying_key.to_montgomery().to_bytes();

        Ok(montgomery_bytes.to_vec())
    }

    /// Perform Diffie-Hellman key exchange
    ///
    /// Computes the shared secret between this private key and another party's public key.
    ///
    /// # Arguments
    ///
    /// * `their_public` - The other party's 32-byte X25519 public key
    ///
    /// # Returns
    ///
    /// 32-byte shared secret
    ///
    /// # Security
    ///
    /// The shared secret should be passed through a KDF (Key Derivation Function)
    /// before using it as an encryption key.
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::X25519KeyPair;
    ///
    /// let alice = X25519KeyPair::generate();
    /// let bob = X25519KeyPair::generate();
    ///
    /// // Alice computes shared secret with Bob's public key
    /// let alice_shared = alice.diffie_hellman(bob.public_key_bytes());
    ///
    /// // Bob computes shared secret with Alice's public key
    /// let bob_shared = bob.diffie_hellman(alice.public_key_bytes());
    ///
    /// // Both should get the same shared secret
    /// assert_eq!(alice_shared, bob_shared);
    /// ```
    pub fn diffie_hellman(&self, their_public: &[u8]) -> Result<Vec<u8>> {
        if their_public.len() != 32 {
            return Err(Error::InvalidInput(format!(
                "X25519 public key must be 32 bytes, got {}",
                their_public.len()
            )));
        }

        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(their_public);

        let shared_secret = x25519(self.secret, public_bytes);

        Ok(shared_secret.to_vec())
    }

    /// Get the public key bytes
    ///
    /// # Returns
    ///
    /// 32-byte public key
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    /// Get the private key bytes
    ///
    /// # Security
    ///
    /// Handle with care! Should be zeroized after use.
    ///
    /// # Returns
    ///
    /// 32-byte private key
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// Get a unique identifier for this key pair
    ///
    /// Uses the first 16 bytes of the public key as the ID
    ///
    /// # Returns
    ///
    /// Hex-encoded key ID
    pub fn key_id(&self) -> String {
        hex::encode(&self.public[..16])
    }
}

// Implement Debug manually to avoid exposing private key
impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public", &hex::encode(self.public))
            .field("private", &"***REDACTED***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let keypair = X25519KeyPair::generate();
        assert_eq!(keypair.public_key_bytes().len(), 32);
        assert_eq!(keypair.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_from_bytes() {
        let private_bytes = [1u8; 32];
        let keypair = X25519KeyPair::from_bytes(&private_bytes).unwrap();

        assert_eq!(keypair.private_key_bytes(), private_bytes);
        assert_eq!(keypair.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let invalid = [0u8; 16];
        let result = X25519KeyPair::from_bytes(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_diffie_hellman() {
        // Generate two key pairs
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        // Compute shared secrets
        let alice_shared = alice.diffie_hellman(bob.public_key_bytes()).unwrap();
        let bob_shared = bob.diffie_hellman(alice.public_key_bytes()).unwrap();

        // Should be equal
        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_diffie_hellman_invalid_key() {
        let keypair = X25519KeyPair::generate();
        let invalid_key = [0u8; 16];

        let result = keypair.diffie_hellman(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_ed25519_private() {
        // Create Ed25519 key
        use crate::crypto::ed25519::generate_signing_key;

        let ed25519 = generate_signing_key();
        let ed25519_private = ed25519.to_bytes();

        // Convert to X25519
        let x25519 = X25519KeyPair::from_ed25519_private(&ed25519_private).unwrap();

        assert_eq!(x25519.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_from_ed25519_private_invalid_length() {
        let invalid = [0u8; 16];
        let result = X25519KeyPair::from_ed25519_private(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_public_to_x25519() {
        use crate::crypto::ed25519::generate_signing_key;

        let ed25519 = generate_signing_key();
        let ed25519_public = ed25519.verifying_key().to_bytes();

        let x25519_public = X25519KeyPair::ed25519_public_to_x25519(&ed25519_public).unwrap();

        assert_eq!(x25519_public.len(), 32);
    }

    #[test]
    fn test_ed25519_public_to_x25519_invalid_length() {
        let invalid = [0u8; 16];
        let result = X25519KeyPair::ed25519_public_to_x25519(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_id() {
        let keypair = X25519KeyPair::generate();
        let key_id = keypair.key_id();

        // Should be 32 hex chars (16 bytes)
        assert_eq!(key_id.len(), 32);
    }

    #[test]
    fn test_diffie_hellman_deterministic() {
        // Same keys should produce same shared secret
        let alice_private = [42u8; 32];
        let bob_private = [84u8; 32];

        let alice1 = X25519KeyPair::from_bytes(&alice_private).unwrap();
        let bob1 = X25519KeyPair::from_bytes(&bob_private).unwrap();

        let shared1 = alice1.diffie_hellman(bob1.public_key_bytes()).unwrap();

        // Create again with same keys
        let alice2 = X25519KeyPair::from_bytes(&alice_private).unwrap();
        let bob2 = X25519KeyPair::from_bytes(&bob_private).unwrap();

        let shared2 = alice2.diffie_hellman(bob2.public_key_bytes()).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_debug_format() {
        let keypair = X25519KeyPair::generate();
        let debug_str = format!("{:?}", keypair);

        // Should not contain actual private key
        assert!(debug_str.contains("***REDACTED***"));
        assert!(debug_str.contains("public"));
    }

    #[test]
    fn test_ed25519_x25519_roundtrip() {
        use crate::crypto::ed25519::generate_signing_key;

        // Generate Ed25519 key
        let ed25519 = generate_signing_key();
        let ed25519_private = ed25519.to_bytes();
        let ed25519_public = ed25519.verifying_key().to_bytes();

        // Convert to X25519
        let x25519 = X25519KeyPair::from_ed25519_private(&ed25519_private).unwrap();
        let x25519_public_from_key = x25519.public_key_bytes();

        // Convert Ed25519 public key separately
        let x25519_public_converted =
            X25519KeyPair::ed25519_public_to_x25519(&ed25519_public).unwrap();

        // Both conversions should produce the same X25519 public key
        assert_eq!(x25519_public_from_key, x25519_public_converted.as_slice());
    }

    #[test]
    fn test_shared_secret_uniqueness() {
        // Different key pairs should produce different shared secrets
        let alice1 = X25519KeyPair::generate();
        let alice2 = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let shared1 = alice1.diffie_hellman(bob.public_key_bytes()).unwrap();
        let shared2 = alice2.diffie_hellman(bob.public_key_bytes()).unwrap();

        assert_ne!(shared1, shared2);
    }
}
