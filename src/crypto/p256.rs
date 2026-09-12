//! P-256 (NIST P-256 / secp256r1) ECDSA Implementation
//!
//! This module provides P-256 ECDSA signature support, which is widely used
//! in enterprise environments and required for compatibility with many systems.
//!
//! # Standards
//! - FIPS 186-4: Digital Signature Standard (DSS)
//! - SEC 2: Recommended Elliptic Curve Domain Parameters (secp256r1)
//! - RFC 6979: Deterministic Usage of DSA and ECDSA

use crate::crypto::Algorithm;
use crate::error::{Error, Result};
use p256::ecdsa::{
    signature::{Signer as P256Signer, Verifier as P256Verifier},
    Signature as P256Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// P-256 ECDSA key pair
///
/// # Key Format
/// - Private key: 32 bytes (scalar)
/// - Public key: 33 bytes (compressed) or 65 bytes (uncompressed)
/// - Signature: 64 bytes (r || s)
///
/// # Example
/// ```
/// use sage_crypto_core::crypto::p256::P256KeyPair;
///
/// let keypair = P256KeyPair::generate().unwrap();
/// let message = b"test message";
/// let signature = keypair.sign(message).unwrap();
/// assert!(keypair.verify(message, &signature).is_ok());
/// ```
#[derive(Clone)]
pub struct P256KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl P256KeyPair {
    /// Generate a new random P-256 key pair
    ///
    /// Uses OS random number generator for cryptographically secure randomness.
    ///
    /// # Example
    /// ```
    /// use sage_crypto_core::crypto::p256::P256KeyPair;
    ///
    /// let keypair = P256KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a key pair from a private key (32 bytes)
    ///
    /// # Arguments
    /// * `bytes` - 32-byte private key scalar
    ///
    /// # Errors
    /// Returns error if the bytes are invalid or wrong length
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidInput(
                "P-256 private key must be 32 bytes".into(),
            ));
        }

        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| Error::CryptoError(format!("Invalid P-256 private key: {e}")))?;

        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a verifying-only instance from a public key
    ///
    /// # Arguments
    /// * `bytes` - 33-byte (compressed) or 65-byte (uncompressed) public key
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| Error::CryptoError(format!("Invalid P-256 public key: {e}")))
    }

    /// Sign a message with this key pair
    ///
    /// Uses deterministic ECDSA (RFC 6979) with SHA-256.
    ///
    /// # Arguments
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// 64-byte signature (r || s)
    ///
    /// # Example
    /// ```
    /// use sage_crypto_core::crypto::p256::P256KeyPair;
    ///
    /// let keypair = P256KeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"test").unwrap();
    /// assert_eq!(signature.len(), 64);
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature: P256Signature = self.signing_key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a signature
    ///
    /// # Arguments
    /// * `message` - Original message
    /// * `signature` - 64-byte signature to verify
    ///
    /// # Returns
    /// `Ok(())` if signature is valid, `Err` otherwise
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(Error::InvalidInput(
                "P-256 signature must be 64 bytes".into(),
            ));
        }

        let sig = P256Signature::try_from(signature)
            .map_err(|e| Error::InvalidInput(format!("Invalid signature format: {e}")))?;
        let sig = sig.normalize_s().unwrap_or(sig);

        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| Error::Verification("Signature verification failed".into()))
    }

    /// Get the public key bytes (uncompressed SEC1, 65 bytes)
    ///
    /// # Example
    /// ```
    /// use sage_crypto_core::crypto::p256::P256KeyPair;
    ///
    /// let keypair = P256KeyPair::generate().unwrap();
    /// let pub_key = keypair.public_key_bytes();
    /// assert_eq!(pub_key.len(), 65); // uncompressed SEC1
    /// ```
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Compressed SEC1 encoding (33 bytes)
    pub fn public_key_bytes_compressed(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Get the public key bytes in uncompressed format (65 bytes)
    pub fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Get the private key bytes (32 bytes)
    ///
    /// # Security
    /// Handle with care! Private key material should be zeroized after use.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get algorithm identifier
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }

    /// Get key ID (SHA-256 hash of public key, first 8 bytes in hex)
    ///
    /// # Example
    /// ```
    /// use sage_crypto_core::crypto::p256::P256KeyPair;
    ///
    /// let keypair = P256KeyPair::generate().unwrap();
    /// let key_id = keypair.key_id();
    /// assert_eq!(key_id.len(), 16); // 8 bytes = 16 hex chars
    /// ```
    pub fn key_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.public_key_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8])
    }
}

impl std::fmt::Debug for P256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256KeyPair")
            .field("public_key", &hex::encode(self.public_key_bytes()))
            .field("key_id", &self.key_id())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let keypair = P256KeyPair::generate().unwrap();
        assert_eq!(keypair.public_key_bytes().len(), 65); // uncompressed SEC1
        assert_eq!(keypair.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = P256KeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verification should succeed
        assert!(keypair.verify(message, &signature).is_ok());

        // Verification with wrong message should fail
        assert!(keypair.verify(b"wrong message", &signature).is_err());

        // Verification with corrupted signature should fail
        let mut bad_sig = signature.clone();
        bad_sig[0] ^= 0xFF;
        assert!(keypair.verify(message, &bad_sig).is_err());
    }

    #[test]
    fn test_from_private_key_bytes() {
        let keypair1 = P256KeyPair::generate().unwrap();
        let priv_bytes = keypair1.private_key_bytes();

        let keypair2 = P256KeyPair::from_private_key_bytes(&priv_bytes).unwrap();

        // Same private key should produce same public key
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

        // Same signature for same message
        let message = b"test";
        let sig1 = keypair1.sign(message).unwrap();
        let sig2 = keypair2.sign(message).unwrap();

        assert!(keypair2.verify(message, &sig1).is_ok());
        assert!(keypair1.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_from_public_key_bytes() {
        let keypair = P256KeyPair::generate().unwrap();
        let pub_bytes = keypair.public_key_bytes();

        let verifying_key = P256KeyPair::from_public_key_bytes(&pub_bytes).unwrap();

        let message = b"test";
        let signature = keypair.sign(message).unwrap();

        // Verification should succeed with public key only
        let sig = P256Signature::try_from(signature.as_slice()).unwrap();
        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_invalid_private_key_length() {
        assert!(P256KeyPair::from_private_key_bytes(&[0u8; 16]).is_err());
        assert!(P256KeyPair::from_private_key_bytes(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let keypair = P256KeyPair::generate().unwrap();
        let message = b"test";

        assert!(keypair.verify(message, &[0u8; 32]).is_err());
        assert!(keypair.verify(message, &[0u8; 65]).is_err());
    }

    #[test]
    fn test_key_id() {
        let keypair = P256KeyPair::generate().unwrap();
        let key_id = keypair.key_id();

        assert_eq!(key_id.len(), 16); // 8 bytes = 16 hex chars
        assert!(key_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_public_key_uncompressed() {
        let keypair = P256KeyPair::generate().unwrap();
        let uncompressed = keypair.public_key_bytes_uncompressed();

        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed marker

        // Should be able to load from uncompressed format too
        let verifying_key = P256KeyPair::from_public_key_bytes(&uncompressed).unwrap();

        let message = b"test";
        let signature = keypair.sign(message).unwrap();
        let sig = P256Signature::try_from(signature.as_slice()).unwrap();

        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_deterministic_signatures() {
        // P-256 uses deterministic ECDSA (RFC 6979)
        // Same message with same key should produce same signature
        let keypair = P256KeyPair::generate().unwrap();
        let message = b"deterministic test";

        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair.sign(message).unwrap();

        assert_eq!(sig1, sig2);
    }
}
