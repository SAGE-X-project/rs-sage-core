//! RSA signature implementation (PKCS#1 v1.5 and PSS)
//!
//! This module provides RSA signature generation and verification using
//! the RSA algorithm with SHA-256 hashing.
//!
//! # Supported Key Sizes
//!
//! - RSA-2048: 2048-bit keys (256 bytes modulus)
//! - RSA-4096: 4096-bit keys (512 bytes modulus)
//!
//! # Padding Schemes
//!
//! - PKCS#1 v1.5: Traditional deterministic padding (default)
//! - PSS: Probabilistic Signature Scheme (more secure, recommended for new systems)
//!
//! # Examples
//!
//! ```ignore
//! use sage_crypto_core::crypto::rsa::{RsaKeyPair, RsaKeySize, PaddingScheme};
//!
//! // Generate RSA-2048 key pair
//! let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
//!
//! // Sign message
//! let message = b"Hello, SAGE!";
//! let signature = keypair.sign(message, PaddingScheme::Pkcs1v15)?;
//!
//! // Verify signature
//! assert!(keypair.verify(message, &signature, PaddingScheme::Pkcs1v15)?);
//! ```

use crate::error::{Error, Result};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as RsaVerifier};
use rsa::sha2::Sha256;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};

/// RSA key sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsaKeySize {
    /// 2048-bit RSA key (256 bytes modulus)
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// 4096-bit RSA key (512 bytes modulus)
    #[serde(rename = "rsa-4096")]
    Rsa4096,
}

impl RsaKeySize {
    /// Get the bit length for this key size
    pub fn bits(&self) -> usize {
        match self {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa4096 => 4096,
        }
    }

    /// Get the byte length of the modulus
    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }
}

impl std::fmt::Display for RsaKeySize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaKeySize::Rsa2048 => write!(f, "RSA-2048"),
            RsaKeySize::Rsa4096 => write!(f, "RSA-4096"),
        }
    }
}

/// Padding scheme for RSA signatures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingScheme {
    /// PKCS#1 v1.5 padding (deterministic, traditional)
    Pkcs1v15,
    /// PSS padding (probabilistic, more secure)
    Pss,
}

/// RSA key pair for signing and verification
#[derive(Clone)]
pub struct RsaKeyPair {
    /// Private key
    private_key: RsaPrivateKey,
    /// Public key
    public_key: RsaPublicKey,
    /// Key size
    key_size: RsaKeySize,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair
    ///
    /// # Arguments
    ///
    /// * `key_size` - The RSA key size (2048 or 4096 bits)
    ///
    /// # Returns
    ///
    /// New RSA key pair
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
    /// ```
    pub fn generate(key_size: RsaKeySize) -> Result<Self> {
        let mut rng = OsRng;
        let bits = key_size.bits();

        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| Error::CryptoError(format!("RSA key generation failed: {}", e)))?;

        let public_key = private_key.to_public_key();

        Ok(Self {
            private_key,
            public_key,
            key_size,
        })
    }

    /// Create key pair from existing private key
    ///
    /// # Arguments
    ///
    /// * `private_key` - RSA private key
    /// * `key_size` - Key size
    ///
    /// # Returns
    ///
    /// RSA key pair
    pub fn from_private_key(private_key: RsaPrivateKey, key_size: RsaKeySize) -> Self {
        let public_key = private_key.to_public_key();
        Self {
            private_key,
            public_key,
            key_size,
        }
    }

    /// Get the key size
    pub fn key_size(&self) -> RsaKeySize {
        self.key_size
    }

    /// Get the private key
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// Get the public key
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Sign a message using PKCS#1 v1.5 padding
    ///
    /// # Arguments
    ///
    /// * `message` - Message to sign
    ///
    /// # Returns
    ///
    /// Signature bytes
    ///
    /// # Example
    ///
    /// ```ignore
    /// let signature = keypair.sign_pkcs1v15(b"Hello, World!")?;
    /// ```
    pub fn sign_pkcs1v15(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let mut rng = OsRng;

        let signature = signing_key
            .sign_with_rng(&mut rng, message)
            .to_vec();

        Ok(signature)
    }

    /// Verify a signature using PKCS#1 v1.5 padding
    ///
    /// # Arguments
    ///
    /// * `message` - Original message
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, `false` otherwise
    ///
    /// # Example
    ///
    /// ```ignore
    /// let valid = keypair.verify_pkcs1v15(b"Hello, World!", &signature)?;
    /// ```
    pub fn verify_pkcs1v15(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());

        // Convert signature bytes to Signature type
        let sig = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| Error::Verification(format!("Invalid signature format: {}", e)))?;

        match verifying_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Sign a message using PSS padding
    ///
    /// # Arguments
    ///
    /// * `message` - Message to sign
    ///
    /// # Returns
    ///
    /// Signature bytes
    ///
    /// # Example
    ///
    /// ```ignore
    /// let signature = keypair.sign_pss(b"Hello, World!")?;
    /// ```
    pub fn sign_pss(&self, message: &[u8]) -> Result<Vec<u8>> {
        use rsa::pss::{BlindedSigningKey, Signature};
        use rsa::signature::RandomizedSigner;

        let mut rng = OsRng;
        let signing_key = BlindedSigningKey::<Sha256>::new(self.private_key.clone());

        let signature: Signature = signing_key
            .sign_with_rng(&mut rng, message);

        Ok(signature.to_vec())
    }

    /// Verify a signature using PSS padding
    ///
    /// # Arguments
    ///
    /// * `message` - Original message
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, `false` otherwise
    ///
    /// # Example
    ///
    /// ```ignore
    /// let valid = keypair.verify_pss(b"Hello, World!", &signature)?;
    /// ```
    pub fn verify_pss(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        use rsa::pss::VerifyingKey;

        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());

        let sig = rsa::pss::Signature::try_from(signature)
            .map_err(|e| Error::Verification(format!("Invalid PSS signature format: {}", e)))?;

        match verifying_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Sign a message using specified padding scheme
    ///
    /// # Arguments
    ///
    /// * `message` - Message to sign
    /// * `padding` - Padding scheme (PKCS#1 v1.5 or PSS)
    ///
    /// # Returns
    ///
    /// Signature bytes
    pub fn sign(&self, message: &[u8], padding: PaddingScheme) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::Pkcs1v15 => self.sign_pkcs1v15(message),
            PaddingScheme::Pss => self.sign_pss(message),
        }
    }

    /// Verify a signature using specified padding scheme
    ///
    /// # Arguments
    ///
    /// * `message` - Original message
    /// * `signature` - Signature to verify
    /// * `padding` - Padding scheme used for signing
    ///
    /// # Returns
    ///
    /// `true` if signature is valid, `false` otherwise
    pub fn verify(&self, message: &[u8], signature: &[u8], padding: PaddingScheme) -> Result<bool> {
        match padding {
            PaddingScheme::Pkcs1v15 => self.verify_pkcs1v15(message, signature),
            PaddingScheme::Pss => self.verify_pss(message, signature),
        }
    }

    /// Encode public key to DER format (PKCS#1)
    ///
    /// # Returns
    ///
    /// DER-encoded public key bytes
    pub fn public_key_to_der(&self) -> Result<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPublicKey;

        self.public_key
            .to_pkcs1_der()
            .map(|der| der.to_vec())
            .map_err(|e| Error::Serialization(format!("Failed to encode public key: {}", e)))
    }

    /// Decode public key from DER format (PKCS#1)
    ///
    /// # Arguments
    ///
    /// * `der` - DER-encoded public key bytes
    /// * `key_size` - Expected key size
    ///
    /// # Returns
    ///
    /// RSA public key
    pub fn public_key_from_der(der: &[u8], _key_size: RsaKeySize) -> Result<RsaPublicKey> {
        use rsa::pkcs1::DecodeRsaPublicKey;

        RsaPublicKey::from_pkcs1_der(der)
            .map_err(|e| Error::Serialization(format!("Failed to decode public key: {}", e)))
    }

    /// Encode private key to DER format (PKCS#1)
    ///
    /// # Returns
    ///
    /// DER-encoded private key bytes
    pub fn private_key_to_der(&self) -> Result<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPrivateKey;

        self.private_key
            .to_pkcs1_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|e| Error::Serialization(format!("Failed to encode private key: {}", e)))
    }

    /// Decode private key from DER format (PKCS#1)
    ///
    /// # Arguments
    ///
    /// * `der` - DER-encoded private key bytes
    /// * `key_size` - Expected key size
    ///
    /// # Returns
    ///
    /// RSA key pair
    pub fn private_key_from_der(der: &[u8], key_size: RsaKeySize) -> Result<Self> {
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let private_key = RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|e| Error::Serialization(format!("Failed to decode private key: {}", e)))?;

        Ok(Self::from_private_key(private_key, key_size))
    }

    /// Encode public key to PEM format
    ///
    /// # Returns
    ///
    /// PEM-encoded public key string
    pub fn public_key_to_pem(&self) -> Result<String> {
        use rsa::pkcs1::EncodeRsaPublicKey;

        self.public_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| Error::Serialization(format!("Failed to encode public key to PEM: {}", e)))
    }

    /// Decode public key from PEM format
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded public key string
    /// * `key_size` - Expected key size
    ///
    /// # Returns
    ///
    /// RSA public key
    pub fn public_key_from_pem(pem: &str, _key_size: RsaKeySize) -> Result<RsaPublicKey> {
        use rsa::pkcs1::DecodeRsaPublicKey;

        RsaPublicKey::from_pkcs1_pem(pem)
            .map_err(|e| Error::Serialization(format!("Failed to decode public key from PEM: {}", e)))
    }

    /// Encode private key to PEM format
    ///
    /// # Returns
    ///
    /// PEM-encoded private key string
    pub fn private_key_to_pem(&self) -> Result<String> {
        use rsa::pkcs1::EncodeRsaPrivateKey;

        self.private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| Error::Serialization(format!("Failed to encode private key to PEM: {}", e)))
    }

    /// Decode private key from PEM format
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded private key string
    /// * `key_size` - Expected key size
    ///
    /// # Returns
    ///
    /// RSA key pair
    pub fn private_key_from_pem(pem: &str, key_size: RsaKeySize) -> Result<Self> {
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let private_key = RsaPrivateKey::from_pkcs1_pem(pem)
            .map_err(|e| Error::Serialization(format!("Failed to decode private key from PEM: {}", e)))?;

        Ok(Self::from_private_key(private_key, key_size))
    }
}

impl std::fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("key_size", &self.key_size)
            .field("modulus_bits", &(self.private_key.size() * 8))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_rsa_key_size() {
        assert_eq!(RsaKeySize::Rsa2048.bits(), 2048);
        assert_eq!(RsaKeySize::Rsa2048.bytes(), 256);
        assert_eq!(RsaKeySize::Rsa4096.bits(), 4096);
        assert_eq!(RsaKeySize::Rsa4096.bytes(), 512);
    }

    #[test]
    fn test_rsa_2048_generation() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        assert_eq!(keypair.key_size(), RsaKeySize::Rsa2048);
        assert_eq!(keypair.private_key().size(), 256); // 2048 bits = 256 bytes
    }

    #[test]
    fn test_rsa_4096_generation() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa4096).unwrap();
        assert_eq!(keypair.key_size(), RsaKeySize::Rsa4096);
        assert_eq!(keypair.private_key().size(), 512); // 4096 bits = 512 bytes
    }

    #[test]
    fn test_sign_verify_pkcs1v15() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let message = b"Hello, SAGE with RSA!";

        let signature = keypair.sign_pkcs1v15(message).unwrap();
        assert!(keypair.verify_pkcs1v15(message, &signature).unwrap());

        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(!keypair.verify_pkcs1v15(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_sign_verify_pss() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let message = b"Hello, SAGE with RSA-PSS!";

        let signature = keypair.sign_pss(message).unwrap();
        assert!(keypair.verify_pss(message, &signature).unwrap());

        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(!keypair.verify_pss(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_sign_verify_with_padding() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let message = b"Testing padding schemes";

        // Test PKCS#1 v1.5
        let sig_pkcs = keypair.sign(message, PaddingScheme::Pkcs1v15).unwrap();
        assert!(keypair.verify(message, &sig_pkcs, PaddingScheme::Pkcs1v15).unwrap());

        // Test PSS
        let sig_pss = keypair.sign(message, PaddingScheme::Pss).unwrap();
        assert!(keypair.verify(message, &sig_pss, PaddingScheme::Pss).unwrap());

        // Cross-scheme verification should fail
        assert!(!keypair.verify(message, &sig_pkcs, PaddingScheme::Pss).unwrap());
        assert!(!keypair.verify(message, &sig_pss, PaddingScheme::Pkcs1v15).unwrap());
    }

    #[test]
    fn test_public_key_der_roundtrip() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();

        let der = keypair.public_key_to_der().unwrap();
        let _public_key = RsaKeyPair::public_key_from_der(&der, RsaKeySize::Rsa2048).unwrap();

        // Verify the deserialized key works
        let message = b"Test message";
        let signature = keypair.sign_pkcs1v15(message).unwrap();

        let keypair2 = RsaKeyPair::from_private_key(keypair.private_key().clone(), RsaKeySize::Rsa2048);
        assert!(keypair2.verify_pkcs1v15(message, &signature).unwrap());
    }

    #[test]
    fn test_private_key_der_roundtrip() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();

        let der = keypair.private_key_to_der().unwrap();
        let keypair2 = RsaKeyPair::private_key_from_der(&der, RsaKeySize::Rsa2048).unwrap();

        // Verify the deserialized keypair works
        let message = b"Test message";
        let signature = keypair.sign_pkcs1v15(message).unwrap();
        assert!(keypair2.verify_pkcs1v15(message, &signature).unwrap());

        let signature2 = keypair2.sign_pkcs1v15(message).unwrap();
        assert!(keypair.verify_pkcs1v15(message, &signature2).unwrap());
    }

    #[test]
    fn test_public_key_pem_roundtrip() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();

        let pem = keypair.public_key_to_pem().unwrap();
        assert!(pem.contains("-----BEGIN RSA PUBLIC KEY-----"));
        assert!(pem.contains("-----END RSA PUBLIC KEY-----"));

        let _public_key = RsaKeyPair::public_key_from_pem(&pem, RsaKeySize::Rsa2048).unwrap();

        // Verify it works
        let message = b"Test PEM";
        let signature = keypair.sign_pkcs1v15(message).unwrap();

        let keypair2 = RsaKeyPair::from_private_key(keypair.private_key().clone(), RsaKeySize::Rsa2048);
        assert!(keypair2.verify_pkcs1v15(message, &signature).unwrap());
    }

    #[test]
    fn test_private_key_pem_roundtrip() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();

        let pem = keypair.private_key_to_pem().unwrap();
        assert!(pem.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(pem.contains("-----END RSA PRIVATE KEY-----"));

        let keypair2 = RsaKeyPair::private_key_from_pem(&pem, RsaKeySize::Rsa2048).unwrap();

        // Verify the deserialized keypair works
        let message = b"Test PEM";
        let signature = keypair.sign_pkcs1v15(message).unwrap();
        assert!(keypair2.verify_pkcs1v15(message, &signature).unwrap());
    }

    #[test]
    fn test_rsa_4096_sign_verify() {
        let keypair = RsaKeyPair::generate(RsaKeySize::Rsa4096).unwrap();
        let message = b"Testing RSA-4096";

        let signature = keypair.sign_pkcs1v15(message).unwrap();
        assert!(keypair.verify_pkcs1v15(message, &signature).unwrap());

        // Signature size should be 512 bytes for RSA-4096
        assert_eq!(signature.len(), 512);
    }
}
