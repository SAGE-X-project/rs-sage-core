//! Signature types and traits

use crate::error::Result;
use base64::{engine::general_purpose, Engine as _};

/// Signature abstraction
#[derive(Debug, Clone)]
pub enum Signature {
    /// Ed25519 signature
    Ed25519(ed25519_dalek::Signature),
    /// Secp256k1 signature
    Secp256k1(k256::ecdsa::Signature),
    /// P-256 signature
    P256(p256::ecdsa::Signature),
    /// RSA signature (PKCS#1 v1.5 or PSS)
    Rsa(Vec<u8>),
}

impl Signature {
    /// Encode signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::Secp256k1(sig) => sig.to_der().as_bytes().to_vec(),
            Signature::P256(sig) => sig.to_der().as_bytes().to_vec(),
            Signature::Rsa(sig) => sig.clone(),
        }
    }

    /// Encode signature to base64
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    /// Get signature type name
    pub fn algorithm(&self) -> &'static str {
        match self {
            Signature::Ed25519(_) => "ed25519",
            Signature::Secp256k1(_) => "secp256k1",
            Signature::P256(_) => "p256",
            Signature::Rsa(_) => "rsa",
        }
    }
}

/// Trait for signing messages
pub trait Signer {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Signature>;
}

/// Trait for verifying signatures
pub trait Verifier {
    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType};

    #[test]
    fn test_ed25519_signature_to_bytes() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_secp256k1_signature_to_bytes() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let bytes = signature.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_p256_signature_to_bytes() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let bytes = signature.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_rsa_signature_to_bytes() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let bytes = signature.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_signature_to_base64() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let base64 = signature.to_base64();
        assert!(!base64.is_empty());

        // Verify it's valid base64
        let decoded = general_purpose::STANDARD.decode(&base64).unwrap();
        assert_eq!(decoded, signature.to_bytes());
    }

    #[test]
    fn test_ed25519_algorithm() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        assert_eq!(signature.algorithm(), "ed25519");
    }

    #[test]
    fn test_secp256k1_algorithm() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        assert_eq!(signature.algorithm(), "secp256k1");
    }

    #[test]
    fn test_p256_algorithm() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        assert_eq!(signature.algorithm(), "p256");
    }

    #[test]
    fn test_rsa_algorithm() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        assert_eq!(signature.algorithm(), "rsa");
    }

    #[test]
    fn test_signature_clone() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let cloned = signature.clone();
        assert_eq!(signature.to_bytes(), cloned.to_bytes());
        assert_eq!(signature.algorithm(), cloned.algorithm());
    }

    #[test]
    fn test_signature_debug() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        let debug_str = format!("{:?}", signature);
        assert!(debug_str.contains("Ed25519"));
    }
}
