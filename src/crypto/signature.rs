//! Signature types and traits
//!
//! Wire encodings (sage-spec `01-crypto.md`): Ed25519 64-byte `R || S`,
//! secp256k1 65-byte `r || s || v` (Keccak-256 digest, low-S), P-256 64-byte
//! `r || s` (SHA-256 digest, low-S). Parsing also accepts 64-byte secp256k1
//! and ASN.1 DER for both ECDSA curves.

use crate::crypto::KeyType;
use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};

/// Signature abstraction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Ed25519 signature
    Ed25519(ed25519_dalek::Signature),
    /// Secp256k1 signature: `r || s || v`
    Secp256k1([u8; 65]),
    /// P-256 signature: `r || s`
    P256([u8; 64]),
}

impl Signature {
    /// Encode signature to its wire bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::Secp256k1(sig) => sig.to_vec(),
            Signature::P256(sig) => sig.to_vec(),
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
        }
    }

    /// The `r || s` part of an ECDSA signature (64 bytes); the whole
    /// signature for Ed25519.
    pub fn rs_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Secp256k1(sig) => sig[..64].to_vec(),
            other => other.to_bytes(),
        }
    }

    /// Parse a signature for the given key type: Ed25519 64 bytes; secp256k1
    /// 64 or 65 bytes or DER (a missing recovery id is stored as 0); P-256
    /// 64 bytes or DER.
    pub fn from_bytes(key_type: KeyType, bytes: &[u8]) -> Result<Self> {
        match key_type {
            KeyType::Ed25519 => {
                let arr: [u8; 64] = bytes.try_into().map_err(|_| {
                    Error::InvalidInput("Ed25519 signature must be 64 bytes".into())
                })?;
                Ok(Signature::Ed25519(ed25519_dalek::Signature::from_bytes(
                    &arr,
                )))
            }
            KeyType::Secp256k1 => {
                let mut out = [0u8; 65];
                match bytes.len() {
                    65 => out.copy_from_slice(bytes),
                    64 => out[..64].copy_from_slice(bytes),
                    _ => {
                        let sig = k256::ecdsa::Signature::from_der(bytes).map_err(|_| {
                            Error::InvalidInput(
                                "Secp256k1 signature must be 64 or 65 bytes or DER".into(),
                            )
                        })?;
                        out[..64].copy_from_slice(&sig.to_bytes());
                    }
                }
                k256::ecdsa::Signature::from_slice(&out[..64])
                    .map_err(|_| Error::InvalidInput("Invalid Secp256k1 signature".into()))?;
                if out[64] > 3 {
                    return Err(Error::InvalidInput("Invalid recovery id".into()));
                }
                Ok(Signature::Secp256k1(out))
            }
            KeyType::P256 => {
                let mut out = [0u8; 64];
                if bytes.len() == 64 {
                    out.copy_from_slice(bytes);
                } else {
                    let sig = p256::ecdsa::Signature::from_der(bytes).map_err(|_| {
                        Error::InvalidInput("P-256 signature must be 64 bytes or DER".into())
                    })?;
                    out.copy_from_slice(&sig.to_bytes());
                }
                p256::ecdsa::Signature::from_slice(&out)
                    .map_err(|_| Error::InvalidInput("Invalid P-256 signature".into()))?;
                Ok(Signature::P256(out))
            }
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

        let debug_str = format!("{signature:?}");
        assert!(debug_str.contains("Ed25519"));
    }
}
