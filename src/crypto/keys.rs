//! Key pair management and operations

use crate::crypto::{Algorithm, Signature, Signer, Verifier};
use crate::error::{Error, Result};
use hex;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Key types supported by SAGE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// Ed25519 key type
    Ed25519,
    /// Secp256k1 key type
    Secp256k1,
    /// P-256 (NIST P-256, secp256r1) key type
    P256,
    /// RSA-2048 key type
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// RSA-4096 key type
    #[serde(rename = "rsa-4096")]
    Rsa4096,
}

impl From<KeyType> for Algorithm {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Algorithm::Ed25519,
            KeyType::Secp256k1 => Algorithm::Secp256k1,
            KeyType::P256 => Algorithm::P256,
            KeyType::Rsa2048 => Algorithm::Rsa2048,
            KeyType::Rsa4096 => Algorithm::Rsa4096,
        }
    }
}

/// Public key abstraction
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// Ed25519 public key (32 bytes)
    Ed25519([u8; 32]),
    /// Secp256k1 public key (33 bytes compressed)
    Secp256k1([u8; 33]),
    /// P-256 public key (33 bytes compressed)
    P256([u8; 33]),
    /// RSA public key (variable length DER-encoded)
    Rsa(Vec<u8>, crate::crypto::rsa::RsaKeySize),
}

impl PublicKey {
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PublicKey::Ed25519(_) => KeyType::Ed25519,
            PublicKey::Secp256k1(_) => KeyType::Secp256k1,
            PublicKey::P256(_) => KeyType::P256,
            PublicKey::Rsa(_, size) => match size {
                crate::crypto::rsa::RsaKeySize::Rsa2048 => KeyType::Rsa2048,
                crate::crypto::rsa::RsaKeySize::Rsa4096 => KeyType::Rsa4096,
            },
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.key_type().into()
    }

    /// Encode public key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key_bytes) => key_bytes.to_vec(),
            PublicKey::Secp256k1(key_bytes) => key_bytes.to_vec(),
            PublicKey::P256(key_bytes) => key_bytes.to_vec(),
            PublicKey::Rsa(der_bytes, _) => der_bytes.clone(),
        }
    }

    /// Get the key ID
    pub fn key_id(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8])
    }

    /// Create PublicKey from bytes
    pub fn from_bytes(key_type: KeyType, bytes: &[u8]) -> Result<Self> {
        match key_type {
            KeyType::Ed25519 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidInput(
                        "Ed25519 public key must be 32 bytes".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);
                Ok(PublicKey::Ed25519(key_bytes))
            }
            KeyType::Secp256k1 => {
                if bytes.len() != 33 {
                    return Err(Error::InvalidInput(
                        "Secp256k1 public key must be 33 bytes (compressed)".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 33];
                key_bytes.copy_from_slice(bytes);
                Ok(PublicKey::Secp256k1(key_bytes))
            }
            KeyType::P256 => {
                if bytes.len() != 33 {
                    return Err(Error::InvalidInput(
                        "P-256 public key must be 33 bytes (compressed)".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 33];
                key_bytes.copy_from_slice(bytes);
                Ok(PublicKey::P256(key_bytes))
            }
            KeyType::Rsa2048 => {
                Ok(PublicKey::Rsa(bytes.to_vec(), crate::crypto::rsa::RsaKeySize::Rsa2048))
            }
            KeyType::Rsa4096 => {
                Ok(PublicKey::Rsa(bytes.to_vec(), crate::crypto::rsa::RsaKeySize::Rsa4096))
            }
        }
    }
}

/// Private key abstraction
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// Ed25519 private key (32 bytes)
    Ed25519([u8; 32]),
    /// Secp256k1 private key (32 bytes)
    Secp256k1([u8; 32]),
    /// P-256 private key (32 bytes)
    P256([u8; 32]),
    /// RSA private key (variable length DER-encoded)
    Rsa(Vec<u8>, crate::crypto::rsa::RsaKeySize),
}

impl PrivateKey {
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PrivateKey::Ed25519(_) => KeyType::Ed25519,
            PrivateKey::Secp256k1(_) => KeyType::Secp256k1,
            PrivateKey::P256(_) => KeyType::P256,
            PrivateKey::Rsa(_, size) => match size {
                crate::crypto::rsa::RsaKeySize::Rsa2048 => KeyType::Rsa2048,
                crate::crypto::rsa::RsaKeySize::Rsa4096 => KeyType::Rsa4096,
            },
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(key_bytes) => {
                use ed25519_dalek::SigningKey;
                let signing_key = SigningKey::from_bytes(key_bytes);
                let verifying_key = signing_key.verifying_key();
                PublicKey::Ed25519(verifying_key.to_bytes())
            }
            PrivateKey::Secp256k1(key_bytes) => {
                use k256::ecdsa::SigningKey;
                let signing_key = SigningKey::from_bytes(key_bytes).unwrap();
                let verifying_key = signing_key.verifying_key();
                let compressed_point = verifying_key.to_encoded_point(true);
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(compressed_point.as_bytes());
                PublicKey::Secp256k1(bytes)
            }
            PrivateKey::P256(key_bytes) => {
                use p256::ecdsa::SigningKey;
                let signing_key = SigningKey::from_bytes(key_bytes.into()).unwrap();
                let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
                let compressed_point = verifying_key.to_encoded_point(true);
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(compressed_point.as_bytes());
                PublicKey::P256(bytes)
            }
            PrivateKey::Rsa(der_bytes, size) => {
                use crate::crypto::rsa::RsaKeyPair;
                let keypair = RsaKeyPair::private_key_from_der(der_bytes, *size).unwrap();
                let pub_der = keypair.public_key_to_der().unwrap();
                PublicKey::Rsa(pub_der, *size)
            }
        }
    }

    /// Encode private key to bytes (CAUTION: contains secret material)
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(key_bytes) => key_bytes.to_vec(),
            PrivateKey::Secp256k1(key_bytes) => key_bytes.to_vec(),
            PrivateKey::P256(key_bytes) => key_bytes.to_vec(),
            PrivateKey::Rsa(der_bytes, _) => der_bytes.clone(),
        }
    }
}

/// Key pair containing both private and public keys
#[derive(Debug, Clone)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
    key_id: String,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(key_type: KeyType) -> Result<Self> {
        let (private_key, public_key) = match key_type {
            KeyType::Ed25519 => {
                use ed25519_dalek::SigningKey;
                let mut rng = OsRng;
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                let signing_key = SigningKey::from_bytes(&bytes);
                let verifying_key = signing_key.verifying_key();
                (
                    PrivateKey::Ed25519(signing_key.to_bytes()),
                    PublicKey::Ed25519(verifying_key.to_bytes()),
                )
            }
            KeyType::Secp256k1 => {
                let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
                let verifying_key = signing_key.verifying_key();
                let compressed_point = verifying_key.to_encoded_point(true);
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(compressed_point.as_bytes());
                (
                    PrivateKey::Secp256k1(signing_key.to_bytes().into()),
                    PublicKey::Secp256k1(bytes),
                )
            }
            KeyType::P256 => {
                let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
                let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
                let compressed_point = verifying_key.to_encoded_point(true);
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(compressed_point.as_bytes());
                (
                    PrivateKey::P256(signing_key.to_bytes().into()),
                    PublicKey::P256(bytes),
                )
            }
            KeyType::Rsa2048 => {
                use crate::crypto::rsa::{RsaKeyPair, RsaKeySize};
                let rsa_keypair = RsaKeyPair::generate(RsaKeySize::Rsa2048)?;
                let priv_der = rsa_keypair.private_key_to_der()?;
                let pub_der = rsa_keypair.public_key_to_der()?;
                (
                    PrivateKey::Rsa(priv_der, RsaKeySize::Rsa2048),
                    PublicKey::Rsa(pub_der, RsaKeySize::Rsa2048),
                )
            }
            KeyType::Rsa4096 => {
                use crate::crypto::rsa::{RsaKeyPair, RsaKeySize};
                let rsa_keypair = RsaKeyPair::generate(RsaKeySize::Rsa4096)?;
                let priv_der = rsa_keypair.private_key_to_der()?;
                let pub_der = rsa_keypair.public_key_to_der()?;
                (
                    PrivateKey::Rsa(priv_der, RsaKeySize::Rsa4096),
                    PublicKey::Rsa(pub_der, RsaKeySize::Rsa4096),
                )
            }
        };

        // Generate key ID from public key hash
        let key_id = Self::generate_key_id(&public_key);

        Ok(Self {
            private_key,
            public_key,
            key_id,
        })
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.private_key.key_type()
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Generate key ID from public key
    fn generate_key_id(public_key: &PublicKey) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(public_key.to_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8])
    }

    /// Create KeyPair from parts (used by importers)
    pub(crate) fn from_parts(private_key: PrivateKey, public_key: PublicKey) -> Self {
        let key_id = Self::generate_key_id(&public_key);
        Self {
            private_key,
            public_key,
            key_id,
        }
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        match &self.private_key {
            PrivateKey::Ed25519(bytes) => bytes.to_vec(),
            PrivateKey::Secp256k1(bytes) => bytes.to_vec(),
            PrivateKey::P256(bytes) => bytes.to_vec(),
            PrivateKey::Rsa(der_bytes, _) => der_bytes.clone(),
        }
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    /// Create KeyPair from private key bytes
    pub fn from_private_key_bytes(key_type: KeyType, bytes: &[u8]) -> Result<Self> {
        let private_key = match key_type {
            KeyType::Ed25519 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidInput(
                        "Ed25519 private key must be 32 bytes".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);
                PrivateKey::Ed25519(key_bytes)
            }
            KeyType::Secp256k1 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidInput(
                        "Secp256k1 private key must be 32 bytes".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);
                PrivateKey::Secp256k1(key_bytes)
            }
            KeyType::P256 => {
                if bytes.len() != 32 {
                    return Err(Error::InvalidInput(
                        "P-256 private key must be 32 bytes".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(bytes);
                PrivateKey::P256(key_bytes)
            }
            KeyType::Rsa2048 => {
                // For RSA, bytes should be DER-encoded private key
                PrivateKey::Rsa(bytes.to_vec(), crate::crypto::rsa::RsaKeySize::Rsa2048)
            }
            KeyType::Rsa4096 => {
                // For RSA, bytes should be DER-encoded private key
                PrivateKey::Rsa(bytes.to_vec(), crate::crypto::rsa::RsaKeySize::Rsa4096)
            }
        };

        // Derive public key from private key
        let public_key = match &private_key {
            PrivateKey::Ed25519(key_bytes) => {
                use ed25519_dalek::SigningKey;
                let signing_key = SigningKey::from_bytes(key_bytes);
                let verifying_key = signing_key.verifying_key();
                PublicKey::Ed25519(verifying_key.to_bytes())
            }
            PrivateKey::Secp256k1(key_bytes) => {
                use k256::ecdsa::SigningKey;
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                let signing_key = SigningKey::from_bytes(key_bytes).map_err(|e| {
                    Error::CryptoError(format!("Invalid Secp256k1 private key: {e}"))
                })?;
                let public_key = signing_key.verifying_key();
                let point = public_key.to_encoded_point(true); // compressed
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(point.as_bytes());
                PublicKey::Secp256k1(bytes)
            }
            PrivateKey::P256(key_bytes) => {
                use p256::ecdsa::SigningKey;
                let signing_key = SigningKey::from_bytes(key_bytes.into()).map_err(|e| {
                    Error::CryptoError(format!("Invalid P-256 private key: {e}"))
                })?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
                let compressed_point = verifying_key.to_encoded_point(true);
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(compressed_point.as_bytes());
                PublicKey::P256(bytes)
            }
            PrivateKey::Rsa(der_bytes, size) => {
                use crate::crypto::rsa::RsaKeyPair;
                let rsa_keypair = RsaKeyPair::private_key_from_der(der_bytes, *size)?;
                let pub_der = rsa_keypair.public_key_to_der()?;
                PublicKey::Rsa(pub_der, *size)
            }
        };

        Ok(Self::from_parts(private_key, public_key))
    }
}

impl Signer for KeyPair {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        match &self.private_key {
            PrivateKey::Ed25519(key_bytes) => {
                use ed25519_dalek::{Signer, SigningKey};
                let signing_key = SigningKey::from_bytes(key_bytes);
                let signature = signing_key.sign(message);
                Ok(Signature::Ed25519(signature))
            }
            PrivateKey::Secp256k1(key_bytes) => {
                use k256::ecdsa::{signature::Signer, Signature as EcdsaSignature, SigningKey};
                let signing_key = SigningKey::from_bytes(key_bytes).unwrap();
                let signature: EcdsaSignature = signing_key.sign(message);
                Ok(Signature::Secp256k1(signature))
            }
            PrivateKey::P256(key_bytes) => {
                use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
                let signing_key = SigningKey::from_bytes(key_bytes.into()).unwrap();
                let signature: P256Signature = signing_key.sign(message);
                Ok(Signature::P256(signature))
            }
            PrivateKey::Rsa(der_bytes, size) => {
                use crate::crypto::rsa::{PaddingScheme, RsaKeyPair};
                let rsa_keypair = RsaKeyPair::private_key_from_der(der_bytes, *size)?;
                let sig_bytes = rsa_keypair.sign(message, PaddingScheme::Pkcs1v15)?;
                Ok(Signature::Rsa(sig_bytes))
            }
        }
    }
}

impl Verifier for KeyPair {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.public_key.verify(message, signature)
    }
}

impl Verifier for PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        match (self, signature) {
            (PublicKey::Ed25519(key_bytes), Signature::Ed25519(sig)) => {
                use ed25519_dalek::{Verifier, VerifyingKey};
                let verifying_key = VerifyingKey::from_bytes(key_bytes)
                    .map_err(|_| Error::Verification("Invalid Ed25519 public key".to_string()))?;
                verifying_key.verify(message, sig).map_err(|_| {
                    Error::Verification("Ed25519 signature verification failed".to_string())
                })
            }
            (PublicKey::Secp256k1(key_bytes), Signature::Secp256k1(sig)) => {
                use k256::ecdsa::{signature::Verifier, VerifyingKey};
                use k256::elliptic_curve::sec1::FromEncodedPoint;
                use k256::PublicKey as K256PublicKey;

                let point = k256::EncodedPoint::from_bytes(key_bytes).map_err(|_| {
                    Error::Verification("Invalid Secp256k1 public key encoding".to_string())
                })?;
                let public_key_opt = K256PublicKey::from_encoded_point(&point);
                if public_key_opt.is_none().into() {
                    return Err(Error::Verification(
                        "Invalid Secp256k1 public key".to_string(),
                    ));
                }
                let public_key = public_key_opt.unwrap();
                let verifying_key = VerifyingKey::from(public_key);

                verifying_key.verify(message, sig).map_err(|_| {
                    Error::Verification("Secp256k1 signature verification failed".to_string())
                })
            }
            (PublicKey::P256(key_bytes), Signature::P256(sig)) => {
                use p256::ecdsa::{signature::Verifier, VerifyingKey};

                let verifying_key = VerifyingKey::from_sec1_bytes(key_bytes).map_err(|_| {
                    Error::Verification("Invalid P-256 public key".to_string())
                })?;

                verifying_key.verify(message, sig).map_err(|_| {
                    Error::Verification("P-256 signature verification failed".to_string())
                })
            }
            (PublicKey::Rsa(der_bytes, _size), Signature::Rsa(sig_bytes)) => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                use rsa::pkcs1v15::VerifyingKey;
                use rsa::signature::Verifier as RsaVerifier;
                use rsa::sha2::Sha256;

                let rsa_public_key = rsa::RsaPublicKey::from_pkcs1_der(der_bytes)
                    .map_err(|e| Error::Verification(format!("Invalid RSA public key: {}", e)))?;

                let verifying_key = VerifyingKey::<Sha256>::new(rsa_public_key);
                let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
                    .map_err(|e| Error::Verification(format!("Invalid RSA signature: {}", e)))?;

                verifying_key.verify(message, &sig)
                    .map_err(|_| Error::Verification("RSA signature verification failed".to_string()))
            }
            _ => Err(Error::InvalidKeyType("Key type mismatch".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== KeyType Tests =====

    #[test]
    fn test_key_type_equality() {
        assert_eq!(KeyType::Ed25519, KeyType::Ed25519);
        assert_ne!(KeyType::Ed25519, KeyType::Secp256k1);
    }

    #[test]
    fn test_key_type_to_algorithm() {
        assert_eq!(Algorithm::from(KeyType::Ed25519), Algorithm::Ed25519);
        assert_eq!(Algorithm::from(KeyType::Secp256k1), Algorithm::Secp256k1);
        assert_eq!(Algorithm::from(KeyType::P256), Algorithm::P256);
        assert_eq!(Algorithm::from(KeyType::Rsa2048), Algorithm::Rsa2048);
        assert_eq!(Algorithm::from(KeyType::Rsa4096), Algorithm::Rsa4096);
    }

    #[test]
    fn test_key_type_serde() {
        let json = serde_json::to_string(&KeyType::Ed25519).unwrap();
        assert_eq!(json, "\"ed25519\"");

        let json = serde_json::to_string(&KeyType::Rsa2048).unwrap();
        assert_eq!(json, "\"rsa-2048\"");
    }

    // ===== KeyPair Generation Tests =====

    #[test]
    fn test_generate_ed25519_keypair() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Ed25519);
        assert!(!keypair.key_id().is_empty());
        assert_eq!(keypair.key_id().len(), 16); // 8 bytes hex = 16 chars
    }

    #[test]
    fn test_generate_secp256k1_keypair() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Secp256k1);
        assert!(!keypair.key_id().is_empty());
    }

    #[test]
    fn test_generate_p256_keypair() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        assert_eq!(keypair.key_type(), KeyType::P256);
        assert!(!keypair.key_id().is_empty());
    }

    #[test]
    fn test_generate_rsa2048_keypair() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Rsa2048);
        assert!(!keypair.key_id().is_empty());
    }

    #[test]
    fn test_generate_rsa4096_keypair() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Rsa4096);
        assert!(!keypair.key_id().is_empty());
    }

    // ===== Sign/Verify Tests =====

    #[test]
    fn test_sign_verify_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"Hello, SAGE!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_sign_verify_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let message = b"Hello, SAGE!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_sign_verify_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let message = b"Hello, SAGE!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_sign_verify_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let message = b"Hello, SAGE!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.verify(b"Wrong message", &signature).is_err());
    }

    // ===== PublicKey Tests =====

    #[test]
    fn test_public_key_type() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.public_key().key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_public_key_algorithm() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.public_key().algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn test_public_key_to_bytes_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let bytes = keypair.public_key().to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_public_key_to_bytes_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let bytes = keypair.public_key().to_bytes();
        assert_eq!(bytes.len(), 33);
    }

    #[test]
    fn test_public_key_to_bytes_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let bytes = keypair.public_key().to_bytes();
        assert_eq!(bytes.len(), 33);
    }

    #[test]
    fn test_public_key_key_id() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let key_id = keypair.public_key().key_id();
        assert_eq!(key_id.len(), 16);
        assert_eq!(key_id, keypair.key_id());
    }

    #[test]
    fn test_public_key_from_bytes_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let bytes = keypair.public_key().to_bytes();

        let reconstructed = PublicKey::from_bytes(KeyType::Ed25519, &bytes).unwrap();
        assert_eq!(reconstructed.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_from_bytes_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let bytes = keypair.public_key().to_bytes();

        let reconstructed = PublicKey::from_bytes(KeyType::Secp256k1, &bytes).unwrap();
        assert_eq!(reconstructed.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_from_bytes_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let bytes = keypair.public_key().to_bytes();

        let reconstructed = PublicKey::from_bytes(KeyType::P256, &bytes).unwrap();
        assert_eq!(reconstructed.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length_ed25519() {
        let result = PublicKey::from_bytes(KeyType::Ed25519, &[0u8; 16]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length_secp256k1() {
        let result = PublicKey::from_bytes(KeyType::Secp256k1, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length_p256() {
        let result = PublicKey::from_bytes(KeyType::P256, &[0u8; 32]);
        assert!(result.is_err());
    }

    // ===== PrivateKey Tests =====

    #[test]
    fn test_private_key_type() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.private_key().key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_private_key_public_key() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let derived_pub = keypair.private_key().public_key();
        assert_eq!(derived_pub.to_bytes(), keypair.public_key().to_bytes());
    }

    #[test]
    fn test_private_key_to_bytes_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let bytes = keypair.private_key().to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_private_key_to_bytes_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let bytes = keypair.private_key().to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_private_key_to_bytes_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let bytes = keypair.private_key().to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    // ===== KeyPair from_private_key_bytes Tests =====

    #[test]
    fn test_ed25519_from_private_key_bytes() {
        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let priv_bytes = keypair1.private_key_bytes();

        let keypair2 = KeyPair::from_private_key_bytes(KeyType::Ed25519, &priv_bytes).unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

        let message = b"test";
        let sig1 = keypair1.sign(message).unwrap();
        assert!(keypair2.verify(message, &sig1).is_ok());
    }

    #[test]
    fn test_secp256k1_from_private_key_bytes() {
        let keypair1 = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let priv_bytes = keypair1.private_key_bytes();

        let keypair2 = KeyPair::from_private_key_bytes(KeyType::Secp256k1, &priv_bytes).unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_p256_from_private_key_bytes() {
        let keypair1 = KeyPair::generate(KeyType::P256).unwrap();
        let priv_bytes = keypair1.private_key_bytes();

        let keypair2 = KeyPair::from_private_key_bytes(KeyType::P256, &priv_bytes).unwrap();

        // Same private key should produce same public key
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

        // Should be able to verify signatures from either keypair
        let message = b"test";
        let sig1 = keypair1.sign(message).unwrap();
        assert!(keypair2.verify(message, &sig1).is_ok());
    }

    #[test]
    fn test_rsa2048_from_private_key_bytes() {
        let keypair1 = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let priv_bytes = keypair1.private_key_bytes();

        let keypair2 = KeyPair::from_private_key_bytes(KeyType::Rsa2048, &priv_bytes).unwrap();

        let message = b"test";
        let sig1 = keypair1.sign(message).unwrap();
        assert!(keypair2.verify(message, &sig1).is_ok());
    }

    #[test]
    fn test_from_private_key_bytes_invalid_length_ed25519() {
        let result = KeyPair::from_private_key_bytes(KeyType::Ed25519, &[0u8; 16]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_from_private_key_bytes_invalid_length_secp256k1() {
        let result = KeyPair::from_private_key_bytes(KeyType::Secp256k1, &[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_private_key_bytes_invalid_length_p256() {
        let result = KeyPair::from_private_key_bytes(KeyType::P256, &[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_private_key_bytes_invalid_key_secp256k1() {
        // All zeros is not a valid secp256k1 private key
        let result = KeyPair::from_private_key_bytes(KeyType::Secp256k1, &[0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::CryptoError(_)));
    }

    // ===== KeyPair Accessors Tests =====

    #[test]
    fn test_keypair_key_id() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let key_id = keypair.key_id();
        assert_eq!(key_id.len(), 16);
        assert!(!key_id.is_empty());
    }

    #[test]
    fn test_keypair_public_key() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key();
        assert_eq!(public_key.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_keypair_private_key() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let private_key = keypair.private_key();
        assert_eq!(private_key.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_keypair_public_key_bytes() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let bytes = keypair.public_key_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, keypair.public_key().to_bytes());
    }

    #[test]
    fn test_keypair_private_key_bytes() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let bytes = keypair.private_key_bytes();
        assert_eq!(bytes.len(), 32);
    }

    // ===== Cross-Key Verification Tests =====

    #[test]
    fn test_verify_with_public_key_directly() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        // Verify using the public key directly
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_key_type_mismatch() {
        let ed25519_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let secp256k1_keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();

        let message = b"test";
        let ed25519_sig = ed25519_keypair.sign(message).unwrap();

        // Try to verify Ed25519 signature with Secp256k1 public key
        let result = secp256k1_keypair.public_key().verify(message, &ed25519_sig);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidKeyType(_)));
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap();

        let message = b"test";
        let sig1 = keypair1.sign(message).unwrap();

        // Verify with different Ed25519 key should fail
        let result = keypair2.verify(message, &sig1);
        assert!(result.is_err());
    }

    // ===== Key ID Consistency Tests =====

    #[test]
    fn test_key_id_deterministic() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let key_id1 = keypair.key_id();
        let key_id2 = keypair.public_key().key_id();
        assert_eq!(key_id1, key_id2);
    }

    #[test]
    fn test_key_id_unique() {
        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_ne!(keypair1.key_id(), keypair2.key_id());
    }

    // ===== Multiple Key Type Tests =====

    #[test]
    fn test_all_key_types_generation() {
        let key_types = vec![
            KeyType::Ed25519,
            KeyType::Secp256k1,
            KeyType::P256,
            KeyType::Rsa2048,
        ];

        for key_type in key_types {
            let keypair = KeyPair::generate(key_type).unwrap();
            assert_eq!(keypair.key_type(), key_type);

            let message = b"test";
            let signature = keypair.sign(message).unwrap();
            assert!(keypair.verify(message, &signature).is_ok());
        }
    }

    #[test]
    fn test_rsa_key_size_preservation() {
        let keypair2048 = KeyPair::generate(KeyType::Rsa2048).unwrap();
        assert_eq!(keypair2048.key_type(), KeyType::Rsa2048);

        let keypair4096 = KeyPair::generate(KeyType::Rsa4096).unwrap();
        assert_eq!(keypair4096.key_type(), KeyType::Rsa4096);
    }

    // ===== Additional RSA Tests =====

    #[test]
    fn test_public_key_from_bytes_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let bytes = keypair.public_key().to_bytes();

        let reconstructed = PublicKey::from_bytes(KeyType::Rsa2048, &bytes).unwrap();
        assert_eq!(reconstructed.key_type(), KeyType::Rsa2048);
    }

    #[test]
    fn test_public_key_from_bytes_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        let bytes = keypair.public_key().to_bytes();

        let reconstructed = PublicKey::from_bytes(KeyType::Rsa4096, &bytes).unwrap();
        assert_eq!(reconstructed.key_type(), KeyType::Rsa4096);
    }

    #[test]
    fn test_private_key_to_bytes_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let bytes = keypair.private_key().to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_private_key_to_bytes_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        let bytes = keypair.private_key().to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_rsa4096_from_private_key_bytes() {
        let keypair1 = KeyPair::generate(KeyType::Rsa4096).unwrap();
        let priv_bytes = keypair1.private_key_bytes();

        let keypair2 = KeyPair::from_private_key_bytes(KeyType::Rsa4096, &priv_bytes).unwrap();

        let message = b"test";
        let sig1 = keypair1.sign(message).unwrap();
        assert!(keypair2.verify(message, &sig1).is_ok());
    }

    #[test]
    fn test_private_key_public_key_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let derived_pub = keypair.private_key().public_key();
        assert_eq!(derived_pub.to_bytes(), keypair.public_key().to_bytes());
        assert_eq!(derived_pub.key_type(), KeyType::Secp256k1);
    }

    #[test]
    fn test_private_key_public_key_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let derived_pub = keypair.private_key().public_key();
        assert_eq!(derived_pub.to_bytes(), keypair.public_key().to_bytes());
        assert_eq!(derived_pub.key_type(), KeyType::P256);
    }

    #[test]
    fn test_private_key_public_key_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let derived_pub = keypair.private_key().public_key();
        assert_eq!(derived_pub.key_type(), KeyType::Rsa2048);
    }

    #[test]
    fn test_private_key_public_key_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        let derived_pub = keypair.private_key().public_key();
        assert_eq!(derived_pub.key_type(), KeyType::Rsa4096);
    }

    #[test]
    fn test_sign_verify_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        let message = b"Hello, SAGE!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.verify(b"Wrong message", &signature).is_err());
    }

    // ===== Invalid Key Tests =====

    #[test]
    fn test_from_private_key_bytes_invalid_key_p256() {
        // All zeros is not a valid P-256 private key
        let result = KeyPair::from_private_key_bytes(KeyType::P256, &[0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::CryptoError(_)));
    }

    // ===== KeyType Additional Tests =====

    #[test]
    fn test_key_type_clone() {
        let kt = KeyType::Ed25519;
        let cloned = kt.clone();
        assert_eq!(kt, cloned);
    }

    #[test]
    fn test_key_type_copy() {
        let kt = KeyType::P256;
        let copied = kt;
        assert_eq!(kt, copied);
    }

    #[test]
    fn test_key_type_debug() {
        let kt = KeyType::Secp256k1;
        let debug_str = format!("{:?}", kt);
        assert!(debug_str.contains("Secp256k1"));
    }

    #[test]
    fn test_key_type_serde_rsa4096() {
        let json = serde_json::to_string(&KeyType::Rsa4096).unwrap();
        assert_eq!(json, "\"rsa-4096\"");

        let deserialized: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, KeyType::Rsa4096);
    }

    // ===== KeyPair::from_parts Tests =====

    #[test]
    fn test_keypair_from_parts() {
        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let priv_key = keypair1.private_key().clone();
        let pub_key = keypair1.public_key().clone();

        let keypair2 = KeyPair::from_parts(priv_key, pub_key);

        assert_eq!(keypair1.key_id(), keypair2.key_id());
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    // ===== Verification Error Path Tests =====

    #[test]
    fn test_verify_with_invalid_ed25519_public_key() {
        // Create an invalid public key by using invalid bytes
        let invalid_bytes = [255u8; 32];
        let message = b"test";

        // Generate a valid signature
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signature = keypair.sign(message).unwrap();

        // Create public key with potentially invalid bytes (may still work as Ed25519 is forgiving)
        let pub_key = PublicKey::Ed25519(invalid_bytes);

        // Verification should fail or succeed based on whether the bytes are actually valid
        let result = pub_key.verify(message, &signature);
        // We just check it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_verify_secp256k1_with_public_key_directly() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        // Verify using the public key directly
        assert!(keypair.public_key().verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.public_key().verify(b"wrong", &signature).is_err());
    }

    #[test]
    fn test_verify_p256_with_public_key_directly() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        // Verify using the public key directly
        assert!(keypair.public_key().verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.public_key().verify(b"wrong", &signature).is_err());
    }

    #[test]
    fn test_verify_rsa_with_public_key_directly() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        // Verify using the public key directly
        assert!(keypair.public_key().verify(message, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.public_key().verify(b"wrong", &signature).is_err());
    }

    #[test]
    fn test_public_key_algorithm_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        assert_eq!(keypair.public_key().algorithm(), Algorithm::P256);
    }

    #[test]
    fn test_public_key_algorithm_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        assert_eq!(keypair.public_key().algorithm(), Algorithm::Secp256k1);
    }

    #[test]
    fn test_public_key_algorithm_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        assert_eq!(keypair.public_key().algorithm(), Algorithm::Rsa2048);
    }

    #[test]
    fn test_public_key_algorithm_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        assert_eq!(keypair.public_key().algorithm(), Algorithm::Rsa4096);
    }

    #[test]
    fn test_keypair_key_type_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Secp256k1);
    }

    #[test]
    fn test_keypair_key_type_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        assert_eq!(keypair.key_type(), KeyType::P256);
    }

    #[test]
    fn test_keypair_key_type_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Rsa2048);
    }

    #[test]
    fn test_keypair_key_type_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Rsa4096);
    }
}
