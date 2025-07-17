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
}

impl From<KeyType> for Algorithm {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Algorithm::Ed25519,
            KeyType::Secp256k1 => Algorithm::Secp256k1,
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
}

impl PublicKey {
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PublicKey::Ed25519(_) => KeyType::Ed25519,
            PublicKey::Secp256k1(_) => KeyType::Secp256k1,
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
        }
    }

    /// Get the key ID
    pub fn key_id(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.to_bytes());
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
}

impl PrivateKey {
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PrivateKey::Ed25519(_) => KeyType::Ed25519,
            PrivateKey::Secp256k1(_) => KeyType::Secp256k1,
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
        }
    }

    /// Encode private key to bytes (CAUTION: contains secret material)
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(key_bytes) => key_bytes.to_vec(),
            PrivateKey::Secp256k1(key_bytes) => key_bytes.to_vec(),
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
        hasher.update(&public_key.to_bytes());
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

    /// Extract private key (consumes self)
    pub(crate) fn into_private_key(self) -> PrivateKey {
        self.private_key
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        match &self.private_key {
            PrivateKey::Ed25519(bytes) => bytes.to_vec(),
            PrivateKey::Secp256k1(bytes) => bytes.to_vec(),
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
                    Error::CryptoError(format!("Invalid Secp256k1 private key: {}", e))
                })?;
                let public_key = signing_key.verifying_key();
                let point = public_key.to_encoded_point(true); // compressed
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(point.as_bytes());
                PublicKey::Secp256k1(bytes)
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
            _ => Err(Error::InvalidKeyType("Key type mismatch".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_keypair() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Ed25519);
        assert!(!keypair.key_id().is_empty());
    }

    #[test]
    fn test_generate_secp256k1_keypair() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Secp256k1);
        assert!(!keypair.key_id().is_empty());
    }

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
}
