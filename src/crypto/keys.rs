//! Key pair management and operations
//!
//! Encodings follow sage-spec `01-crypto.md`: Ed25519 keys are 32 bytes,
//! secp256k1 and P-256 public keys are 65-byte uncompressed SEC1 points
//! (33-byte compressed points are accepted on input), secp256k1 signatures
//! are 65-byte `r || s || v` over Keccak-256 with low-S, and P-256
//! signatures are 64-byte `r || s` over SHA-256 with low-S.

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
}

impl From<KeyType> for Algorithm {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Algorithm::Ed25519,
            KeyType::Secp256k1 => Algorithm::Secp256k1,
            KeyType::P256 => Algorithm::P256,
        }
    }
}

/// Keccak-256 digest (Ethereum convention for secp256k1 signatures).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Public key abstraction
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// Ed25519 public key (32 bytes)
    Ed25519([u8; 32]),
    /// Secp256k1 public key (65 bytes, uncompressed SEC1: `04 || X || Y`)
    Secp256k1([u8; 65]),
    /// P-256 public key (65 bytes, uncompressed SEC1: `04 || X || Y`)
    P256([u8; 65]),
}

impl PublicKey {
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PublicKey::Ed25519(_) => KeyType::Ed25519,
            PublicKey::Secp256k1(_) => KeyType::Secp256k1,
            PublicKey::P256(_) => KeyType::P256,
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.key_type().into()
    }

    /// Encode public key to bytes (32 bytes for Ed25519, 65 bytes uncompressed
    /// for the ECDSA curves).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key_bytes) => key_bytes.to_vec(),
            PublicKey::Secp256k1(key_bytes) => key_bytes.to_vec(),
            PublicKey::P256(key_bytes) => key_bytes.to_vec(),
        }
    }

    /// Compressed SEC1 encoding (33 bytes) for the ECDSA curves; the raw key
    /// for Ed25519.
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key_bytes) => key_bytes.to_vec(),
            PublicKey::Secp256k1(key_bytes) => k256::PublicKey::from_sec1_bytes(key_bytes)
                .map(|k| k.to_encoded_point(true).as_bytes().to_vec())
                .unwrap_or_default(),
            PublicKey::P256(key_bytes) => p256::PublicKey::from_sec1_bytes(key_bytes)
                .map(|k| k.to_encoded_point(true).as_bytes().to_vec())
                .unwrap_or_default(),
        }
    }

    /// Key identifier: `hex(SHA-256(to_bytes())[0:8])` (sage-spec 01 §4).
    pub fn key_id(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8])
    }

    /// Ethereum address of a secp256k1 key: `0x` + lower-case hex of
    /// `Keccak-256(X || Y)[12..32]` (the Go core's `keys.EthereumAddress`;
    /// `did:sage:ethereum` identifiers use this form).
    pub fn ethereum_address(&self) -> Result<String> {
        let bytes = match self {
            PublicKey::Secp256k1(b) => b,
            _ => {
                return Err(Error::InvalidKeyType(
                    "Ethereum address requires a secp256k1 key".to_string(),
                ))
            }
        };
        let hash = keccak256(&bytes[1..]);
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    /// Create PublicKey from bytes. ECDSA keys are accepted as 33-byte
    /// compressed or 65-byte uncompressed SEC1 points and stored uncompressed.
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
                if bytes.len() != 33 && bytes.len() != 65 {
                    return Err(Error::InvalidInput(
                        "Secp256k1 public key must be 33 (compressed) or 65 (uncompressed) bytes"
                            .to_string(),
                    ));
                }
                let key = k256::PublicKey::from_sec1_bytes(bytes)
                    .map_err(|_| Error::InvalidInput("Invalid Secp256k1 public key".to_string()))?;
                Ok(PublicKey::Secp256k1(uncompressed_65(
                    key.to_encoded_point(false).as_bytes(),
                )))
            }
            KeyType::P256 => {
                if bytes.len() != 33 && bytes.len() != 65 {
                    return Err(Error::InvalidInput(
                        "P-256 public key must be 33 (compressed) or 65 (uncompressed) bytes"
                            .to_string(),
                    ));
                }
                let key = p256::PublicKey::from_sec1_bytes(bytes)
                    .map_err(|_| Error::InvalidInput("Invalid P-256 public key".to_string()))?;
                Ok(PublicKey::P256(uncompressed_65(
                    key.to_encoded_point(false).as_bytes(),
                )))
            }
        }
    }
}

fn uncompressed_65(bytes: &[u8]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    out
}

/// Private key abstraction
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// Ed25519 seed (32 bytes)
    Ed25519([u8; 32]),
    /// Secp256k1 scalar (32 bytes)
    Secp256k1([u8; 32]),
    /// P-256 scalar (32 bytes)
    P256([u8; 32]),
}

impl PrivateKey {
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PrivateKey::Ed25519(_) => KeyType::Ed25519,
            PrivateKey::Secp256k1(_) => KeyType::Secp256k1,
            PrivateKey::P256(_) => KeyType::P256,
        }
    }

    /// Derive the public key
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(key_bytes) => {
                use ed25519_dalek::SigningKey;
                let signing_key = SigningKey::from_bytes(key_bytes);
                PublicKey::Ed25519(signing_key.verifying_key().to_bytes())
            }
            PrivateKey::Secp256k1(key_bytes) => {
                let signing_key = k256::ecdsa::SigningKey::from_slice(key_bytes)
                    .expect("validated on construction");
                PublicKey::Secp256k1(uncompressed_65(
                    signing_key
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes(),
                ))
            }
            PrivateKey::P256(key_bytes) => {
                let signing_key = p256::ecdsa::SigningKey::from_slice(key_bytes)
                    .expect("validated on construction");
                PublicKey::P256(uncompressed_65(
                    signing_key
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes(),
                ))
            }
        }
    }

    /// Encode private key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(key_bytes) => key_bytes.to_vec(),
            PrivateKey::Secp256k1(key_bytes) => key_bytes.to_vec(),
            PrivateKey::P256(key_bytes) => key_bytes.to_vec(),
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
        let private_key = match key_type {
            KeyType::Ed25519 => {
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                PrivateKey::Ed25519(bytes)
            }
            KeyType::Secp256k1 => {
                let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
                PrivateKey::Secp256k1(signing_key.to_bytes().into())
            }
            KeyType::P256 => {
                let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
                PrivateKey::P256(signing_key.to_bytes().into())
            }
        };
        let public_key = private_key.public_key();
        Ok(Self::from_parts(private_key, public_key))
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

    fn generate_key_id(public_key: &PublicKey) -> String {
        public_key.key_id()
    }

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
        self.private_key.to_bytes()
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    /// Create key pair from private key bytes (32 bytes for every key type)
    pub fn from_private_key_bytes(key_type: KeyType, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidInput(format!(
                "{key_type:?} private key must be 32 bytes"
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        let private_key = match key_type {
            KeyType::Ed25519 => PrivateKey::Ed25519(key_bytes),
            KeyType::Secp256k1 => {
                k256::ecdsa::SigningKey::from_slice(&key_bytes).map_err(|e| {
                    Error::CryptoError(format!("Invalid Secp256k1 private key: {e}"))
                })?;
                PrivateKey::Secp256k1(key_bytes)
            }
            KeyType::P256 => {
                p256::ecdsa::SigningKey::from_slice(&key_bytes)
                    .map_err(|e| Error::CryptoError(format!("Invalid P-256 private key: {e}")))?;
                PrivateKey::P256(key_bytes)
            }
        };
        let public_key = private_key.public_key();
        Ok(Self::from_parts(private_key, public_key))
    }
}

impl Signer for KeyPair {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        match &self.private_key {
            PrivateKey::Ed25519(key_bytes) => {
                use ed25519_dalek::{Signer, SigningKey};
                let signing_key = SigningKey::from_bytes(key_bytes);
                Ok(Signature::Ed25519(signing_key.sign(message)))
            }
            PrivateKey::Secp256k1(key_bytes) => {
                let signing_key = k256::ecdsa::SigningKey::from_slice(key_bytes)
                    .map_err(|e| Error::CryptoError(format!("Invalid Secp256k1 key: {e}")))?;
                let digest = keccak256(message);
                let (sig, recid) = signing_key
                    .sign_prehash_recoverable(&digest)
                    .map_err(|e| Error::CryptoError(format!("Secp256k1 signing failed: {e}")))?;
                // k256 emits low-S; normalise defensively and keep v consistent.
                let (sig, recid) = match sig.normalize_s() {
                    Some(low) => (
                        low,
                        k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1).unwrap(),
                    ),
                    None => (sig, recid),
                };
                let mut out = [0u8; 65];
                out[..64].copy_from_slice(&sig.to_bytes());
                out[64] = recid.to_byte();
                Ok(Signature::Secp256k1(out))
            }
            PrivateKey::P256(key_bytes) => {
                use p256::ecdsa::signature::Signer;
                let signing_key = p256::ecdsa::SigningKey::from_slice(key_bytes)
                    .map_err(|e| Error::CryptoError(format!("Invalid P-256 key: {e}")))?;
                let sig: p256::ecdsa::Signature = signing_key.sign(message);
                let sig = sig.normalize_s().unwrap_or(sig);
                let mut out = [0u8; 64];
                out.copy_from_slice(&sig.to_bytes());
                Ok(Signature::P256(out))
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
            (PublicKey::Secp256k1(key_bytes), Signature::Secp256k1(sig_bytes)) => {
                use k256::ecdsa::signature::hazmat::PrehashVerifier;
                let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|_| Error::Verification("Invalid Secp256k1 public key".to_string()))?;
                let sig = k256::ecdsa::Signature::from_slice(&sig_bytes[..64])
                    .map_err(|_| Error::Verification("Invalid Secp256k1 signature".to_string()))?;
                // (r, s) and (r, N - s) are both valid; verify the low-S form.
                let sig = sig.normalize_s().unwrap_or(sig);
                verifying_key
                    .verify_prehash(&keccak256(message), &sig)
                    .map_err(|_| {
                        Error::Verification("Secp256k1 signature verification failed".to_string())
                    })
            }
            (PublicKey::P256(key_bytes), Signature::P256(sig_bytes)) => {
                use p256::ecdsa::signature::Verifier;
                let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|_| Error::Verification("Invalid P-256 public key".to_string()))?;
                let sig = p256::ecdsa::Signature::from_slice(sig_bytes)
                    .map_err(|_| Error::Verification("Invalid P-256 signature".to_string()))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                verifying_key.verify(message, &sig).map_err(|_| {
                    Error::Verification("P-256 signature verification failed".to_string())
                })
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
        assert_eq!(bytes.len(), 65);
    }

    #[test]
    fn test_public_key_to_bytes_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let bytes = keypair.public_key().to_bytes();
        assert_eq!(bytes.len(), 65);
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
        let key_types = vec![KeyType::Ed25519, KeyType::Secp256k1, KeyType::P256];

        for key_type in key_types {
            let keypair = KeyPair::generate(key_type).unwrap();
            assert_eq!(keypair.key_type(), key_type);

            let message = b"test";
            let signature = keypair.sign(message).unwrap();
            assert!(keypair.verify(message, &signature).is_ok());
        }
    }

    // ===== Additional RSA Tests =====

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
        let cloned = kt;
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
        let debug_str = format!("{kt:?}");
        assert!(debug_str.contains("Secp256k1"));
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
    fn test_keypair_key_type_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        assert_eq!(keypair.key_type(), KeyType::Secp256k1);
    }

    #[test]
    fn test_keypair_key_type_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        assert_eq!(keypair.key_type(), KeyType::P256);
    }
}
