//! Ed25519 signature implementation

use crate::error::{Error, Result};
use ed25519_dalek::{PublicKey, SecretKey, Signature as Ed25519Signature};
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate a new Ed25519 signing key
/// Generate a new Ed25519 keypair and return the secret key
pub fn generate_signing_key() -> SecretKey {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    SecretKey::from_bytes(&bytes).expect("Valid secret key")
}

/// Create signing key from bytes
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    if bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat(
            "Ed25519 private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    Ok(SecretKey::from_bytes(&key_bytes).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?)
}

/// Create verifying key from bytes
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    PublicKey::from_bytes(&key_bytes).map_err(|e| Error::InvalidKeyFormat(e.to_string()))
}

/// Create signature from bytes
pub fn signature_from_bytes(bytes: &[u8]) -> Result<Ed25519Signature> {
    if bytes.len() != 64 {
        return Err(Error::InvalidKeyFormat(
            "Ed25519 signature must be 64 bytes".to_string(),
        ));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(bytes);
    Ed25519Signature::from_bytes(&sig_bytes).map_err(|e| Error::InvalidKeyFormat(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Keypair, Signer};

    #[test]
    fn test_key_generation() {
        let secret_key = generate_signing_key();
        let public_key = PublicKey::from(&secret_key);

        assert_eq!(secret_key.to_bytes().len(), 32);
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_key_serialization() {
        let secret_key = generate_signing_key();
        let bytes = secret_key.to_bytes();

        let restored_key = signing_key_from_bytes(&bytes).unwrap();
        assert_eq!(secret_key.to_bytes(), restored_key.to_bytes());
    }

    #[test]
    fn test_signature_roundtrip() {
        let secret_key = generate_signing_key();
        let public_key = PublicKey::from(&secret_key);
        let keypair = Keypair {
            secret: secret_key,
            public: public_key,
        };
        let message = b"Test message";

        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();

        let restored_sig = signature_from_bytes(&sig_bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored_sig.to_bytes());
    }
}
