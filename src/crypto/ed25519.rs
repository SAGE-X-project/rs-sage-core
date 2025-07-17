//! Ed25519 signature implementation

use crate::error::{Error, Result};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};

/// Generate a new Ed25519 signing key
pub fn generate_signing_key() -> SigningKey {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

/// Create signing key from bytes
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey> {
    if bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat(
            "Ed25519 private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Create verifying key from bytes
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
    if bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| Error::InvalidKeyFormat(e.to_string()))
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
    Ok(Ed25519Signature::from_bytes(&sig_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn test_key_generation() {
        let signing_key = generate_signing_key();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(signing_key.to_bytes().len(), 32);
        assert_eq!(verifying_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_key_serialization() {
        let signing_key = generate_signing_key();
        let bytes = signing_key.to_bytes();

        let restored_key = signing_key_from_bytes(&bytes).unwrap();
        assert_eq!(signing_key.to_bytes(), restored_key.to_bytes());
    }

    #[test]
    fn test_signature_roundtrip() {
        let signing_key = generate_signing_key();
        let message = b"Test message";

        let signature = signing_key.sign(message);
        let sig_bytes = signature.to_bytes();

        let restored_sig = signature_from_bytes(&sig_bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored_sig.to_bytes());
    }
}
