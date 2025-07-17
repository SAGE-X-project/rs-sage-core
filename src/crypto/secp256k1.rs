//! Secp256k1 (ECDSA) signature implementation

use crate::error::{Error, Result};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Generate a new Secp256k1 signing key
pub fn generate_signing_key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

/// Create signing key from bytes
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey> {
    SigningKey::from_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::InvalidKeyFormat("Invalid key length".to_string()))?,
    )
    .map_err(|e| Error::InvalidKeyFormat(format!("Invalid Secp256k1 private key: {}", e)))
}

/// Create verifying key from SEC1 bytes
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|e| Error::InvalidKeyFormat(format!("Invalid Secp256k1 public key: {}", e)))
}

/// Create signature from DER bytes
pub fn signature_from_der(bytes: &[u8]) -> Result<EcdsaSignature> {
    EcdsaSignature::from_der(bytes)
        .map_err(|e| Error::InvalidKeyFormat(format!("Invalid ECDSA signature: {}", e)))
}

/// Create signature from fixed-size bytes
pub fn signature_from_bytes(bytes: &[u8]) -> Result<EcdsaSignature> {
    // Try DER format first, then try fixed format
    EcdsaSignature::from_der(bytes).or_else(|_| {
        if bytes.len() == 64 {
            // For fixed-size format, split into r and s components
            let _r_bytes = &bytes[..32];
            let _s_bytes = &bytes[32..];

            // For 64-byte format, parse as r||s components
            use k256::FieldBytes;
            EcdsaSignature::from_scalars(
                FieldBytes::clone_from_slice(&bytes[..32]),
                FieldBytes::clone_from_slice(&bytes[32..]),
            )
            .map_err(|e| Error::InvalidKeyFormat(format!("Invalid ECDSA signature: {}", e)))
        } else {
            Err(Error::InvalidKeyFormat(
                "Invalid ECDSA signature length".to_string(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer;

    #[test]
    fn test_key_generation() {
        let signing_key = generate_signing_key();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(signing_key.to_bytes().len(), 32);
        // Verify key was generated correctly - verifying key is 33 bytes (compressed)
        assert_eq!(verifying_key.to_bytes().len(), 33);
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

        let signature: EcdsaSignature = signing_key.sign(message);
        let der_bytes = signature.to_der();

        let restored_sig = signature_from_der(der_bytes.as_bytes()).unwrap();
        // Compare the actual bytes since DER signatures don't implement PartialEq
        assert_eq!(
            signature.to_der().as_bytes(),
            restored_sig.to_der().as_bytes()
        );
    }
}
