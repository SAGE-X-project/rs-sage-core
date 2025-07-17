//! Key format handling for import/export
//! 
//! This module provides functionality to import and export cryptographic keys
//! in various formats including JWK, PEM, and raw bytes.

use crate::error::{Error, Result};
use crate::crypto::{KeyPair, PublicKey, PrivateKey};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};

/// Supported key formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// JSON Web Key format
    Jwk,
    /// PEM encoded format
    Pem,
    /// DER encoded format
    Der,
    /// Raw bytes
    Raw,
}

/// Trait for importing keys from various formats
pub trait KeyImporter {
    /// Import a public key from the specified format
    fn import_public_key(data: &[u8], format: KeyFormat) -> Result<PublicKey>;
    
    /// Import a private key from the specified format
    fn import_private_key(data: &[u8], format: KeyFormat) -> Result<PrivateKey>;
    
    /// Import a key pair from the specified format
    fn import_key_pair(data: &[u8], format: KeyFormat) -> Result<KeyPair>;
}

/// Trait for exporting keys to various formats
pub trait KeyExporter {
    /// Export to the specified format
    fn export(&self, format: KeyFormat) -> Result<Vec<u8>>;
    
    /// Export to JWK format
    fn to_jwk(&self) -> Result<serde_json::Value>;
    
    /// Export to PEM format
    fn to_pem(&self) -> Result<String>;
}

/// JWK representation for Ed25519 keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Jwk {
    /// Key type (always "OKP" for Ed25519)
    pub kty: String,
    /// Curve name (always "Ed25519")
    pub crv: String,
    /// Public key (base64url encoded)
    pub x: String,
    /// Private key (base64url encoded) - optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// Key ID - optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// JWK representation for Secp256k1 keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secp256k1Jwk {
    /// Key type (always "EC" for elliptic curve)
    pub kty: String,
    /// Curve name (always "secp256k1")
    pub crv: String,
    /// X coordinate (base64url encoded)
    pub x: String,
    /// Y coordinate (base64url encoded)
    pub y: String,
    /// Private key (base64url encoded) - optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// Key ID - optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl KeyExporter for PublicKey {
    fn export(&self, format: KeyFormat) -> Result<Vec<u8>> {
        match format {
            KeyFormat::Jwk => {
                let jwk = self.to_jwk()?;
                serde_json::to_vec(&jwk).map_err(|e| Error::Serialization(e.to_string()))
            }
            KeyFormat::Pem => {
                Ok(self.to_pem()?.into_bytes())
            }
            KeyFormat::Der => {
                // For DER format, export as PEM then convert to DER
                // TODO: Implement proper DER export
                Err(Error::Unsupported("DER format not yet implemented".to_string()))
            }
            KeyFormat::Raw => {
                Ok(self.to_bytes())
            }
        }
    }
    
    fn to_jwk(&self) -> Result<serde_json::Value> {
        match self {
            PublicKey::Ed25519(key_bytes) => {
                let jwk = Ed25519Jwk {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: general_purpose::URL_SAFE_NO_PAD.encode(key_bytes),
                    d: None,
                    kid: Some(self.key_id()),
                };
                serde_json::to_value(jwk).map_err(|e| Error::Serialization(e.to_string()))
            }
            PublicKey::Secp256k1(_key_bytes) => {
                // For secp256k1, we need to decode the compressed public key
                // In a real implementation, this would use the k256 library to properly decode
                // For now, we'll return an error as this requires more complex handling
                Err(Error::Unsupported("Secp256k1 JWK export not yet implemented".to_string()))
            }
        }
    }
    
    fn to_pem(&self) -> Result<String> {
        match self {
            PublicKey::Ed25519(key_bytes) => {
                let pem = pem::Pem {
                    tag: "PUBLIC KEY".to_string(),
                    contents: key_bytes.to_vec(),
                };
                Ok(pem::encode(&pem))
            }
            PublicKey::Secp256k1(key_bytes) => {
                let pem = pem::Pem {
                    tag: "PUBLIC KEY".to_string(),
                    contents: key_bytes.to_vec(),
                };
                Ok(pem::encode(&pem))
            }
        }
    }
}

impl KeyExporter for PrivateKey {
    fn export(&self, format: KeyFormat) -> Result<Vec<u8>> {
        match format {
            KeyFormat::Jwk => {
                let jwk = self.to_jwk()?;
                serde_json::to_vec(&jwk).map_err(|e| Error::Serialization(e.to_string()))
            }
            KeyFormat::Pem => {
                Ok(self.to_pem()?.into_bytes())
            }
            KeyFormat::Der => {
                // For DER format, export as PKCS#8 DER
                // TODO: Implement proper DER export
                Err(Error::Unsupported("DER format not yet implemented".to_string()))
            }
            KeyFormat::Raw => {
                Ok(self.to_bytes())
            }
        }
    }
    
    fn to_jwk(&self) -> Result<serde_json::Value> {
        match self {
            PrivateKey::Ed25519(key_bytes) => {
                // For Ed25519, the private key is 32 bytes and public key is derived from it
                let jwk = Ed25519Jwk {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: general_purpose::URL_SAFE_NO_PAD.encode(&self.public_key().to_bytes()[..32]),
                    d: Some(general_purpose::URL_SAFE_NO_PAD.encode(key_bytes)),
                    kid: Some(self.public_key().key_id()),
                };
                serde_json::to_value(jwk).map_err(|e| Error::Serialization(e.to_string()))
            }
            PrivateKey::Secp256k1(_) => {
                Err(Error::Unsupported("Secp256k1 JWK export not yet implemented".to_string()))
            }
        }
    }
    
    fn to_pem(&self) -> Result<String> {
        match self {
            PrivateKey::Ed25519(key_bytes) => {
                let pem = pem::Pem {
                    tag: "PRIVATE KEY".to_string(),
                    contents: key_bytes.to_vec(),
                };
                Ok(pem::encode(&pem))
            }
            PrivateKey::Secp256k1(key_bytes) => {
                let pem = pem::Pem {
                    tag: "EC PRIVATE KEY".to_string(),
                    contents: key_bytes.to_vec(),
                };
                Ok(pem::encode(&pem))
            }
        }
    }
}

impl KeyExporter for KeyPair {
    fn export(&self, format: KeyFormat) -> Result<Vec<u8>> {
        self.private_key().export(format)
    }
    
    fn to_jwk(&self) -> Result<serde_json::Value> {
        self.private_key().to_jwk()
    }
    
    fn to_pem(&self) -> Result<String> {
        self.private_key().to_pem()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_format_equality() {
        assert_eq!(KeyFormat::Jwk, KeyFormat::Jwk);
        assert_ne!(KeyFormat::Jwk, KeyFormat::Pem);
    }
}