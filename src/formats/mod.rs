//! Key format handling for import/export
//!
//! This module provides functionality to import and export cryptographic keys
//! in various formats including JWK, PEM, and raw bytes.

use crate::crypto::{KeyPair, PrivateKey, PublicKey};
use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

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
            KeyFormat::Pem => Ok(self.to_pem()?.into_bytes()),
            KeyFormat::Der => {
                // For DER format, export as PEM then convert to DER
                // TODO: Implement proper DER export
                Err(Error::Unsupported(
                    "DER format not yet implemented".to_string(),
                ))
            }
            KeyFormat::Raw => Ok(self.to_bytes()),
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
                Err(Error::Unsupported(
                    "Secp256k1 JWK export not yet implemented".to_string(),
                ))
            }
            PublicKey::P256(key_bytes) => {
                // P-256 uses EC JWK format
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                use p256::PublicKey as P256PublicKey;

                let public_key = P256PublicKey::from_sec1_bytes(key_bytes)
                    .map_err(|e| Error::Serialization(format!("Invalid P-256 public key: {}", e)))?;

                let point = public_key.to_encoded_point(false); // uncompressed
                let x = general_purpose::URL_SAFE_NO_PAD.encode(point.x().ok_or_else(|| {
                    Error::Serialization("Failed to get x coordinate".to_string())
                })?);
                let y = general_purpose::URL_SAFE_NO_PAD.encode(point.y().ok_or_else(|| {
                    Error::Serialization("Failed to get y coordinate".to_string())
                })?);

                let jwk = serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y,
                    "kid": self.key_id(),
                });

                Ok(jwk)
            }
            PublicKey::Rsa(_, _) => {
                // RSA JWK export not yet implemented
                Err(Error::Unsupported(
                    "RSA JWK export not yet implemented".to_string(),
                ))
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
            PublicKey::P256(key_bytes) => {
                let pem = pem::Pem {
                    tag: "PUBLIC KEY".to_string(),
                    contents: key_bytes.to_vec(),
                };
                Ok(pem::encode(&pem))
            }
            PublicKey::Rsa(der_bytes, _) => {
                // RSA public keys are already DER-encoded, just convert to PEM
                use crate::crypto::rsa::RsaKeyPair;
                let rsa_pubkey = RsaKeyPair::public_key_from_der(der_bytes, crate::crypto::rsa::RsaKeySize::Rsa2048)?;
                use rsa::pkcs1::EncodeRsaPublicKey;
                rsa_pubkey.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                    .map(|p| p.to_string())
                    .map_err(|e| Error::Serialization(format!("RSA PEM encoding failed: {}", e)))
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
            KeyFormat::Pem => Ok(self.to_pem()?.into_bytes()),
            KeyFormat::Der => {
                // For DER format, export as PKCS#8 DER
                // TODO: Implement proper DER export
                Err(Error::Unsupported(
                    "DER format not yet implemented".to_string(),
                ))
            }
            KeyFormat::Raw => Ok(self.to_bytes()),
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
            PrivateKey::Secp256k1(_) => Err(Error::Unsupported(
                "Secp256k1 JWK export not yet implemented".to_string(),
            )),
            PrivateKey::P256(key_bytes) => {
                // P-256 private key JWK export
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                use p256::SecretKey as P256SecretKey;

                let secret_key = P256SecretKey::from_slice(key_bytes)
                    .map_err(|e| Error::Serialization(format!("Invalid P-256 private key: {}", e)))?;

                let public_key = secret_key.public_key();
                let point = public_key.to_encoded_point(false); // uncompressed

                let x = general_purpose::URL_SAFE_NO_PAD.encode(point.x().ok_or_else(|| {
                    Error::Serialization("Failed to get x coordinate".to_string())
                })?);
                let y = general_purpose::URL_SAFE_NO_PAD.encode(point.y().ok_or_else(|| {
                    Error::Serialization("Failed to get y coordinate".to_string())
                })?);
                let d = general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);

                let jwk = serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y,
                    "d": d,
                    "kid": self.public_key().key_id(),
                });

                Ok(jwk)
            }
            PrivateKey::Rsa(_, _) => Err(Error::Unsupported(
                "RSA JWK export not yet implemented".to_string(),
            )),
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
            PrivateKey::P256(key_bytes) => {
                let pem = pem::Pem {
                    tag: "EC PRIVATE KEY".to_string(),
                    contents: key_bytes.to_vec(),
                };
                Ok(pem::encode(&pem))
            }
            PrivateKey::Rsa(der_bytes, _) => {
                // RSA private keys are already DER-encoded, just convert to PEM
                use crate::crypto::rsa::RsaKeyPair;
                let rsa_keypair = RsaKeyPair::private_key_from_der(der_bytes, crate::crypto::rsa::RsaKeySize::Rsa2048)?;
                rsa_keypair.private_key_to_pem()
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
    use crate::crypto::{KeyPair, KeyType};

    // ===== KeyFormat Enum Tests =====
    #[test]
    fn test_key_format_equality() {
        assert_eq!(KeyFormat::Jwk, KeyFormat::Jwk);
        assert_ne!(KeyFormat::Jwk, KeyFormat::Pem);
    }

    #[test]
    fn test_key_format_all_variants() {
        assert_ne!(KeyFormat::Jwk, KeyFormat::Pem);
        assert_ne!(KeyFormat::Jwk, KeyFormat::Der);
        assert_ne!(KeyFormat::Jwk, KeyFormat::Raw);
        assert_ne!(KeyFormat::Pem, KeyFormat::Der);
    }

    // ===== Ed25519 Tests =====
    #[test]
    fn test_ed25519_jwk_public_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let jwk = keypair.public_key().to_jwk().unwrap();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert!(jwk["x"].is_string());
        assert!(jwk["kid"].is_string());
        assert!(jwk["d"].is_null());
    }

    #[test]
    fn test_ed25519_jwk_private_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let jwk = keypair.private_key().to_jwk().unwrap();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert!(jwk["x"].is_string());
        assert!(jwk["d"].is_string());
        assert!(jwk["kid"].is_string());
    }

    #[test]
    fn test_ed25519_pem_public_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pem = keypair.public_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_ed25519_pem_private_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN"));
        assert!(pem.contains("-----END"));
    }

    #[test]
    fn test_ed25519_raw_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let raw = keypair.public_key().export(KeyFormat::Raw).unwrap();
        assert_eq!(raw.len(), 32);
    }

    // ===== P-256 Tests =====
    #[test]
    fn test_p256_jwk_export() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let pub_jwk = keypair.public_key().to_jwk().unwrap();
        assert_eq!(pub_jwk["kty"], "EC");
        assert_eq!(pub_jwk["crv"], "P-256");
        assert!(pub_jwk["x"].is_string());
        assert!(pub_jwk["y"].is_string());
        assert!(pub_jwk["kid"].is_string());

        let priv_jwk = keypair.private_key().to_jwk().unwrap();
        assert_eq!(priv_jwk["kty"], "EC");
        assert_eq!(priv_jwk["crv"], "P-256");
        assert!(priv_jwk["x"].is_string());
        assert!(priv_jwk["y"].is_string());
        assert!(priv_jwk["d"].is_string());
        assert!(priv_jwk["kid"].is_string());
    }

    #[test]
    fn test_p256_pem_export() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let pub_pem = keypair.public_key().to_pem().unwrap();
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pub_pem.contains("-----END PUBLIC KEY-----"));

        let priv_pem = keypair.private_key().to_pem().unwrap();
        assert!(priv_pem.contains("-----BEGIN"));
        assert!(priv_pem.contains("-----END"));
    }

    #[test]
    fn test_p256_raw_export() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let raw = keypair.public_key().export(KeyFormat::Raw).unwrap();
        assert!(!raw.is_empty());
    }

    // ===== Secp256k1 Tests =====
    #[test]
    fn test_secp256k1_pem_public_export() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let pem = keypair.public_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_secp256k1_pem_private_export() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN"));
        assert!(pem.contains("-----END"));
    }

    #[test]
    fn test_secp256k1_jwk_unsupported() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let result = keypair.public_key().to_jwk();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    #[test]
    fn test_secp256k1_raw_export() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let raw = keypair.public_key().export(KeyFormat::Raw).unwrap();
        assert_eq!(raw.len(), 33); // compressed
    }

    // ===== RSA Tests =====
    #[test]
    fn test_rsa_pem_export() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let pub_pem = keypair.public_key().to_pem().unwrap();
        assert!(pub_pem.contains("-----BEGIN"));
        assert!(pub_pem.contains("-----END"));

        let priv_pem = keypair.private_key().to_pem().unwrap();
        assert!(priv_pem.contains("-----BEGIN"));
        assert!(priv_pem.contains("-----END"));
    }

    #[test]
    fn test_rsa_jwk_unsupported() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let result = keypair.public_key().to_jwk();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    // ===== Error Cases =====
    #[test]
    fn test_der_export_unsupported() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let result = keypair.public_key().export(KeyFormat::Der);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    #[test]
    fn test_all_keys_jwk_export() {
        let key_types = vec![KeyType::Ed25519, KeyType::P256];
        for key_type in key_types {
            let keypair = KeyPair::generate(key_type).unwrap();
            let jwk = keypair.public_key().export(KeyFormat::Jwk);
            assert!(jwk.is_ok(), "Failed for {:?}", key_type);
        }
    }

    #[test]
    fn test_all_keys_pem_export() {
        let key_types = vec![KeyType::Ed25519, KeyType::Secp256k1, KeyType::P256, KeyType::Rsa2048];
        for key_type in key_types {
            let keypair = KeyPair::generate(key_type).unwrap();
            let pem = keypair.public_key().export(KeyFormat::Pem);
            assert!(pem.is_ok(), "Failed for {:?}", key_type);
        }
    }

    #[test]
    fn test_all_keys_raw_export() {
        let key_types = vec![KeyType::Ed25519, KeyType::Secp256k1, KeyType::P256, KeyType::Rsa2048];
        for key_type in key_types {
            let keypair = KeyPair::generate(key_type).unwrap();
            let raw = keypair.public_key().export(KeyFormat::Raw);
            assert!(raw.is_ok(), "Failed for {:?}", key_type);
            assert!(!raw.unwrap().is_empty());
        }
    }

    // ===== Additional Format Tests =====
    #[test]
    fn test_key_format_debug() {
        let format = KeyFormat::Jwk;
        let debug_str = format!("{:?}", format);
        assert!(debug_str.contains("Jwk"));
    }

    #[test]
    fn test_key_format_clone() {
        let format = KeyFormat::Pem;
        let cloned = format.clone();
        assert_eq!(format, cloned);
    }

    #[test]
    fn test_key_format_copy() {
        let format = KeyFormat::Raw;
        let copied = format;
        assert_eq!(format, copied);
    }

    // ===== JWK Struct Tests =====
    #[test]
    fn test_ed25519_jwk_serialization() {
        let jwk = Ed25519Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "test_x".to_string(),
            d: Some("test_d".to_string()),
            kid: Some("test_kid".to_string()),
        };
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("OKP"));
        assert!(json.contains("Ed25519"));
        assert!(json.contains("test_x"));
        assert!(json.contains("test_d"));
        assert!(json.contains("test_kid"));
    }

    #[test]
    fn test_ed25519_jwk_deserialization() {
        let json = r#"{"kty":"OKP","crv":"Ed25519","x":"test_x"}"#;
        let jwk: Ed25519Jwk = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.x, "test_x");
        assert!(jwk.d.is_none());
        assert!(jwk.kid.is_none());
    }

    #[test]
    fn test_secp256k1_jwk_serialization() {
        let jwk = Secp256k1Jwk {
            kty: "EC".to_string(),
            crv: "secp256k1".to_string(),
            x: "test_x".to_string(),
            y: "test_y".to_string(),
            d: None,
            kid: Some("test_kid".to_string()),
        };
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("EC"));
        assert!(json.contains("secp256k1"));
        assert!(!json.contains("\"d\""));
    }

    #[test]
    fn test_secp256k1_jwk_deserialization() {
        let json = r#"{"kty":"EC","crv":"secp256k1","x":"x_val","y":"y_val","d":"d_val"}"#;
        let jwk: Secp256k1Jwk = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "secp256k1");
        assert_eq!(jwk.x, "x_val");
        assert_eq!(jwk.y, "y_val");
        assert_eq!(jwk.d.unwrap(), "d_val");
    }

    // ===== Private Key Export Tests =====
    #[test]
    fn test_ed25519_private_pem_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_ed25519_private_raw_export() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let raw = keypair.private_key().export(KeyFormat::Raw).unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn test_p256_private_jwk_export() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let jwk = keypair.private_key().to_jwk().unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["d"].is_string());
    }

    #[test]
    fn test_p256_private_pem_export() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pem.contains("-----END EC PRIVATE KEY-----"));
    }

    #[test]
    fn test_secp256k1_private_pem_export() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();
        assert!(pem.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pem.contains("-----END EC PRIVATE KEY-----"));
    }

    #[test]
    fn test_secp256k1_private_jwk_unsupported() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let result = keypair.private_key().to_jwk();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    #[test]
    fn test_rsa_private_jwk_unsupported() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let result = keypair.private_key().to_jwk();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    // ===== KeyPair Delegation Tests =====
    #[test]
    fn test_keypair_export_delegates_to_private() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair_pem = keypair.export(KeyFormat::Pem).unwrap();
        let private_pem = keypair.private_key().export(KeyFormat::Pem).unwrap();
        assert_eq!(keypair_pem, private_pem);
    }

    #[test]
    fn test_keypair_jwk_delegates_to_private() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair_jwk = keypair.to_jwk().unwrap();
        let private_jwk = keypair.private_key().to_jwk().unwrap();
        assert_eq!(keypair_jwk, private_jwk);
    }

    #[test]
    fn test_keypair_pem_delegates_to_private() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair_pem = keypair.to_pem().unwrap();
        let private_pem = keypair.private_key().to_pem().unwrap();
        assert_eq!(keypair_pem, private_pem);
    }

    // ===== Export Format Validation Tests =====
    #[test]
    fn test_ed25519_jwk_base64_encoding() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let jwk = keypair.public_key().to_jwk().unwrap();
        let x_str = jwk["x"].as_str().unwrap();
        // Verify it's valid base64url (no padding, no special chars)
        assert!(!x_str.contains('='));
        assert!(!x_str.contains('+'));
        assert!(!x_str.contains('/'));
    }

    #[test]
    fn test_p256_jwk_has_coordinates() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let jwk = keypair.public_key().to_jwk().unwrap();
        let x = jwk["x"].as_str().unwrap();
        let y = jwk["y"].as_str().unwrap();
        // Both coordinates should be non-empty base64url strings
        assert!(!x.is_empty());
        assert!(!y.is_empty());
        assert!(!x.contains('='));
        assert!(!y.contains('='));
    }

    #[test]
    fn test_ed25519_private_jwk_has_d_parameter() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let jwk = keypair.private_key().to_jwk().unwrap();
        let d = jwk["d"].as_str().unwrap();
        assert!(!d.is_empty());
        assert!(!d.contains('='));
    }

    // ===== Error Handling Tests =====
    #[test]
    fn test_private_key_der_export_unsupported() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let result = keypair.private_key().export(KeyFormat::Der);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    #[test]
    fn test_ed25519_jwk_has_kid() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let jwk = keypair.public_key().to_jwk().unwrap();
        assert!(jwk["kid"].is_string());
        let kid = jwk["kid"].as_str().unwrap();
        assert!(!kid.is_empty());
    }

    #[test]
    fn test_p256_jwk_has_kid() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let jwk = keypair.public_key().to_jwk().unwrap();
        assert!(jwk["kid"].is_string());
        let kid = jwk["kid"].as_str().unwrap();
        assert!(!kid.is_empty());
    }

    // ===== Raw Export Size Tests =====
    #[test]
    fn test_p256_raw_export_size() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let raw = keypair.public_key().export(KeyFormat::Raw).unwrap();
        // P-256 public key is 33 bytes (compressed) or 65 bytes (uncompressed)
        assert!(raw.len() == 33 || raw.len() == 65);
    }

    #[test]
    fn test_rsa_raw_export_non_empty() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let raw = keypair.public_key().export(KeyFormat::Raw).unwrap();
        // RSA keys are much larger
        assert!(raw.len() > 100);
    }

    // ===== PEM Format Validation Tests =====
    #[test]
    fn test_secp256k1_pem_has_correct_tag() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let pub_pem = keypair.public_key().to_pem().unwrap();
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));

        let priv_pem = keypair.private_key().to_pem().unwrap();
        assert!(priv_pem.contains("-----BEGIN EC PRIVATE KEY-----"));
    }

    #[test]
    fn test_p256_pem_has_correct_tag() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let pub_pem = keypair.public_key().to_pem().unwrap();
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));

        let priv_pem = keypair.private_key().to_pem().unwrap();
        assert!(priv_pem.contains("-----BEGIN EC PRIVATE KEY-----"));
    }
}
