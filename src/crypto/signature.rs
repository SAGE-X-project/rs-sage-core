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
}

impl Signature {
    /// Encode signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
            Signature::Secp256k1(sig) => sig.to_der().as_bytes().to_vec(),
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
