//! Cryptographic primitives and key management

pub mod ed25519;
pub mod keys;
pub mod secp256k1;
pub mod signature;

pub use keys::{KeyPair, KeyType, PrivateKey, PublicKey};
pub use signature::{Signature, Signer, Verifier};

/// Supported key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 signature algorithm
    Ed25519,
    /// Secp256k1 (ECDSA) signature algorithm
    Secp256k1,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "Ed25519"),
            Algorithm::Secp256k1 => write!(f, "Secp256k1"),
        }
    }
}
