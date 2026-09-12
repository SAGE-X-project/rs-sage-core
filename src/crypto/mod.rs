//! Cryptographic primitives and key management

pub mod algorithm_registry;
pub mod ed25519;
pub mod keys;
pub mod manager;
pub mod multi_key;
pub mod p256;
pub mod rotation;
pub mod secp256k1;
pub mod signature;
pub mod storage;
pub mod x25519;

pub use algorithm_registry::{
    AlgorithmMetadata, AlgorithmRegistry, PerformanceTier, SecurityLevel,
};
pub use keys::{KeyPair, KeyType, PrivateKey, PublicKey};
pub use manager::CryptoManager;
pub use multi_key::{MultiKeyManager, Protocol, MAX_KEYS_PER_AGENT};
pub use rotation::{DefaultKeyRotator, KeyRotationConfig, KeyRotationEvent, KeyRotator};
pub use signature::{Signature, Signer, Verifier};
pub use storage::{FileKeyStorage, KeyStorage, MemoryKeyStorage};
pub use x25519::X25519KeyPair;

/// Supported key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519 signature algorithm
    Ed25519,
    /// Secp256k1 (ECDSA) signature algorithm
    Secp256k1,
    /// P-256 (NIST P-256, secp256r1) ECDSA signature algorithm
    P256,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "Ed25519"),
            Algorithm::Secp256k1 => write!(f, "Secp256k1"),
            Algorithm::P256 => write!(f, "P-256"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Algorithm Display Tests =====

    #[test]
    fn test_algorithm_display_ed25519() {
        let algo = Algorithm::Ed25519;
        assert_eq!(format!("{algo}"), "Ed25519");
    }

    #[test]
    fn test_algorithm_display_secp256k1() {
        let algo = Algorithm::Secp256k1;
        assert_eq!(format!("{algo}"), "Secp256k1");
    }

    #[test]
    fn test_algorithm_display_p256() {
        let algo = Algorithm::P256;
        assert_eq!(format!("{algo}"), "P-256");
    }

    // ===== Algorithm Equality Tests =====

    #[test]
    fn test_algorithm_equality() {
        assert_eq!(Algorithm::Ed25519, Algorithm::Ed25519);
        assert_ne!(Algorithm::Ed25519, Algorithm::Secp256k1);
    }

    #[test]
    fn test_algorithm_clone() {
        let algo = Algorithm::Ed25519;
        let cloned = algo;
        assert_eq!(algo, cloned);
    }

    #[test]
    fn test_algorithm_copy() {
        let algo = Algorithm::P256;
        let copied = algo;
        assert_eq!(algo, copied);
    }

    #[test]
    fn test_algorithm_debug() {
        let algo = Algorithm::Ed25519;
        let debug_str = format!("{algo:?}");
        assert!(debug_str.contains("Ed25519"));
    }

    #[test]
    fn test_all_algorithms() {
        let algorithms = [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256];

        assert_eq!(algorithms.len(), 3);
    }
}
