//! Algorithm Registry
//!
//! This module provides a registry of supported cryptographic algorithms
//! with their metadata, capabilities, and selection logic.
//!
//! # Features
//!
//! - Algorithm metadata (key size, signature size, security level)
//! - Performance characteristics
//! - Protocol/chain compatibility
//! - Algorithm selection and recommendation logic
//!
//! # Example
//!
//! ```
//! use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm, SecurityLevel};
//!
//! // Get algorithm metadata
//! let metadata = AlgorithmRegistry::get_metadata(Algorithm::Ed25519);
//! println!("Ed25519 security level: {:?}", metadata.security_level);
//!
//! // Find algorithm by requirements
//! let fast_algo = AlgorithmRegistry::recommend_for_performance();
//! println!("Fastest algorithm: {}", fast_algo);
//!
//! // Get blockchain-compatible algorithms
//! let eth_algos = AlgorithmRegistry::compatible_with_ethereum();
//! println!("Ethereum-compatible: {} algorithms", eth_algos.len());
//! ```

use super::Algorithm;
use std::collections::HashMap;

/// Security level classification for algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// 128-bit security level
    Standard = 128,
    /// 192-bit security level
    High = 192,
    /// 256-bit security level
    VeryHigh = 256,
}

/// Performance tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PerformanceTier {
    /// Fastest performance
    Fast,
    /// Medium performance
    Medium,
    /// Slower performance
    Slow,
}

/// Algorithm metadata and characteristics
#[derive(Debug, Clone)]
pub struct AlgorithmMetadata {
    /// Algorithm identifier
    pub algorithm: Algorithm,

    /// Private key size in bytes
    pub private_key_size: usize,

    /// Public key size in bytes (compressed if applicable)
    pub public_key_size: usize,

    /// Signature size in bytes
    pub signature_size: usize,

    /// Security level (bit strength)
    pub security_level: SecurityLevel,

    /// Performance tier
    pub performance: PerformanceTier,

    /// Whether deterministic signatures are used
    pub deterministic: bool,

    /// Compatible with Ethereum
    pub ethereum_compatible: bool,

    /// Compatible with Solana
    pub solana_compatible: bool,

    /// FIPS 140-2 compliant
    pub fips_compliant: bool,

    /// Description
    pub description: &'static str,
}

/// Algorithm registry singleton
pub struct AlgorithmRegistry;

impl AlgorithmRegistry {
    /// Get metadata for a specific algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to look up
    ///
    /// # Returns
    ///
    /// Algorithm metadata
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};
    ///
    /// let metadata = AlgorithmRegistry::get_metadata(Algorithm::Ed25519);
    /// assert_eq!(metadata.private_key_size, 32);
    /// assert_eq!(metadata.signature_size, 64);
    /// ```
    pub fn get_metadata(algorithm: Algorithm) -> AlgorithmMetadata {
        match algorithm {
            Algorithm::Ed25519 => AlgorithmMetadata {
                algorithm: Algorithm::Ed25519,
                private_key_size: 32,
                public_key_size: 32,
                signature_size: 64,
                security_level: SecurityLevel::Standard,
                performance: PerformanceTier::Fast,
                deterministic: true,
                ethereum_compatible: true,
                solana_compatible: true,
                fips_compliant: false,
                description: "Ed25519 signature algorithm (EdDSA). Fast, secure, and widely supported.",
            },

            Algorithm::Secp256k1 => AlgorithmMetadata {
                algorithm: Algorithm::Secp256k1,
                private_key_size: 32,
                public_key_size: 33, // compressed
                signature_size: 64,
                security_level: SecurityLevel::Standard,
                performance: PerformanceTier::Medium,
                deterministic: true, // RFC 6979
                ethereum_compatible: true,
                solana_compatible: false,
                fips_compliant: false,
                description: "Secp256k1 ECDSA (Bitcoin/Ethereum). RFC 6979 deterministic signatures.",
            },

            Algorithm::P256 => AlgorithmMetadata {
                algorithm: Algorithm::P256,
                private_key_size: 32,
                public_key_size: 33, // compressed
                signature_size: 64,
                security_level: SecurityLevel::Standard,
                performance: PerformanceTier::Medium,
                deterministic: true, // RFC 6979
                ethereum_compatible: true,
                solana_compatible: false,
                fips_compliant: true,
                description: "NIST P-256 ECDSA (secp256r1). FIPS 186-4 compliant, enterprise-grade.",
            },

            Algorithm::Rsa2048 => AlgorithmMetadata {
                algorithm: Algorithm::Rsa2048,
                private_key_size: 256, // DER encoded
                public_key_size: 256,  // DER encoded
                signature_size: 256,
                security_level: SecurityLevel::Standard,
                performance: PerformanceTier::Slow,
                deterministic: false,
                ethereum_compatible: false,
                solana_compatible: false,
                fips_compliant: true,
                description: "RSA-2048 with PKCS#1 v1.5 or PSS. FIPS 186-4 compliant, legacy support.",
            },

            Algorithm::Rsa4096 => AlgorithmMetadata {
                algorithm: Algorithm::Rsa4096,
                private_key_size: 512, // DER encoded
                public_key_size: 512,  // DER encoded
                signature_size: 512,
                security_level: SecurityLevel::High,
                performance: PerformanceTier::Slow,
                deterministic: false,
                ethereum_compatible: false,
                solana_compatible: false,
                fips_compliant: true,
                description: "RSA-4096 with PKCS#1 v1.5 or PSS. High security, slow performance.",
            },
        }
    }

    /// Get all supported algorithms
    ///
    /// # Returns
    ///
    /// Vector of all supported algorithms
    pub fn all_algorithms() -> Vec<Algorithm> {
        vec![
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::P256,
            Algorithm::Rsa2048,
            Algorithm::Rsa4096,
        ]
    }

    /// Get all algorithm metadata as a map
    ///
    /// # Returns
    ///
    /// HashMap of algorithm to metadata
    pub fn all_metadata() -> HashMap<Algorithm, AlgorithmMetadata> {
        let mut map = HashMap::new();
        for algo in Self::all_algorithms() {
            map.insert(algo, Self::get_metadata(algo));
        }
        map
    }

    /// Recommend algorithm for best performance
    ///
    /// # Returns
    ///
    /// Fastest algorithm (Ed25519)
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};
    ///
    /// let fast = AlgorithmRegistry::recommend_for_performance();
    /// assert_eq!(fast, Algorithm::Ed25519);
    /// ```
    pub fn recommend_for_performance() -> Algorithm {
        Algorithm::Ed25519
    }

    /// Recommend algorithm for FIPS compliance
    ///
    /// # Returns
    ///
    /// FIPS-compliant algorithm with best balance (P-256)
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};
    ///
    /// let fips = AlgorithmRegistry::recommend_for_fips();
    /// assert_eq!(fips, Algorithm::P256);
    /// ```
    pub fn recommend_for_fips() -> Algorithm {
        Algorithm::P256
    }

    /// Recommend algorithm for Ethereum
    ///
    /// # Returns
    ///
    /// Best algorithm for Ethereum (Secp256k1)
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};
    ///
    /// let eth = AlgorithmRegistry::recommend_for_ethereum();
    /// assert_eq!(eth, Algorithm::Secp256k1);
    /// ```
    pub fn recommend_for_ethereum() -> Algorithm {
        Algorithm::Secp256k1
    }

    /// Recommend algorithm for Solana
    ///
    /// # Returns
    ///
    /// Only supported algorithm for Solana (Ed25519)
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::{AlgorithmRegistry, Algorithm};
    ///
    /// let sol = AlgorithmRegistry::recommend_for_solana();
    /// assert_eq!(sol, Algorithm::Ed25519);
    /// ```
    pub fn recommend_for_solana() -> Algorithm {
        Algorithm::Ed25519
    }

    /// Get algorithms compatible with Ethereum
    ///
    /// # Returns
    ///
    /// Vector of Ethereum-compatible algorithms
    pub fn compatible_with_ethereum() -> Vec<Algorithm> {
        Self::all_algorithms()
            .into_iter()
            .filter(|algo| Self::get_metadata(*algo).ethereum_compatible)
            .collect()
    }

    /// Get algorithms compatible with Solana
    ///
    /// # Returns
    ///
    /// Vector of Solana-compatible algorithms
    pub fn compatible_with_solana() -> Vec<Algorithm> {
        Self::all_algorithms()
            .into_iter()
            .filter(|algo| Self::get_metadata(*algo).solana_compatible)
            .collect()
    }

    /// Get FIPS-compliant algorithms
    ///
    /// # Returns
    ///
    /// Vector of FIPS 140-2 compliant algorithms
    pub fn fips_compliant_algorithms() -> Vec<Algorithm> {
        Self::all_algorithms()
            .into_iter()
            .filter(|algo| Self::get_metadata(*algo).fips_compliant)
            .collect()
    }

    /// Get algorithms by security level
    ///
    /// # Arguments
    ///
    /// * `min_level` - Minimum security level required
    ///
    /// # Returns
    ///
    /// Vector of algorithms meeting the security requirement
    pub fn by_security_level(min_level: SecurityLevel) -> Vec<Algorithm> {
        Self::all_algorithms()
            .into_iter()
            .filter(|algo| Self::get_metadata(*algo).security_level >= min_level)
            .collect()
    }

    /// Get algorithms by performance tier
    ///
    /// # Arguments
    ///
    /// * `tier` - Desired performance tier
    ///
    /// # Returns
    ///
    /// Vector of algorithms in the performance tier
    pub fn by_performance_tier(tier: PerformanceTier) -> Vec<Algorithm> {
        Self::all_algorithms()
            .into_iter()
            .filter(|algo| Self::get_metadata(*algo).performance == tier)
            .collect()
    }

    /// Check if an algorithm is deterministic
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Algorithm to check
    ///
    /// # Returns
    ///
    /// `true` if signatures are deterministic
    pub fn is_deterministic(algorithm: Algorithm) -> bool {
        Self::get_metadata(algorithm).deterministic
    }

    /// Select best algorithm based on requirements
    ///
    /// # Arguments
    ///
    /// * `ethereum` - Must be compatible with Ethereum
    /// * `solana` - Must be compatible with Solana
    /// * `fips` - Must be FIPS compliant
    /// * `prefer_performance` - Prefer faster algorithms
    ///
    /// # Returns
    ///
    /// Recommended algorithm, or None if no match
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::crypto::AlgorithmRegistry;
    ///
    /// // Need Ethereum-compatible, performance-focused
    /// let algo = AlgorithmRegistry::select_algorithm(true, false, false, true);
    /// assert!(algo.is_some());
    /// ```
    pub fn select_algorithm(
        ethereum: bool,
        solana: bool,
        fips: bool,
        prefer_performance: bool,
    ) -> Option<Algorithm> {
        let mut candidates: Vec<Algorithm> = Self::all_algorithms()
            .into_iter()
            .filter(|algo| {
                let meta = Self::get_metadata(*algo);
                (!ethereum || meta.ethereum_compatible)
                    && (!solana || meta.solana_compatible)
                    && (!fips || meta.fips_compliant)
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Sort by performance if preferred
        if prefer_performance {
            candidates.sort_by_key(|algo| Self::get_metadata(*algo).performance);
        }

        candidates.first().copied()
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Standard => write!(f, "128-bit (Standard)"),
            SecurityLevel::High => write!(f, "192-bit (High)"),
            SecurityLevel::VeryHigh => write!(f, "256-bit (Very High)"),
        }
    }
}

impl std::fmt::Display for PerformanceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PerformanceTier::Fast => write!(f, "Fast"),
            PerformanceTier::Medium => write!(f, "Medium"),
            PerformanceTier::Slow => write!(f, "Slow"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_metadata() {
        let ed25519 = AlgorithmRegistry::get_metadata(Algorithm::Ed25519);
        assert_eq!(ed25519.private_key_size, 32);
        assert_eq!(ed25519.public_key_size, 32);
        assert_eq!(ed25519.signature_size, 64);
        assert_eq!(ed25519.security_level, SecurityLevel::Standard);
        assert_eq!(ed25519.performance, PerformanceTier::Fast);
        assert!(ed25519.deterministic);
    }

    #[test]
    fn test_all_algorithms() {
        let algos = AlgorithmRegistry::all_algorithms();
        assert_eq!(algos.len(), 5);
        assert!(algos.contains(&Algorithm::Ed25519));
        assert!(algos.contains(&Algorithm::Secp256k1));
        assert!(algos.contains(&Algorithm::P256));
        assert!(algos.contains(&Algorithm::Rsa2048));
        assert!(algos.contains(&Algorithm::Rsa4096));
    }

    #[test]
    fn test_recommend_for_performance() {
        let algo = AlgorithmRegistry::recommend_for_performance();
        assert_eq!(algo, Algorithm::Ed25519);
    }

    #[test]
    fn test_recommend_for_fips() {
        let algo = AlgorithmRegistry::recommend_for_fips();
        assert_eq!(algo, Algorithm::P256);
        assert!(AlgorithmRegistry::get_metadata(algo).fips_compliant);
    }

    #[test]
    fn test_recommend_for_ethereum() {
        let algo = AlgorithmRegistry::recommend_for_ethereum();
        assert_eq!(algo, Algorithm::Secp256k1);
        assert!(AlgorithmRegistry::get_metadata(algo).ethereum_compatible);
    }

    #[test]
    fn test_recommend_for_solana() {
        let algo = AlgorithmRegistry::recommend_for_solana();
        assert_eq!(algo, Algorithm::Ed25519);
        assert!(AlgorithmRegistry::get_metadata(algo).solana_compatible);
    }

    #[test]
    fn test_compatible_with_ethereum() {
        let algos = AlgorithmRegistry::compatible_with_ethereum();
        assert!(algos.contains(&Algorithm::Ed25519));
        assert!(algos.contains(&Algorithm::Secp256k1));
        assert!(algos.contains(&Algorithm::P256));
        assert!(!algos.contains(&Algorithm::Rsa2048));
    }

    #[test]
    fn test_compatible_with_solana() {
        let algos = AlgorithmRegistry::compatible_with_solana();
        assert_eq!(algos.len(), 1);
        assert!(algos.contains(&Algorithm::Ed25519));
    }

    #[test]
    fn test_fips_compliant_algorithms() {
        let algos = AlgorithmRegistry::fips_compliant_algorithms();
        assert!(algos.contains(&Algorithm::P256));
        assert!(algos.contains(&Algorithm::Rsa2048));
        assert!(algos.contains(&Algorithm::Rsa4096));
        assert!(!algos.contains(&Algorithm::Ed25519));
        assert!(!algos.contains(&Algorithm::Secp256k1));
    }

    #[test]
    fn test_by_security_level() {
        let standard = AlgorithmRegistry::by_security_level(SecurityLevel::Standard);
        assert_eq!(standard.len(), 5); // All algorithms are at least 128-bit

        let high = AlgorithmRegistry::by_security_level(SecurityLevel::High);
        assert_eq!(high.len(), 1); // Only RSA-4096
        assert!(high.contains(&Algorithm::Rsa4096));
    }

    #[test]
    fn test_by_performance_tier() {
        let fast = AlgorithmRegistry::by_performance_tier(PerformanceTier::Fast);
        assert_eq!(fast.len(), 1);
        assert!(fast.contains(&Algorithm::Ed25519));

        let medium = AlgorithmRegistry::by_performance_tier(PerformanceTier::Medium);
        assert_eq!(medium.len(), 2);
        assert!(medium.contains(&Algorithm::Secp256k1));
        assert!(medium.contains(&Algorithm::P256));

        let slow = AlgorithmRegistry::by_performance_tier(PerformanceTier::Slow);
        assert_eq!(slow.len(), 2);
        assert!(slow.contains(&Algorithm::Rsa2048));
        assert!(slow.contains(&Algorithm::Rsa4096));
    }

    #[test]
    fn test_is_deterministic() {
        assert!(AlgorithmRegistry::is_deterministic(Algorithm::Ed25519));
        assert!(AlgorithmRegistry::is_deterministic(Algorithm::Secp256k1));
        assert!(AlgorithmRegistry::is_deterministic(Algorithm::P256));
        assert!(!AlgorithmRegistry::is_deterministic(Algorithm::Rsa2048));
        assert!(!AlgorithmRegistry::is_deterministic(Algorithm::Rsa4096));
    }

    #[test]
    fn test_select_algorithm_ethereum_only() {
        let algo = AlgorithmRegistry::select_algorithm(true, false, false, true);
        assert!(algo.is_some());
        let selected = algo.unwrap();
        assert!(AlgorithmRegistry::get_metadata(selected).ethereum_compatible);
    }

    #[test]
    fn test_select_algorithm_solana_only() {
        let algo = AlgorithmRegistry::select_algorithm(false, true, false, true);
        assert_eq!(algo, Some(Algorithm::Ed25519));
    }

    #[test]
    fn test_select_algorithm_fips_only() {
        let algo = AlgorithmRegistry::select_algorithm(false, false, true, true);
        assert!(algo.is_some());
        let selected = algo.unwrap();
        assert!(AlgorithmRegistry::get_metadata(selected).fips_compliant);
    }

    #[test]
    fn test_select_algorithm_ethereum_and_fips() {
        let algo = AlgorithmRegistry::select_algorithm(true, false, true, false);
        assert_eq!(algo, Some(Algorithm::P256));
    }

    #[test]
    fn test_select_algorithm_impossible_requirements() {
        // Solana requires Ed25519, but FIPS requires P-256/RSA
        let algo = AlgorithmRegistry::select_algorithm(false, true, true, false);
        assert!(algo.is_none());
    }

    #[test]
    fn test_all_metadata() {
        let all = AlgorithmRegistry::all_metadata();
        assert_eq!(all.len(), 5);
        assert!(all.contains_key(&Algorithm::Ed25519));
        assert!(all.contains_key(&Algorithm::Secp256k1));
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::High > SecurityLevel::Standard);
        assert!(SecurityLevel::VeryHigh > SecurityLevel::High);
    }

    #[test]
    fn test_performance_tier_ordering() {
        assert!(PerformanceTier::Fast < PerformanceTier::Medium);
        assert!(PerformanceTier::Medium < PerformanceTier::Slow);
    }
}
