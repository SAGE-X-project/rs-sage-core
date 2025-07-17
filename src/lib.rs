//! SAGE Crypto Core Library
//! 
//! This library provides core cryptographic functionality for SAGE,
//! including Ed25519 and Secp256k1 signatures, key management,
//! and RFC 9421 HTTP Message Signatures support.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod formats;
pub mod rfc9421;

// Re-export main types
pub use crypto::{KeyPair, KeyType, PublicKey, PrivateKey, Signature};
pub use error::{Error, Result};
pub use formats::{KeyFormat, KeyImporter, KeyExporter};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
