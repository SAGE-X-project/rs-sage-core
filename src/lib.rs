//! SAGE Crypto Core Library
//!
//! This library provides core cryptographic functionality for SAGE,
//! including Ed25519 and Secp256k1 signatures, key management,
//! and RFC 9421 HTTP Message Signatures support.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "ffi"), deny(unsafe_code))]

pub mod crypto;
pub mod error;
pub mod formats;
pub mod rfc9421;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export main types
pub use crypto::{KeyPair, KeyType, PrivateKey, PublicKey, Signature};
pub use error::{Error, Result};
pub use formats::{KeyExporter, KeyFormat, KeyImporter};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }
}
