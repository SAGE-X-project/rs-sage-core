//! SAGE Crypto Core Library
//!
//! This library provides core cryptographic functionality for SAGE,
//! including Ed25519 and Secp256k1 signatures, key management,
//! and RFC 9421 HTTP Message Signatures support.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "ffi"), deny(unsafe_code))]

pub mod core;
pub mod crypto;
pub mod error;
pub mod formats;
pub mod rfc9421;

// Phase 4: HPKE, Handshake, Session Management
// DEPRECATED: These modules used old DID implementation
// TODO: Rewrite based on sage (Go) v1.3.1 implementation
// - session: ChaCha20-Poly1305 based secure sessions (no DID dependency)
// - hpke/handshake: Need to verify if needed in Go implementation
// #[cfg(feature = "blockchain")]
// pub mod hpke;
// #[cfg(feature = "blockchain")]
// pub mod handshake;
// #[cfg(feature = "blockchain")]
// pub mod session;

// Phase 5.1: Transport Layer
pub mod transport;

// Phase 6.3: Input Validation
pub mod validation;

// Phase 9: Blockchain integration - Re-implemented with alloy crate
// DID functionality is now in blockchain module (sage Go v1.3.1 based)
#[cfg(feature = "blockchain")]
pub mod blockchain;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export main types
pub use core::{
    Message, MessageBuilder, VerificationOptions, VerificationResult, VerificationService,
};
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
