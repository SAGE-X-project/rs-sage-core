//! HPKE (Hybrid Public Key Encryption) Module
//!
//! This module implements RFC 9180 HPKE with the SAGE-specific extensions
//! including E2E ECDH secret combination, ACK tag generation, and traffic
//! key derivation.
//!
//! # Architecture
//!
//! - `types`: Core types, traits, and constants
//! - `common`: Utility functions for secret combination and key derivation
//! - `nonce_store`: Replay protection via nonce tracking
//! - `client`: HPKE sender (initiator)
//! - `server`: HPKE receiver (responder)
//!
//! # Security Features (sage v1.0.1)
//!
//! - **Memory Safety**: Zeroization of sensitive data
//! - **DoS Protection**: Cookie verification before expensive operations
//! - **Enhanced Verification**: Signed envelopes with hash binding
//! - **Traffic Keys**: Bidirectional key derivation for C2S and S2C
//!
//! # Example
//!
//! ```no_run
//! use sage_crypto_core::hpke::{HpkeClient, HpkeServer, DefaultInfoBuilder};
//!
//! // Server setup
//! // let server = HpkeServer::new(...);
//!
//! // Client initiates HPKE handshake
//! // let response = client.initialize(...).await?;
//!
//! // Server processes request
//! // let result = server.handle_message(...).await?;
//! ```

pub mod client;
pub mod common;
pub mod nonce_store;
pub mod server;
pub mod types;

// Re-export main types
pub use common::{
    combine_secrets, derive_traffic_keys, is_all_zero_32, make_ack_tag, sha256_hash,
    sha256_hash_hex, verify_ack_tag, zero_bytes,
};
pub use nonce_store::NonceStore;
pub use types::{
    CookieSource, CookieVerifier, DefaultInfoBuilder, HpkeInitPayload, InfoBuilder, KeyIDBinder,
    ServerSigEnvelope, TrafficKeys, ACK_KEY_LABEL, ACK_MSG_LABEL, C2S_IV_LABEL, C2S_KEY_LABEL,
    CB_LABEL, COMBINER_ID, COMBINER_LABEL, HPKE_SUITE_ID, S2C_IV_LABEL, S2C_KEY_LABEL,
};

pub use client::{HpkeClient, HpkeClientConfig, ServerResponse};
pub use server::{HpkeServer, HpkeServerConfig};
