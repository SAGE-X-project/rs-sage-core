//! Core integration layer for SAGE
//!
//! This module provides the core types and services for SAGE message handling,
//! verification, and integration with the cryptographic and DID systems.

pub mod message;
pub mod types;

pub use message::Message;
pub use types::{VerificationOptions, VerificationResult};
