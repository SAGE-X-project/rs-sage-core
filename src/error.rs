//! Error types for SAGE Crypto Core

use thiserror::Error;

/// Result type alias for SAGE Crypto operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for SAGE Crypto Core
#[derive(Error, Debug)]
pub enum Error {
    /// Key generation error
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Signature error
    #[error("Signature operation failed: {0}")]
    Signature(String),

    /// Verification error
    #[error("Signature verification failed: {0}")]
    Verification(String),

    /// Key format error
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// PEM error
    #[error("PEM format error: {0}")]
    Pem(#[from] pem::PemError),

    /// HTTP signature error
    #[error("HTTP signature error: {0}")]
    HttpSignature(String),

    /// Invalid key type
    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Other errors
    #[error("{0}")]
    Other(String),

    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
}
