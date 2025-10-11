//! Core types for verification and validation

use std::collections::HashMap;

/// Options for message verification
#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    /// Check timestamp validity
    pub check_timestamp: bool,
    /// Maximum age of message in seconds
    pub max_age_secs: Option<u64>,
    /// Check nonce uniqueness
    pub check_nonce: bool,
    /// Check message ordering
    pub check_order: bool,
    /// Additional options
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Result of message verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the signature is valid
    pub signature_valid: bool,
    /// Whether the timestamp is valid
    pub timestamp_valid: bool,
    /// Whether the nonce is valid
    pub nonce_valid: bool,
    /// Whether the order is valid
    pub order_valid: bool,
    /// Overall verification status
    pub verified: bool,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl VerificationResult {
    /// Creates a successful verification result
    pub fn success() -> Self {
        Self {
            signature_valid: true,
            timestamp_valid: true,
            nonce_valid: true,
            order_valid: true,
            verified: true,
            error: None,
            metadata: HashMap::new(),
        }
    }

    /// Creates a failed verification result with error message
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            signature_valid: false,
            timestamp_valid: false,
            nonce_valid: false,
            order_valid: false,
            verified: false,
            error: Some(error.into()),
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_success() {
        let result = VerificationResult::success();
        assert!(result.verified);
        assert!(result.signature_valid);
        assert!(result.timestamp_valid);
        assert!(result.nonce_valid);
        assert!(result.order_valid);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_verification_result_failure() {
        let result = VerificationResult::failure("Invalid signature");
        assert!(!result.verified);
        assert_eq!(result.error.unwrap(), "Invalid signature");
    }
}
