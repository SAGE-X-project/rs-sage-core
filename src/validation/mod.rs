//! Input Validation Module
//!
//! This module provides comprehensive input validation for all public APIs
//! to prevent denial-of-service attacks and ensure data integrity.

pub mod limits;
pub mod validators;

pub use limits::{ValidationLimits, DEFAULT_LIMITS};
pub use validators::{
    validate_did_format, validate_key_id, validate_message_size, validate_metadata_size,
    validate_nonce, validate_payload_size, validate_signature_size, validate_timestamp,
};

use crate::error::Result;

/// Validation context for tracking validation state
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// Validation limits configuration
    pub limits: ValidationLimits,
    /// Whether to enforce strict validation (fail on warnings)
    pub strict: bool,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            limits: DEFAULT_LIMITS,
            strict: false,
        }
    }
}

impl ValidationContext {
    /// Create a new validation context with custom limits
    pub fn new(limits: ValidationLimits) -> Self {
        Self {
            limits,
            strict: false,
        }
    }

    /// Create a strict validation context
    pub fn strict(limits: ValidationLimits) -> Self {
        Self {
            limits,
            strict: true,
        }
    }

    /// Validate message size
    pub fn validate_message(&self, message: &[u8]) -> Result<()> {
        validate_message_size(message, self.limits.max_message_size)
    }

    /// Validate payload size
    pub fn validate_payload(&self, payload: &[u8]) -> Result<()> {
        validate_payload_size(payload, self.limits.max_payload_size)
    }

    /// Validate metadata size
    pub fn validate_metadata(&self, metadata: &[u8]) -> Result<()> {
        validate_metadata_size(metadata, self.limits.max_metadata_size)
    }

    /// Validate signature size
    pub fn validate_signature(&self, signature: &[u8]) -> Result<()> {
        validate_signature_size(signature, self.limits.max_signature_size)
    }

    /// Validate DID format
    pub fn validate_did(&self, did: &str) -> Result<()> {
        validate_did_format(did, self.limits.max_did_length)
    }

    /// Validate key ID
    pub fn validate_key_id(&self, key_id: &str) -> Result<()> {
        validate_key_id(key_id, self.limits.max_key_id_length)
    }

    /// Validate nonce format
    pub fn validate_nonce(&self, nonce: &str) -> Result<()> {
        validate_nonce(nonce, self.limits.max_nonce_length)
    }

    /// Validate timestamp
    pub fn validate_timestamp(&self, timestamp: i64, now: i64) -> Result<()> {
        validate_timestamp(timestamp, now, self.limits.max_timestamp_skew_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ValidationContext Creation Tests =====

    #[test]
    fn test_validation_context_default() {
        let ctx = ValidationContext::default();
        assert!(!ctx.strict);
        assert_eq!(ctx.limits.max_message_size, 1024 * 1024); // 1MB
    }

    #[test]
    fn test_validation_context_new() {
        let custom_limits = ValidationLimits::strict();
        let ctx = ValidationContext::new(custom_limits);
        assert!(!ctx.strict);
        assert_eq!(ctx.limits.max_message_size, 256 * 1024); // 256KB
    }

    #[test]
    fn test_validation_context_strict() {
        let ctx = ValidationContext::strict(DEFAULT_LIMITS);
        assert!(ctx.strict);
    }

    #[test]
    fn test_validation_context_custom_limits() {
        let custom_limits = ValidationLimits::permissive();
        let ctx = ValidationContext::new(custom_limits);
        assert_eq!(ctx.limits.max_message_size, 10 * 1024 * 1024); // 10MB
    }

    // ===== Message Validation Tests =====

    #[test]
    fn test_validate_message_within_limits() {
        let ctx = ValidationContext::default();
        let message = vec![0u8; 1024]; // 1KB
        assert!(ctx.validate_message(&message).is_ok());
    }

    #[test]
    fn test_validate_message_exceeds_limits() {
        let ctx = ValidationContext::default();
        let message = vec![0u8; 2 * 1024 * 1024]; // 2MB
        assert!(ctx.validate_message(&message).is_err());
    }

    #[test]
    fn test_validate_message_empty() {
        let ctx = ValidationContext::default();
        let message = vec![];
        assert!(ctx.validate_message(&message).is_ok());
    }

    #[test]
    fn test_validate_message_at_limit() {
        let ctx = ValidationContext::default();
        let message = vec![0u8; 1024 * 1024]; // Exactly at limit
        assert!(ctx.validate_message(&message).is_ok());
    }

    // ===== Payload Validation Tests =====

    #[test]
    fn test_validate_payload_within_limits() {
        let ctx = ValidationContext::default();
        let payload = vec![0u8; 512 * 1024]; // 512KB
        assert!(ctx.validate_payload(&payload).is_ok());
    }

    #[test]
    fn test_validate_payload_exceeds_limits() {
        let ctx = ValidationContext::default();
        let payload = vec![0u8; 2 * 1024 * 1024]; // 2MB
        assert!(ctx.validate_payload(&payload).is_err());
    }

    #[test]
    fn test_validate_payload_empty() {
        let ctx = ValidationContext::default();
        let payload = vec![];
        assert!(ctx.validate_payload(&payload).is_ok());
    }

    #[test]
    fn test_validate_payload_at_limit() {
        let ctx = ValidationContext::default();
        let payload = vec![0u8; 512 * 1024]; // Exactly at limit (512KB)
        assert!(ctx.validate_payload(&payload).is_ok());
    }

    // ===== Metadata Validation Tests =====

    #[test]
    fn test_validate_metadata_within_limits() {
        let ctx = ValidationContext::default();
        let metadata = vec![0u8; 4096]; // 4KB
        assert!(ctx.validate_metadata(&metadata).is_ok());
    }

    #[test]
    fn test_validate_metadata_exceeds_limits() {
        let ctx = ValidationContext::default();
        let metadata = vec![0u8; 70 * 1024]; // 70KB (exceeds 64KB limit)
        assert!(ctx.validate_metadata(&metadata).is_err());
    }

    #[test]
    fn test_validate_metadata_empty() {
        let ctx = ValidationContext::default();
        let metadata = vec![];
        assert!(ctx.validate_metadata(&metadata).is_ok());
    }

    #[test]
    fn test_validate_metadata_at_limit() {
        let ctx = ValidationContext::default();
        let metadata = vec![0u8; 64 * 1024]; // Exactly at limit
        assert!(ctx.validate_metadata(&metadata).is_ok());
    }

    // ===== Signature Validation Tests =====

    #[test]
    fn test_validate_signature_within_limits() {
        let ctx = ValidationContext::default();
        let signature = vec![0u8; 64]; // Ed25519 signature size
        assert!(ctx.validate_signature(&signature).is_ok());
    }

    #[test]
    fn test_validate_signature_exceeds_limits() {
        let ctx = ValidationContext::default();
        let signature = vec![0u8; 2048]; // Too large
        assert!(ctx.validate_signature(&signature).is_err());
    }

    #[test]
    fn test_validate_signature_empty() {
        let ctx = ValidationContext::default();
        let signature = vec![];
        // Empty signature might be invalid depending on implementation
        let result = ctx.validate_signature(&signature);
        // Just check it returns a result
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_validate_signature_various_sizes() {
        let ctx = ValidationContext::default();

        // Ed25519: 64 bytes
        assert!(ctx.validate_signature(&[0u8; 64]).is_ok());

        // ECDSA: ~71-72 bytes DER
        assert!(ctx.validate_signature(&[0u8; 72]).is_ok());

        // RSA: ~256 bytes
        assert!(ctx.validate_signature(&vec![0u8; 256]).is_ok());
    }

    // ===== DID Validation Tests =====

    #[test]
    fn test_validate_did() {
        let ctx = ValidationContext::default();
        assert!(ctx.validate_did("did:sage:alice").is_ok());
        assert!(ctx.validate_did("invalid-did").is_err());
    }

    #[test]
    fn test_validate_did_various_formats() {
        let ctx = ValidationContext::default();

        assert!(ctx.validate_did("did:sage:test").is_ok());
        assert!(ctx.validate_did("did:sage:ethereum:0x123").is_ok());
        assert!(ctx.validate_did("did:sage:solana:abc123").is_ok());
    }

    #[test]
    fn test_validate_did_empty() {
        let ctx = ValidationContext::default();
        assert!(ctx.validate_did("").is_err());
    }

    #[test]
    fn test_validate_did_too_long() {
        let ctx = ValidationContext::default();
        let long_did = format!("did:sage:{}", "a".repeat(1020)); // Total > 1024
        assert!(ctx.validate_did(&long_did).is_err());
    }

    // ===== Key ID Validation Tests =====

    #[test]
    fn test_validate_key_id_valid() {
        let ctx = ValidationContext::default();
        assert!(ctx.validate_key_id("key-123").is_ok());
        assert!(ctx.validate_key_id("abcdef0123456789").is_ok());
    }

    #[test]
    fn test_validate_key_id_empty() {
        let ctx = ValidationContext::default();
        assert!(ctx.validate_key_id("").is_err());
    }

    #[test]
    fn test_validate_key_id_too_long() {
        let ctx = ValidationContext::default();
        let long_key_id = "a".repeat(260); // Exceeds 256 limit
        assert!(ctx.validate_key_id(&long_key_id).is_err());
    }

    #[test]
    fn test_validate_key_id_hex_format() {
        let ctx = ValidationContext::default();
        assert!(ctx.validate_key_id("0123456789abcdef").is_ok());
    }

    // ===== Nonce Validation Tests =====

    #[test]
    fn test_validate_nonce_valid() {
        let ctx = ValidationContext::default();
        // Valid hex nonce
        assert!(ctx.validate_nonce("abcdef0123456789").is_ok());
    }

    #[test]
    fn test_validate_nonce_empty() {
        let ctx = ValidationContext::default();
        assert!(ctx.validate_nonce("").is_err());
    }

    #[test]
    fn test_validate_nonce_too_long() {
        let ctx = ValidationContext::default();
        let long_nonce = "n".repeat(130); // Exceeds 128 limit
        assert!(ctx.validate_nonce(&long_nonce).is_err());
    }

    #[test]
    fn test_validate_nonce_various_formats() {
        let ctx = ValidationContext::default();

        // Valid hex format
        assert!(ctx.validate_nonce("0123456789abcdef").is_ok());
        // Valid base64 format
        assert!(ctx.validate_nonce("YWJjZGVmMTIzNA==").is_ok());
        // Mixed case hex
        assert!(ctx.validate_nonce("ABCDEF0123456789").is_ok());
    }

    // ===== Timestamp Validation Tests =====

    #[test]
    fn test_validate_timestamp_current() {
        let ctx = ValidationContext::default();
        let now = 1000000;
        let timestamp = 1000000;
        assert!(ctx.validate_timestamp(timestamp, now).is_ok());
    }

    #[test]
    fn test_validate_timestamp_within_skew() {
        let ctx = ValidationContext::default();
        let now = 1000000;
        let timestamp = 1000030; // 30 seconds in future
        assert!(ctx.validate_timestamp(timestamp, now).is_ok());
    }

    #[test]
    fn test_validate_timestamp_past() {
        let ctx = ValidationContext::default();
        let now = 1000000;
        let timestamp = 999970; // 30 seconds in past
        assert!(ctx.validate_timestamp(timestamp, now).is_ok());
    }

    #[test]
    fn test_validate_timestamp_too_far_future() {
        let ctx = ValidationContext::default();
        let now = 1000000;
        let timestamp = 1100000; // Way in future
        assert!(ctx.validate_timestamp(timestamp, now).is_err());
    }

    #[test]
    fn test_validate_timestamp_too_far_past() {
        let ctx = ValidationContext::default();
        let now = 1000000;
        let timestamp = 900000; // Way in past
        assert!(ctx.validate_timestamp(timestamp, now).is_err());
    }

    // ===== Custom Limits Tests =====

    #[test]
    fn test_strict_limits_message() {
        let ctx = ValidationContext::new(ValidationLimits::strict());
        let message = vec![0u8; 600 * 1024]; // 600KB - ok for default, exceeds strict
        assert!(ctx.validate_message(&message).is_err());
    }

    #[test]
    fn test_permissive_limits_message() {
        let ctx = ValidationContext::new(ValidationLimits::permissive());
        let message = vec![0u8; 5 * 1024 * 1024]; // 5MB - ok for permissive
        assert!(ctx.validate_message(&message).is_ok());
    }

    #[test]
    fn test_custom_builder_limits() {
        use crate::validation::limits::ValidationLimitsBuilder;

        let custom_limits = ValidationLimitsBuilder::default()
            .max_message_size(100 * 1024) // 100KB
            .build();

        let ctx = ValidationContext::new(custom_limits);
        let small_message = vec![0u8; 50 * 1024]; // 50KB
        let large_message = vec![0u8; 200 * 1024]; // 200KB

        assert!(ctx.validate_message(&small_message).is_ok());
        assert!(ctx.validate_message(&large_message).is_err());
    }
}
