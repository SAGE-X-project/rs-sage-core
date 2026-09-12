//! Validation Limits Configuration
//!
//! This module defines size limits and constraints for input validation.

use serde::{Deserialize, Serialize};

/// Validation limits for input data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationLimits {
    /// Maximum message size in bytes (default: 1MB)
    pub max_message_size: usize,

    /// Maximum payload size in bytes (default: 512KB)
    pub max_payload_size: usize,

    /// Maximum metadata size in bytes (default: 64KB)
    pub max_metadata_size: usize,

    /// Maximum signature size in bytes (default: 256 bytes)
    pub max_signature_size: usize,

    /// Maximum DID length in characters (default: 1024)
    pub max_did_length: usize,

    /// Maximum key ID length in characters (default: 256)
    pub max_key_id_length: usize,

    /// Maximum nonce length in characters (default: 128)
    pub max_nonce_length: usize,

    /// Maximum timestamp skew in seconds (default: 300 = 5 minutes)
    pub max_timestamp_skew_secs: i64,

    /// Maximum number of headers in HTTP signature (default: 100)
    pub max_signature_headers: usize,

    /// Maximum header name length (default: 256)
    pub max_header_name_length: usize,

    /// Maximum header value length (default: 8KB)
    pub max_header_value_length: usize,

    /// Maximum number of verification methods in DID document (default: 50)
    pub max_verification_methods: usize,

    /// Maximum session count per pool (default: 10000)
    pub max_sessions_per_pool: usize,

    /// Maximum messages per session (default: 1000)
    pub max_messages_per_session: u64,
}

/// Default validation limits (balanced for security and usability)
pub const DEFAULT_LIMITS: ValidationLimits = ValidationLimits {
    max_message_size: 1024 * 1024,     // 1MB
    max_payload_size: 512 * 1024,      // 512KB
    max_metadata_size: 64 * 1024,      // 64KB
    max_signature_size: 256,           // 256 bytes
    max_did_length: 1024,              // 1024 chars
    max_key_id_length: 256,            // 256 chars
    max_nonce_length: 128,             // 128 chars
    max_timestamp_skew_secs: 300,      // 5 minutes
    max_signature_headers: 100,        // 100 headers
    max_header_name_length: 256,       // 256 chars
    max_header_value_length: 8 * 1024, // 8KB
    max_verification_methods: 50,      // 50 methods
    max_sessions_per_pool: 10000,      // 10k sessions
    max_messages_per_session: 1000,    // 1k messages
};

/// Strict validation limits (for high-security environments)
pub const STRICT_LIMITS: ValidationLimits = ValidationLimits {
    max_message_size: 256 * 1024,      // 256KB
    max_payload_size: 128 * 1024,      // 128KB
    max_metadata_size: 16 * 1024,      // 16KB
    max_signature_size: 128,           // 128 bytes
    max_did_length: 512,               // 512 chars
    max_key_id_length: 128,            // 128 chars
    max_nonce_length: 64,              // 64 chars
    max_timestamp_skew_secs: 60,       // 1 minute
    max_signature_headers: 20,         // 20 headers
    max_header_name_length: 128,       // 128 chars
    max_header_value_length: 2 * 1024, // 2KB
    max_verification_methods: 10,      // 10 methods
    max_sessions_per_pool: 1000,       // 1k sessions
    max_messages_per_session: 100,     // 100 messages
};

/// Permissive validation limits (for development/testing)
pub const PERMISSIVE_LIMITS: ValidationLimits = ValidationLimits {
    max_message_size: 10 * 1024 * 1024, // 10MB
    max_payload_size: 5 * 1024 * 1024,  // 5MB
    max_metadata_size: 256 * 1024,      // 256KB
    max_signature_size: 512,            // 512 bytes
    max_did_length: 4096,               // 4096 chars
    max_key_id_length: 1024,            // 1024 chars
    max_nonce_length: 256,              // 256 chars
    max_timestamp_skew_secs: 3600,      // 1 hour
    max_signature_headers: 500,         // 500 headers
    max_header_name_length: 512,        // 512 chars
    max_header_value_length: 32 * 1024, // 32KB
    max_verification_methods: 200,      // 200 methods
    max_sessions_per_pool: 100000,      // 100k sessions
    max_messages_per_session: 10000,    // 10k messages
};

impl Default for ValidationLimits {
    fn default() -> Self {
        DEFAULT_LIMITS
    }
}

impl ValidationLimits {
    /// Create a new ValidationLimits with default values
    pub fn new() -> Self {
        DEFAULT_LIMITS
    }

    /// Create strict validation limits
    pub fn strict() -> Self {
        STRICT_LIMITS
    }

    /// Create permissive validation limits
    pub fn permissive() -> Self {
        PERMISSIVE_LIMITS
    }

    /// Create custom validation limits with a builder pattern
    pub fn builder() -> ValidationLimitsBuilder {
        ValidationLimitsBuilder::default()
    }
}

/// Builder for ValidationLimits
#[derive(Debug, Clone)]
pub struct ValidationLimitsBuilder {
    limits: ValidationLimits,
}

impl Default for ValidationLimitsBuilder {
    fn default() -> Self {
        Self {
            limits: DEFAULT_LIMITS,
        }
    }
}

impl ValidationLimitsBuilder {
    /// Set maximum message size
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.limits.max_message_size = size;
        self
    }

    /// Set maximum payload size
    pub fn max_payload_size(mut self, size: usize) -> Self {
        self.limits.max_payload_size = size;
        self
    }

    /// Set maximum metadata size
    pub fn max_metadata_size(mut self, size: usize) -> Self {
        self.limits.max_metadata_size = size;
        self
    }

    /// Set maximum signature size
    pub fn max_signature_size(mut self, size: usize) -> Self {
        self.limits.max_signature_size = size;
        self
    }

    /// Set maximum DID length
    pub fn max_did_length(mut self, length: usize) -> Self {
        self.limits.max_did_length = length;
        self
    }

    /// Set maximum timestamp skew
    pub fn max_timestamp_skew_secs(mut self, secs: i64) -> Self {
        self.limits.max_timestamp_skew_secs = secs;
        self
    }

    /// Build the ValidationLimits
    pub fn build(self) -> ValidationLimits {
        self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ValidationLimits::default();
        assert_eq!(limits.max_message_size, 1024 * 1024);
        assert_eq!(limits.max_payload_size, 512 * 1024);
    }

    #[test]
    fn test_strict_limits() {
        let limits = ValidationLimits::strict();
        assert_eq!(limits.max_message_size, 256 * 1024);
        assert!(limits.max_timestamp_skew_secs < DEFAULT_LIMITS.max_timestamp_skew_secs);
    }

    #[test]
    fn test_permissive_limits() {
        let limits = ValidationLimits::permissive();
        assert_eq!(limits.max_message_size, 10 * 1024 * 1024);
        assert!(limits.max_timestamp_skew_secs > DEFAULT_LIMITS.max_timestamp_skew_secs);
    }

    #[test]
    fn test_builder() {
        let limits = ValidationLimits::builder()
            .max_message_size(2048)
            .max_payload_size(1024)
            .build();

        assert_eq!(limits.max_message_size, 2048);
        assert_eq!(limits.max_payload_size, 1024);
    }

    #[test]
    fn test_serialization() {
        let limits = ValidationLimits::default();
        let json = serde_json::to_string(&limits).unwrap();
        let deserialized: ValidationLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(limits, deserialized);
    }
}
