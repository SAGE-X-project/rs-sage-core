//! Session Types and Traits
//!
//! This module defines the core session interface and configuration types.

use crate::error::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum age before session expires (absolute timeout)
    pub max_age: Duration,
    /// Idle timeout - session expires if not used within this duration
    pub idle_timeout: Duration,
    /// Maximum number of messages allowed in this session
    pub max_messages: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::seconds(3600),      // 1 hour
            idle_timeout: Duration::seconds(600),  // 10 minutes
            max_messages: 10_000,
        }
    }
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session is active and ready for use
    Active,
    /// Session has expired
    Expired,
    /// Session has been closed
    Closed,
}

/// Session trait defining cryptographic operations and lifecycle
pub trait Session: Send + Sync {
    /// Get session ID
    fn get_id(&self) -> &str;

    /// Get creation timestamp
    fn get_created_at(&self) -> DateTime<Utc>;

    /// Get last used timestamp
    fn get_last_used_at(&self) -> DateTime<Utc>;

    /// Get session status
    fn get_status(&self) -> SessionStatus;

    /// Check if session is expired
    fn is_expired(&self) -> bool;

    /// Update last used timestamp
    fn update_last_used(&mut self);

    /// Close the session
    fn close(&mut self) -> Result<()>;

    /// Encrypt plaintext data
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext data
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt and sign data with MAC
    /// Returns (ciphertext, mac)
    fn encrypt_and_sign(&self, plaintext: &[u8], covered: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decrypt and verify MAC
    fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        covered: &[u8],
        mac: &[u8],
    ) -> Result<Vec<u8>>;

    /// Sign covered data (for MAC generation)
    fn sign_covered(&self, covered: &[u8]) -> Vec<u8>;

    /// Verify covered data signature
    fn verify_covered(&self, covered: &[u8], signature: &[u8]) -> Result<()>;

    /// Get message count
    fn get_message_count(&self) -> usize;

    /// Get session configuration
    fn get_config(&self) -> &SessionConfig;
}

/// Session options for creation
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct SessionOpts {
    /// Custom session ID (if None, will be generated)
    pub session_id: Option<String>,
    /// Custom configuration
    pub config: SessionConfig,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.max_age.num_seconds(), 3600);
        assert_eq!(config.idle_timeout.num_seconds(), 600);
        assert_eq!(config.max_messages, 10_000);
    }

    #[test]
    fn test_session_status() {
        assert_eq!(SessionStatus::Active, SessionStatus::Active);
        assert_ne!(SessionStatus::Active, SessionStatus::Expired);
    }

    #[test]
    fn test_session_opts_default() {
        let opts = SessionOpts::default();
        assert!(opts.session_id.is_none());
        assert_eq!(opts.config.max_age.num_seconds(), 3600);
        assert!(opts.metadata.is_empty());
    }

    #[test]
    fn test_session_config_serialization() {
        let config = SessionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.max_age, deserialized.max_age);
        assert_eq!(config.max_messages, deserialized.max_messages);
    }
}
