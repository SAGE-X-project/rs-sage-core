//! Session types and configuration.

use crate::error::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Default number of records per direction after which the AEAD key rotates.
pub const DEFAULT_REKEY_INTERVAL: u64 = 256;

/// Session lifetime and rotation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum age before the session expires (absolute)
    pub max_age: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Maximum number of records (sent plus received); 0 disables the limit
    pub max_messages: usize,
    /// Records per direction between key rotations; 0 disables rotation
    pub rekey_interval: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::seconds(3600),
            idle_timeout: Duration::seconds(600),
            max_messages: 1000,
            rekey_interval: DEFAULT_REKEY_INTERVAL,
        }
    }
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Usable
    Active,
    /// Expired by age, idle time or record count
    Expired,
    /// Closed by the application
    Closed,
}

/// The session interface shared by every session type.
pub trait Session: Send + Sync {
    /// Session id
    fn get_id(&self) -> &str;
    /// Creation time
    fn get_created_at(&self) -> DateTime<Utc>;
    /// Last use
    fn get_last_used_at(&self) -> DateTime<Utc>;
    /// Status
    fn get_status(&self) -> SessionStatus;
    /// Whether the session can no longer be used
    fn is_expired(&self) -> bool;
    /// Mark the session as used now
    fn update_last_used(&mut self);
    /// Close the session
    fn close(&mut self) -> Result<()>;
    /// Encrypt with the shared session key
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypt with the shared session key
    fn decrypt(&self, record: &[u8]) -> Result<Vec<u8>>;
    /// Encrypt with `covered` as AAD and return a separate HMAC over it
    fn encrypt_and_sign(&self, plaintext: &[u8], covered: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Verify the HMAC and decrypt with `covered` as AAD
    fn decrypt_and_verify(&self, record: &[u8], covered: &[u8], mac: &[u8]) -> Result<Vec<u8>>;
    /// HMAC-SHA256 over `covered` with the signing key
    fn sign_covered(&self, covered: &[u8]) -> Vec<u8>;
    /// Verify an HMAC produced by the peer
    fn verify_covered(&self, covered: &[u8], mac: &[u8]) -> Result<()>;
    /// Records sent plus received
    fn get_message_count(&self) -> usize;
    /// Configuration
    fn get_config(&self) -> &SessionConfig;
}

/// Per-session options for the manager.
#[derive(Debug, Clone, Default)]
pub struct SessionOpts {
    /// Explicit session id (derived from the seed when `None`)
    pub session_id: Option<String>,
    /// Session configuration
    pub config: SessionConfig,
    /// Free-form metadata
    pub metadata: std::collections::HashMap<String, String>,
}
