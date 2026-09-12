//! Session Management Module (Phase 4-3)
//!
//! This module provides secure session lifecycle management including:
//! - Session creation from HPKE exporter secrets
//! - Encryption/decryption with traffic keys
//! - MAC generation and verification
//! - Session expiration and cleanup
//! - Key ID binding and session pool management

pub mod derive;
pub mod manager;
pub mod secure_session;
pub mod types;

// Re-export main types
pub use derive::{
    compute_session_id, derive_session_seed, SessionParams, DEFAULT_LABEL, HPKE_E2E_LABEL,
    HPKE_LABEL,
};
pub use manager::{SessionManager, SessionManagerConfig};
pub use secure_session::{SecureSession, HEADER_SIZE, NONCE_SIZE, REPLAY_WINDOW_SIZE, SEQ_SIZE};
pub use types::{Session, SessionConfig, SessionOpts, SessionStatus, DEFAULT_REKEY_INTERVAL};
