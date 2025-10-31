//! Session Management Module (Phase 4-3)
//!
//! This module provides secure session lifecycle management including:
//! - Session creation from HPKE exporter secrets
//! - Encryption/decryption with traffic keys
//! - MAC generation and verification
//! - Session expiration and cleanup
//! - Key ID binding and session pool management

pub mod manager;
pub mod secure_session;
pub mod types;

// Re-export main types
pub use manager::{SessionManager, SessionManagerConfig};
pub use secure_session::SecureSession;
pub use types::{Session, SessionConfig, SessionOpts, SessionStatus};
