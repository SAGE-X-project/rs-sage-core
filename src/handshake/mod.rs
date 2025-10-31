//! Handshake Protocol Module (Phase 4-2)
//!
//! This module implements the 4-phase handshake protocol for establishing
//! secure sessions between SAGE agents.
//!
//! # Protocol Phases
//!
//! 1. **Invitation**: Service discovery and initial contact
//! 2. **Request**: Initiator sends ephemeral public key
//! 3. **Response**: Responder sends ephemeral public key and acknowledgment
//! 4. **Complete**: Session confirmation and activation

pub mod client;
pub mod server;
pub mod types;

// Re-export main types
pub use client::{HandshakeClient, HandshakeClientConfig};
pub use server::{HandshakeServer, HandshakeServerConfig};
pub use types::{
    BaseMessage, CompleteMessage, HandshakeEvents, InvitationMessage, MessageControlHeader,
    NoopEvents, Phase, RequestMessage, ResponseMessage, SessionParams,
};
