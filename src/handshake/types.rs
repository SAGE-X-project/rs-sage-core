//! Handshake Protocol Types
//!
//! This module defines the 4-phase handshake protocol messages and types.

use crate::crypto::PublicKey;
use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Handshake protocol phases
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// Phase 1: Service discovery and invitation
    Invitation = 1,
    /// Phase 2: Ephemeral key exchange request
    Request = 2,
    /// Phase 3: Mutual authentication response
    Response = 3,
    /// Phase 4: Session confirmation complete
    Complete = 4,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase::Invitation => write!(f, "invitation"),
            Phase::Request => write!(f, "request"),
            Phase::Response => write!(f, "response"),
            Phase::Complete => write!(f, "complete"),
        }
    }
}

impl TryFrom<u8> for Phase {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Phase::Invitation),
            2 => Ok(Phase::Request),
            3 => Ok(Phase::Response),
            4 => Ok(Phase::Complete),
            _ => Err(crate::error::Error::InvalidInput(format!(
                "Invalid phase: {value}"
            ))),
        }
    }
}

/// Base message fields common to all handshake messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseMessage {
    /// Session ID (context ID)
    pub session_id: String,
    /// Sender DID
    pub from: String,
    /// Receiver DID
    pub to: String,
}

/// Message control header for sequencing and replay protection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageControlHeader {
    /// Message sequence number
    pub sequence: u64,
    /// Random nonce for replay protection
    pub nonce: String,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
}

/// Phase 1: Invitation message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationMessage {
    /// Base message fields
    #[serde(flatten)]
    pub base: BaseMessage,
    /// Control header
    #[serde(flatten)]
    pub control: MessageControlHeader,
}

/// Phase 2: Request message with ephemeral key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMessage {
    /// Base message fields
    #[serde(flatten)]
    pub base: BaseMessage,
    /// Control header
    #[serde(flatten)]
    pub control: MessageControlHeader,
    /// Ephemeral public key in JWK format
    #[serde(rename = "ephemeralPublicKey")]
    pub ephemeral_pub_key: serde_json::Value,
}

/// Phase 3: Response message with ephemeral key and acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMessage {
    /// Base message fields
    #[serde(flatten)]
    pub base: BaseMessage,
    /// Control header
    #[serde(flatten)]
    pub control: MessageControlHeader,
    /// Ephemeral public key in JWK format
    #[serde(rename = "ephemeralPublicKey")]
    pub ephemeral_pub_key: serde_json::Value,
    /// Key ID for session binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Acknowledgment flag
    pub ack: bool,
}

/// Phase 4: Complete message for session confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteMessage {
    /// Base message fields
    #[serde(flatten)]
    pub base: BaseMessage,
    /// Control header
    #[serde(flatten)]
    pub control: MessageControlHeader,
}

/// Session parameters after successful handshake
#[derive(Debug, Clone)]
pub struct SessionParams {
    /// Session ID
    pub session_id: String,
    /// Key ID
    pub key_id: String,
    /// Initiator DID
    pub initiator_did: String,
    /// Responder DID
    pub responder_did: String,
    /// Combined secret for session keys
    pub combined_secret: Vec<u8>,
    /// Whether this party is the initiator
    pub is_initiator: bool,
}

/// Handshake events interface for application integration
pub trait HandshakeEvents: Send + Sync {
    /// Called when an invitation is received
    fn on_invitation(&self, ctx_id: &str, inv: InvitationMessage) -> Result<()>;

    /// Called when a request is received
    fn on_request(&self, ctx_id: &str, req: RequestMessage, sender_pub: PublicKey)
        -> Result<()>;

    /// Called when a response is received
    fn on_response(
        &self,
        ctx_id: &str,
        res: ResponseMessage,
        sender_pub: PublicKey,
    ) -> Result<()>;

    /// Called when a complete message is received
    fn on_complete(&self, ctx_id: &str, comp: CompleteMessage, sess_params: SessionParams)
        -> Result<()>;

    /// Request application to generate ephemeral X25519 keypair
    /// Returns (raw_pub_bytes, jwk_pub_json)
    fn ask_ephemeral(&self, ctx_id: &str) -> Result<(Vec<u8>, serde_json::Value)>;
}

/// Default no-op implementation of HandshakeEvents
#[derive(Debug, Clone, Default)]
pub struct NoopEvents;

impl HandshakeEvents for NoopEvents {
    fn on_invitation(&self, _ctx_id: &str, _inv: InvitationMessage) -> Result<()> {
        Ok(())
    }

    fn on_request(
        &self,
        _ctx_id: &str,
        _req: RequestMessage,
        _sender_pub: PublicKey,
    ) -> Result<()> {
        Ok(())
    }

    fn on_response(
        &self,
        _ctx_id: &str,
        _res: ResponseMessage,
        _sender_pub: PublicKey,
    ) -> Result<()> {
        Ok(())
    }

    fn on_complete(
        &self,
        _ctx_id: &str,
        _comp: CompleteMessage,
        _sess_params: SessionParams,
    ) -> Result<()> {
        Ok(())
    }

    fn ask_ephemeral(&self, _ctx_id: &str) -> Result<(Vec<u8>, serde_json::Value)> {
        Err(crate::error::Error::Other(
            "ask_ephemeral not implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_display() {
        assert_eq!(Phase::Invitation.to_string(), "invitation");
        assert_eq!(Phase::Request.to_string(), "request");
        assert_eq!(Phase::Response.to_string(), "response");
        assert_eq!(Phase::Complete.to_string(), "complete");
    }

    #[test]
    fn test_phase_try_from() {
        assert_eq!(Phase::try_from(1).unwrap(), Phase::Invitation);
        assert_eq!(Phase::try_from(2).unwrap(), Phase::Request);
        assert_eq!(Phase::try_from(3).unwrap(), Phase::Response);
        assert_eq!(Phase::try_from(4).unwrap(), Phase::Complete);
        assert!(Phase::try_from(5).is_err());
    }

    #[test]
    fn test_phase_ordering() {
        assert!(Phase::Invitation < Phase::Request);
        assert!(Phase::Request < Phase::Response);
        assert!(Phase::Response < Phase::Complete);
    }

    #[test]
    fn test_base_message_serialization() {
        let base = BaseMessage {
            session_id: "session-1".to_string(),
            from: "did:sage:alice".to_string(),
            to: "did:sage:bob".to_string(),
        };

        let json = serde_json::to_string(&base).unwrap();
        assert!(json.contains("sessionId"));
        assert!(json.contains("did:sage:alice"));

        let deserialized: BaseMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_id, base.session_id);
    }

    #[test]
    fn test_invitation_message_serialization() {
        let inv = InvitationMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:alice".to_string(),
                to: "did:sage:bob".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
        };

        let json = serde_json::to_string(&inv).unwrap();
        let deserialized: InvitationMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base.session_id, inv.base.session_id);
        assert_eq!(deserialized.control.sequence, 1);
    }
}
