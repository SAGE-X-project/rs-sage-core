//! Message type and builder pattern implementation
//!
//! This module provides the core Message type that represents a SAGE message
//! with all required fields for secure agent communication.

use std::collections::HashMap;

use crate::error::Result;

/// Represents a SAGE message with RFC 9421 signature
#[derive(Debug, Clone)]
pub struct Message {
    /// Agent DID (Decentralized Identifier)
    pub agent_did: String,
    /// Unique message identifier
    pub message_id: String,
    /// Unix timestamp when the message was created
    pub timestamp: i64,
    /// Nonce for replay attack prevention
    pub nonce: String,
    /// HTTP headers included in the message
    pub headers: HashMap<String, String>,
    /// Message body content
    pub body: Vec<u8>,
    /// Signature algorithm used (e.g., "ed25519", "secp256k1")
    pub algorithm: String,
    /// Key identifier used for signing
    pub key_id: String,
    /// Cryptographic signature of the message
    pub signature: Vec<u8>,
    /// List of fields that were signed
    pub signed_fields: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Builder for creating Message instances
pub struct MessageBuilder {
    agent_did: Option<String>,
    message_id: Option<String>,
    timestamp: Option<i64>,
    nonce: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    metadata: HashMap<String, serde_json::Value>,
}

impl MessageBuilder {
    /// Creates a new MessageBuilder
    pub fn new() -> Self {
        Self {
            agent_did: None,
            message_id: None,
            timestamp: None,
            nonce: None,
            headers: HashMap::new(),
            body: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Sets the agent DID
    pub fn agent_did(mut self, did: impl Into<String>) -> Self {
        self.agent_did = Some(did.into());
        self
    }

    /// Sets the message ID
    pub fn message_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }

    /// Sets the timestamp
    pub fn timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Sets the nonce
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Adds a header
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Sets the body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Adds metadata
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Builds the Message (placeholder - will implement signing in later tasks)
    pub fn build(self) -> Result<Message> {
        // TODO: Implement actual signing logic in Task 1-4
        Ok(Message {
            agent_did: self.agent_did.unwrap_or_default(),
            message_id: self.message_id.unwrap_or_default(),
            timestamp: self.timestamp.unwrap_or(0),
            nonce: self.nonce.unwrap_or_default(),
            headers: self.headers,
            body: self.body,
            algorithm: String::new(),
            key_id: String::new(),
            signature: Vec::new(),
            signed_fields: Vec::new(),
            metadata: self.metadata,
        })
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_builder() {
        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .message_id("msg-123")
            .timestamp(1234567890)
            .nonce("test-nonce")
            .header("content-type", "application/json")
            .body(b"test body".to_vec())
            .build()
            .expect("Failed to build message");

        assert_eq!(msg.agent_did, "did:sage:test");
        assert_eq!(msg.message_id, "msg-123");
        assert_eq!(msg.timestamp, 1234567890);
        assert_eq!(msg.nonce, "test-nonce");
        assert_eq!(msg.headers.get("content-type").unwrap(), "application/json");
        assert_eq!(msg.body, b"test body");
    }
}
