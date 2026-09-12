//! Message type and builder pattern implementation
//!
//! This module provides the core Message type that represents a SAGE message
//! with all required fields for secure agent communication.

use std::collections::HashMap;

use crate::crypto::keys::KeyPair;
use crate::error::Result;
use crate::rfc9421::{HttpSigner, SignatureComponent};
use base64::Engine;

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
    /// RFC 9421 signature-input header value (e.g., "sig1=(...);created=...;keyid=...")
    pub signature_input: String,
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
    keypair: Option<KeyPair>,
    components: Vec<SignatureComponent>,
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
            keypair: None,
            components: vec![
                SignatureComponent::Method,
                SignatureComponent::Path,
                SignatureComponent::Header("x-sage-agent-did".to_string()),
                SignatureComponent::Header("x-sage-message-id".to_string()),
                SignatureComponent::Header("x-sage-timestamp".to_string()),
                SignatureComponent::Header("x-sage-nonce".to_string()),
            ],
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

    /// Sets the keypair for signing
    pub fn keypair(mut self, keypair: KeyPair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Sets the signature components
    pub fn signature_components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.components = components;
        self
    }

    /// Builds and signs the Message
    pub fn build(self) -> Result<Message> {
        // Generate defaults if not provided
        let agent_did = self.agent_did.unwrap_or_default();
        let message_id = self
            .message_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let timestamp = self
            .timestamp
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let nonce = self
            .nonce
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // If no keypair provided, return unsigned message
        let Some(keypair) = self.keypair else {
            return Ok(Message {
                agent_did,
                message_id,
                timestamp,
                nonce,
                headers: self.headers,
                body: self.body,
                algorithm: String::new(),
                key_id: String::new(),
                signature: Vec::new(),
                signature_input: String::new(),
                signed_fields: Vec::new(),
                metadata: self.metadata,
            });
        };

        // Create HTTP request for signing
        let mut request_builder = http::Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .header("x-sage-agent-did", &agent_did)
            .header("x-sage-message-id", &message_id)
            .header("x-sage-timestamp", timestamp.to_string())
            .header("x-sage-nonce", &nonce);

        // Add custom headers
        for (key, value) in &self.headers {
            request_builder = request_builder.header(key, value);
        }

        let request = request_builder
            .body(self.body.clone())
            .map_err(|e| crate::error::Error::Other(format!("Failed to build request: {e}")))?;

        // Sign the request
        let signer =
            HttpSigner::new(keypair.clone()).with_default_components(self.components.clone());
        let signed_request = signer.sign_request(request)?;

        // Extract signature from headers
        let signature_header = signed_request
            .headers()
            .get("signature")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        let signature_input_header = signed_request
            .headers()
            .get("signature-input")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Parse signature value (format: "sig1=:base64:")
        let signature_bytes = if let Some(sig_val) = signature_header.strip_prefix("sig1=:") {
            base64::engine::general_purpose::STANDARD
                .decode(sig_val)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Extract signed fields from signature-input
        let signed_fields = self
            .components
            .iter()
            .map(|c| c.identifier().to_string())
            .collect();

        let algorithm = match keypair.key_type() {
            crate::crypto::KeyType::Ed25519 => "ed25519",
            crate::crypto::KeyType::Secp256k1 => "es256k",
            crate::crypto::KeyType::P256 => "ecdsa-p256-sha256",
        }
        .to_string();

        Ok(Message {
            agent_did,
            message_id,
            timestamp,
            nonce,
            headers: self.headers,
            body: self.body,
            algorithm,
            key_id: keypair.public_key().key_id(),
            signature: signature_bytes,
            signature_input: signature_input_header,
            signed_fields,
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
    use crate::crypto::keys::KeyType;

    #[test]
    fn test_message_builder_unsigned() {
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
        assert!(msg.signature.is_empty());
    }

    #[test]
    fn test_message_builder_signed() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .body(b"test body".to_vec())
            .keypair(keypair.clone())
            .build()
            .expect("Failed to build signed message");

        assert_eq!(msg.agent_did, "did:sage:test");
        assert!(!msg.signature.is_empty());
        assert!(!msg.key_id.is_empty());
        assert_eq!(msg.algorithm, "ed25519");
        assert!(!msg.signed_fields.is_empty());
        assert_eq!(msg.key_id, keypair.public_key().key_id());
    }

    #[test]
    fn test_message_builder_auto_fields() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        // Build without explicit message_id, timestamp, nonce
        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .keypair(keypair)
            .build()
            .expect("Failed to build message");

        // Should auto-generate these fields
        assert!(!msg.message_id.is_empty());
        assert!(msg.timestamp > 0);
        assert!(!msg.nonce.is_empty());
    }
}
