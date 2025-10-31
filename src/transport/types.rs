//! Transport Types and Configuration

use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Transport-specific error types
#[derive(Debug, Error)]
pub enum TransportError {
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Send error
    #[error("Send error: {0}")]
    SendError(String),

    /// Receive error
    #[error("Receive error: {0}")]
    ReceiveError(String),

    /// Timeout error
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Invalid destination
    #[error("Invalid destination: {0}")]
    InvalidDestination(String),

    /// Transport not available
    #[error("Transport not available: {0}")]
    TransportNotAvailable(String),

    /// Other transport error
    #[error("Transport error: {0}")]
    Other(String),
}

/// Transport result type
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Connection timeout
    pub connect_timeout: Duration,

    /// Request timeout
    pub request_timeout: Duration,

    /// Maximum retries
    pub max_retries: u32,

    /// Retry delay
    pub retry_delay: Duration,

    /// Custom headers for HTTP transport
    pub headers: HashMap<String, String>,

    /// Enable TLS verification
    pub verify_tls: bool,

    /// User agent string
    pub user_agent: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            headers: HashMap::new(),
            verify_tls: true,
            user_agent: format!("sage-crypto-core/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Transport message envelope
#[derive(Debug, Clone)]
pub struct TransportMessage {
    /// Destination identifier (DID or URL)
    pub destination: String,

    /// Message payload (encrypted or plaintext)
    pub payload: Vec<u8>,

    /// Optional metadata
    pub metadata: HashMap<String, String>,

    /// Message ID for tracking
    pub message_id: Option<String>,
}

impl TransportMessage {
    /// Create a new transport message
    pub fn new(destination: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            destination: destination.into(),
            payload,
            metadata: HashMap::new(),
            message_id: None,
        }
    }

    /// Add metadata to the message
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set message ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }
}

/// Transport response envelope
#[derive(Debug, Clone)]
pub struct TransportResponse {
    /// Response payload
    pub payload: Vec<u8>,

    /// Status code (HTTP status or custom)
    pub status: u16,

    /// Response metadata
    pub metadata: HashMap<String, String>,

    /// Message ID (if present in request)
    pub message_id: Option<String>,
}

impl TransportResponse {
    /// Create a new transport response
    pub fn new(payload: Vec<u8>, status: u16) -> Self {
        Self {
            payload,
            status,
            metadata: HashMap::new(),
            message_id: None,
        }
    }

    /// Check if response is successful (2xx status)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if response is error (4xx or 5xx status)
    pub fn is_error(&self) -> bool {
        self.status >= 400
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert!(config.verify_tls);
        assert!(config.user_agent.contains("sage-crypto-core"));
    }

    #[test]
    fn test_transport_message() {
        let msg = TransportMessage::new("did:sage:alice", b"Hello".to_vec())
            .with_metadata("key", "value")
            .with_id("msg-123");

        assert_eq!(msg.destination, "did:sage:alice");
        assert_eq!(msg.payload, b"Hello");
        assert_eq!(msg.metadata.get("key").unwrap(), "value");
        assert_eq!(msg.message_id.unwrap(), "msg-123");
    }

    #[test]
    fn test_transport_response() {
        let response = TransportResponse::new(b"OK".to_vec(), 200);

        assert!(response.is_success());
        assert!(!response.is_error());
        assert_eq!(response.status, 200);

        let error_response = TransportResponse::new(vec![], 404);
        assert!(!error_response.is_success());
        assert!(error_response.is_error());
    }
}
