//! Transport Traits

use async_trait::async_trait;
use crate::transport::types::{TransportMessage, TransportResponse, TransportResult};

/// Message transport trait for sending and receiving messages
#[async_trait]
pub trait MessageTransport: Send + Sync {
    /// Send a message to a destination
    ///
    /// # Arguments
    ///
    /// * `destination` - Target identifier (DID or URL)
    /// * `payload` - Message payload bytes
    ///
    /// # Returns
    ///
    /// Transport response with status and payload
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if sending fails
    async fn send(&self, destination: &str, payload: Vec<u8>) -> TransportResult<TransportResponse>;

    /// Send a transport message envelope
    ///
    /// # Arguments
    ///
    /// * `message` - Transport message with metadata
    ///
    /// # Returns
    ///
    /// Transport response with status and payload
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if sending fails
    async fn send_message(&self, message: TransportMessage) -> TransportResult<TransportResponse> {
        self.send(&message.destination, message.payload).await
    }

    /// Check if transport is available
    fn is_available(&self) -> bool {
        true
    }

    /// Get transport name
    fn name(&self) -> &'static str;

    /// Close the transport connection
    async fn close(&self) -> TransportResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTransport;

    #[async_trait]
    impl MessageTransport for TestTransport {
        async fn send(&self, _destination: &str, payload: Vec<u8>) -> TransportResult<TransportResponse> {
            Ok(TransportResponse::new(payload, 200))
        }

        fn name(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn test_transport_trait() {
        let transport = TestTransport;

        let response = transport.send("did:sage:alice", b"Hello".to_vec()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.payload, b"Hello");
        assert!(response.is_success());
        assert_eq!(transport.name(), "test");
    }

    #[tokio::test]
    async fn test_send_message() {
        let transport = TestTransport;
        let message = TransportMessage::new("did:sage:bob", b"Test".to_vec());

        let response = transport.send_message(message).await.unwrap();
        assert!(response.is_success());
    }
}
