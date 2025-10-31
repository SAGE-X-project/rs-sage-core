//! Mock Transport for Testing

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;

use crate::transport::traits::MessageTransport;
use crate::transport::types::{TransportMessage, TransportResponse, TransportResult};

/// Mock transport for testing
///
/// This transport stores messages in memory and provides methods
/// to inspect sent messages and configure responses.
#[derive(Debug, Clone)]
pub struct MockTransport {
    /// Sent messages (destination -> payloads)
    sent_messages: Arc<DashMap<String, Vec<Vec<u8>>>>,
    /// Response configuration (destination -> response)
    responses: Arc<DashMap<String, TransportResponse>>,
    /// Default response
    default_response: Arc<parking_lot::RwLock<TransportResponse>>,
    /// Availability flag
    available: Arc<parking_lot::RwLock<bool>>,
}

impl MockTransport {
    /// Create a new mock transport
    pub fn new() -> Self {
        Self {
            sent_messages: Arc::new(DashMap::new()),
            responses: Arc::new(DashMap::new()),
            default_response: Arc::new(parking_lot::RwLock::new(
                TransportResponse::new(b"OK".to_vec(), 200)
            )),
            available: Arc::new(parking_lot::RwLock::new(true)),
        }
    }

    /// Set response for a specific destination
    pub fn set_response(&self, destination: &str, response: TransportResponse) {
        self.responses.insert(destination.to_string(), response);
    }

    /// Set default response for all destinations
    pub fn set_default_response(&self, response: TransportResponse) {
        *self.default_response.write() = response;
    }

    /// Get sent messages for a destination
    pub fn get_sent_messages(&self, destination: &str) -> Vec<Vec<u8>> {
        self.sent_messages
            .get(destination)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Get all sent messages across all destinations
    pub fn get_all_sent_messages(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        self.sent_messages
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Count sent messages for a destination
    pub fn count_sent_messages(&self, destination: &str) -> usize {
        self.sent_messages
            .get(destination)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Clear all sent messages
    pub fn clear_sent_messages(&self) {
        self.sent_messages.clear();
    }

    /// Clear responses
    pub fn clear_responses(&self) {
        self.responses.clear();
    }

    /// Set transport availability
    pub fn set_available(&self, available: bool) {
        *self.available.write() = available;
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessageTransport for MockTransport {
    async fn send(&self, destination: &str, payload: Vec<u8>) -> TransportResult<TransportResponse> {
        // Store sent message
        self.sent_messages
            .entry(destination.to_string())
            .or_insert_with(Vec::new)
            .push(payload.clone());

        // Return configured response or default
        let response = self.responses
            .get(destination)
            .map(|r| r.clone())
            .unwrap_or_else(|| self.default_response.read().clone());

        Ok(response)
    }

    async fn send_message(&self, message: TransportMessage) -> TransportResult<TransportResponse> {
        let mut response = self.send(&message.destination, message.payload).await?;

        // Preserve message ID in response
        if let Some(msg_id) = message.message_id {
            response.message_id = Some(msg_id);
        }

        Ok(response)
    }

    fn is_available(&self) -> bool {
        *self.available.read()
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_transport_send() {
        let transport = MockTransport::new();
        let destination = "did:sage:alice";
        let payload = b"Hello, Alice!".to_vec();

        let response = transport.send(destination, payload.clone()).await.unwrap();

        assert!(response.is_success());
        assert_eq!(response.status, 200);
        assert_eq!(response.payload, b"OK");

        // Verify message was stored
        let sent = transport.get_sent_messages(destination);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], payload);
    }

    #[tokio::test]
    async fn test_mock_transport_custom_response() {
        let transport = MockTransport::new();
        let destination = "did:sage:bob";

        // Configure custom response
        let custom_response = TransportResponse::new(b"Custom response".to_vec(), 201);
        transport.set_response(destination, custom_response);

        let response = transport.send(destination, b"Test".to_vec()).await.unwrap();

        assert_eq!(response.status, 201);
        assert_eq!(response.payload, b"Custom response");
    }

    #[tokio::test]
    async fn test_mock_transport_multiple_messages() {
        let transport = MockTransport::new();
        let destination = "did:sage:charlie";

        // Send multiple messages
        for i in 0..5 {
            let payload = format!("Message {}", i).into_bytes();
            transport.send(destination, payload).await.unwrap();
        }

        // Verify all messages stored
        assert_eq!(transport.count_sent_messages(destination), 5);

        let messages = transport.get_sent_messages(destination);
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0], b"Message 0");
        assert_eq!(messages[4], b"Message 4");
    }

    #[tokio::test]
    async fn test_mock_transport_clear() {
        let transport = MockTransport::new();
        let destination = "did:sage:dave";

        transport.send(destination, b"Test".to_vec()).await.unwrap();
        assert_eq!(transport.count_sent_messages(destination), 1);

        transport.clear_sent_messages();
        assert_eq!(transport.count_sent_messages(destination), 0);
    }

    #[tokio::test]
    async fn test_mock_transport_message_envelope() {
        let transport = MockTransport::new();
        let message = TransportMessage::new("did:sage:eve", b"Hello".to_vec())
            .with_id("msg-123");

        let response = transport.send_message(message).await.unwrap();

        assert!(response.is_success());
        assert_eq!(response.message_id.unwrap(), "msg-123");
    }

    #[tokio::test]
    async fn test_mock_transport_availability() {
        let transport = MockTransport::new();

        assert!(transport.is_available());

        transport.set_available(false);
        assert!(!transport.is_available());

        transport.set_available(true);
        assert!(transport.is_available());
    }

    #[tokio::test]
    async fn test_mock_transport_get_all_sent_messages() {
        let transport = MockTransport::new();

        transport.send("did:sage:alice", b"Msg1".to_vec()).await.unwrap();
        transport.send("did:sage:bob", b"Msg2".to_vec()).await.unwrap();
        transport.send("did:sage:alice", b"Msg3".to_vec()).await.unwrap();

        let all_messages = transport.get_all_sent_messages();
        assert_eq!(all_messages.len(), 2); // Two destinations

        // Find Alice's messages
        let alice_messages = all_messages.iter()
            .find(|(dest, _)| dest == "did:sage:alice")
            .unwrap();
        assert_eq!(alice_messages.1.len(), 2);
    }

    #[tokio::test]
    async fn test_mock_transport_name() {
        let transport = MockTransport::new();
        assert_eq!(transport.name(), "mock");
    }
}
