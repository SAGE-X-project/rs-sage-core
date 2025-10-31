//! Phase 5.1 Transport Layer Integration Tests
//!
//! Tests the transport layer components:
//! - MockTransport for testing
//! - TransportManager for routing
//! - Transport selection based on destination
//! - Message envelope handling

use sage_crypto_core::transport::{
    HttpTransport, MessageTransport, MockTransport, TransportConfig, TransportManager,
    TransportMessage, TransportResponse,
};
use std::sync::Arc;
use std::time::Duration;

/// Test MockTransport basic functionality
#[tokio::test]
async fn test_mock_transport_basic() {
    let transport = MockTransport::new();

    let response = transport
        .send("did:sage:alice", b"Hello, Alice!".to_vec())
        .await
        .unwrap();

    assert!(response.is_success());
    assert_eq!(response.status, 200);

    // Verify message was stored
    let sent = transport.get_sent_messages("did:sage:alice");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0], b"Hello, Alice!");
}

/// Test MockTransport with message envelope
#[tokio::test]
async fn test_mock_transport_message_envelope() {
    let transport = MockTransport::new();

    let message = TransportMessage::new("did:sage:bob", b"Test message".to_vec())
        .with_id("msg-123")
        .with_metadata("priority", "high");

    let response = transport.send_message(message).await.unwrap();

    assert!(response.is_success());
    assert_eq!(response.message_id.unwrap(), "msg-123");
}

/// Test MockTransport custom response
#[tokio::test]
async fn test_mock_transport_custom_response() {
    let transport = MockTransport::new();

    // Set custom response for specific destination
    let custom_response = TransportResponse::new(b"Custom reply".to_vec(), 201);
    transport.set_response("did:sage:charlie", custom_response);

    let response = transport
        .send("did:sage:charlie", b"Request".to_vec())
        .await
        .unwrap();

    assert_eq!(response.status, 201);
    assert_eq!(response.payload, b"Custom reply");
}

/// Test TransportManager with single transport
#[tokio::test]
async fn test_transport_manager_single() {
    let manager = TransportManager::new();
    let transport = Arc::new(MockTransport::new());

    manager.register_transport("mock", transport.clone());

    let response = manager
        .send("did:sage:dave", b"Hello".to_vec())
        .await
        .unwrap();

    assert!(response.is_success());

    // Verify message was routed correctly
    assert_eq!(transport.count_sent_messages("did:sage:dave"), 1);
}

/// Test TransportManager with multiple transports
#[tokio::test]
async fn test_transport_manager_multiple() {
    let manager = TransportManager::new();
    let transport1 = Arc::new(MockTransport::new());
    let transport2 = Arc::new(MockTransport::new());

    manager.register_transport("mock1", transport1.clone());
    manager.register_transport("mock2", transport2.clone());

    // First transport becomes default
    assert_eq!(manager.get_default_transport_name().unwrap(), "mock1");

    // Send using default transport
    manager
        .send("did:sage:eve", b"Test".to_vec())
        .await
        .unwrap();

    assert_eq!(transport1.count_sent_messages("did:sage:eve"), 1);
    assert_eq!(transport2.count_sent_messages("did:sage:eve"), 0);

    // Change default and send again
    manager.set_default_transport("mock2").unwrap();
    manager
        .send("did:sage:eve", b"Test2".to_vec())
        .await
        .unwrap();

    assert_eq!(transport1.count_sent_messages("did:sage:eve"), 1);
    assert_eq!(transport2.count_sent_messages("did:sage:eve"), 1);
}

/// Test TransportManager explicit transport selection
#[tokio::test]
async fn test_transport_manager_explicit_selection() {
    let manager = TransportManager::new();
    let transport1 = Arc::new(MockTransport::new());
    let transport2 = Arc::new(MockTransport::new());

    manager.register_transport("mock1", transport1.clone());
    manager.register_transport("mock2", transport2.clone());

    // Send using explicit transport
    manager
        .send_with_transport("mock2", "did:sage:frank", b"Hello".to_vec())
        .await
        .unwrap();

    // Verify only mock2 received the message
    assert_eq!(transport1.count_sent_messages("did:sage:frank"), 0);
    assert_eq!(transport2.count_sent_messages("did:sage:frank"), 1);
}

/// Test TransportManager automatic transport selection
#[tokio::test]
async fn test_transport_manager_auto_selection() {
    let manager = TransportManager::new();
    let mock = Arc::new(MockTransport::new());
    let http_mock = Arc::new(MockTransport::new()); // Mock for HTTP

    manager.register_transport("mock", mock.clone());
    manager.register_transport("http", http_mock.clone());

    // URL should select HTTP transport
    manager
        .send_auto("https://example.com/api", b"Request".to_vec())
        .await
        .unwrap();

    assert_eq!(http_mock.count_sent_messages("https://example.com/api"), 1);
    assert_eq!(mock.count_sent_messages("https://example.com/api"), 0);

    // DID should use default transport
    manager
        .send_auto("did:sage:grace", b"Message".to_vec())
        .await
        .unwrap();

    assert_eq!(mock.count_sent_messages("did:sage:grace"), 1);
}

/// Test HttpTransport configuration
#[test]
fn test_http_transport_config() {
    let mut config = TransportConfig::default();
    config.request_timeout = Duration::from_secs(60);
    config.max_retries = 5;
    config.verify_tls = false;

    let transport = HttpTransport::with_config(config);
    assert!(transport.is_ok());
}

/// Test HttpTransport basic properties
#[test]
fn test_http_transport_properties() {
    let transport = HttpTransport::new().unwrap();

    assert_eq!(transport.name(), "http");
    assert!(transport.is_available());
}

/// Test transport availability
#[tokio::test]
async fn test_transport_availability() {
    let transport = MockTransport::new();
    assert!(transport.is_available());

    transport.set_available(false);
    assert!(!transport.is_available());

    transport.set_available(true);
    assert!(transport.is_available());
}

/// Test transport cleanup
#[tokio::test]
async fn test_transport_cleanup() {
    let transport = MockTransport::new();

    // Send multiple messages
    for i in 0..5 {
        transport
            .send(&format!("did:sage:user{}", i), b"Test".to_vec())
            .await
            .unwrap();
    }

    let all_messages = transport.get_all_sent_messages();
    assert_eq!(all_messages.len(), 5);

    // Clear all messages
    transport.clear_sent_messages();

    let all_messages = transport.get_all_sent_messages();
    assert_eq!(all_messages.len(), 0);
}

/// Test TransportManager as MessageTransport trait
#[tokio::test]
async fn test_transport_manager_as_trait() {
    let manager = TransportManager::new();
    let transport = Arc::new(MockTransport::new());

    manager.register_transport("mock", transport.clone());

    // Use manager as MessageTransport
    let trait_obj: &dyn MessageTransport = &manager;

    assert_eq!(trait_obj.name(), "manager");
    assert!(trait_obj.is_available());

    let response = trait_obj
        .send("did:sage:harry", b"Test".to_vec())
        .await
        .unwrap();

    assert!(response.is_success());
}

/// Test transport error handling
#[tokio::test]
async fn test_transport_error_handling() {
    let manager = TransportManager::new();

    // No transports registered - should fail
    let result = manager.send("did:sage:invalid", b"Test".to_vec()).await;
    assert!(result.is_err());

    // Invalid transport name - should fail
    let result = manager
        .send_with_transport("nonexistent", "did:sage:test", b"Test".to_vec())
        .await;
    assert!(result.is_err());
}

/// Test message ID preservation
#[tokio::test]
async fn test_message_id_preservation() {
    let transport = MockTransport::new();

    let message = TransportMessage::new("did:sage:iris", b"Test".to_vec())
        .with_id("unique-msg-id-123");

    let response = transport.send_message(message).await.unwrap();

    assert_eq!(response.message_id.unwrap(), "unique-msg-id-123");
}

/// Test transport response status codes
#[test]
fn test_response_status_codes() {
    let success = TransportResponse::new(vec![], 200);
    assert!(success.is_success());
    assert!(!success.is_error());

    let created = TransportResponse::new(vec![], 201);
    assert!(created.is_success());
    assert!(!created.is_error());

    let not_found = TransportResponse::new(vec![], 404);
    assert!(!not_found.is_success());
    assert!(not_found.is_error());

    let server_error = TransportResponse::new(vec![], 500);
    assert!(!server_error.is_success());
    assert!(server_error.is_error());
}
