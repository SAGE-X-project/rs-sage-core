//! Transport Manager

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;

use crate::transport::traits::MessageTransport;
use crate::transport::types::{TransportError, TransportMessage, TransportResponse, TransportResult};

/// Transport manager for managing multiple transports
///
/// The transport manager routes messages to appropriate transports
/// based on destination or explicit transport selection.
pub struct TransportManager {
    /// Registered transports (name -> transport)
    transports: Arc<DashMap<String, Arc<dyn MessageTransport>>>,
    /// Default transport name
    default_transport: Arc<parking_lot::RwLock<Option<String>>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new() -> Self {
        Self {
            transports: Arc::new(DashMap::new()),
            default_transport: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Register a transport
    pub fn register_transport(&self, name: impl Into<String>, transport: Arc<dyn MessageTransport>) {
        let name = name.into();
        self.transports.insert(name.clone(), transport);

        // Set as default if it's the first transport
        let mut default = self.default_transport.write();
        if default.is_none() {
            *default = Some(name);
        }
    }

    /// Unregister a transport
    pub fn unregister_transport(&self, name: &str) -> Option<Arc<dyn MessageTransport>> {
        self.transports.remove(name).map(|(_, t)| t)
    }

    /// Get a transport by name
    pub fn get_transport(&self, name: &str) -> Option<Arc<dyn MessageTransport>> {
        self.transports.get(name).map(|t| t.clone())
    }

    /// Set default transport
    pub fn set_default_transport(&self, name: impl Into<String>) -> TransportResult<()> {
        let name = name.into();

        if !self.transports.contains_key(&name) {
            return Err(TransportError::TransportNotAvailable(
                format!("Transport not registered: {}", name)
            ));
        }

        *self.default_transport.write() = Some(name);
        Ok(())
    }

    /// Get default transport name
    pub fn get_default_transport_name(&self) -> Option<String> {
        self.default_transport.read().clone()
    }

    /// Get default transport
    pub fn get_default_transport(&self) -> Option<Arc<dyn MessageTransport>> {
        self.default_transport
            .read()
            .as_ref()
            .and_then(|name| self.get_transport(name))
    }

    /// List all registered transport names
    pub fn list_transports(&self) -> Vec<String> {
        self.transports.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Count registered transports
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    /// Clear all transports
    pub fn clear(&self) {
        self.transports.clear();
        *self.default_transport.write() = None;
    }

    /// Send using a specific transport
    pub async fn send_with_transport(
        &self,
        transport_name: &str,
        destination: &str,
        payload: Vec<u8>,
    ) -> TransportResult<TransportResponse> {
        let transport = self.get_transport(transport_name)
            .ok_or_else(|| TransportError::TransportNotAvailable(
                format!("Transport not found: {}", transport_name)
            ))?;

        transport.send(destination, payload).await
    }

    /// Send using default transport
    pub async fn send(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> TransportResult<TransportResponse> {
        let transport = self.get_default_transport()
            .ok_or_else(|| TransportError::TransportNotAvailable(
                "No default transport configured".to_string()
            ))?;

        transport.send(destination, payload).await
    }

    /// Send message using default transport
    pub async fn send_message(&self, message: TransportMessage) -> TransportResult<TransportResponse> {
        let transport = self.get_default_transport()
            .ok_or_else(|| TransportError::TransportNotAvailable(
                "No default transport configured".to_string()
            ))?;

        transport.send_message(message).await
    }

    /// Select transport based on destination
    ///
    /// This method uses heuristics to select appropriate transport:
    /// - URLs starting with http:// or https:// -> HTTP transport
    /// - DIDs -> Default transport
    pub fn select_transport_for_destination(&self, destination: &str) -> Option<Arc<dyn MessageTransport>> {
        // URL detection
        if destination.starts_with("http://") || destination.starts_with("https://") {
            if let Some(transport) = self.get_transport("http") {
                return Some(transport);
            }
        }

        // Fall back to default
        self.get_default_transport()
    }

    /// Send with automatic transport selection
    pub async fn send_auto(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> TransportResult<TransportResponse> {
        let transport = self.select_transport_for_destination(destination)
            .ok_or_else(|| TransportError::TransportNotAvailable(
                "No suitable transport found".to_string()
            ))?;

        transport.send(destination, payload).await
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessageTransport for TransportManager {
    async fn send(&self, destination: &str, payload: Vec<u8>) -> TransportResult<TransportResponse> {
        self.send_auto(destination, payload).await
    }

    async fn send_message(&self, message: TransportMessage) -> TransportResult<TransportResponse> {
        let transport = self.select_transport_for_destination(&message.destination)
            .ok_or_else(|| TransportError::TransportNotAvailable(
                "No suitable transport found".to_string()
            ))?;

        transport.send_message(message).await
    }

    fn is_available(&self) -> bool {
        self.get_default_transport().is_some()
    }

    fn name(&self) -> &'static str {
        "manager"
    }

    async fn close(&self) -> TransportResult<()> {
        // Collect all transports before closing to avoid lifetime issues
        let transports: Vec<Arc<dyn MessageTransport>> = self.transports
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        // Close all transports
        for transport in transports {
            let _ = transport.close().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn test_transport_manager_creation() {
        let manager = TransportManager::new();
        assert_eq!(manager.transport_count(), 0);
        assert!(manager.get_default_transport().is_none());
    }

    #[test]
    fn test_register_transport() {
        let manager = TransportManager::new();
        let transport = Arc::new(MockTransport::new());

        manager.register_transport("mock", transport);

        assert_eq!(manager.transport_count(), 1);
        assert!(manager.get_transport("mock").is_some());

        // First transport becomes default
        assert_eq!(manager.get_default_transport_name().unwrap(), "mock");
    }

    #[test]
    fn test_unregister_transport() {
        let manager = TransportManager::new();
        let transport = Arc::new(MockTransport::new());

        manager.register_transport("mock", transport);
        assert_eq!(manager.transport_count(), 1);

        let removed = manager.unregister_transport("mock");
        assert!(removed.is_some());
        assert_eq!(manager.transport_count(), 0);
    }

    #[test]
    fn test_set_default_transport() {
        let manager = TransportManager::new();
        let transport1 = Arc::new(MockTransport::new());
        let transport2 = Arc::new(MockTransport::new());

        manager.register_transport("mock1", transport1);
        manager.register_transport("mock2", transport2);

        // First becomes default
        assert_eq!(manager.get_default_transport_name().unwrap(), "mock1");

        // Change default
        manager.set_default_transport("mock2").unwrap();
        assert_eq!(manager.get_default_transport_name().unwrap(), "mock2");
    }

    #[test]
    fn test_set_invalid_default_transport() {
        let manager = TransportManager::new();
        let result = manager.set_default_transport("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_transports() {
        let manager = TransportManager::new();

        manager.register_transport("mock1", Arc::new(MockTransport::new()));
        manager.register_transport("mock2", Arc::new(MockTransport::new()));

        let transports = manager.list_transports();
        assert_eq!(transports.len(), 2);
        assert!(transports.contains(&"mock1".to_string()));
        assert!(transports.contains(&"mock2".to_string()));
    }

    #[test]
    fn test_clear_transports() {
        let manager = TransportManager::new();

        manager.register_transport("mock1", Arc::new(MockTransport::new()));
        manager.register_transport("mock2", Arc::new(MockTransport::new()));

        assert_eq!(manager.transport_count(), 2);

        manager.clear();

        assert_eq!(manager.transport_count(), 0);
        assert!(manager.get_default_transport().is_none());
    }

    #[tokio::test]
    async fn test_send_with_transport() {
        let manager = TransportManager::new();
        let transport = Arc::new(MockTransport::new());

        manager.register_transport("mock", transport.clone());

        let response = manager
            .send_with_transport("mock", "did:sage:alice", b"Hello".to_vec())
            .await
            .unwrap();

        assert!(response.is_success());

        // Verify message was sent
        assert_eq!(transport.count_sent_messages("did:sage:alice"), 1);
    }

    #[tokio::test]
    async fn test_send_default_transport() {
        let manager = TransportManager::new();
        let transport = Arc::new(MockTransport::new());

        manager.register_transport("mock", transport.clone());

        let response = manager.send("did:sage:bob", b"Test".to_vec()).await.unwrap();

        assert!(response.is_success());
        assert_eq!(transport.count_sent_messages("did:sage:bob"), 1);
    }

    #[tokio::test]
    async fn test_send_no_default_transport() {
        let manager = TransportManager::new();

        let result = manager.send("did:sage:charlie", b"Test".to_vec()).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_message() {
        let manager = TransportManager::new();
        let transport = Arc::new(MockTransport::new());

        manager.register_transport("mock", transport.clone());

        let message = TransportMessage::new("did:sage:dave", b"Hello".to_vec())
            .with_id("msg-123");

        let response = manager.send_message(message).await.unwrap();

        assert!(response.is_success());
        assert_eq!(response.message_id.unwrap(), "msg-123");
    }

    #[test]
    fn test_select_transport_for_destination() {
        let manager = TransportManager::new();
        let mock_transport = Arc::new(MockTransport::new());
        let http_transport = Arc::new(MockTransport::new()); // Using mock for testing

        manager.register_transport("mock", mock_transport);
        manager.register_transport("http", http_transport);

        // URL should select HTTP transport
        let transport = manager.select_transport_for_destination("https://example.com");
        assert!(transport.is_some());

        // DID should fall back to default
        let transport = manager.select_transport_for_destination("did:sage:alice");
        assert!(transport.is_some());
    }

    #[tokio::test]
    async fn test_send_auto() {
        let manager = TransportManager::new();
        let transport = Arc::new(MockTransport::new());

        manager.register_transport("mock", transport.clone());

        let response = manager.send_auto("did:sage:eve", b"Auto".to_vec()).await.unwrap();

        assert!(response.is_success());
    }

    #[test]
    fn test_transport_manager_name() {
        let manager = TransportManager::new();
        assert_eq!(manager.name(), "manager");
    }

    #[tokio::test]
    async fn test_transport_manager_close() {
        let manager = TransportManager::new();
        manager.register_transport("mock", Arc::new(MockTransport::new()));

        let result = manager.close().await;
        assert!(result.is_ok());
    }
}
