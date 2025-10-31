//! HTTP Transport

use async_trait::async_trait;
use reqwest::{Client, ClientBuilder};
use std::sync::Arc;

use crate::transport::traits::MessageTransport;
use crate::transport::types::{TransportConfig, TransportError, TransportMessage, TransportResponse, TransportResult};

/// HTTP-based message transport
///
/// This transport sends messages over HTTP POST requests.
/// It supports timeouts, retries, and custom headers.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: Arc<Client>,
    config: TransportConfig,
}

impl HttpTransport {
    /// Create a new HTTP transport with default configuration
    pub fn new() -> TransportResult<Self> {
        Self::with_config(TransportConfig::default())
    }

    /// Create a new HTTP transport with custom configuration
    pub fn with_config(config: TransportConfig) -> TransportResult<Self> {
        let client = ClientBuilder::new()
            .timeout(config.request_timeout)
            .connect_timeout(config.connect_timeout)
            .danger_accept_invalid_certs(!config.verify_tls)
            .user_agent(&config.user_agent)
            .build()
            .map_err(|e| TransportError::ConnectionError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client: Arc::new(client),
            config,
        })
    }

    /// Convert destination (DID or URL) to HTTP endpoint
    fn resolve_endpoint(&self, destination: &str) -> TransportResult<String> {
        // If destination is already a URL, use it directly
        if destination.starts_with("http://") || destination.starts_with("https://") {
            return Ok(destination.to_string());
        }

        // If destination is a DID, we would need a DID-to-URL resolver
        // For now, return an error for DIDs
        Err(TransportError::InvalidDestination(
            format!("Cannot resolve DID to HTTP endpoint: {}", destination)
        ))
    }

    /// Send HTTP request with retry logic
    async fn send_with_retry(&self, url: &str, payload: Vec<u8>) -> TransportResult<TransportResponse> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                tokio::time::sleep(self.config.retry_delay).await;
            }

            match self.send_once(url, payload.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            TransportError::SendError("All retry attempts failed".to_string())
        }))
    }

    /// Send a single HTTP request
    async fn send_once(&self, url: &str, payload: Vec<u8>) -> TransportResult<TransportResponse> {
        let mut request = self.client
            .post(url)
            .header("Content-Type", "application/octet-stream");

        // Add custom headers
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        let response = request
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    TransportError::Timeout(format!("Request timeout: {}", e))
                } else if e.is_connect() {
                    TransportError::ConnectionError(format!("Connection failed: {}", e))
                } else {
                    TransportError::SendError(format!("Request failed: {}", e))
                }
            })?;

        let status = response.status().as_u16();
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| TransportError::ReceiveError(format!("Failed to read response: {}", e)))?
            .to_vec();

        Ok(TransportResponse::new(response_bytes, status))
    }
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new().expect("Failed to create default HTTP transport")
    }
}

#[async_trait]
impl MessageTransport for HttpTransport {
    async fn send(&self, destination: &str, payload: Vec<u8>) -> TransportResult<TransportResponse> {
        let url = self.resolve_endpoint(destination)?;
        self.send_with_retry(&url, payload).await
    }

    async fn send_message(&self, message: TransportMessage) -> TransportResult<TransportResponse> {
        let url = self.resolve_endpoint(&message.destination)?;
        let mut response = self.send_with_retry(&url, message.payload).await?;

        // Preserve message ID
        if let Some(msg_id) = message.message_id {
            response.message_id = Some(msg_id);
        }

        Ok(response)
    }

    fn is_available(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "http"
    }

    async fn close(&self) -> TransportResult<()> {
        // HTTP client doesn't need explicit cleanup
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_http_transport_creation() {
        let transport = HttpTransport::new();
        assert!(transport.is_ok());
    }

    #[test]
    fn test_http_transport_with_config() {
        let mut config = TransportConfig::default();
        config.request_timeout = Duration::from_secs(60);
        config.max_retries = 5;

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_resolve_endpoint_url() {
        let transport = HttpTransport::new().unwrap();

        let url = "https://example.com/api/message";
        let resolved = transport.resolve_endpoint(url);
        assert!(resolved.is_ok());
        assert_eq!(resolved.unwrap(), url);
    }

    #[test]
    fn test_resolve_endpoint_did() {
        let transport = HttpTransport::new().unwrap();

        let did = "did:sage:alice";
        let resolved = transport.resolve_endpoint(did);
        assert!(resolved.is_err());
    }

    #[test]
    fn test_http_transport_name() {
        let transport = HttpTransport::new().unwrap();
        assert_eq!(transport.name(), "http");
    }

    #[test]
    fn test_http_transport_is_available() {
        let transport = HttpTransport::new().unwrap();
        assert!(transport.is_available());
    }

    #[tokio::test]
    async fn test_http_transport_close() {
        let transport = HttpTransport::new().unwrap();
        let result = transport.close().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_http_transport_default() {
        let transport = HttpTransport::default();
        assert_eq!(transport.name(), "http");
        assert!(transport.is_available());
    }

    #[test]
    fn test_resolve_endpoint_http_url() {
        let transport = HttpTransport::new().unwrap();

        let url = "http://example.com/api/message";
        let resolved = transport.resolve_endpoint(url);
        assert!(resolved.is_ok());
        assert_eq!(resolved.unwrap(), url);
    }

    #[test]
    fn test_resolve_endpoint_https_url() {
        let transport = HttpTransport::new().unwrap();

        let url = "https://secure.example.com/api";
        let resolved = transport.resolve_endpoint(url);
        assert!(resolved.is_ok());
        assert_eq!(resolved.unwrap(), url);
    }

    #[test]
    fn test_resolve_endpoint_invalid() {
        let transport = HttpTransport::new().unwrap();

        let invalid = "ftp://example.com";
        let resolved = transport.resolve_endpoint(invalid);
        assert!(resolved.is_err());
    }

    #[test]
    fn test_config_custom_headers() {
        let mut config = TransportConfig::default();
        config.headers.insert("X-Custom-Header".to_string(), "custom-value".to_string());
        config.headers.insert("Authorization".to_string(), "Bearer token123".to_string());

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_config_verify_tls_enabled() {
        let mut config = TransportConfig::default();
        config.verify_tls = true;

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_config_verify_tls_disabled() {
        let mut config = TransportConfig::default();
        config.verify_tls = false;

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_config_custom_user_agent() {
        let mut config = TransportConfig::default();
        config.user_agent = "CustomAgent/1.0".to_string();

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_config_timeouts() {
        let mut config = TransportConfig::default();
        config.request_timeout = Duration::from_secs(30);
        config.connect_timeout = Duration::from_secs(10);

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_config_retry_settings() {
        let mut config = TransportConfig::default();
        config.max_retries = 3;
        config.retry_delay = Duration::from_millis(100);

        let transport = HttpTransport::with_config(config.clone());
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert_eq!(transport.config.max_retries, 3);
        assert_eq!(transport.config.retry_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_config_all_options() {
        let mut config = TransportConfig::default();
        config.request_timeout = Duration::from_secs(45);
        config.connect_timeout = Duration::from_secs(15);
        config.max_retries = 5;
        config.retry_delay = Duration::from_millis(500);
        config.verify_tls = false;
        config.user_agent = "TestAgent/2.0".to_string();
        config.headers.insert("X-Test".to_string(), "test-value".to_string());

        let transport = HttpTransport::with_config(config);
        assert!(transport.is_ok());
    }

    // Integration test with a real HTTP endpoint would require a test server
    // This is better suited for integration tests in tests/ directory
}
