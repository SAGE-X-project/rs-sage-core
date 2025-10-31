//! Transport Layer (Phase 5.1)
//!
//! This module provides transport abstraction for SAGE agent communication.
//! It supports multiple transport types (HTTP, WebSocket, Mock) through a
//! unified MessageTransport trait.
//!
//! # Architecture
//!
//! - **MessageTransport trait**: Abstract interface for all transports
//! - **MockTransport**: In-memory transport for testing
//! - **HttpTransport**: HTTP-based request/response transport
//! - **TransportManager**: Manages transport instances and routing
//!
//! # Example
//!
//! ```rust
//! use sage_crypto_core::transport::{MockTransport, MessageTransport};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let transport = MockTransport::new();
//!     let payload = b"Hello, SAGE!".to_vec();
//!
//!     let response = transport.send("did:sage:alice", payload).await?;
//!     println!("Response: {:?}", response);
//!     Ok(())
//! }
//! ```

pub mod types;
pub mod traits;
pub mod mock;
pub mod http;
pub mod manager;

// Re-export main types
pub use traits::MessageTransport;
pub use types::{TransportConfig, TransportError, TransportMessage, TransportResponse, TransportResult};
pub use mock::MockTransport;
pub use http::HttpTransport;
pub use manager::TransportManager;
