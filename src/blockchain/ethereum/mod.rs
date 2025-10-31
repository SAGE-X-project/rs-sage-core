//! Ethereum Blockchain Integration
//!
//! Ethereum-specific client and resolver implementations for AgentCardRegistry.

pub mod client;
pub mod resolver;

pub use client::EthereumClient;
pub use resolver::EthereumResolver;
