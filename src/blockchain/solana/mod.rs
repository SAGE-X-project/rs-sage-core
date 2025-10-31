//! Solana Blockchain Integration
//!
//! Solana-specific client and resolver implementations for SAGE Agent Registry.

pub mod client;
pub mod resolver;

pub use client::{SolanaClient, AgentAccount, RegistrationParams};
pub use resolver::SolanaResolver;
