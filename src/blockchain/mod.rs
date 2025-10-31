//! Blockchain Integration Module
//!
//! This module provides blockchain integration for agent registration and DID resolution
//! using secure, modern libraries (alloy for Ethereum, solana-sdk for Solana).
//!
//! # Phase 9 Implementation
//!
//! This is a complete rewrite of the blockchain integration, replacing the deprecated
//! ethers-based implementation with alloy (RUSTSEC-2025-0009 fix).
//!
//! # Features
//!
//! - Multi-chain support (Ethereum, Solana)
//! - Enhanced DID format with owner address validation
//! - Public key ownership verification
//! - Atomic key rotation
//! - Multi-key support (up to 10 keys per agent)
//! - SageRegistryV4 contract integration

pub mod types;

#[cfg(feature = "blockchain")]
pub mod ethereum;

#[cfg(feature = "blockchain")]
pub mod solana;

#[cfg(feature = "blockchain")]
pub mod ownership;

#[cfg(feature = "blockchain")]
pub mod manager;

pub use types::{
    AgentDID, AgentMetadata, Chain, DIDFormat, Network, PublicKeyInfo,
    derive_ethereum_address, generate_agent_did_with_address, generate_agent_did_with_nonce,
};

#[cfg(feature = "blockchain")]
pub use ownership::{
    recover_public_key, verify_ecdsa_ownership, verify_ownership_signature,
};

#[cfg(feature = "blockchain")]
pub use ethereum::{EthereumClient, EthereumResolver};

#[cfg(feature = "blockchain")]
pub use solana::{SolanaClient, SolanaResolver};

#[cfg(feature = "blockchain")]
pub use manager::MultiChainManager;
