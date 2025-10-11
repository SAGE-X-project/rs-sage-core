//! Blockchain Integration Module
//!
//! This module provides blockchain integration for SAGE, enabling on-chain
//! DID registration, resolution, and nonce tracking.
//!
//! ## Features
//!
//! - Ethereum/EVM-compatible blockchain client
//! - Transaction signing and submission
//! - Smart contract interaction
//! - DID Registry integration
//! - Event listening and synchronization
//!
//! ## Usage
//!
//! This module is only available when the `blockchain` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! sage_crypto_core = { version = "0.1", features = ["blockchain"] }
//! ```

#[cfg(feature = "blockchain")]
pub mod client;
#[cfg(feature = "blockchain")]
pub mod transaction;
#[cfg(feature = "blockchain")]
pub mod contract;
#[cfg(feature = "blockchain")]
pub mod did_registry;
#[cfg(feature = "blockchain")]
pub mod nonce_tracker;
#[cfg(feature = "blockchain")]
pub mod event_listener;
#[cfg(feature = "blockchain")]
pub mod synchronizer;

#[cfg(feature = "blockchain")]
pub use client::{BlockchainClient, BlockchainConfig};
#[cfg(feature = "blockchain")]
pub use transaction::{Transaction, TransactionReceipt};
#[cfg(feature = "blockchain")]
pub use contract::{ContractCall, ContractHelper, ContractInterface};
#[cfg(feature = "blockchain")]
pub use did_registry::DIDRegistry;
#[cfg(feature = "blockchain")]
pub use nonce_tracker::NonceTracker;
#[cfg(feature = "blockchain")]
pub use event_listener::{EventListener, EventListenerConfig, RegistryEvent, EventCallback, EventCallbacks};
#[cfg(feature = "blockchain")]
pub use synchronizer::{Synchronizer, SynchronizerBuilder};

/// Re-export ethers types for convenience
#[cfg(feature = "blockchain")]
pub use ethers::prelude::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_blockchain_module() {
        // Module structure test
        #[cfg(feature = "blockchain")]
        {
            // Blockchain feature is enabled
            assert!(true);
        }

        #[cfg(not(feature = "blockchain"))]
        {
            // Blockchain feature is disabled
            assert!(true);
        }
    }
}
