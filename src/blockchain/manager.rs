//! Multi-Chain Manager
//!
//! This module provides a unified interface for managing multiple blockchain clients.
//!
//! # Features
//!
//! - Support for multiple chains (Ethereum, Solana)
//! - Unified interface for agent operations
//! - Chain-specific client management
//! - Async operations
//!
//! # Example
//!
//! ```ignore
//! use sage_crypto_core::blockchain::{MultiChainManager, Chain};
//!
//! let mut manager = MultiChainManager::new();
//!
//! // Add Ethereum client
//! manager.add_ethereum_client(
//!     "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
//!     "0x1234567890123456789012345678901234567890",
//! ).await?;
//!
//! // Add Solana client
//! manager.add_solana_client(
//!     "https://api.devnet.solana.com",
//!     "11111111111111111111111111111111",
//! ).await?;
//!
//! // Use a specific chain
//! let metadata = manager.get_agent(Chain::Ethereum, "did:sage:ethereum:0x...").await?;
//! ```

use crate::blockchain::types::{AgentMetadata, Chain};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "blockchain")]
use crate::blockchain::{EthereumClient, SolanaClient};

/// Multi-chain manager for agent registry operations
///
/// Manages multiple blockchain clients and provides a unified interface
/// for agent operations across different chains.
#[cfg(feature = "blockchain")]
pub struct MultiChainManager {
    /// Ethereum clients by network
    ethereum_clients: HashMap<String, Arc<EthereumClient>>,
    /// Solana clients by network
    solana_clients: HashMap<String, Arc<SolanaClient>>,
    /// Default chain to use when not specified
    default_chain: Option<Chain>,
}

#[cfg(feature = "blockchain")]
impl MultiChainManager {
    /// Create a new multi-chain manager
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::blockchain::MultiChainManager;
    ///
    /// let manager = MultiChainManager::new();
    /// ```
    pub fn new() -> Self {
        Self {
            ethereum_clients: HashMap::new(),
            solana_clients: HashMap::new(),
            default_chain: None,
        }
    }

    /// Set the default chain
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to use as default
    ///
    /// # Example
    ///
    /// ```
    /// use sage_crypto_core::blockchain::{MultiChainManager, Chain};
    ///
    /// let mut manager = MultiChainManager::new();
    /// manager.set_default_chain(Chain::Ethereum);
    /// ```
    pub fn set_default_chain(&mut self, chain: Chain) {
        self.default_chain = Some(chain);
    }

    /// Get the default chain
    ///
    /// # Returns
    ///
    /// The default chain, or None if not set
    pub fn default_chain(&self) -> Option<Chain> {
        self.default_chain
    }

    /// Add an Ethereum client
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - Ethereum RPC URL
    /// * `registry_address` - AgentCardRegistry contract address
    /// * `network_name` - Optional network identifier (e.g., "sepolia", "mainnet")
    ///
    /// # Errors
    ///
    /// Returns error if client creation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut manager = MultiChainManager::new();
    /// manager.add_ethereum_client(
    ///     "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
    ///     "0x1234567890123456789012345678901234567890",
    ///     Some("sepolia"),
    /// ).await?;
    /// ```
    pub async fn add_ethereum_client(
        &mut self,
        rpc_url: &str,
        registry_address: &str,
        network_name: Option<&str>,
    ) -> Result<()> {
        let client = EthereumClient::new(rpc_url, registry_address).await?;
        let network = network_name.unwrap_or("default").to_string();
        self.ethereum_clients.insert(network, Arc::new(client));

        // Set as default if first client added
        if self.default_chain.is_none() {
            self.default_chain = Some(Chain::Ethereum);
        }

        Ok(())
    }

    /// Add a Solana client
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - Solana RPC URL
    /// * `program_id` - SAGE Agent Registry program ID
    /// * `network_name` - Optional network identifier (e.g., "devnet", "mainnet")
    ///
    /// # Errors
    ///
    /// Returns error if client creation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut manager = MultiChainManager::new();
    /// manager.add_solana_client(
    ///     "https://api.devnet.solana.com",
    ///     "11111111111111111111111111111111",
    ///     Some("devnet"),
    /// ).await?;
    /// ```
    pub async fn add_solana_client(
        &mut self,
        rpc_url: &str,
        program_id: &str,
        network_name: Option<&str>,
    ) -> Result<()> {
        let client = SolanaClient::new(rpc_url, program_id)?;
        let network = network_name.unwrap_or("default").to_string();
        self.solana_clients.insert(network, Arc::new(client));

        // Set as default if no chain set yet
        if self.default_chain.is_none() {
            self.default_chain = Some(Chain::Solana);
        }

        Ok(())
    }

    /// Get Ethereum client for a specific network
    ///
    /// # Arguments
    ///
    /// * `network_name` - Network identifier (default: "default")
    ///
    /// # Errors
    ///
    /// Returns error if client not found
    pub fn get_ethereum_client(&self, network_name: Option<&str>) -> Result<Arc<EthereumClient>> {
        let network = network_name.unwrap_or("default");
        self.ethereum_clients
            .get(network)
            .cloned()
            .ok_or_else(|| Error::InvalidInput(format!("Ethereum client not found for network: {}", network)))
    }

    /// Get Solana client for a specific network
    ///
    /// # Arguments
    ///
    /// * `network_name` - Network identifier (default: "default")
    ///
    /// # Errors
    ///
    /// Returns error if client not found
    pub fn get_solana_client(&self, network_name: Option<&str>) -> Result<Arc<SolanaClient>> {
        let network = network_name.unwrap_or("default");
        self.solana_clients
            .get(network)
            .cloned()
            .ok_or_else(|| Error::InvalidInput(format!("Solana client not found for network: {}", network)))
    }

    /// Get agent metadata from Ethereum
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID
    /// * `network_name` - Optional network identifier
    ///
    /// # Errors
    ///
    /// Returns error if client not found or agent not found
    ///
    /// # Example
    ///
    /// ```ignore
    /// let metadata = manager.get_ethereum_agent(
    ///     "did:sage:ethereum:0x...",
    ///     None,
    /// ).await?;
    /// ```
    pub async fn get_ethereum_agent(
        &self,
        did: &str,
        network_name: Option<&str>,
    ) -> Result<AgentMetadata> {
        let client = self.get_ethereum_client(network_name)?;
        client.get_agent_by_did(did).await
    }

    /// Get agent metadata from Solana
    ///
    /// # Arguments
    ///
    /// * `owner` - Owner's public key
    /// * `did` - Agent DID
    /// * `network_name` - Optional network identifier
    ///
    /// # Errors
    ///
    /// Returns error if client not found or agent not found
    pub async fn get_solana_agent(
        &self,
        owner: &str,
        did: &str,
        network_name: Option<&str>,
    ) -> Result<crate::blockchain::solana::AgentAccount> {
        use solana_sdk::pubkey::Pubkey;
        use std::str::FromStr;

        let client = self.get_solana_client(network_name)?;
        let owner_pubkey = Pubkey::from_str(owner)
            .map_err(|e| Error::InvalidInput(format!("Invalid Solana pubkey: {}", e)))?;
        client.get_agent(&owner_pubkey, did).await
    }

    /// Check if Ethereum agent is active
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID
    /// * `network_name` - Optional network identifier
    ///
    /// # Errors
    ///
    /// Returns error if chain not supported or query fails
    pub async fn is_ethereum_agent_active(
        &self,
        did: &str,
        network_name: Option<&str>,
    ) -> Result<bool> {
        let metadata = self.get_ethereum_agent(did, network_name).await?;
        Ok(metadata.is_active)
    }

    /// Check if Solana agent is active
    ///
    /// # Arguments
    ///
    /// * `owner` - Owner's public key
    /// * `did` - Agent DID
    /// * `network_name` - Optional network identifier
    ///
    /// # Errors
    ///
    /// Returns error if chain not supported or query fails
    pub async fn is_solana_agent_active(
        &self,
        owner: &str,
        did: &str,
        network_name: Option<&str>,
    ) -> Result<bool> {
        use solana_sdk::pubkey::Pubkey;
        use std::str::FromStr;

        let client = self.get_solana_client(network_name)?;
        let owner_pubkey = Pubkey::from_str(owner)
            .map_err(|e| Error::InvalidInput(format!("Invalid Solana pubkey: {}", e)))?;
        client.is_agent_active(&owner_pubkey, did).await
    }

    /// List all registered chains
    ///
    /// # Returns
    ///
    /// Vector of registered chains with their network names
    pub fn list_chains(&self) -> Vec<(Chain, Vec<String>)> {
        let mut chains = Vec::new();

        if !self.ethereum_clients.is_empty() {
            let networks: Vec<String> = self.ethereum_clients.keys().cloned().collect();
            chains.push((Chain::Ethereum, networks));
        }

        if !self.solana_clients.is_empty() {
            let networks: Vec<String> = self.solana_clients.keys().cloned().collect();
            chains.push((Chain::Solana, networks));
        }

        chains
    }

    /// Check if a chain is registered
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to check
    ///
    /// # Returns
    ///
    /// true if the chain has at least one client registered
    pub fn has_chain(&self, chain: Chain) -> bool {
        match chain {
            Chain::Ethereum => !self.ethereum_clients.is_empty(),
            Chain::Solana => !self.solana_clients.is_empty(),
        }
    }

    /// Remove all clients for a specific chain
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to remove
    pub fn remove_chain(&mut self, chain: Chain) {
        match chain {
            Chain::Ethereum => self.ethereum_clients.clear(),
            Chain::Solana => self.solana_clients.clear(),
        }

        // Update default chain if removed
        if self.default_chain == Some(chain) {
            self.default_chain = None;
        }
    }

    /// Remove a specific network client
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain
    /// * `network_name` - Network identifier
    pub fn remove_network(&mut self, chain: Chain, network_name: &str) {
        match chain {
            Chain::Ethereum => {
                self.ethereum_clients.remove(network_name);
            }
            Chain::Solana => {
                self.solana_clients.remove(network_name);
            }
        }
    }

    /// Get the number of registered clients
    ///
    /// # Returns
    ///
    /// Total number of registered blockchain clients
    pub fn client_count(&self) -> usize {
        self.ethereum_clients.len() + self.solana_clients.len()
    }
}

#[cfg(feature = "blockchain")]
impl Default for MultiChainManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "blockchain")]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let manager = MultiChainManager::new();
        assert_eq!(manager.client_count(), 0);
        assert!(manager.default_chain().is_none());
    }

    #[test]
    fn test_set_default_chain() {
        let mut manager = MultiChainManager::new();
        manager.set_default_chain(Chain::Ethereum);
        assert_eq!(manager.default_chain(), Some(Chain::Ethereum));

        manager.set_default_chain(Chain::Solana);
        assert_eq!(manager.default_chain(), Some(Chain::Solana));
    }

    #[test]
    fn test_has_chain() {
        let manager = MultiChainManager::new();
        assert!(!manager.has_chain(Chain::Ethereum));
        assert!(!manager.has_chain(Chain::Solana));
    }

    #[test]
    fn test_list_chains_empty() {
        let manager = MultiChainManager::new();
        let chains = manager.list_chains();
        assert_eq!(chains.len(), 0);
    }

    #[test]
    fn test_client_count() {
        let manager = MultiChainManager::new();
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_remove_chain() {
        let mut manager = MultiChainManager::new();
        manager.set_default_chain(Chain::Ethereum);

        manager.remove_chain(Chain::Ethereum);
        assert!(manager.default_chain().is_none());
    }

    #[test]
    fn test_get_ethereum_client_not_found() {
        let manager = MultiChainManager::new();
        let result = manager.get_ethereum_client(Some("mainnet"));
        assert!(result.is_err());
    }

    #[test]
    fn test_get_solana_client_not_found() {
        let manager = MultiChainManager::new();
        let result = manager.get_solana_client(Some("devnet"));
        assert!(result.is_err());
    }

    #[test]
    fn test_default_trait() {
        let manager = MultiChainManager::default();
        assert_eq!(manager.client_count(), 0);
        assert!(manager.default_chain().is_none());
    }

    #[test]
    fn test_get_ethereum_client_default_network() {
        let manager = MultiChainManager::new();
        // Test with None (should use "default")
        let result = manager.get_ethereum_client(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_solana_client_default_network() {
        let manager = MultiChainManager::new();
        // Test with None (should use "default")
        let result = manager.get_solana_client(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_network_ethereum() {
        let mut manager = MultiChainManager::new();
        // Can't actually add clients without network, but can test remove logic
        manager.remove_network(Chain::Ethereum, "mainnet");
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_remove_network_solana() {
        let mut manager = MultiChainManager::new();
        manager.remove_network(Chain::Solana, "devnet");
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_remove_chain_ethereum() {
        let mut manager = MultiChainManager::new();
        manager.remove_chain(Chain::Ethereum);
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_remove_chain_solana() {
        let mut manager = MultiChainManager::new();
        manager.remove_chain(Chain::Solana);
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_remove_chain_updates_default() {
        let mut manager = MultiChainManager::new();
        manager.set_default_chain(Chain::Solana);
        assert_eq!(manager.default_chain(), Some(Chain::Solana));

        manager.remove_chain(Chain::Solana);
        assert!(manager.default_chain().is_none());
    }

    #[test]
    fn test_remove_chain_preserves_other_default() {
        let mut manager = MultiChainManager::new();
        manager.set_default_chain(Chain::Ethereum);

        // Removing Solana shouldn't affect Ethereum default
        manager.remove_chain(Chain::Solana);
        assert_eq!(manager.default_chain(), Some(Chain::Ethereum));
    }

    #[test]
    fn test_has_chain_both_empty() {
        let manager = MultiChainManager::new();
        assert!(!manager.has_chain(Chain::Ethereum));
        assert!(!manager.has_chain(Chain::Solana));
    }

    #[test]
    fn test_list_chains_returns_empty_vec() {
        let manager = MultiChainManager::new();
        let chains = manager.list_chains();
        assert!(chains.is_empty());
    }

    #[test]
    fn test_client_count_zero() {
        let manager = MultiChainManager::new();
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_multiple_default_chain_changes() {
        let mut manager = MultiChainManager::new();

        manager.set_default_chain(Chain::Ethereum);
        assert_eq!(manager.default_chain(), Some(Chain::Ethereum));

        manager.set_default_chain(Chain::Solana);
        assert_eq!(manager.default_chain(), Some(Chain::Solana));

        manager.set_default_chain(Chain::Ethereum);
        assert_eq!(manager.default_chain(), Some(Chain::Ethereum));
    }

    #[test]
    fn test_get_ethereum_client_error_message() {
        let manager = MultiChainManager::new();
        let result = manager.get_ethereum_client(Some("testnet"));
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Ethereum client not found for network: testnet"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_get_solana_client_error_message() {
        let manager = MultiChainManager::new();
        let result = manager.get_solana_client(Some("testnet"));
        assert!(result.is_err());

        if let Err(Error::InvalidInput(msg)) = result {
            assert!(msg.contains("Solana client not found for network: testnet"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_default_chain_none_initially() {
        let manager = MultiChainManager::new();
        assert!(manager.default_chain().is_none());
    }

    #[test]
    fn test_new_equals_default() {
        let manager1 = MultiChainManager::new();
        let manager2 = MultiChainManager::default();

        assert_eq!(manager1.client_count(), manager2.client_count());
        assert_eq!(manager1.default_chain(), manager2.default_chain());
    }

    #[test]
    fn test_remove_chain_idempotent() {
        let mut manager = MultiChainManager::new();
        manager.remove_chain(Chain::Ethereum);
        manager.remove_chain(Chain::Ethereum);
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_remove_network_idempotent() {
        let mut manager = MultiChainManager::new();
        manager.remove_network(Chain::Ethereum, "mainnet");
        manager.remove_network(Chain::Ethereum, "mainnet");
        assert_eq!(manager.client_count(), 0);
    }

    #[test]
    fn test_has_chain_consistent_with_list_chains() {
        let manager = MultiChainManager::new();
        let chains = manager.list_chains();

        // If list_chains is empty, has_chain should return false for all
        assert!(chains.is_empty());
        assert!(!manager.has_chain(Chain::Ethereum));
        assert!(!manager.has_chain(Chain::Solana));
    }
}
