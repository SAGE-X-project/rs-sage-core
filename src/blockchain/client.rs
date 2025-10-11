//! Blockchain Client Implementation
//!
//! Provides a high-level interface for interacting with Ethereum/EVM-compatible blockchains.

use crate::error::{Error, Result};
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;

/// Configuration for blockchain client
#[derive(Debug, Clone)]
pub struct BlockchainConfig {
    /// RPC endpoint URL (e.g., "http://localhost:8545")
    pub rpc_url: String,
    /// Chain ID (e.g., 1 for Ethereum mainnet, 1337 for local)
    pub chain_id: u64,
    /// Optional private key for signing transactions
    pub private_key: Option<String>,
}

impl BlockchainConfig {
    /// Creates a new blockchain configuration
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain_id,
            private_key: None,
        }
    }

    /// Sets the private key for transaction signing
    pub fn with_private_key(mut self, private_key: impl Into<String>) -> Self {
        self.private_key = Some(private_key.into());
        self
    }

    /// Creates a configuration for local development (Hardhat/Anvil)
    pub fn local() -> Self {
        Self::new("http://localhost:8545", 1337)
    }

    /// Creates a configuration for Sepolia testnet
    pub fn sepolia(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, 11155111)
    }

    /// Creates a configuration for Ethereum mainnet
    pub fn mainnet(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, 1)
    }
}

/// Blockchain client for interacting with Ethereum/EVM-compatible chains
pub struct BlockchainClient {
    /// Ethers provider
    provider: Provider<Http>,
    /// Chain ID
    chain_id: u64,
    /// Optional signer wallet
    signer: Option<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl BlockchainClient {
    /// Creates a new blockchain client from configuration
    pub async fn new(config: BlockchainConfig) -> Result<Self> {
        // Create HTTP provider
        let provider = Provider::<Http>::try_from(&config.rpc_url)
            .map_err(|e| Error::Other(format!("Failed to create provider: {}", e)))?;

        // Create signer if private key is provided
        let signer = if let Some(pk) = config.private_key {
            let wallet = pk
                .parse::<LocalWallet>()
                .map_err(|e| Error::Other(format!("Invalid private key: {}", e)))?
                .with_chain_id(config.chain_id);

            Some(SignerMiddleware::new(provider.clone(), wallet))
        } else {
            None
        };

        Ok(Self {
            provider,
            chain_id: config.chain_id,
            signer,
        })
    }

    /// Returns the provider
    pub fn provider(&self) -> &Provider<Http> {
        &self.provider
    }

    /// Returns the signer (if available)
    pub fn signer(&self) -> Option<&SignerMiddleware<Provider<Http>, LocalWallet>> {
        self.signer.as_ref()
    }

    /// Returns the chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Gets the current block number
    pub async fn get_block_number(&self) -> Result<u64> {
        self.provider
            .get_block_number()
            .await
            .map(|n| n.as_u64())
            .map_err(|e| Error::Other(format!("Failed to get block number: {}", e)))
    }

    /// Gets the balance of an address
    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        self.provider
            .get_balance(address, None)
            .await
            .map_err(|e| Error::Other(format!("Failed to get balance: {}", e)))
    }

    /// Gets the transaction count (nonce) for an address
    pub async fn get_transaction_count(&self, address: Address) -> Result<U256> {
        self.provider
            .get_transaction_count(address, None)
            .await
            .map_err(|e| Error::Other(format!("Failed to get transaction count: {}", e)))
    }

    /// Estimates gas for a transaction
    pub async fn estimate_gas(&self, tx: &TypedTransaction) -> Result<U256> {
        self.provider
            .estimate_gas(tx, None)
            .await
            .map_err(|e| Error::Other(format!("Failed to estimate gas: {}", e)))
    }

    /// Gets the current gas price
    pub async fn get_gas_price(&self) -> Result<U256> {
        self.provider
            .get_gas_price()
            .await
            .map_err(|e| Error::Other(format!("Failed to get gas price: {}", e)))
    }

    /// Sends a raw transaction
    pub async fn send_raw_transaction(&self, tx: Bytes) -> Result<H256> {
        self.provider
            .send_raw_transaction(tx)
            .await
            .map(|pending| *pending)
            .map_err(|e| Error::Other(format!("Failed to send transaction: {}", e)))
    }

    /// Waits for a transaction receipt
    pub async fn get_transaction_receipt(&self, tx_hash: H256) -> Result<Option<TransactionReceipt>> {
        self.provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| Error::Other(format!("Failed to get transaction receipt: {}", e)))
    }

    /// Checks if the client has a signer (can send transactions)
    pub fn can_sign(&self) -> bool {
        self.signer.is_some()
    }

    /// Gets the signer's address (if available)
    pub fn signer_address(&self) -> Option<Address> {
        self.signer.as_ref().map(|s| s.address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_config() {
        let config = BlockchainConfig::local();
        assert_eq!(config.rpc_url, "http://localhost:8545");
        assert_eq!(config.chain_id, 1337);
        assert!(config.private_key.is_none());
    }

    #[test]
    fn test_blockchain_config_with_private_key() {
        let config = BlockchainConfig::local()
            .with_private_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert!(config.private_key.is_some());
    }

    #[test]
    fn test_sepolia_config() {
        let config = BlockchainConfig::sepolia("https://sepolia.infura.io/v3/YOUR-PROJECT-ID");
        assert_eq!(config.chain_id, 11155111);
    }

    #[test]
    fn test_mainnet_config() {
        let config = BlockchainConfig::mainnet("https://mainnet.infura.io/v3/YOUR-PROJECT-ID");
        assert_eq!(config.chain_id, 1);
    }

    // Integration tests require a running blockchain node
    #[tokio::test]
    #[ignore = "Requires local blockchain node"]
    async fn test_blockchain_client_creation() {
        let config = BlockchainConfig::local();
        let client = BlockchainClient::new(config).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    #[ignore = "Requires local blockchain node"]
    async fn test_get_block_number() {
        let config = BlockchainConfig::local();
        let client = BlockchainClient::new(config).await.unwrap();
        let block_number = client.get_block_number().await;
        assert!(block_number.is_ok());
    }
}
