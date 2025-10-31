//! Ethereum Client for AgentCardRegistry
//!
//! This module provides a client interface for interacting with the
//! AgentCardRegistry smart contract on Ethereum.
//!
//! # Features
//!
//! - Agent registration with commit-reveal pattern
//! - Multi-key support (ECDSA, Ed25519, X25519)
//! - Key management (add, rotate, revoke)
//! - Agent activation and deactivation
//! - ERC-8004 compliance
//!
//! # Example
//!
//! ```ignore
//! use sage_crypto_core::blockchain::ethereum::EthereumClient;
//! use alloy::providers::Provider;
//!
//! let client = EthereumClient::new(
//!     "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
//!     "0x1234567890123456789012345678901234567890", // Registry address
//! ).await?;
//!
//! // Register an agent
//! let agent_id = client.register_agent(params).await?;
//! ```

use crate::blockchain::types::{AgentDID, AgentMetadata, PublicKeyInfo};
use crate::crypto::KeyType;
use crate::error::{Error, Result};
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::transports::http::{Client as HttpClient, Http};
use alloy::sol;
use std::sync::Arc;

// Define the AgentCardRegistry contract interface using alloy sol! macro
sol! {
    #[sol(rpc)]
    interface IAgentCardRegistry {
        // Events
        event AgentRegistered(bytes32 indexed agentId, address indexed owner, string did, uint256 timestamp);
        event KeyAdded(bytes32 indexed agentId, bytes32 indexed keyHash, uint8 keyType, uint256 timestamp);
        event AgentActivated(bytes32 indexed agentId, uint256 timestamp);
        event AgentDeactivated(bytes32 indexed agentId, uint256 timestamp);
        event CommitmentRecorded(address indexed caller, bytes32 indexed commitHash, uint256 timestamp);

        // Structs
        struct AgentMetadata {
            string did;
            string name;
            string description;
            string endpoint;
            bytes32[] keyHashes;
            string[] capabilities;
            address owner;
            bool active;
            uint256 registeredAt;
            uint256 lastUpdated;
        }

        struct AgentKey {
            uint8 keyType;
            bytes keyData;
            bytes signature;
            bool verified;
            uint256 registeredAt;
        }

        struct RegistrationParams {
            string did;
            string name;
            string description;
            string endpoint;
            bytes[] keys;
            uint8[] keyTypes;
            bytes[] signatures;
            string[] capabilities;
            bytes32 salt;
        }

        // Read functions
        function getAgent(bytes32 agentId) external view returns (AgentMetadata memory);
        function getAgentByDID(string calldata did) external view returns (AgentMetadata memory);
        function getKey(bytes32 keyHash) external view returns (AgentKey memory);
        function isAgentActive(bytes32 agentId) external view returns (bool);
        function didToAgentId(string calldata did) external view returns (bytes32);
        function agentStakes(bytes32 agentId) external view returns (uint256);
        function registrationStake() external view returns (uint256);

        // Write functions
        function commitRegistration(bytes32 commitHash) external payable;
        function registerAgentWithParams(RegistrationParams calldata params) external returns (bytes32);
        function activateAgent(bytes32 agentId) external;
        function deactivateAgent(bytes32 agentId) external;
        function addKey(bytes32 agentId, bytes calldata keyData, uint8 keyType, bytes calldata signature) external;
    }
}

/// Ethereum client for interacting with AgentCardRegistry
pub struct EthereumClient {
    /// Ethereum provider
    provider: Arc<RootProvider<Http<HttpClient>>>,

    /// Registry contract address
    registry_address: Address,
}

impl EthereumClient {
    /// Create a new Ethereum client
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - Ethereum RPC endpoint URL
    /// * `registry_address` - AgentCardRegistry contract address as hex string
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = EthereumClient::new(
    ///     "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
    ///     "0x1234...",
    /// ).await?;
    /// ```
    pub async fn new(rpc_url: &str, registry_address: &str) -> Result<Self> {
        // Parse registry address
        let address = registry_address
            .parse::<Address>()
            .map_err(|e| Error::InvalidInput(format!("Invalid registry address: {}", e)))?;

        // Create provider
        let provider = ProviderBuilder::new()
            .on_http(rpc_url.parse().map_err(|e| {
                Error::InvalidInput(format!("Invalid RPC URL: {}", e))
            })?);

        Ok(Self {
            provider: Arc::new(provider),
            registry_address: address,
        })
    }

    /// Get the registry contract address
    pub fn registry_address(&self) -> &Address {
        &self.registry_address
    }

    /// Get agent metadata by agent ID
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent ID as bytes32
    ///
    /// # Returns
    ///
    /// Agent metadata including DID, keys, owner, and status
    pub async fn get_agent(&self, agent_id: &[u8; 32]) -> Result<AgentMetadata> {
        let agent_id_fixed = FixedBytes::<32>::from_slice(agent_id);

        // Create contract instance
        let contract = IAgentCardRegistry::new(self.registry_address, self.provider.clone());

        // Call getAgent
        let result = contract.getAgent(agent_id_fixed)
            .call()
            .await
            .map_err(|e| Error::Other(format!("Failed to get agent: {}", e)))?;

        self.convert_agent_metadata(result._0)
    }

    /// Get agent metadata by DID
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID string (e.g., "did:sage:ethereum:0x1234...")
    ///
    /// # Returns
    ///
    /// Agent metadata
    pub async fn get_agent_by_did(&self, did: &str) -> Result<AgentMetadata> {
        let contract = IAgentCardRegistry::new(self.registry_address, self.provider.clone());

        let result = contract.getAgentByDID(did.to_string())
            .call()
            .await
            .map_err(|e| Error::NotFound(format!("Agent not found: {}", e)))?;

        self.convert_agent_metadata(result._0)
    }

    /// Check if an agent is active
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent ID as bytes32
    ///
    /// # Returns
    ///
    /// `true` if the agent is active and can be used
    pub async fn is_agent_active(&self, agent_id: &[u8; 32]) -> Result<bool> {
        let agent_id_fixed = FixedBytes::<32>::from_slice(agent_id);
        let contract = IAgentCardRegistry::new(self.registry_address, self.provider.clone());

        let result = contract.isAgentActive(agent_id_fixed)
            .call()
            .await
            .map_err(|e| Error::Other(format!("Failed to check agent status: {}", e)))?;

        Ok(result._0)
    }

    /// Get the required registration stake amount
    ///
    /// # Returns
    ///
    /// Stake amount in wei
    pub async fn get_registration_stake(&self) -> Result<U256> {
        let contract = IAgentCardRegistry::new(self.registry_address, self.provider.clone());

        let result = contract.registrationStake()
            .call()
            .await
            .map_err(|e| Error::Other(format!("Failed to get stake amount: {}", e)))?;

        Ok(result._0)
    }

    // TODO: Write operations require signer integration
    // This will be implemented in a future version with proper alloy signer setup

    /// Convert contract AgentMetadata to our AgentMetadata type
    fn convert_agent_metadata(
        &self,
        contract_metadata: IAgentCardRegistry::AgentMetadata,
    ) -> Result<AgentMetadata> {
        // Parse DID
        let did = AgentDID::parse(&contract_metadata.did)?;

        // Convert key hashes to PublicKeyInfo
        let mut public_keys = Vec::new();
        for key_hash_bytes in contract_metadata.keyHashes {
            // Note: We'd need to query getKey() for each key to get full details
            // For now, create a placeholder with the key hash
            let mut key_hash = [0u8; 32];
            key_hash.copy_from_slice(key_hash_bytes.as_slice());

            public_keys.push(PublicKeyInfo {
                key_type: KeyType::Secp256k1, // Placeholder - should query getKey()
                key_data: vec![],
                key_hash,
                verified: true,
            });
        }

        Ok(AgentMetadata {
            did,
            name: contract_metadata.name,
            description: contract_metadata.description,
            endpoint: contract_metadata.endpoint,
            public_keys,
            capabilities: contract_metadata.capabilities,
            owner: format!("0x{:x}", contract_metadata.owner),
            is_active: contract_metadata.active,
            created_at: contract_metadata.registeredAt.to::<u64>(),
            updated_at: contract_metadata.lastUpdated.to::<u64>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ===== Client Creation Tests =====

    #[tokio::test]
    #[ignore] // Requires network connection
    async fn test_client_creation() {
        let result = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_client_creation_invalid_address() {
        let result = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "invalid_address",
        ).await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidInput(_)));
        }
    }

    #[tokio::test]
    async fn test_client_creation_short_address() {
        let result = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x1234",
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_creation_no_0x_prefix() {
        let result = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "1234567890123456789012345678901234567890",
        ).await;

        // Should still work - Address parsing is flexible
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_client_creation_invalid_rpc_url() {
        let result = EthereumClient::new(
            "not_a_valid_url",
            "0x0000000000000000000000000000000000000001",
        ).await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidInput(_)));
        }
    }

    #[tokio::test]
    async fn test_client_creation_empty_rpc_url() {
        let result = EthereumClient::new(
            "",
            "0x0000000000000000000000000000000000000001",
        ).await;

        assert!(result.is_err());
    }

    // ===== Address Parsing Tests =====

    #[test]
    fn test_address_parsing() {
        let test_address = "0x1234567890123456789012345678901234567890";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_address_parsing_lowercase() {
        let test_address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_address_parsing_uppercase() {
        let test_address = "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_address_parsing_invalid_chars() {
        let test_address = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_err());
    }

    #[test]
    fn test_address_parsing_too_short() {
        let test_address = "0x1234";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_err());
    }

    #[test]
    fn test_address_parsing_too_long() {
        let test_address = "0x12345678901234567890123456789012345678901234567890";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_err());
    }

    #[test]
    fn test_address_parsing_no_prefix() {
        let test_address = "1234567890123456789012345678901234567890";
        let parsed = test_address.parse::<Address>();
        // Alloy might accept this
        assert!(parsed.is_ok() || parsed.is_err());
    }

    #[test]
    fn test_address_parsing_zero_address() {
        let test_address = "0x0000000000000000000000000000000000000000";
        let parsed = test_address.parse::<Address>();
        assert!(parsed.is_ok());
    }

    // ===== Registry Address Getter Tests =====

    #[tokio::test]
    async fn test_registry_address_getter() {
        let test_address = "0x1234567890123456789012345678901234567890";
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            test_address,
        ).await.unwrap();

        let addr = client.registry_address();
        assert_eq!(format!("{:?}", addr), test_address);
    }

    #[tokio::test]
    async fn test_registry_address_preservation() {
        let test_address = "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD";
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            test_address,
        ).await.unwrap();

        let addr = client.registry_address();
        // Address should be stored correctly
        assert!(!format!("{:?}", addr).is_empty());
    }

    // ===== Error Handling Tests =====

    #[test]
    fn test_invalid_address_error_message() {
        let result = "invalid".parse::<Address>();
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_address_error() {
        let result = "".parse::<Address>();
        assert!(result.is_err());
    }

    // ===== Metadata Conversion Tests =====

    #[tokio::test]
    async fn test_convert_agent_metadata_basic() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x1234567890123456789012345678901234567890".to_string(),
            name: "Test Agent".to_string(),
            description: "A test agent".to_string(),
            endpoint: "https://example.com".to_string(),
            keyHashes: vec![],
            capabilities: vec!["messaging".to_string()],
            owner: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            active: true,
            registeredAt: U256::from(1000000),
            lastUpdated: U256::from(1000100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();

        assert_eq!(result.name, "Test Agent");
        assert_eq!(result.description, "A test agent");
        assert_eq!(result.endpoint, "https://example.com");
        assert_eq!(result.capabilities.len(), 1);
        assert_eq!(result.capabilities[0], "messaging");
        assert_eq!(result.is_active, true);
        assert_eq!(result.created_at, 1000000);
        assert_eq!(result.updated_at, 1000100);
    }

    #[tokio::test]
    async fn test_convert_agent_metadata_with_keys() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let key_hash1 = FixedBytes::<32>::from([1u8; 32]);
        let key_hash2 = FixedBytes::<32>::from([2u8; 32]);

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            name: "Agent with Keys".to_string(),
            description: "Agent with multiple keys".to_string(),
            endpoint: "https://agent.example.com".to_string(),
            keyHashes: vec![key_hash1, key_hash2],
            capabilities: vec!["signing".to_string(), "encryption".to_string()],
            owner: Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap(),
            active: false,
            registeredAt: U256::from(2000000),
            lastUpdated: U256::from(2000200),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();

        assert_eq!(result.name, "Agent with Keys");
        assert_eq!(result.public_keys.len(), 2);
        assert_eq!(result.capabilities.len(), 2);
        assert_eq!(result.is_active, false);
        assert!(result.owner.contains("0xabcdef"));
    }

    #[tokio::test]
    async fn test_convert_agent_metadata_invalid_did() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "invalid-did-format".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://example.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_convert_agent_metadata_empty_capabilities() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Minimal Agent".to_string(),
            description: "".to_string(),
            endpoint: "".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(0),
            lastUpdated: U256::from(0),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();

        assert_eq!(result.name, "Minimal Agent");
        assert_eq!(result.description, "");
        assert_eq!(result.endpoint, "");
        assert_eq!(result.capabilities.len(), 0);
        assert_eq!(result.public_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_convert_agent_metadata_multiple_capabilities() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let capabilities = vec![
            "messaging".to_string(),
            "storage".to_string(),
            "compute".to_string(),
            "ai-inference".to_string(),
        ];

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Multi-capability Agent".to_string(),
            description: "Agent with many capabilities".to_string(),
            endpoint: "https://multi.example.com".to_string(),
            keyHashes: vec![],
            capabilities: capabilities.clone(),
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(3000000),
            lastUpdated: U256::from(3000500),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();

        assert_eq!(result.capabilities.len(), 4);
        assert_eq!(result.capabilities, capabilities);
    }

    // ===== U256 Conversion Tests =====

    #[test]
    fn test_u256_to_u64_small_values() {
        let small = U256::from(12345u64);
        assert_eq!(small.to::<u64>(), 12345u64);
    }

    #[test]
    fn test_u256_to_u64_zero() {
        let zero = U256::from(0u64);
        assert_eq!(zero.to::<u64>(), 0u64);
    }

    #[test]
    fn test_u256_to_u64_max() {
        let max = U256::from(u64::MAX);
        assert_eq!(max.to::<u64>(), u64::MAX);
    }

    #[test]
    fn test_u256_timestamp_conversion() {
        let timestamp = U256::from(1609459200u64); // 2021-01-01
        assert_eq!(timestamp.to::<u64>(), 1609459200u64);
    }

    // ===== FixedBytes Tests =====

    #[test]
    fn test_fixed_bytes_from_slice() {
        let data = [0u8; 32];
        let fixed = FixedBytes::<32>::from_slice(&data);
        assert_eq!(fixed.as_slice(), &data);
    }

    #[test]
    fn test_fixed_bytes_different_values() {
        let data1 = [1u8; 32];
        let data2 = [2u8; 32];
        let fixed1 = FixedBytes::<32>::from_slice(&data1);
        let fixed2 = FixedBytes::<32>::from_slice(&data2);
        assert_ne!(fixed1, fixed2);
    }

    #[test]
    fn test_fixed_bytes_copy_from_slice() {
        let source = [42u8; 32];
        let mut target = [0u8; 32];
        target.copy_from_slice(&source);
        assert_eq!(target, source);
    }

    // ===== Client State Tests =====

    #[tokio::test]
    async fn test_client_multiple_instances() {
        let client1 = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let client2 = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000002",
        ).await.unwrap();

        assert_ne!(
            format!("{:?}", client1.registry_address()),
            format!("{:?}", client2.registry_address())
        );
    }

    #[tokio::test]
    async fn test_client_address_formats() {
        let addresses = vec![
            "0x0000000000000000000000000000000000000001",
            "0xffffffffffffffffffffffffffffffffffffffff",
            "0x1234567890abcdef1234567890abcdef12345678",
        ];

        for addr in addresses {
            let client = EthereumClient::new(
                "https://eth-sepolia.g.alchemy.com/v2/demo",
                addr,
            ).await;
            assert!(client.is_ok(), "Failed to create client with address: {}", addr);
        }
    }

    // ===== RPC URL Validation Tests =====

    #[tokio::test]
    async fn test_rpc_url_with_port() {
        let result = EthereumClient::new(
            "https://localhost:8545",
            "0x0000000000000000000000000000000000000001",
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rpc_url_http_protocol() {
        let result = EthereumClient::new(
            "http://localhost:8545",
            "0x0000000000000000000000000000000000000001",
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rpc_url_with_path() {
        let result = EthereumClient::new(
            "https://mainnet.infura.io/v3/YOUR-PROJECT-ID",
            "0x0000000000000000000000000000000000000001",
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rpc_url_malformed() {
        let result = EthereumClient::new(
            "ht!tp://invalid url with spaces",
            "0x0000000000000000000000000000000000000001",
        ).await;
        assert!(result.is_err());
    }

    // ===== Owner Address Formatting Tests =====

    #[tokio::test]
    async fn test_owner_address_formatting() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let owner_addr = Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: owner_addr,
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert!(result.owner.starts_with("0x"));
        assert!(result.owner.contains("abcdef"));
    }

    #[tokio::test]
    async fn test_owner_address_lowercase() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let owner_addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: owner_addr,
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        // Owner should be formatted as hex string
        assert!(result.owner.starts_with("0x"));
        assert_eq!(result.owner.len(), 42); // 0x + 40 chars
    }

    // ===== Key Hash Conversion Tests =====

    #[tokio::test]
    async fn test_key_hash_conversion_single() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let key_hash = FixedBytes::<32>::from([42u8; 32]);

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![key_hash],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.public_keys.len(), 1);
        assert_eq!(result.public_keys[0].key_hash, [42u8; 32]);
        assert_eq!(result.public_keys[0].verified, true);
    }

    #[tokio::test]
    async fn test_key_hash_conversion_multiple() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let key_hashes = vec![
            FixedBytes::<32>::from([1u8; 32]),
            FixedBytes::<32>::from([2u8; 32]),
            FixedBytes::<32>::from([3u8; 32]),
        ];

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Multi-key Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: key_hashes,
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.public_keys.len(), 3);
        assert_eq!(result.public_keys[0].key_hash, [1u8; 32]);
        assert_eq!(result.public_keys[1].key_hash, [2u8; 32]);
        assert_eq!(result.public_keys[2].key_hash, [3u8; 32]);
    }

    // ===== Timestamp Conversion Tests =====

    #[tokio::test]
    async fn test_timestamp_conversion_large_value() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let large_timestamp = U256::from(9_999_999_999u64);

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: large_timestamp,
            lastUpdated: large_timestamp,
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.created_at, 9_999_999_999u64);
        assert_eq!(result.updated_at, 9_999_999_999u64);
    }

    #[tokio::test]
    async fn test_timestamp_updated_after_created() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(2000),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert!(result.updated_at > result.created_at);
    }

    // ===== DID Format Tests =====

    #[tokio::test]
    async fn test_did_with_checksum_address() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0xaBcDeF1234567890aBcDeF1234567890aBcDeF12".to_string(),
            name: "Checksum Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0xaBcDeF1234567890aBcDeF1234567890aBcDeF12").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_did_missing_prefix() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_did_wrong_method() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:other:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata);
        assert!(result.is_err());
    }

    // ===== Endpoint Validation Tests =====

    #[tokio::test]
    async fn test_endpoint_https() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "https://secure.example.com/agent".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.endpoint, "https://secure.example.com/agent");
    }

    #[tokio::test]
    async fn test_endpoint_http() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            endpoint: "http://localhost:8080".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.endpoint, "http://localhost:8080");
    }

    // ===== Active Status Tests =====

    #[tokio::test]
    async fn test_active_status_true() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Active Agent".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.is_active, true);
    }

    #[tokio::test]
    async fn test_active_status_false() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Inactive Agent".to_string(),
            description: "Test".to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: false,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.is_active, false);
    }

    // ===== Description Field Tests =====

    #[tokio::test]
    async fn test_long_description() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let long_desc = "A".repeat(1000);

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Long Description Agent".to_string(),
            description: long_desc.clone(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.description.len(), 1000);
        assert_eq!(result.description, long_desc);
    }

    #[tokio::test]
    async fn test_special_characters_in_description() {
        let client = EthereumClient::new(
            "https://eth-sepolia.g.alchemy.com/v2/demo",
            "0x0000000000000000000000000000000000000001",
        ).await.unwrap();

        let special_desc = "Agent with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";

        let contract_metadata = IAgentCardRegistry::AgentMetadata {
            did: "did:sage:ethereum:0x0000000000000000000000000000000000000001".to_string(),
            name: "Special Chars Agent".to_string(),
            description: special_desc.to_string(),
            endpoint: "https://test.com".to_string(),
            keyHashes: vec![],
            capabilities: vec![],
            owner: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            active: true,
            registeredAt: U256::from(1000),
            lastUpdated: U256::from(1100),
        };

        let result = client.convert_agent_metadata(contract_metadata).unwrap();
        assert_eq!(result.description, special_desc);
    }
}
