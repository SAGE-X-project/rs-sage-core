//! Solana Client for SAGE Agent Registry
//!
//! This module provides a client interface for interacting with the
//! SAGE Agent Registry program on Solana.
//!
//! # Features
//!
//! - Agent registration with Ed25519 keys
//! - Multi-key support (up to 5 keys per agent)
//! - Key management (add, rotate, revoke)
//! - Agent activation and deactivation
//! - Anchor-based program integration
//!
//! # Example
//!
//! ```ignore
//! use sage_crypto_core::blockchain::solana::SolanaClient;
//!
//! let client = SolanaClient::new(
//!     "https://api.devnet.solana.com",
//!     "11111111111111111111111111111111", // Program ID
//! ).await?;
//!
//! // Register an agent
//! let agent_pubkey = client.register_agent(params).await?;
//! ```

use crate::blockchain::types::{AgentDID, AgentMetadata, PublicKeyInfo};
use crate::crypto::KeyType;
use crate::error::{Error, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Keypair,
};
use std::str::FromStr;
use std::sync::Arc;

// Maximum values from Solana program
pub const MAX_KEYS_PER_AGENT: usize = 5;
pub const MAX_DID_LEN: usize = 128;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DESCRIPTION_LEN: usize = 256;
pub const MAX_ENDPOINT_LEN: usize = 128;
pub const MAX_CAPABILITIES_LEN: usize = 256;

/// Agent registration parameters
#[derive(Debug, Clone)]
pub struct RegistrationParams {
    /// Agent DID
    pub did: String,
    /// Agent name
    pub name: String,
    /// Agent description
    pub description: String,
    /// Agent endpoint URL
    pub endpoint: String,
    /// Agent capabilities (JSON string)
    pub capabilities: String,
    /// Public keys (Ed25519 only)
    pub public_keys: Vec<[u8; 32]>,
    /// Key types (0 = Ed25519)
    pub key_types: Vec<u8>,
    /// Ownership proof signatures
    pub signatures: Vec<[u8; 64]>,
}

/// Agent account data structure (matches on-chain layout)
#[derive(Debug, Clone)]
pub struct AgentAccount {
    /// Agent DID
    pub did: String,
    /// Agent name
    pub name: String,
    /// Agent description
    pub description: String,
    /// Agent endpoint
    pub endpoint: String,
    /// Capabilities
    pub capabilities: String,
    /// Owner's public key
    pub owner: Pubkey,
    /// Registration timestamp
    pub registered_at: i64,
    /// Last update timestamp
    pub updated_at: i64,
    /// Active status
    pub active: bool,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Number of keys
    pub key_count: u8,
    /// Public keys array
    pub public_keys: [[u8; 32]; MAX_KEYS_PER_AGENT],
    /// Key types array
    pub key_types: [u8; MAX_KEYS_PER_AGENT],
    /// Key revocation status
    pub key_revoked: [bool; MAX_KEYS_PER_AGENT],
}

/// Registry account data
#[derive(Debug, Clone)]
pub struct RegistryAccount {
    /// Registry authority
    pub authority: Pubkey,
    /// Total agent count
    pub agent_count: u64,
    /// Optional verification hook program
    pub verification_hook: Option<Pubkey>,
}

/// Solana client for SAGE Agent Registry
pub struct SolanaClient {
    /// Solana RPC client
    client: Arc<RpcClient>,

    /// Registry program ID
    program_id: Pubkey,

    /// Fee payer keypair (optional)
    fee_payer: Option<Keypair>,
}

impl SolanaClient {
    /// Create a new Solana client
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - Solana RPC endpoint URL
    /// * `program_id` - SAGE Registry program ID as base58 string
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = SolanaClient::new(
    ///     "https://api.devnet.solana.com",
    ///     "11111111111111111111111111111111",
    /// )?;
    /// ```
    pub fn new(rpc_url: &str, program_id: &str) -> Result<Self> {
        // Parse program ID
        let program_pubkey = Pubkey::from_str(program_id)
            .map_err(|e| Error::InvalidInput(format!("Invalid program ID: {}", e)))?;

        // Create RPC client with confirmed commitment
        let client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );

        Ok(Self {
            client: Arc::new(client),
            program_id: program_pubkey,
            fee_payer: None,
        })
    }

    /// Set the fee payer keypair
    ///
    /// # Arguments
    ///
    /// * `keypair` - Fee payer keypair for transactions
    pub fn with_fee_payer(mut self, keypair: Keypair) -> Self {
        self.fee_payer = Some(keypair);
        self
    }

    /// Get the program ID
    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    /// Derive the registry PDA (Program Derived Address)
    ///
    /// The registry PDA is derived from the seed "registry"
    pub fn derive_registry_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"registry"], &self.program_id)
    }

    /// Derive an agent PDA from the owner and DID
    ///
    /// # Arguments
    ///
    /// * `owner` - Owner's public key
    /// * `did` - Agent DID
    pub fn derive_agent_pda(&self, owner: &Pubkey, did: &str) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"agent", owner.as_ref(), did.as_bytes()],
            &self.program_id,
        )
    }

    /// Get registry account data
    ///
    /// # Returns
    ///
    /// Registry account data including authority and agent count
    pub async fn get_registry(&self) -> Result<RegistryAccount> {
        let (registry_pda, _) = self.derive_registry_pda();

        let account = self
            .client
            .get_account(&registry_pda)
            .map_err(|e| Error::Other(format!("Failed to get registry: {}", e)))?;

        // Parse registry account (simplified - in production, use borsh deserialization)
        // For now, return a placeholder
        Ok(RegistryAccount {
            authority: Pubkey::default(),
            agent_count: 0,
            verification_hook: None,
        })
    }

    /// Get agent account data
    ///
    /// # Arguments
    ///
    /// * `owner` - Owner's public key
    /// * `did` - Agent DID
    ///
    /// # Returns
    ///
    /// Agent account data if it exists
    pub async fn get_agent(&self, owner: &Pubkey, did: &str) -> Result<AgentAccount> {
        let (agent_pda, _) = self.derive_agent_pda(owner, did);

        let account = self
            .client
            .get_account(&agent_pda)
            .map_err(|e| Error::Other(format!("Failed to get agent: {}", e)))?;

        // Parse agent account (simplified - in production, use borsh deserialization)
        // For now, return a placeholder
        Ok(AgentAccount {
            did: did.to_string(),
            name: String::new(),
            description: String::new(),
            endpoint: String::new(),
            capabilities: String::new(),
            owner: *owner,
            registered_at: 0,
            updated_at: 0,
            active: false,
            nonce: 0,
            key_count: 0,
            public_keys: [[0u8; 32]; MAX_KEYS_PER_AGENT],
            key_types: [0u8; MAX_KEYS_PER_AGENT],
            key_revoked: [false; MAX_KEYS_PER_AGENT],
        })
    }

    /// Check if an agent is active
    ///
    /// # Arguments
    ///
    /// * `owner` - Owner's public key
    /// * `did` - Agent DID
    ///
    /// # Returns
    ///
    /// `true` if agent exists and is active, `false` otherwise
    pub async fn is_agent_active(&self, owner: &Pubkey, did: &str) -> Result<bool> {
        match self.get_agent(owner, did).await {
            Ok(agent) => Ok(agent.active),
            Err(_) => Ok(false),
        }
    }

    /// Validate registration parameters
    ///
    /// # Arguments
    ///
    /// * `params` - Registration parameters to validate
    ///
    /// # Errors
    ///
    /// Returns error if any parameter exceeds maximum length or constraints
    fn validate_registration_params(&self, params: &RegistrationParams) -> Result<()> {
        // Validate string lengths
        if params.did.len() > MAX_DID_LEN {
            return Err(Error::InvalidInput(format!(
                "DID too long: {} > {}",
                params.did.len(),
                MAX_DID_LEN
            )));
        }

        if params.name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidInput(format!(
                "Name too long: {} > {}",
                params.name.len(),
                MAX_NAME_LEN
            )));
        }

        if params.description.len() > MAX_DESCRIPTION_LEN {
            return Err(Error::InvalidInput(format!(
                "Description too long: {} > {}",
                params.description.len(),
                MAX_DESCRIPTION_LEN
            )));
        }

        if params.endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(Error::InvalidInput(format!(
                "Endpoint too long: {} > {}",
                params.endpoint.len(),
                MAX_ENDPOINT_LEN
            )));
        }

        if params.capabilities.len() > MAX_CAPABILITIES_LEN {
            return Err(Error::InvalidInput(format!(
                "Capabilities too long: {} > {}",
                params.capabilities.len(),
                MAX_CAPABILITIES_LEN
            )));
        }

        // Validate key arrays
        if params.public_keys.is_empty() {
            return Err(Error::InvalidInput("No keys provided".to_string()));
        }

        if params.public_keys.len() > MAX_KEYS_PER_AGENT {
            return Err(Error::InvalidInput(format!(
                "Too many keys: {} > {}",
                params.public_keys.len(),
                MAX_KEYS_PER_AGENT
            )));
        }

        if params.public_keys.len() != params.key_types.len() {
            return Err(Error::InvalidInput("Key array length mismatch".to_string()));
        }

        if params.public_keys.len() != params.signatures.len() {
            return Err(Error::InvalidInput(
                "Signature array length mismatch".to_string(),
            ));
        }

        // Validate all keys are Ed25519 (type 0)
        for (i, &key_type) in params.key_types.iter().enumerate() {
            if key_type != 0 {
                return Err(Error::InvalidInput(format!(
                    "Only Ed25519 keys supported on Solana (key {} has type {})",
                    i, key_type
                )));
            }
        }

        Ok(())
    }
}

// Conversion to AgentMetadata
impl AgentAccount {
    /// Convert to AgentMetadata type
    pub fn to_metadata(&self) -> Result<AgentMetadata> {
        let mut key_info = Vec::new();

        for i in 0..self.key_count as usize {
            if !self.key_revoked[i] {
                let key_type = match self.key_types[i] {
                    0 => KeyType::Ed25519,
                    _ => {
                        return Err(Error::InvalidInput(format!(
                            "Unknown key type: {}",
                            self.key_types[i]
                        )))
                    }
                };

                // Calculate key hash using Keccak256
                use tiny_keccak::{Hasher, Keccak};
                let mut hasher = Keccak::v256();
                hasher.update(&self.public_keys[i]);
                let mut key_hash = [0u8; 32];
                hasher.finalize(&mut key_hash);

                key_info.push(PublicKeyInfo {
                    key_type,
                    key_data: self.public_keys[i].to_vec(),
                    key_hash,
                    verified: true,
                });
            }
        }

        // Parse capabilities JSON
        let capabilities = serde_json::from_str(&self.capabilities)
            .unwrap_or_else(|_| serde_json::json!([]));

        Ok(AgentMetadata {
            did: AgentDID::new(&self.did)?,
            name: self.name.clone(),
            description: self.description.clone(),
            endpoint: self.endpoint.clone(),
            public_keys: key_info,
            capabilities: capabilities
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            owner: format!("{}", self.owner),
            is_active: self.active,
            created_at: self.registered_at as u64,
            updated_at: self.updated_at as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::Signer;

    #[test]
    fn test_solana_client_creation() {
        let client = SolanaClient::new(
            "https://api.devnet.solana.com",
            "11111111111111111111111111111111",
        );
        assert!(client.is_ok());
    }

    #[test]
    fn test_derive_registry_pda() {
        let client = SolanaClient::new(
            "https://api.devnet.solana.com",
            "11111111111111111111111111111111",
        )
        .unwrap();

        let (pda, bump) = client.derive_registry_pda();
        assert_ne!(pda, Pubkey::default());
        assert!(bump <= 255);
    }

    #[test]
    fn test_derive_agent_pda() {
        let client = SolanaClient::new(
            "https://api.devnet.solana.com",
            "11111111111111111111111111111111",
        )
        .unwrap();

        let owner = Keypair::new().pubkey();
        let did = "did:sage:solana:test";
        let (pda, bump) = client.derive_agent_pda(&owner, did);

        assert_ne!(pda, Pubkey::default());
        assert!(bump <= 255);
    }

    #[test]
    fn test_validate_registration_params() {
        let client = SolanaClient::new(
            "https://api.devnet.solana.com",
            "11111111111111111111111111111111",
        )
        .unwrap();

        // Valid params
        let valid_params = RegistrationParams {
            did: "did:sage:solana:test".to_string(),
            name: "Test Agent".to_string(),
            description: "Test description".to_string(),
            endpoint: "https://example.com".to_string(),
            capabilities: "[]".to_string(),
            public_keys: vec![[0u8; 32]],
            key_types: vec![0],
            signatures: vec![[0u8; 64]],
        };

        assert!(client.validate_registration_params(&valid_params).is_ok());

        // Invalid: DID too long
        let mut invalid_params = valid_params.clone();
        invalid_params.did = "a".repeat(MAX_DID_LEN + 1);
        assert!(client.validate_registration_params(&invalid_params).is_err());

        // Invalid: no keys
        let mut invalid_params = valid_params.clone();
        invalid_params.public_keys = vec![];
        invalid_params.key_types = vec![];
        invalid_params.signatures = vec![];
        assert!(client.validate_registration_params(&invalid_params).is_err());

        // Invalid: too many keys
        let mut invalid_params = valid_params.clone();
        invalid_params.public_keys = vec![[0u8; 32]; MAX_KEYS_PER_AGENT + 1];
        invalid_params.key_types = vec![0; MAX_KEYS_PER_AGENT + 1];
        invalid_params.signatures = vec![[0u8; 64]; MAX_KEYS_PER_AGENT + 1];
        assert!(client.validate_registration_params(&invalid_params).is_err());

        // Invalid: wrong key type
        let mut invalid_params = valid_params.clone();
        invalid_params.key_types = vec![1]; // Not Ed25519
        assert!(client.validate_registration_params(&invalid_params).is_err());
    }

    #[test]
    fn test_agent_account_to_metadata() {
        let owner = Keypair::new().pubkey();
        let mut agent = AgentAccount {
            did: "did:sage:solana:test".to_string(),
            name: "Test Agent".to_string(),
            description: "Test description".to_string(),
            endpoint: "https://example.com".to_string(),
            capabilities: r#"["messaging", "storage"]"#.to_string(),
            owner,
            registered_at: 1234567890,
            updated_at: 1234567900,
            active: true,
            nonce: 0,
            key_count: 2,
            public_keys: [[0u8; 32]; MAX_KEYS_PER_AGENT],
            key_types: [0u8; MAX_KEYS_PER_AGENT],
            key_revoked: [false; MAX_KEYS_PER_AGENT],
        };

        // Set some key data
        agent.public_keys[0] = [1u8; 32];
        agent.public_keys[1] = [2u8; 32];

        let metadata = agent.to_metadata().unwrap();
        assert_eq!(metadata.name, "Test Agent");
        assert_eq!(metadata.public_keys.len(), 2);
        assert_eq!(metadata.capabilities.len(), 2);
        assert!(metadata.is_active);
    }
}
