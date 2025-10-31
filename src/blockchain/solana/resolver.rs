//! Solana DID Resolver
//!
//! This module provides DID resolution functionality for Solana-based DIDs.

use crate::blockchain::types::{AgentDID, AgentMetadata};
use crate::error::{Error, Result};
use super::client::SolanaClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Arc;

/// Solana DID resolver
///
/// Resolves DIDs in the format `did:sage:solana:{owner_address}` or
/// `did:sage:solana:{owner_address}:{nonce}` to agent metadata.
pub struct SolanaResolver {
    /// Solana client for blockchain queries
    client: Arc<SolanaClient>,
}

impl SolanaResolver {
    /// Create a new Solana resolver
    ///
    /// # Arguments
    ///
    /// * `client` - Solana client instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sage_crypto_core::blockchain::solana::{SolanaClient, SolanaResolver};
    ///
    /// let client = SolanaClient::new(
    ///     "https://api.devnet.solana.com",
    ///     "11111111111111111111111111111111",
    /// )?;
    /// let resolver = SolanaResolver::new(client);
    /// ```
    pub fn new(client: SolanaClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Create a resolver from an Arc-wrapped client
    pub fn from_arc(client: Arc<SolanaClient>) -> Self {
        Self { client }
    }

    /// Resolve a DID to agent metadata
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID to resolve
    ///
    /// # Returns
    ///
    /// Agent metadata if the DID exists and is valid
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DID format is invalid
    /// - Agent does not exist
    /// - Blockchain query fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let metadata = resolver.resolve_did(&did).await?;
    /// println!("Agent name: {}", metadata.name);
    /// ```
    pub async fn resolve_did(&self, did: &AgentDID) -> Result<AgentMetadata> {
        // Parse DID to extract owner address
        let (owner, _nonce) = Self::parse_solana_did(did.as_str())?;

        // Query agent account
        let agent_account = self
            .client
            .get_agent(&owner, did.as_str())
            .await
            .map_err(|e| Error::NotFound(format!("Agent not found: {}", e)))?;

        // Convert to metadata
        agent_account.to_metadata()
    }

    /// Check if a DID exists and is active
    ///
    /// # Arguments
    ///
    /// * `did` - Agent DID to check
    ///
    /// # Returns
    ///
    /// `true` if the agent exists and is active, `false` otherwise
    pub async fn is_did_active(&self, did: &AgentDID) -> Result<bool> {
        let (owner, _nonce) = Self::parse_solana_did(did.as_str())?;
        self.client.is_agent_active(&owner, did.as_str()).await
    }

    /// Parse a Solana DID to extract owner address and optional nonce
    ///
    /// # DID Format
    ///
    /// - Simple: `did:sage:solana:{owner_address}`
    /// - With nonce: `did:sage:solana:{owner_address}:{nonce}`
    ///
    /// # Arguments
    ///
    /// * `did` - DID string to parse
    ///
    /// # Returns
    ///
    /// Tuple of (owner_pubkey, optional_nonce)
    ///
    /// # Errors
    ///
    /// Returns error if DID format is invalid or owner address cannot be parsed
    fn parse_solana_did(did: &str) -> Result<(Pubkey, Option<u64>)> {
        // Expected format: did:sage:solana:{owner}[:nonce]
        let parts: Vec<&str> = did.split(':').collect();

        if parts.len() < 4 || parts.len() > 5 {
            return Err(Error::InvalidInput(format!(
                "Invalid Solana DID format: {}",
                did
            )));
        }

        if parts[0] != "did" || parts[1] != "sage" || parts[2] != "solana" {
            return Err(Error::InvalidInput(format!(
                "Invalid DID method or chain: {}",
                did
            )));
        }

        // Parse owner address
        let owner = Pubkey::from_str(parts[3]).map_err(|e| {
            Error::InvalidInput(format!("Invalid owner address in DID: {}", e))
        })?;

        // Parse optional nonce
        let nonce = if parts.len() == 5 {
            Some(parts[4].parse::<u64>().map_err(|e| {
                Error::InvalidInput(format!("Invalid nonce in DID: {}", e))
            })?)
        } else {
            None
        };

        Ok((owner, nonce))
    }

    /// Batch resolve multiple DIDs
    ///
    /// # Arguments
    ///
    /// * `dids` - Vector of DIDs to resolve
    ///
    /// # Returns
    ///
    /// Vector of results, one for each input DID
    pub async fn batch_resolve_dids(&self, dids: &[AgentDID]) -> Vec<Result<AgentMetadata>> {
        let mut results = Vec::with_capacity(dids.len());

        for did in dids {
            results.push(self.resolve_did(did).await);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;

    #[test]
    fn test_parse_solana_did_simple() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let did = format!("did:sage:solana:{}", owner_str);

        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_ok());

        let (owner, nonce) = result.unwrap();
        assert_eq!(owner, keypair.pubkey());
        assert_eq!(nonce, None);
    }

    #[test]
    fn test_parse_solana_did_with_nonce() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let did = format!("did:sage:solana:{}:42", owner_str);

        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_ok());

        let (owner, nonce) = result.unwrap();
        assert_eq!(owner, keypair.pubkey());
        assert_eq!(nonce, Some(42));
    }

    #[test]
    fn test_parse_solana_did_invalid_format() {
        // Wrong method
        let result = SolanaResolver::parse_solana_did("did:other:solana:address");
        assert!(result.is_err());

        // Wrong chain
        let result = SolanaResolver::parse_solana_did("did:sage:ethereum:address");
        assert!(result.is_err());

        // Too few parts
        let result = SolanaResolver::parse_solana_did("did:sage:solana");
        assert!(result.is_err());

        // Too many parts
        let result =
            SolanaResolver::parse_solana_did("did:sage:solana:address:1:extra");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_solana_did_invalid_address() {
        let result = SolanaResolver::parse_solana_did("did:sage:solana:invalid_address");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_solana_did_invalid_nonce() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let did = format!("did:sage:solana:{}:not_a_number", owner_str);

        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolver_creation() {
        let client = SolanaClient::new(
            "https://api.devnet.solana.com",
            "11111111111111111111111111111111",
        )
        .unwrap();

        let resolver = SolanaResolver::new(client);
        assert!(Arc::strong_count(&resolver.client) == 1);
    }

    #[test]
    fn test_resolver_from_arc() {
        let client = SolanaClient::new(
            "https://api.devnet.solana.com",
            "11111111111111111111111111111111",
        )
        .unwrap();

        let arc_client = Arc::new(client);
        let resolver = SolanaResolver::from_arc(arc_client.clone());
        assert!(Arc::strong_count(&resolver.client) == 2);
    }

    #[test]
    fn test_parse_solana_did_with_zero_nonce() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let did = format!("did:sage:solana:{}:0", owner_str);

        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_ok());

        let (owner, nonce) = result.unwrap();
        assert_eq!(owner, keypair.pubkey());
        assert_eq!(nonce, Some(0));
    }

    #[test]
    fn test_parse_solana_did_with_large_nonce() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let max_nonce = u64::MAX;
        let did = format!("did:sage:solana:{}:{}", owner_str, max_nonce);

        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_ok());

        let (owner, nonce) = result.unwrap();
        assert_eq!(owner, keypair.pubkey());
        assert_eq!(nonce, Some(max_nonce));
    }

    #[test]
    fn test_parse_solana_did_negative_nonce() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let did = format!("did:sage:solana:{}:-1", owner_str);

        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_solana_did_empty_parts() {
        // Empty method
        let result = SolanaResolver::parse_solana_did(":sage:solana:address");
        assert!(result.is_err());

        // Empty namespace
        let result = SolanaResolver::parse_solana_did("did::solana:address");
        assert!(result.is_err());

        // Empty chain
        let result = SolanaResolver::parse_solana_did("did:sage::address");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_solana_did_case_sensitivity() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();

        // Should fail with different case
        let did = format!("DID:SAGE:SOLANA:{}", owner_str);
        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());

        // Should fail with different method case
        let did = format!("did:SAGE:solana:{}", owner_str);
        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());

        // Should fail with different chain case
        let did = format!("did:sage:SOLANA:{}", owner_str);
        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_solana_did_whitespace() {
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();

        // Should fail with whitespace
        let did = format!("did:sage:solana: {}", owner_str);
        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());

        // Should fail with trailing whitespace
        let did = format!("did:sage:solana:{} ", owner_str);
        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_solana_did_special_characters() {
        // Test with special characters in address
        let result = SolanaResolver::parse_solana_did("did:sage:solana:addr@#$%");
        assert!(result.is_err());

        // Test with special characters in nonce
        let keypair = Keypair::new();
        let owner_str = keypair.pubkey().to_string();
        let did = format!("did:sage:solana:{}:1@2", owner_str);
        let result = SolanaResolver::parse_solana_did(&did);
        assert!(result.is_err());
    }
}
