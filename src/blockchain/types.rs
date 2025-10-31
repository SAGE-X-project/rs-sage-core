//! Blockchain Type Definitions
//!
//! Core types for multi-chain DID and agent metadata management.

use crate::crypto::KeyType;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported blockchain networks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// Ethereum blockchain
    Ethereum,
    /// Solana blockchain
    Solana,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Ethereum => write!(f, "ethereum"),
            Chain::Solana => write!(f, "solana"),
        }
    }
}

impl std::str::FromStr for Chain {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ethereum" => Ok(Chain::Ethereum),
            "solana" => Ok(Chain::Solana),
            _ => Err(Error::InvalidInput(format!("Unknown chain: {}", s))),
        }
    }
}

/// Network identifiers for different blockchain environments
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    // Ethereum networks
    /// Ethereum mainnet
    EthereumMainnet,
    /// Ethereum Sepolia testnet
    EthereumSepolia,
    /// Ethereum Goerli testnet (deprecated)
    EthereumGoerli,
    /// Ethereum Holesky testnet
    EthereumHolesky,

    // Solana networks
    /// Solana mainnet-beta
    SolanaMainnet,
    /// Solana devnet
    SolanaDevnet,
    /// Solana testnet
    SolanaTestnet,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::EthereumMainnet => write!(f, "ethereum-mainnet"),
            Network::EthereumSepolia => write!(f, "ethereum-sepolia"),
            Network::EthereumGoerli => write!(f, "ethereum-goerli"),
            Network::EthereumHolesky => write!(f, "ethereum-holesky"),
            Network::SolanaMainnet => write!(f, "solana-mainnet"),
            Network::SolanaDevnet => write!(f, "solana-devnet"),
            Network::SolanaTestnet => write!(f, "solana-testnet"),
        }
    }
}

/// Agent DID (Decentralized Identifier)
///
/// Format: `did:sage:{chain}:{identifier}`
///
/// Examples:
/// - Simple: `did:sage:ethereum:0x1234...`
/// - With owner: `did:sage:ethereum:0xowner_address`
/// - With nonce: `did:sage:ethereum:0xowner_address:42`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentDID(String);

impl AgentDID {
    /// Create a new AgentDID from a string
    ///
    /// # Arguments
    /// * `did` - DID string in format `did:sage:{chain}:{identifier}`
    ///
    /// # Errors
    /// Returns error if DID format is invalid
    pub fn new(did: impl Into<String>) -> Result<Self> {
        let did_str = did.into();
        Self::validate(&did_str)?;
        Ok(Self(did_str))
    }

    /// Parse a DID string (alias for new)
    pub fn parse(did: &str) -> Result<Self> {
        Self::new(did.to_string())
    }

    /// Validate DID format
    fn validate(did: &str) -> Result<()> {
        if !did.starts_with("did:sage:") {
            return Err(Error::InvalidInput(
                "DID must start with 'did:sage:'".into(),
            ));
        }

        let parts: Vec<&str> = did.split(':').collect();
        if parts.len() < 4 {
            return Err(Error::InvalidInput(
                "DID must have format 'did:sage:chain:identifier'".into(),
            ));
        }

        // Validate chain
        let _ = parts[2].parse::<Chain>()?;

        Ok(())
    }

    /// Extract chain from DID
    ///
    /// # Example
    /// ```
    /// # use sage_crypto_core::blockchain::AgentDID;
    /// let did = AgentDID::parse("did:sage:ethereum:0x123").unwrap();
    /// assert_eq!(did.chain().unwrap().to_string(), "ethereum");
    /// ```
    pub fn chain(&self) -> Result<Chain> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() < 3 {
            return Err(Error::InvalidInput("Invalid DID format".into()));
        }
        parts[2].parse()
    }

    /// Extract identifier/address from DID
    ///
    /// # Example
    /// ```
    /// # use sage_crypto_core::blockchain::AgentDID;
    /// let did = AgentDID::parse("did:sage:ethereum:0x123").unwrap();
    /// assert_eq!(did.identifier(), "0x123");
    /// ```
    pub fn identifier(&self) -> &str {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() >= 4 {
            parts[3]
        } else {
            ""
        }
    }

    /// Extract address from DID (same as identifier)
    pub fn address(&self) -> Result<String> {
        let identifier = self.identifier();
        if identifier.is_empty() {
            return Err(Error::InvalidInput("Missing address in DID".into()));
        }
        Ok(identifier.to_string())
    }

    /// Extract nonce if present (for DIDs with nonce: did:sage:chain:address:nonce)
    ///
    /// # Example
    /// ```
    /// # use sage_crypto_core::blockchain::AgentDID;
    /// let did = AgentDID::parse("did:sage:ethereum:0x123:42").unwrap();
    /// assert_eq!(did.nonce(), Some(42));
    /// ```
    pub fn nonce(&self) -> Option<u64> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() >= 5 {
            parts[4].parse().ok()
        } else {
            None
        }
    }

    /// Get the DID string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentDID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AgentDID {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// DID format variants
#[derive(Debug, Clone)]
pub enum DIDFormat {
    /// Simple format: did:sage:{chain}:{identifier}
    Simple,
    /// With owner address: did:sage:{chain}:0x{address}
    WithAddress(String),
    /// With nonce: did:sage:{chain}:0x{address}:{nonce}
    WithNonce(String, u64),
}

/// Generate agent DID with owner address
///
/// Format: `did:sage:{chain}:{owner_address}`
///
/// # Arguments
/// * `chain` - Blockchain network
/// * `owner_address` - Owner's address (Ethereum: 0x-prefixed hex, Solana: base58)
///
/// # Example
/// ```
/// # use sage_crypto_core::blockchain::{Chain, generate_agent_did_with_address};
/// let did = generate_agent_did_with_address(
///     Chain::Ethereum,
///     "0x1234567890123456789012345678901234567890"
/// ).unwrap();
/// assert_eq!(did, "did:sage:ethereum:0x1234567890123456789012345678901234567890");
/// ```
pub fn generate_agent_did_with_address(chain: Chain, owner_address: &str) -> Result<String> {
    validate_address(chain, owner_address)?;
    Ok(format!("did:sage:{}:{}", chain, owner_address))
}

/// Generate agent DID with nonce
///
/// Format: `did:sage:{chain}:{owner_address}:{nonce}`
///
/// # Arguments
/// * `chain` - Blockchain network
/// * `owner_address` - Owner's address
/// * `nonce` - Unique nonce value
///
/// # Example
/// ```
/// # use sage_crypto_core::blockchain::{Chain, generate_agent_did_with_nonce};
/// let did = generate_agent_did_with_nonce(
///     Chain::Ethereum,
///     "0x1234567890123456789012345678901234567890",
///     42
/// ).unwrap();
/// assert_eq!(did, "did:sage:ethereum:0x1234567890123456789012345678901234567890:42");
/// ```
pub fn generate_agent_did_with_nonce(
    chain: Chain,
    owner_address: &str,
    nonce: u64,
) -> Result<String> {
    validate_address(chain, owner_address)?;
    Ok(format!("did:sage:{}:{}:{}", chain, owner_address, nonce))
}

/// Derive Ethereum address from secp256k1 public key
///
/// Uses Keccak256 hashing (Ethereum-style) to derive the address from an
/// uncompressed public key.
///
/// # Arguments
/// * `public_key` - Uncompressed public key (65 bytes: 0x04 + x + y)
///
/// # Returns
/// Ethereum address in checksummed hex format (0x-prefixed)
///
/// # Example
/// ```no_run
/// # use sage_crypto_core::blockchain::derive_ethereum_address;
/// let public_key = vec![0x04; 65]; // Placeholder
/// let address = derive_ethereum_address(&public_key).unwrap();
/// assert!(address.starts_with("0x"));
/// assert_eq!(address.len(), 42); // 0x + 40 hex chars
/// ```
pub fn derive_ethereum_address(public_key: &[u8]) -> Result<String> {
    use tiny_keccak::{Hasher, Keccak};

    if public_key.len() != 65 {
        return Err(Error::InvalidInput(
            "Public key must be 65 bytes (uncompressed)".into(),
        ));
    }

    if public_key[0] != 0x04 {
        return Err(Error::InvalidInput(
            "Public key must start with 0x04 (uncompressed marker)".into(),
        ));
    }

    // Skip the 0x04 prefix
    let key_bytes = &public_key[1..];

    // Keccak256 hash
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(key_bytes);
    keccak.finalize(&mut hash);

    // Take last 20 bytes
    let address_bytes = &hash[12..];

    // Return with 0x prefix (lowercase)
    Ok(format!("0x{}", hex::encode(address_bytes)))
}

/// Validate address format for the given chain
fn validate_address(chain: Chain, address: &str) -> Result<()> {
    match chain {
        Chain::Ethereum => {
            if !address.starts_with("0x") {
                return Err(Error::InvalidInput(
                    "Ethereum address must start with '0x'".into(),
                ));
            }
            if address.len() != 42 {
                return Err(Error::InvalidInput(format!(
                    "Ethereum address must be 42 characters (0x + 40 hex), got {}",
                    address.len()
                )));
            }
            // Validate hex
            if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Error::InvalidInput(
                    "Ethereum address must contain only hex characters".into(),
                ));
            }
        }
        Chain::Solana => {
            // Solana uses base58 encoding, typically 32-44 characters
            if address.is_empty() {
                return Err(Error::InvalidInput("Solana address cannot be empty".into()));
            }
            // Basic validation: check if it's valid base58
            if bs58::decode(address).into_vec().is_err() {
                return Err(Error::InvalidInput(
                    "Invalid Solana address (not valid base58)".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Public key information stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Key type (Ed25519, Secp256k1, P256, etc.)
    pub key_type: KeyType,
    /// Public key bytes
    pub key_data: Vec<u8>,
    /// Keccak256 hash of the public key
    pub key_hash: [u8; 32],
    /// Whether this key has been verified on-chain
    pub verified: bool,
}

/// Agent metadata stored on or resolved from blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    /// Agent DID
    pub did: AgentDID,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// API endpoint URL
    pub endpoint: String,
    /// List of public keys (up to 10)
    pub public_keys: Vec<PublicKeyInfo>,
    /// Agent capabilities (e.g., ["chat", "analysis"])
    pub capabilities: Vec<String>,
    /// Owner address (who registered the agent)
    pub owner: String,
    /// Whether the agent is active
    pub is_active: bool,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Last update timestamp (Unix seconds)
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_display() {
        assert_eq!(Chain::Ethereum.to_string(), "ethereum");
        assert_eq!(Chain::Solana.to_string(), "solana");
    }

    #[test]
    fn test_chain_from_str() {
        assert_eq!("ethereum".parse::<Chain>().unwrap(), Chain::Ethereum);
        assert_eq!("ETHEREUM".parse::<Chain>().unwrap(), Chain::Ethereum);
        assert_eq!("solana".parse::<Chain>().unwrap(), Chain::Solana);
        assert!("bitcoin".parse::<Chain>().is_err());
    }

    #[test]
    fn test_agent_did_parse() {
        let did = AgentDID::parse("did:sage:ethereum:0x123").unwrap();
        assert_eq!(did.chain().unwrap(), Chain::Ethereum);
        assert_eq!(did.identifier(), "0x123");
        assert_eq!(did.nonce(), None);
    }

    #[test]
    fn test_agent_did_with_nonce() {
        let did = AgentDID::parse("did:sage:solana:ABC123:42").unwrap();
        assert_eq!(did.chain().unwrap(), Chain::Solana);
        assert_eq!(did.identifier(), "ABC123");
        assert_eq!(did.nonce(), Some(42));
    }

    #[test]
    fn test_agent_did_invalid() {
        assert!(AgentDID::parse("invalid-did").is_err());
        assert!(AgentDID::parse("did:other:ethereum:123").is_err());
        assert!(AgentDID::parse("did:sage:unknown:123").is_err());
    }

    #[test]
    fn test_generate_agent_did_with_address() {
        let did = generate_agent_did_with_address(
            Chain::Ethereum,
            "0x1234567890123456789012345678901234567890",
        )
        .unwrap();
        assert_eq!(
            did,
            "did:sage:ethereum:0x1234567890123456789012345678901234567890"
        );
    }

    #[test]
    fn test_generate_agent_did_with_nonce() {
        let did = generate_agent_did_with_nonce(
            Chain::Ethereum,
            "0x1234567890123456789012345678901234567890",
            42,
        )
        .unwrap();
        assert_eq!(
            did,
            "did:sage:ethereum:0x1234567890123456789012345678901234567890:42"
        );
    }

    #[test]
    fn test_validate_ethereum_address() {
        assert!(validate_address(
            Chain::Ethereum,
            "0x1234567890123456789012345678901234567890"
        )
        .is_ok());
        assert!(validate_address(Chain::Ethereum, "0x123").is_err()); // Too short
        assert!(validate_address(Chain::Ethereum, "1234567890123456789012345678901234567890").is_err()); // No 0x
        assert!(validate_address(Chain::Ethereum, "0x123456789012345678901234567890123456789g").is_err()); // Invalid hex
    }

    #[test]
    fn test_derive_ethereum_address() {
        // Test with a known public key (this is a placeholder test)
        // In real tests, use known test vectors from Ethereum
        let mut public_key = vec![0x04]; // Uncompressed marker
        public_key.extend_from_slice(&[0u8; 64]); // x + y coordinates

        let address = derive_ethereum_address(&public_key).unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_derive_ethereum_address_invalid() {
        // Wrong length
        assert!(derive_ethereum_address(&[0u8; 32]).is_err());

        // Wrong prefix
        let mut wrong_prefix = vec![0x03]; // Compressed marker
        wrong_prefix.extend_from_slice(&[0u8; 64]);
        assert!(derive_ethereum_address(&wrong_prefix).is_err());
    }
}
