//! The `did:sage` method (sage-spec `06-did-sage.md`) and the A2A agent
//! card (`07-a2a.md`).
//!
//! ```
//! use sage_crypto_core::did::{parse_did, Chain};
//! let (chain, id) = parse_did("did:sage:ethereum:0xabc:42").unwrap();
//! assert_eq!(chain, Chain::Ethereum);
//! assert_eq!(id, "0xabc:42");
//! ```

pub mod a2a;
pub mod proof;
pub mod resolver;

use crate::crypto::{KeyType, PublicKey};
use crate::error::{Error, Result};

// Re-export the DID document types for existing resolver users.
pub use crate::hpke::types::{
    AgentDID as DID, DIDDocument, DIDResolutionResult, VerificationMethod, VerificationReference,
};
pub use a2a::{A2AAgentCard, A2AEndpoint, A2AProof, A2APublicKey, CardMetadata};
pub use proof::{generate_key_pop, pop_challenge, verify_key_pop};
pub use resolver::{DIDResolver, MemoryDIDResolver, MockDIDResolver};

/// Chains a `did:sage` identifier can live on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// EVM chains (Ethereum, Kaia, ...)
    Ethereum,
    /// Solana
    Solana,
}

impl Chain {
    /// The canonical chain name used inside DIDs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Chain::Ethereum => "ethereum",
            Chain::Solana => "solana",
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a chain name: trimmed, case-insensitive, with the `eth` and `sol`
/// aliases (`06-did-sage.md` §2).
pub fn parse_chain(name: &str) -> Result<Chain> {
    match name.trim().to_lowercase().as_str() {
        "ethereum" | "eth" => Ok(Chain::Ethereum),
        "solana" | "sol" => Ok(Chain::Solana),
        other => Err(Error::InvalidInput(format!("unsupported chain {other:?}"))),
    }
}

/// Build `did:sage:<chain>:<identifier>`.
pub fn generate_did(chain: Chain, identifier: &str) -> String {
    format!("did:sage:{}:{identifier}", chain.as_str())
}

/// Parse `did:sage:<chain>:<identifier>`; the identifier keeps any further
/// colons (`06-did-sage.md` §1).
pub fn parse_did(did: &str) -> Result<(Chain, String)> {
    if did.len() < 10 || !did.starts_with("did:") {
        return Err(Error::InvalidInput("invalid DID".into()));
    }
    let mut parts = did.splitn(4, ':');
    let (Some("did"), Some("sage"), Some(chain), Some(identifier)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::InvalidInput(format!(
            "DID must be did:sage:<chain>:<identifier>: {did}"
        )));
    };
    if identifier.is_empty() {
        return Err(Error::InvalidInput("empty DID identifier".into()));
    }
    Ok((parse_chain(chain)?, identifier.to_string()))
}

/// Whether the string is a well-formed `did:sage` identifier.
pub fn validate_did(did: &str) -> bool {
    parse_did(did).is_ok()
}

/// Derive an agent DID from a public key: secp256k1 keys map to their
/// Ethereum address on `ethereum`, Ed25519 keys to their base58 encoding on
/// `solana`.
pub fn generate_did_from_pubkey(public_key: &PublicKey) -> Result<DID> {
    match public_key.key_type() {
        KeyType::Secp256k1 => Ok(generate_did(
            Chain::Ethereum,
            &public_key.ethereum_address()?,
        )),
        KeyType::Ed25519 => Ok(generate_did(
            Chain::Solana,
            &bs58::encode(public_key.to_bytes()).into_string(),
        )),
        KeyType::P256 => Err(Error::Unsupported(
            "no did:sage chain uses P-256 keys".into(),
        )),
    }
}

/// Convenience accessors on DID strings.
pub trait DIDExt {
    /// Identifier part after `did:sage:<chain>:`
    fn identifier(&self) -> String;
    /// Chain part
    fn chain(&self) -> Option<Chain>;
    /// The DID as a string slice
    fn as_str(&self) -> &str;
}

impl DIDExt for DID {
    fn identifier(&self) -> String {
        parse_did(self).map(|(_, id)| id).unwrap_or_default()
    }
    fn chain(&self) -> Option<Chain> {
        parse_did(self).ok().map(|(c, _)| c)
    }
    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        assert_eq!(
            parse_did("did:sage:ethereum:0xabc").unwrap(),
            (Chain::Ethereum, "0xabc".into())
        );
        assert_eq!(
            parse_did("did:sage:ETH:0xabc:7").unwrap(),
            (Chain::Ethereum, "0xabc:7".into())
        );
        assert_eq!(
            parse_did("did:sage:sol:Abc").unwrap(),
            (Chain::Solana, "Abc".into())
        );
        for bad in [
            "",
            "did:sage",
            "did:sage:ethereum",
            "did:web:x",
            "did:sage:polkadot:abc",
            "sage:ethereum:0xabc",
            "did:sage::0xabc",
        ] {
            assert!(parse_did(bad).is_err(), "{bad}");
        }
        assert_eq!(generate_did(Chain::Solana, "X"), "did:sage:solana:X");
        assert_eq!(parse_chain(" Solana ").unwrap(), Chain::Solana);
        assert!(parse_chain("bitcoin").is_err());
    }

    #[test]
    fn did_from_keys() {
        use crate::crypto::KeyPair;
        let k = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let did = generate_did_from_pubkey(k.public_key()).unwrap();
        assert!(did.starts_with("did:sage:ethereum:0x"));
        assert_eq!(did.identifier().len(), 42);
        let e = KeyPair::generate(KeyType::Ed25519).unwrap();
        assert!(generate_did_from_pubkey(e.public_key())
            .unwrap()
            .starts_with("did:sage:solana:"));
    }
}
