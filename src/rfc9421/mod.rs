//! RFC 9421 HTTP Message Signatures implementation

pub mod canonicalize;
pub mod components;
pub mod signer;
pub mod verifier;

pub use components::{SignatureComponent, SignatureParams};
pub use signer::HttpSigner;
pub use verifier::HttpVerifier;

/// Signature algorithm identifiers for RFC 9421
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Ed25519 signature algorithm
    Ed25519,
    /// ECDSA P-256 SHA-256
    EcdsaP256Sha256,
    /// ECDSA Secp256k1 SHA-256
    EcdsaSecp256k1Sha256,
}

impl SignatureAlgorithm {
    /// Get the algorithm identifier string
    pub fn identifier(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            SignatureAlgorithm::EcdsaSecp256k1Sha256 => "ecdsa-secp256k1-sha256",
        }
    }
}

/// HTTP signature input string builder
pub struct SignatureInput {
    components: Vec<String>,
    params: SignatureParams,
}

impl SignatureInput {
    /// Create a new signature input builder
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            params: SignatureParams::default(),
        }
    }

    /// Add a component to sign
    pub fn add_component(mut self, component: SignatureComponent) -> Self {
        self.components.push(component.identifier().to_string());
        self
    }

    /// Set the key ID
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.params.key_id = Some(key_id.into());
        self
    }

    /// Set the algorithm
    pub fn algorithm(mut self, alg: SignatureAlgorithm) -> Self {
        self.params.alg = Some(alg.identifier().to_string());
        self
    }

    /// Set the created timestamp
    pub fn created(mut self, timestamp: i64) -> Self {
        self.params.created = Some(timestamp);
        self
    }

    /// Set the expires timestamp
    pub fn expires(mut self, timestamp: i64) -> Self {
        self.params.expires = Some(timestamp);
        self
    }

    /// Build the signature input string
    pub fn build(self) -> String {
        let components = self.components.join(" ");
        let params = self.params.to_string();

        if params.is_empty() {
            format!("({})", components)
        } else {
            format!("({});{}", components, params)
        }
    }
}
