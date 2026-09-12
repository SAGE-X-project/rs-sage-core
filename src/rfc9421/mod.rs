//! RFC 9421 HTTP Message Signatures as profiled by sage-spec
//! `03-rfc9421.md`: covered components with `;req` binding, `Content-Digest`,
//! `keyid` carrying the agent DID, nonce replay protection and the SAGE
//! algorithm identifiers.

pub mod canonicalize;
pub mod components;
pub mod dictionary;
pub mod replay;
pub mod signer;
pub mod verifier;

pub use canonicalize::{content_digest, verify_content_digest};
pub use components::{
    format_signature_input, parse_signature_input_value, SignatureComponent, SignatureParams,
};
pub use dictionary::{parse_signature_header, parse_signature_input, SignatureInputMember};
pub use replay::{MemoryReplayGuard, ReplayGuard};
pub use signer::{
    algorithm_for, default_request_components, default_response_components, HttpSigner,
};
pub use verifier::{HttpVerifier, VerifyOptions, DEFAULT_MAX_AGE};

/// Signature algorithm identifiers for RFC 9421 (sage-spec `01-crypto.md` §3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// `ed25519`
    Ed25519,
    /// `ecdsa-p256-sha256`
    EcdsaP256Sha256,
    /// `es256k`: ECDSA secp256k1 over Keccak-256 (Ethereum convention)
    EcdsaSecp256k1Sha256,
}

impl SignatureAlgorithm {
    /// Get the algorithm identifier string
    pub fn identifier(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            SignatureAlgorithm::EcdsaSecp256k1Sha256 => "es256k",
        }
    }

    /// Parse an identifier string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(SignatureAlgorithm::Ed25519),
            "ecdsa-p256-sha256" => Some(SignatureAlgorithm::EcdsaP256Sha256),
            "es256k" => Some(SignatureAlgorithm::EcdsaSecp256k1Sha256),
            _ => None,
        }
    }
}

/// Builder for a `Signature-Input` member value.
#[derive(Debug, Clone, Default)]
pub struct SignatureInput {
    components: Vec<SignatureComponent>,
    params: SignatureParams,
}

impl SignatureInput {
    /// Empty builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a covered component
    pub fn add_component(mut self, component: SignatureComponent) -> Self {
        self.components.push(component);
        self
    }

    /// Set `keyid`
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.params.key_id = Some(key_id.into());
        self
    }

    /// Set `alg`
    pub fn algorithm(mut self, alg: SignatureAlgorithm) -> Self {
        self.params.alg = Some(alg.identifier().to_string());
        self
    }

    /// Set `created`
    pub fn created(mut self, created: i64) -> Self {
        self.params.created = Some(created);
        self
    }

    /// Set `expires`
    pub fn expires(mut self, expires: i64) -> Self {
        self.params.expires = Some(expires);
        self
    }

    /// Set `nonce`
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.params.nonce = Some(nonce.into());
        self
    }

    /// The components
    pub fn components(&self) -> &[SignatureComponent] {
        &self.components
    }

    /// The parameters
    pub fn params(&self) -> &SignatureParams {
        &self.params
    }

    /// Build the member value: `("@method" …);keyid="…";…`
    pub fn build(&self) -> String {
        format_signature_input(&self.components, &self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        assert_eq!(SignatureAlgorithm::Ed25519.identifier(), "ed25519");
        assert_eq!(
            SignatureAlgorithm::EcdsaSecp256k1Sha256.identifier(),
            "es256k"
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaP256Sha256.identifier(),
            "ecdsa-p256-sha256"
        );
        assert_eq!(
            SignatureAlgorithm::parse("es256k"),
            Some(SignatureAlgorithm::EcdsaSecp256k1Sha256)
        );
        assert_eq!(SignatureAlgorithm::parse("rsa-pss-sha256"), None);
    }

    #[test]
    fn builder() {
        let v = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::Header("date".into()))
            .key_id("did:sage:ethereum:0x1")
            .algorithm(SignatureAlgorithm::Ed25519)
            .created(1)
            .nonce("n")
            .build();
        assert_eq!(v, "(\"@method\" \"date\");keyid=\"did:sage:ethereum:0x1\";alg=\"ed25519\";created=1;nonce=\"n\"");
    }
}
