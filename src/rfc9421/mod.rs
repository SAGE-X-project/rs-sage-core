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
    /// ECDSA secp256k1 over Keccak-256 (Ethereum convention), `es256k`
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
}

/// HTTP signature input string builder
pub struct SignatureInput {
    components: Vec<String>,
    params: SignatureParams,
}

impl Default for SignatureInput {
    fn default() -> Self {
        Self::new()
    }
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
            format!("({components})")
        } else {
            format!("({components});{params}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== SignatureAlgorithm Tests =====

    #[test]
    fn test_signature_algorithm_ed25519_identifier() {
        let alg = SignatureAlgorithm::Ed25519;
        assert_eq!(alg.identifier(), "ed25519");
    }

    #[test]
    fn test_signature_algorithm_ecdsa_p256_identifier() {
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        assert_eq!(alg.identifier(), "ecdsa-p256-sha256");
    }

    #[test]
    fn test_signature_algorithm_ecdsa_secp256k1_identifier() {
        let alg = SignatureAlgorithm::EcdsaSecp256k1Sha256;
        assert_eq!(alg.identifier(), "es256k");
    }

    #[test]
    fn test_signature_algorithm_equality() {
        let alg1 = SignatureAlgorithm::Ed25519;
        let alg2 = SignatureAlgorithm::Ed25519;
        let alg3 = SignatureAlgorithm::EcdsaP256Sha256;

        assert_eq!(alg1, alg2);
        assert_ne!(alg1, alg3);
    }

    #[test]
    fn test_signature_algorithm_clone() {
        let alg1 = SignatureAlgorithm::Ed25519;
        let alg2 = alg1;

        assert_eq!(alg1, alg2);
    }

    // ===== SignatureInput Builder Tests =====

    #[test]
    fn test_signature_input_new() {
        let input = SignatureInput::new();
        assert_eq!(input.components.len(), 0);
    }

    #[test]
    fn test_signature_input_default() {
        let input = SignatureInput::default();
        assert_eq!(input.components.len(), 0);
    }

    #[test]
    fn test_signature_input_add_component() {
        let input = SignatureInput::new().add_component(SignatureComponent::Method);

        assert_eq!(input.components.len(), 1);
        assert_eq!(input.components[0], "@method");
    }

    #[test]
    fn test_signature_input_add_multiple_components() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::Path)
            .add_component(SignatureComponent::Header("content-type".to_string()));

        assert_eq!(input.components.len(), 3);
        assert_eq!(input.components[0], "@method");
        assert_eq!(input.components[1], "@path");
        assert_eq!(input.components[2], "content-type");
    }

    #[test]
    fn test_signature_input_key_id() {
        let input = SignatureInput::new().key_id("test-key-123");

        assert_eq!(input.params.key_id, Some("test-key-123".to_string()));
    }

    #[test]
    fn test_signature_input_algorithm() {
        let input = SignatureInput::new().algorithm(SignatureAlgorithm::Ed25519);

        assert_eq!(input.params.alg, Some("ed25519".to_string()));
    }

    #[test]
    fn test_signature_input_created() {
        let input = SignatureInput::new().created(1618884473);

        assert_eq!(input.params.created, Some(1618884473));
    }

    #[test]
    fn test_signature_input_expires() {
        let input = SignatureInput::new().expires(1618884773);

        assert_eq!(input.params.expires, Some(1618884773));
    }

    #[test]
    fn test_signature_input_build_empty() {
        let input = SignatureInput::new();
        let result = input.build();

        assert_eq!(result, "()");
    }

    #[test]
    fn test_signature_input_build_single_component() {
        let input = SignatureInput::new().add_component(SignatureComponent::Method);

        let result = input.build();

        assert_eq!(result, "(@method)");
    }

    #[test]
    fn test_signature_input_build_multiple_components() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::Path);

        let result = input.build();

        assert_eq!(result, "(@method @path)");
    }

    #[test]
    fn test_signature_input_build_with_key_id() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .key_id("test-key");

        let result = input.build();

        assert!(result.starts_with("(@method);"));
        assert!(result.contains("keyid=\"test-key\""));
    }

    #[test]
    fn test_signature_input_build_with_algorithm() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .algorithm(SignatureAlgorithm::Ed25519);

        let result = input.build();

        assert!(result.starts_with("(@method);"));
        assert!(result.contains("alg=\"ed25519\""));
    }

    #[test]
    fn test_signature_input_build_with_created() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .created(1618884473);

        let result = input.build();

        assert!(result.starts_with("(@method);"));
        assert!(result.contains("created=1618884473"));
    }

    #[test]
    fn test_signature_input_build_with_expires() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .expires(1618884773);

        let result = input.build();

        assert!(result.starts_with("(@method);"));
        assert!(result.contains("expires=1618884773"));
    }

    #[test]
    fn test_signature_input_build_with_all_params() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::Path)
            .key_id("test-key")
            .algorithm(SignatureAlgorithm::Ed25519)
            .created(1618884473)
            .expires(1618884773);

        let result = input.build();

        assert!(result.starts_with("(@method @path);"));
        assert!(result.contains("keyid=\"test-key\""));
        assert!(result.contains("alg=\"ed25519\""));
        assert!(result.contains("created=1618884473"));
        assert!(result.contains("expires=1618884773"));
    }

    #[test]
    fn test_signature_input_builder_chain() {
        let result = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::Path)
            .add_component(SignatureComponent::Authority)
            .key_id("my-key")
            .algorithm(SignatureAlgorithm::EcdsaP256Sha256)
            .created(1000000)
            .expires(2000000)
            .build();

        assert!(result.starts_with("(@method @path @authority);"));
    }

    #[test]
    fn test_signature_input_with_header_component() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Header("content-type".to_string()))
            .add_component(SignatureComponent::Header("x-custom".to_string()));

        let result = input.build();

        assert_eq!(result, "(content-type x-custom)");
    }

    #[test]
    fn test_signature_input_all_component_types() {
        let input = SignatureInput::new()
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::TargetUri)
            .add_component(SignatureComponent::Authority)
            .add_component(SignatureComponent::Scheme)
            .add_component(SignatureComponent::RequestTarget)
            .add_component(SignatureComponent::Path)
            .add_component(SignatureComponent::Query)
            .add_component(SignatureComponent::Header("content-type".to_string()));

        assert_eq!(input.components.len(), 8);
    }
}
