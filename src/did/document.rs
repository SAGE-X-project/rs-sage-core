//! DID Document Structures
//!
//! This module provides DID Document types according to the W3C DID specification.

use crate::crypto::PublicKey;
use crate::did::DID;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a DID Document as per W3C DID Core specification
///
/// A DID Document contains metadata about a DID subject, including
/// verification methods, service endpoints, and other properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocument {
    /// The DID that this document describes
    pub id: String,

    /// Verification methods available for this DID
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    /// Authentication verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<VerificationReference>,

    /// Assertion verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<VerificationReference>,

    /// Key agreement verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<VerificationReference>,

    /// Capability invocation verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<VerificationReference>,

    /// Capability delegation verification methods
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<VerificationReference>,

    /// Service endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<ServiceEndpoint>,

    /// Additional properties (for extensibility)
    #[serde(flatten)]
    pub additional_properties: HashMap<String, serde_json::Value>,
}

impl DIDDocument {
    /// Creates a new DID Document for the given DID
    pub fn new(did: DID) -> Self {
        Self {
            id: did.to_string(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            additional_properties: HashMap::new(),
        }
    }

    /// Adds a verification method to the document
    pub fn add_verification_method(&mut self, method: VerificationMethod) {
        self.verification_method.push(method);
    }

    /// Adds an authentication method reference
    pub fn add_authentication(&mut self, reference: VerificationReference) {
        self.authentication.push(reference);
    }

    /// Adds an assertion method reference
    pub fn add_assertion_method(&mut self, reference: VerificationReference) {
        self.assertion_method.push(reference);
    }

    /// Adds a service endpoint
    pub fn add_service(&mut self, service: ServiceEndpoint) {
        self.service.push(service);
    }

    /// Gets a verification method by ID
    pub fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|m| m.id == id)
    }
}

/// A verification method in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// The verification method ID (typically DID#fragment)
    pub id: String,

    /// The type of verification method (e.g., "Ed25519VerificationKey2020")
    #[serde(rename = "type")]
    pub method_type: String,

    /// The DID of the controller
    pub controller: String,

    /// Public key multibase (for key material)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    /// Public key JWK (alternative format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

impl VerificationMethod {
    /// Creates a new verification method from a public key
    pub fn from_public_key(
        did: &DID,
        key_id: &str,
        public_key: &PublicKey,
    ) -> Self {
        use base58::ToBase58;

        let method_type = match public_key.key_type() {
            crate::crypto::KeyType::Ed25519 => "Ed25519VerificationKey2020",
            crate::crypto::KeyType::Secp256k1 => "EcdsaSecp256k1VerificationKey2019",
        };

        // Encode public key as multibase (base58-btc with 'z' prefix)
        let public_key_multibase = format!("z{}", public_key.to_bytes().to_base58());

        Self {
            id: format!("{}#{}", did, key_id),
            method_type: method_type.to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(public_key_multibase),
            public_key_jwk: None,
        }
    }
}

/// A reference to a verification method (can be embedded or referenced)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationReference {
    /// A reference by ID
    Reference(String),
    /// An embedded verification method
    Embedded(VerificationMethod),
}

/// A service endpoint in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpoint {
    /// The service ID
    pub id: String,

    /// The service type
    #[serde(rename = "type")]
    pub service_type: String,

    /// The service endpoint URL(s)
    pub service_endpoint: ServiceEndpointValue,
}

/// Service endpoint value (can be string or array of strings)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpointValue {
    /// Single endpoint
    Single(String),
    /// Multiple endpoints
    Multiple(Vec<String>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType};
    use crate::did::method::DIDMethod;
    use crate::did::method::generate_did_from_pubkey;

    #[test]
    fn test_did_document_new() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let doc = DIDDocument::new(did.clone());

        assert_eq!(doc.id, did.to_string());
        assert!(doc.verification_method.is_empty());
    }

    #[test]
    fn test_verification_method_from_public_key() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());

        assert_eq!(vm.id, format!("{}#key-1", did));
        assert_eq!(vm.method_type, "Ed25519VerificationKey2020");
        assert_eq!(vm.controller, did.to_string());
        assert!(vm.public_key_multibase.is_some());
        assert!(vm.public_key_multibase.unwrap().starts_with('z'));
    }

    #[test]
    fn test_did_document_with_verification_method() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let mut doc = DIDDocument::new(did.clone());

        let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
        let vm_id = vm.id.clone();
        doc.add_verification_method(vm);

        assert_eq!(doc.verification_method.len(), 1);
        assert!(doc.get_verification_method(&vm_id).is_some());
    }

    #[test]
    fn test_did_document_serialization() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Key).unwrap();
        let mut doc = DIDDocument::new(did.clone());

        let vm = VerificationMethod::from_public_key(&did, "key-1", keypair.public_key());
        doc.add_verification_method(vm);

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"verificationMethod\""));

        // Deserialize back
        let deserialized: DIDDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, doc.id);
        assert_eq!(deserialized.verification_method.len(), 1);
    }
}
