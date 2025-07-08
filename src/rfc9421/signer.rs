//! HTTP message signing implementation for RFC 9421

use crate::crypto::{KeyPair, Signature, Signer as CryptoSigner};
use crate::error::{Error, Result};
use crate::rfc9421::{SignatureAlgorithm, SignatureComponent, SignatureParams};
use base64::{engine::general_purpose, Engine as _};
use http::{HeaderValue, Request, Response};
use std::time::{SystemTime, UNIX_EPOCH};

/// HTTP message signer
pub struct HttpSigner {
    keypair: KeyPair,
    default_components: Vec<SignatureComponent>,
}

impl HttpSigner {
    /// Create a new HTTP signer with a keypair
    pub fn new(keypair: KeyPair) -> Self {
        Self {
            keypair,
            default_components: vec![
                SignatureComponent::Method,
                SignatureComponent::Path,
                SignatureComponent::Authority,
            ],
        }
    }

    /// Set default components to sign
    pub fn with_default_components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.default_components = components;
        self
    }

    /// Sign an HTTP request
    pub fn sign_request<B>(&self, mut request: Request<B>) -> Result<Request<B>> {
        let components = &self.default_components;
        let signature_params = self.build_signature_params()?;

        // Canonicalize the request
        let canonical_values = super::canonicalize::canonicalize_request(&request, components)?;

        // Build signature input
        let sig_input = self.build_signature_input(components, &signature_params);

        // Build signature base
        let signature_base =
            super::canonicalize::build_signature_base(&canonical_values, &sig_input);

        // Sign the signature base
        let signature = self.keypair.sign(signature_base.as_bytes())?;
        let sig_value = general_purpose::STANDARD.encode(signature.to_bytes());

        // Add signature headers
        request.headers_mut().insert(
            "signature-input",
            HeaderValue::from_str(&format!("sig1={}", sig_input))
                .map_err(|_| Error::InvalidInput("Invalid signature input".to_string()))?,
        );

        request.headers_mut().insert(
            "signature",
            HeaderValue::from_str(&format!("sig1=:{}", sig_value))
                .map_err(|_| Error::InvalidInput("Invalid signature value".to_string()))?,
        );

        Ok(request)
    }

    /// Sign an HTTP response
    pub fn sign_response<B>(&self, mut response: Response<B>) -> Result<Response<B>> {
        let components = vec![
            SignatureComponent::Status,
            SignatureComponent::Header("content-type".to_string()),
        ];
        let signature_params = self.build_signature_params()?;

        // Canonicalize the response
        let canonical_values = super::canonicalize::canonicalize_response(&response, &components)?;

        // Build signature input
        let sig_input = self.build_signature_input(&components, &signature_params);

        // Build signature base
        let signature_base =
            super::canonicalize::build_signature_base(&canonical_values, &sig_input);

        // Sign the signature base
        let signature = self.keypair.sign(signature_base.as_bytes())?;
        let sig_value = general_purpose::STANDARD.encode(signature.to_bytes());

        // Add signature headers
        response.headers_mut().insert(
            "signature-input",
            HeaderValue::from_str(&format!("sig1={}", sig_input))
                .map_err(|_| Error::InvalidInput("Invalid signature input".to_string()))?,
        );

        response.headers_mut().insert(
            "signature",
            HeaderValue::from_str(&format!("sig1=:{}", sig_value))
                .map_err(|_| Error::InvalidInput("Invalid signature value".to_string()))?,
        );

        Ok(response)
    }

    /// Build signature parameters
    fn build_signature_params(&self) -> Result<SignatureParams> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Other("System time error".to_string()))?
            .as_secs() as i64;

        let alg = match self.keypair.key_type() {
            crate::crypto::KeyType::Ed25519 => SignatureAlgorithm::Ed25519,
            crate::crypto::KeyType::Secp256k1 => SignatureAlgorithm::EcdsaP256Sha256,
        };

        Ok(SignatureParams {
            key_id: Some(self.keypair.public_key().key_id()),
            alg: Some(alg.identifier().to_string()),
            created: Some(now),
            expires: Some(now + 300), // 5 minutes
            nonce: None,
            tag: None,
        })
    }

    /// Build signature input string
    fn build_signature_input(
        &self,
        components: &[SignatureComponent],
        params: &SignatureParams,
    ) -> String {
        let component_ids: Vec<String> = components
            .iter()
            .map(|c| format!("\"{}\"", c.identifier()))
            .collect();

        format!("({}){}", component_ids.join(" "), params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;

    #[test]
    fn test_http_signer_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);
        assert_eq!(signer.default_components.len(), 3);
    }
}
