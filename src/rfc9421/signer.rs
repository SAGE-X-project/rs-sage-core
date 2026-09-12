//! HTTP message signing implementation for RFC 9421

use crate::crypto::{KeyPair, Signer as CryptoSigner};
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
            HeaderValue::from_str(&format!("sig1={sig_input}"))
                .map_err(|_| Error::InvalidInput("Invalid signature input".to_string()))?,
        );

        request.headers_mut().insert(
            "signature",
            HeaderValue::from_str(&format!("sig1=:{sig_value}"))
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
            HeaderValue::from_str(&format!("sig1={sig_input}"))
                .map_err(|_| Error::InvalidInput("Invalid signature input".to_string()))?,
        );

        response.headers_mut().insert(
            "signature",
            HeaderValue::from_str(&format!("sig1=:{sig_value}"))
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
            crate::crypto::KeyType::Secp256k1 => SignatureAlgorithm::EcdsaSecp256k1Sha256,
            crate::crypto::KeyType::P256 => SignatureAlgorithm::EcdsaP256Sha256,
            crate::crypto::KeyType::Rsa2048 | crate::crypto::KeyType::Rsa4096 => {
                SignatureAlgorithm::RsaPkcs1v15Sha256
            }
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

        format!("({});{}", component_ids.join(" "), params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;
    use http::{Request, Response, StatusCode};

    // ===== HttpSigner Creation Tests =====

    #[test]
    fn test_http_signer_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);
        assert_eq!(signer.default_components.len(), 3);
    }

    #[test]
    fn test_http_signer_with_custom_components() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let custom_components = vec![
            SignatureComponent::Method,
            SignatureComponent::Path,
            SignatureComponent::Header("content-type".to_string()),
        ];
        let signer = HttpSigner::new(keypair).with_default_components(custom_components.clone());
        assert_eq!(signer.default_components.len(), 3);
        assert_eq!(signer.default_components, custom_components);
    }

    #[test]
    fn test_http_signer_with_empty_components() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair).with_default_components(vec![]);
        assert_eq!(signer.default_components.len(), 0);
    }

    // ===== Request Signing Tests =====

    #[test]
    fn test_sign_request_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/foo")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        // Verify signature headers exist
        assert!(signed_request.headers().contains_key("signature"));
        assert!(signed_request.headers().contains_key("signature-input"));
    }

    #[test]
    fn test_sign_request_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(keypair);

        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/test")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        assert!(signed_request.headers().contains_key("signature"));
        assert!(signed_request.headers().contains_key("signature-input"));
    }

    #[test]
    fn test_sign_request_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let signer = HttpSigner::new(keypair);

        let request = Request::builder()
            .method("PUT")
            .uri("https://example.com/data")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        assert!(signed_request.headers().contains_key("signature"));
        assert!(signed_request.headers().contains_key("signature-input"));
    }

    #[test]
    fn test_sign_request_rsa() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let signer = HttpSigner::new(keypair);

        let request = Request::builder()
            .method("DELETE")
            .uri("https://example.com/item/123")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        assert!(signed_request.headers().contains_key("signature"));
        assert!(signed_request.headers().contains_key("signature-input"));
    }

    #[test]
    fn test_sign_request_signature_format() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/api")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        // Check signature format: "sig1=:base64:"
        let sig_header = signed_request.headers().get("signature").unwrap();
        let sig_str = sig_header.to_str().unwrap();
        assert!(sig_str.starts_with("sig1=:"));

        // Check signature-input format: "sig1=(...);..."
        let sig_input_header = signed_request.headers().get("signature-input").unwrap();
        let sig_input_str = sig_input_header.to_str().unwrap();
        assert!(sig_input_str.starts_with("sig1=("));
        assert!(sig_input_str.contains(");"));
    }

    #[test]
    fn test_sign_request_custom_components() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let custom_components = vec![
            SignatureComponent::Method,
            SignatureComponent::Path,
            SignatureComponent::Header("host".to_string()),
        ];
        let signer = HttpSigner::new(keypair).with_default_components(custom_components);

        let request = Request::builder()
            .method("GET")
            .uri("https://api.example.com/users")
            .header("host", "api.example.com")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        let sig_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        // Verify custom components are in signature input
        assert!(sig_input.contains("@method"));
        assert!(sig_input.contains("@path"));
        assert!(sig_input.contains("\"host\""));
    }

    // ===== Response Signing Tests =====

    #[test]
    fn test_sign_response_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_response = signer.sign_response(response).unwrap();

        assert!(signed_response.headers().contains_key("signature"));
        assert!(signed_response.headers().contains_key("signature-input"));
    }

    #[test]
    fn test_sign_response_status_codes() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let test_statuses = vec![
            StatusCode::OK,
            StatusCode::CREATED,
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ];

        for status in test_statuses {
            let response = Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(())
                .unwrap();

            let signed_response = signer.sign_response(response).unwrap();

            assert!(signed_response.headers().contains_key("signature"));
            assert!(signed_response.headers().contains_key("signature-input"));

            let sig_input = signed_response
                .headers()
                .get("signature-input")
                .unwrap()
                .to_str()
                .unwrap();

            // Response signatures should include @status
            assert!(sig_input.contains("@status"));
        }
    }

    #[test]
    fn test_sign_response_different_algorithms() {
        let key_types = vec![
            KeyType::Ed25519,
            KeyType::Secp256k1,
            KeyType::P256,
            KeyType::Rsa2048,
        ];

        for key_type in key_types {
            let keypair = KeyPair::generate(key_type).unwrap();
            let signer = HttpSigner::new(keypair);

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(())
                .unwrap();

            let signed_response = signer.sign_response(response).unwrap();

            assert!(signed_response.headers().contains_key("signature"));
            assert!(signed_response.headers().contains_key("signature-input"));
        }
    }

    // ===== Signature Parameters Tests =====

    #[test]
    fn test_build_signature_params_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let params = signer.build_signature_params().unwrap();

        assert!(params.key_id.is_some());
        assert!(params.alg.is_some());
        assert_eq!(params.alg.unwrap(), "ed25519");
        assert!(params.created.is_some());
        assert!(params.expires.is_some());

        // Expires should be ~5 minutes after created
        let created = params.created.unwrap();
        let expires = params.expires.unwrap();
        assert_eq!(expires - created, 300);
    }

    #[test]
    fn test_build_signature_params_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(keypair);

        let params = signer.build_signature_params().unwrap();

        assert_eq!(params.alg.unwrap(), "ecdsa-secp256k1-sha256");
    }

    #[test]
    fn test_build_signature_params_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let signer = HttpSigner::new(keypair);

        let params = signer.build_signature_params().unwrap();

        assert_eq!(params.alg.unwrap(), "ecdsa-p256-sha256");
    }

    #[test]
    fn test_build_signature_params_rsa2048() {
        let keypair = KeyPair::generate(KeyType::Rsa2048).unwrap();
        let signer = HttpSigner::new(keypair);

        let params = signer.build_signature_params().unwrap();

        assert_eq!(params.alg.unwrap(), "rsa-v1_5-sha256");
    }

    #[test]
    fn test_build_signature_params_rsa4096() {
        let keypair = KeyPair::generate(KeyType::Rsa4096).unwrap();
        let signer = HttpSigner::new(keypair);

        let params = signer.build_signature_params().unwrap();

        assert_eq!(params.alg.unwrap(), "rsa-v1_5-sha256");
    }

    // ===== Signature Input Tests =====

    #[test]
    fn test_build_signature_input_single_component() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let components = vec![SignatureComponent::Method];
        let params = SignatureParams {
            key_id: Some("test-key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1618884473),
            expires: Some(1618884773),
            nonce: None,
            tag: None,
        };

        let sig_input = signer.build_signature_input(&components, &params);

        assert!(sig_input.starts_with("(\"@method\");"));
        assert!(sig_input.contains("created=1618884473"));
        assert!(sig_input.contains("expires=1618884773"));
        assert!(sig_input.contains("alg=\"ed25519\""));
    }

    #[test]
    fn test_build_signature_input_multiple_components() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let components = vec![
            SignatureComponent::Method,
            SignatureComponent::Path,
            SignatureComponent::Header("content-type".to_string()),
        ];
        let params = SignatureParams {
            key_id: Some("test-key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1618884473),
            expires: None,
            nonce: None,
            tag: None,
        };

        let sig_input = signer.build_signature_input(&components, &params);

        assert!(sig_input.starts_with("(\"@method\" \"@path\" \"content-type\");"));
        assert!(sig_input.contains("created=1618884473"));
    }

    #[test]
    fn test_build_signature_input_empty_components() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let components = vec![];
        let params = SignatureParams {
            key_id: Some("test-key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1618884473),
            expires: None,
            nonce: None,
            tag: None,
        };

        let sig_input = signer.build_signature_input(&components, &params);

        assert!(sig_input.starts_with("();"));
    }

    // ===== Integration Tests =====

    #[test]
    fn test_request_sign_and_verify_headers() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed = signer.sign_request(request).unwrap();

        // Verify both headers are present
        let signature = signed.headers().get("signature").unwrap().to_str().unwrap();
        let sig_input = signed
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        // Signature should be base64 encoded with format "sig1=:base64"
        assert!(signature.starts_with("sig1=:"));
        assert!(signature.len() > 7); // More than just "sig1=:"

        // Signature input should have proper format
        assert!(sig_input.starts_with("sig1=("));
        assert!(sig_input.contains("@method"));
        assert!(sig_input.contains("@path"));
        assert!(sig_input.contains("@authority"));
    }

    #[test]
    fn test_response_sign_and_verify_headers() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair);

        let response = Response::builder()
            .status(StatusCode::CREATED)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed = signer.sign_response(response).unwrap();

        let signature = signed.headers().get("signature").unwrap().to_str().unwrap();
        let sig_input = signed
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(signature.starts_with("sig1=:"));
        assert!(sig_input.starts_with("sig1=("));
        assert!(sig_input.contains("@status"));
        assert!(sig_input.contains("\"content-type\""));
    }
}
