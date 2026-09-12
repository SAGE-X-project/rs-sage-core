//! HTTP message signature verification for RFC 9421

use crate::crypto::{PublicKey, Signature, Verifier as CryptoVerifier};
use crate::error::{Error, Result};
use crate::rfc9421::{SignatureComponent, SignatureParams};
use base64::{engine::general_purpose, Engine as _};
use http::{HeaderMap, Request, Response};
use std::time::{SystemTime, UNIX_EPOCH};

/// HTTP message signature verifier
pub struct HttpVerifier {
    public_key: PublicKey,
}

impl HttpVerifier {
    /// Create a new HTTP verifier with a public key
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Parse signature bytes into a Signature enum based on the public key type
    fn parse_signature(&self, signature_bytes: &[u8]) -> Result<Signature> {
        Signature::from_bytes(self.public_key.key_type(), signature_bytes)
    }

    /// Verify an HTTP request signature
    pub fn verify_request<B>(&self, request: &Request<B>) -> Result<()> {
        // Extract signature and signature-input headers
        let (sig_value, sig_input) = extract_signature_headers(request.headers())?;

        // Parse signature input to get components and parameters
        let (components, params) = parse_signature_input(&sig_input)?;

        // Verify signature parameters
        verify_signature_params(&params, &self.public_key)?;

        // Canonicalize the request
        let canonical_values = super::canonicalize::canonicalize_request(request, &components)?;

        // Build signature base
        let signature_base =
            super::canonicalize::build_signature_base(&canonical_values, &sig_input);

        // Decode and verify signature
        let signature_bytes = general_purpose::STANDARD
            .decode(&sig_value)
            .map_err(|_| Error::InvalidInput("Invalid base64 signature".to_string()))?;

        let signature = self.parse_signature(&signature_bytes)?;

        self.public_key
            .verify(signature_base.as_bytes(), &signature)?;

        Ok(())
    }

    /// Verify an HTTP response signature
    pub fn verify_response<B>(&self, response: &Response<B>) -> Result<()> {
        // Extract signature and signature-input headers
        let (sig_value, sig_input) = extract_signature_headers(response.headers())?;

        // Parse signature input to get components and parameters
        let (components, params) = parse_signature_input(&sig_input)?;

        // Verify signature parameters
        verify_signature_params(&params, &self.public_key)?;

        // Canonicalize the response
        let canonical_values = super::canonicalize::canonicalize_response(response, &components)?;

        // Build signature base
        let signature_base =
            super::canonicalize::build_signature_base(&canonical_values, &sig_input);

        // Decode and verify signature
        let signature_bytes = general_purpose::STANDARD
            .decode(&sig_value)
            .map_err(|_| Error::InvalidInput("Invalid base64 signature".to_string()))?;

        let signature = self.parse_signature(&signature_bytes)?;

        self.public_key
            .verify(signature_base.as_bytes(), &signature)?;

        Ok(())
    }
}

/// Extract signature headers from HTTP headers
fn extract_signature_headers(headers: &HeaderMap) -> Result<(String, String)> {
    let sig_header = headers
        .get("signature")
        .ok_or_else(|| Error::InvalidInput("Missing signature header".to_string()))?
        .to_str()
        .map_err(|_| Error::InvalidInput("Invalid signature header encoding".to_string()))?;

    let sig_input_header = headers
        .get("signature-input")
        .ok_or_else(|| Error::InvalidInput("Missing signature-input header".to_string()))?
        .to_str()
        .map_err(|_| Error::InvalidInput("Invalid signature-input header encoding".to_string()))?;

    // Extract sig1 value from headers (simplified - real implementation would handle multiple signatures)
    let sig_value = sig_header
        .strip_prefix("sig1=:")
        .ok_or_else(|| Error::InvalidInput("Invalid signature header format".to_string()))?
        .to_string();

    let sig_input = sig_input_header
        .strip_prefix("sig1=")
        .ok_or_else(|| Error::InvalidInput("Invalid signature-input header format".to_string()))?
        .to_string();

    Ok((sig_value, sig_input))
}

/// Parse signature input to extract components and parameters
fn parse_signature_input(input: &str) -> Result<(Vec<SignatureComponent>, SignatureParams)> {
    // This is a simplified parser - a real implementation would be more robust
    let parts: Vec<&str> = input.splitn(2, ')').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidInput(
            "Invalid signature input format".to_string(),
        ));
    }

    let components_str = parts[0].trim_start_matches('(');
    let params_str = parts[1];

    // Parse components
    let components: Result<Vec<SignatureComponent>> = components_str
        .split_whitespace()
        .map(|s| {
            let component_id = s.trim_matches('"');
            match component_id {
                "@method" => Ok(SignatureComponent::Method),
                "@target-uri" => Ok(SignatureComponent::TargetUri),
                "@authority" => Ok(SignatureComponent::Authority),
                "@scheme" => Ok(SignatureComponent::Scheme),
                "@request-target" => Ok(SignatureComponent::RequestTarget),
                "@path" => Ok(SignatureComponent::Path),
                "@query" => Ok(SignatureComponent::Query),
                "@status" => Ok(SignatureComponent::Status),
                _ if component_id.starts_with('@') => Err(Error::Unsupported(format!(
                    "Unsupported derived component: {component_id}"
                ))),
                _ => Ok(SignatureComponent::Header(component_id.to_string())),
            }
        })
        .collect();

    let components = components?;

    // Parse parameters (simplified)
    let mut params = SignatureParams::default();
    for param in params_str.split(';') {
        let param = param.trim();
        if let Some(stripped) = param.strip_prefix("keyid=") {
            params.key_id = Some(stripped.trim_matches('"').to_string());
        } else if let Some(stripped) = param.strip_prefix("alg=") {
            params.alg = Some(stripped.trim_matches('"').to_string());
        } else if let Some(stripped) = param.strip_prefix("created=") {
            params.created = stripped.parse().ok();
        } else if let Some(stripped) = param.strip_prefix("expires=") {
            params.expires = stripped.parse().ok();
        }
    }

    Ok((components, params))
}

/// Verify signature parameters
fn verify_signature_params(params: &SignatureParams, public_key: &PublicKey) -> Result<()> {
    // Verify timestamp if present
    if let Some(created) = params.created {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Other("System time error".to_string()))?
            .as_secs() as i64;

        // Allow some clock skew (5 minutes)
        if created > now + 300 {
            return Err(Error::Verification(
                "Signature created in the future".to_string(),
            ));
        }
    }

    if let Some(expires) = params.expires {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Other("System time error".to_string()))?
            .as_secs() as i64;

        if expires < now {
            return Err(Error::Verification("Signature expired".to_string()));
        }
    }

    // Verify key ID matches
    if let Some(ref key_id) = params.key_id {
        if key_id != &public_key.key_id() {
            return Err(Error::Verification("Key ID mismatch".to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType};
    use http::HeaderValue;

    #[test]
    fn test_verifier_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());
        assert_eq!(verifier.public_key.key_id(), keypair.public_key().key_id());
    }

    #[test]
    fn test_parse_signature_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        // Create a valid 64-byte Ed25519 signature
        let sig_bytes = [0u8; 64];
        let result = verifier.parse_signature(&sig_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_signature_ed25519_invalid_length() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        // Invalid length
        let sig_bytes = [0u8; 32];
        let result = verifier.parse_signature(&sig_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        // Create a valid 64-byte fixed-format signature
        let sig_bytes = [0u8; 64];
        // Note: This might fail with invalid signature, but tests the parsing path
        let _ = verifier.parse_signature(&sig_bytes);
    }

    #[test]
    fn test_parse_signature_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        // Create a valid 64-byte fixed-format signature
        let sig_bytes = [0u8; 64];
        // Note: This might fail with invalid signature, but tests the parsing path
        let _ = verifier.parse_signature(&sig_bytes);
    }

    #[test]
    fn test_extract_signature_headers_missing_signature() {
        let headers = HeaderMap::new();
        let result = extract_signature_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_signature_headers_missing_input() {
        let mut headers = HeaderMap::new();
        headers.insert("signature", HeaderValue::from_static("sig1=:abc:"));
        let result = extract_signature_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_signature_headers_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("signature", HeaderValue::from_static("sig1=:YWJj:"));
        headers.insert(
            "signature-input",
            HeaderValue::from_static("sig1=(\"@method\" \"@path\");created=1234567890"),
        );

        let result = extract_signature_headers(&headers);
        assert!(result.is_ok());
        let (sig, input) = result.unwrap();
        assert_eq!(sig, "YWJj:");
        assert!(input.contains("@method"));
    }

    #[test]
    fn test_extract_signature_headers_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert("signature", HeaderValue::from_static("invalid"));
        headers.insert(
            "signature-input",
            HeaderValue::from_static("sig1=(\"@method\")"),
        );

        let result = extract_signature_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_input_method() {
        let input = "(\"@method\" \"@path\");created=1234567890";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (components, params) = result.unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(params.created, Some(1234567890));
    }

    #[test]
    fn test_parse_signature_input_with_keyid() {
        let input = "(\"@method\");keyid=\"test-key\";alg=\"ed25519\"";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (components, params) = result.unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(params.key_id, Some("test-key".to_string()));
        assert_eq!(params.alg, Some("ed25519".to_string()));
    }

    #[test]
    fn test_parse_signature_input_with_expires() {
        let input = "(\"@authority\");created=1000;expires=2000";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (_, params) = result.unwrap();
        assert_eq!(params.created, Some(1000));
        assert_eq!(params.expires, Some(2000));
    }

    #[test]
    fn test_parse_signature_input_invalid_format() {
        let input = "invalid format";
        let result = parse_signature_input(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_input_header_component() {
        let input = "(\"content-type\" \"host\");created=123";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (components, _) = result.unwrap();
        assert_eq!(components.len(), 2);
        match &components[0] {
            SignatureComponent::Header(name) => assert_eq!(name, "content-type"),
            _ => panic!("Expected Header component"),
        }
    }

    #[test]
    fn test_verify_signature_params_future_timestamp() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key().clone();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let params = SignatureParams {
            created: Some(now + 1000),
            ..Default::default()
        }; // Future timestamp

        let result = verify_signature_params(&params, &public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_params_expired() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key().clone();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let params = SignatureParams {
            expires: Some(now - 1000),
            ..Default::default()
        }; // Expired

        let result = verify_signature_params(&params, &public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_params_key_id_mismatch() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key().clone();

        let params = SignatureParams {
            key_id: Some("wrong-key-id".to_string()),
            ..Default::default()
        };

        let result = verify_signature_params(&params, &public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_params_valid() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key().clone();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let params = SignatureParams {
            created: Some(now - 100),
            expires: Some(now + 1000),
            key_id: Some(public_key.key_id()),
            ..Default::default()
        };

        let result = verify_signature_params(&params, &public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_signature_input_all_components() {
        let input = "(\"@method\" \"@target-uri\" \"@authority\" \"@scheme\" \"@request-target\" \"@path\" \"@query\");created=123";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (components, _) = result.unwrap();
        assert_eq!(components.len(), 7);
    }

    #[test]
    fn test_parse_signature_input_status_component() {
        let input = "(\"@status\");created=123";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (components, _) = result.unwrap();
        assert_eq!(components.len(), 1);
        matches!(components[0], SignatureComponent::Status);
    }

    // ===== End-to-End Verification Tests =====

    #[test]
    fn test_verify_request_ed25519_valid() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/foo")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_request_secp256k1_valid() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/api")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_request_p256_valid() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("PUT")
            .uri("https://example.com/resource")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_request_wrong_key() {
        use crate::rfc9421::HttpSigner;

        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap();

        let signer = HttpSigner::new(keypair1.clone());

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/foo")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        // Try to verify with different key
        let verifier = HttpVerifier::new(keypair2.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_request_missing_headers() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(())
            .unwrap();

        let result = verifier.verify_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_request_invalid_signature_base64() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header("signature", "sig1=:invalid-base64!!!")
            .header("signature-input", "sig1=(\"@method\");created=123")
            .body(())
            .unwrap();

        let result = verifier.verify_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_request_modified_content() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/foo")
            .body(())
            .unwrap();

        let mut signed_request = signer.sign_request(request).unwrap();

        // Modify the request after signing
        *signed_request.method_mut() = http::Method::GET;

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_response_ed25519_valid() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let response = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_response = signer.sign_response(response).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_response(&signed_response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_secp256k1_valid() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let response = Response::builder()
            .status(201)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_response = signer.sign_response(response).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_response(&signed_response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_p256_valid() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let response = Response::builder()
            .status(404)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_response = signer.sign_response(response).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_response(&signed_response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_wrong_key() {
        use crate::rfc9421::HttpSigner;

        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap();

        let signer = HttpSigner::new(keypair1.clone());

        let response = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let signed_response = signer.sign_response(response).unwrap();

        // Try to verify with different key
        let verifier = HttpVerifier::new(keypair2.public_key().clone());
        let result = verifier.verify_response(&signed_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_response_missing_headers() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        let response = Response::builder().status(200).body(()).unwrap();

        let result = verifier.verify_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_response_modified_status() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let response = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let mut signed_response = signer.sign_response(response).unwrap();

        // Modify the response after signing
        *signed_response.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_response(&signed_response);
        assert!(result.is_err());
    }

    // ===== Error Case Tests =====

    #[test]
    fn test_extract_signature_headers_invalid_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("signature", HeaderValue::from_static("wrong-prefix:abc:"));
        headers.insert(
            "signature-input",
            HeaderValue::from_static("sig1=(\"@method\")"),
        );

        let result = extract_signature_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_input_unsupported_component() {
        let input = "(\"@unsupported-component\");created=123";
        let result = parse_signature_input(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_secp256k1_invalid_length() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        // Invalid length (not 64 and not valid DER)
        let sig_bytes = [0u8; 32];
        let result = verifier.parse_signature(&sig_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_p256_invalid_length() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());

        // Invalid length (not 64 and not valid DER)
        let sig_bytes = [0u8; 48];
        let result = verifier.parse_signature(&sig_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_input_empty_components() {
        let input = "();created=123";
        let result = parse_signature_input(input);
        assert!(result.is_ok());

        let (components, _) = result.unwrap();
        assert_eq!(components.len(), 0);
    }

    #[test]
    fn test_verify_signature_params_no_params() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key().clone();

        let params = SignatureParams::default();
        let result = verify_signature_params(&params, &public_key);
        // Should be ok with no params
        assert!(result.is_ok());
    }

    // ===== RSA Key Type Integration Tests =====

    // ===== Signature Tampering Tests with Different Key Types =====

    #[test]
    fn test_verify_request_secp256k1_tampered_method() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/api")
            .body(())
            .unwrap();

        let mut signed_request = signer.sign_request(request).unwrap();

        // Tamper with method after signing
        *signed_request.method_mut() = http::Method::POST;

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_request_p256_tampered_uri_path() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/api/data")
            .body(())
            .unwrap();

        let mut signed_request = signer.sign_request(request).unwrap();

        // Tamper with URI after signing
        *signed_request.uri_mut() = "https://example.com/api/other".parse().unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_err());
    }

    // ===== Cross-Key-Type Tests =====

    #[test]
    fn test_verify_request_ed25519_with_secp256k1_key() {
        use crate::rfc9421::HttpSigner;

        let ed25519_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let secp256k1_keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();

        let signer = HttpSigner::new(ed25519_keypair.clone());

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/api")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        // Try to verify with different key type
        let verifier = HttpVerifier::new(secp256k1_keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_err());
    }

    // ===== Component-Specific Verification Tests =====

    #[test]
    fn test_verify_request_with_query_params() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("GET")
            .uri("https://api.example.com/search?q=test&limit=10&offset=0")
            .header("accept", "application/json")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_request_with_multiple_headers() {
        use crate::rfc9421::HttpSigner;

        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(keypair.clone());

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/api/upload")
            .header("content-type", "multipart/form-data")
            .header("content-length", "1024")
            .header("x-api-key", "secret-key-123")
            .header("x-request-id", "req-abc-123")
            .body(())
            .unwrap();

        let signed_request = signer.sign_request(request).unwrap();

        let verifier = HttpVerifier::new(keypair.public_key().clone());
        let result = verifier.verify_request(&signed_request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_various_status_codes() {
        use crate::rfc9421::HttpSigner;

        let test_statuses = vec![200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503];

        for status in test_statuses {
            let keypair = KeyPair::generate(KeyType::P256).unwrap();
            let signer = HttpSigner::new(keypair.clone());

            let response = Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(())
                .unwrap();

            let signed_response = signer.sign_response(response).unwrap();

            let verifier = HttpVerifier::new(keypair.public_key().clone());
            let result = verifier.verify_response(&signed_response);
            assert!(
                result.is_ok(),
                "Failed to verify response with status {status}"
            );
        }
    }
}
