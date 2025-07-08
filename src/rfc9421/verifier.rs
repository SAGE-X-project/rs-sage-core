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

        let signature = match self.public_key {
            PublicKey::Ed25519(_) => {
                if signature_bytes.len() != 64 {
                    return Err(Error::InvalidInput(
                        "Ed25519 signature must be 64 bytes".to_string(),
                    ));
                }
                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&signature_bytes);
                Signature::Ed25519(ed25519_dalek::Signature::from_bytes(&sig_array).map_err(
                    |e| Error::InvalidInput(format!("Invalid Ed25519 signature: {}", e)),
                )?)
            }
            PublicKey::Secp256k1(_) => {
                Signature::Secp256k1(k256::ecdsa::Signature::from_der(&signature_bytes).or_else(
                    |_| {
                        // Try fixed-size format if DER fails
                        if signature_bytes.len() == 64 {
                            k256::ecdsa::Signature::try_from(&signature_bytes[..]).map_err(|e| {
                                Error::InvalidInput(format!("Invalid ECDSA signature: {}", e))
                            })
                        } else {
                            Err(Error::InvalidInput(
                                "Invalid Secp256k1 signature format".to_string(),
                            ))
                        }
                    },
                )?)
            }
        };

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

        let signature = match self.public_key {
            PublicKey::Ed25519(_) => {
                if signature_bytes.len() != 64 {
                    return Err(Error::InvalidInput(
                        "Ed25519 signature must be 64 bytes".to_string(),
                    ));
                }
                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&signature_bytes);
                Signature::Ed25519(ed25519_dalek::Signature::from_bytes(&sig_array).map_err(
                    |e| Error::InvalidInput(format!("Invalid Ed25519 signature: {}", e)),
                )?)
            }
            PublicKey::Secp256k1(_) => {
                Signature::Secp256k1(k256::ecdsa::Signature::from_der(&signature_bytes).or_else(
                    |_| {
                        // Try fixed-size format if DER fails
                        if signature_bytes.len() == 64 {
                            k256::ecdsa::Signature::try_from(&signature_bytes[..]).map_err(|e| {
                                Error::InvalidInput(format!("Invalid ECDSA signature: {}", e))
                            })
                        } else {
                            Err(Error::InvalidInput(
                                "Invalid Secp256k1 signature format".to_string(),
                            ))
                        }
                    },
                )?)
            }
        };

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
                    "Unsupported derived component: {}",
                    component_id
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
        if param.starts_with("keyid=") {
            params.key_id = Some(param[7..].trim_matches('"').to_string());
        } else if param.starts_with("alg=") {
            params.alg = Some(param[5..].trim_matches('"').to_string());
        } else if param.starts_with("created=") {
            params.created = param[8..].parse().ok();
        } else if param.starts_with("expires=") {
            params.expires = param[8..].parse().ok();
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

    #[test]
    fn test_verifier_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let verifier = HttpVerifier::new(keypair.public_key().clone());
        assert_eq!(verifier.public_key.key_id(), keypair.public_key().key_id());
    }
}
