//! Input Validators
//!
//! This module provides validation functions for various input types.

use crate::error::{Error, Result};

/// Validate message size
pub fn validate_message_size(message: &[u8], max_size: usize) -> Result<()> {
    if message.len() > max_size {
        return Err(Error::ValidationError(format!(
            "Message size {} exceeds maximum {}",
            message.len(),
            max_size
        )));
    }
    Ok(())
}

/// Validate payload size
pub fn validate_payload_size(payload: &[u8], max_size: usize) -> Result<()> {
    if payload.len() > max_size {
        return Err(Error::ValidationError(format!(
            "Payload size {} exceeds maximum {}",
            payload.len(),
            max_size
        )));
    }
    Ok(())
}

/// Validate metadata size
pub fn validate_metadata_size(metadata: &[u8], max_size: usize) -> Result<()> {
    if metadata.len() > max_size {
        return Err(Error::ValidationError(format!(
            "Metadata size {} exceeds maximum {}",
            metadata.len(),
            max_size
        )));
    }
    Ok(())
}

/// Validate signature size
pub fn validate_signature_size(signature: &[u8], max_size: usize) -> Result<()> {
    if signature.is_empty() {
        return Err(Error::ValidationError("Signature cannot be empty".into()));
    }
    if signature.len() > max_size {
        return Err(Error::ValidationError(format!(
            "Signature size {} exceeds maximum {}",
            signature.len(),
            max_size
        )));
    }
    Ok(())
}

/// Validate DID format
///
/// DID format: did:method:identifier
/// - Must start with "did:"
/// - Method must be alphanumeric and lowercase
/// - Identifier can contain alphanumeric, dots, dashes, underscores
pub fn validate_did_format(did: &str, max_length: usize) -> Result<()> {
    if did.is_empty() {
        return Err(Error::ValidationError("DID cannot be empty".into()));
    }

    if did.len() > max_length {
        return Err(Error::ValidationError(format!(
            "DID length {} exceeds maximum {}",
            did.len(),
            max_length
        )));
    }

    // Must start with "did:"
    if !did.starts_with("did:") {
        return Err(Error::ValidationError("DID must start with 'did:'".into()));
    }

    // Split into parts: did:method:identifier
    let parts: Vec<&str> = did.splitn(3, ':').collect();
    if parts.len() < 3 {
        return Err(Error::ValidationError(
            "DID must have format 'did:method:identifier'".into(),
        ));
    }

    // Validate method (alphanumeric, lowercase)
    let method = parts[1];
    if method.is_empty() {
        return Err(Error::ValidationError("DID method cannot be empty".into()));
    }
    if !method
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(Error::ValidationError(
            "DID method must be lowercase alphanumeric".into(),
        ));
    }

    // Validate identifier (alphanumeric + allowed special chars)
    let identifier = parts[2];
    if identifier.is_empty() {
        return Err(Error::ValidationError(
            "DID identifier cannot be empty".into(),
        ));
    }
    if !identifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':')
    {
        return Err(Error::ValidationError(
            "DID identifier contains invalid characters".into(),
        ));
    }

    Ok(())
}

/// Validate key ID format
pub fn validate_key_id(key_id: &str, max_length: usize) -> Result<()> {
    if key_id.is_empty() {
        return Err(Error::ValidationError("Key ID cannot be empty".into()));
    }

    if key_id.len() > max_length {
        return Err(Error::ValidationError(format!(
            "Key ID length {} exceeds maximum {}",
            key_id.len(),
            max_length
        )));
    }

    // Key ID should be printable ASCII
    if !key_id.chars().all(|c| c.is_ascii() && !c.is_control()) {
        return Err(Error::ValidationError(
            "Key ID must be printable ASCII".into(),
        ));
    }

    Ok(())
}

/// Validate nonce format
pub fn validate_nonce(nonce: &str, max_length: usize) -> Result<()> {
    if nonce.is_empty() {
        return Err(Error::ValidationError("Nonce cannot be empty".into()));
    }

    if nonce.len() > max_length {
        return Err(Error::ValidationError(format!(
            "Nonce length {} exceeds maximum {}",
            nonce.len(),
            max_length
        )));
    }

    // Nonce should be hexadecimal or base64
    let is_hex = nonce.chars().all(|c| c.is_ascii_hexdigit());
    let is_base64 = nonce
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

    if !is_hex && !is_base64 {
        return Err(Error::ValidationError(
            "Nonce must be hexadecimal or base64".into(),
        ));
    }

    Ok(())
}

/// Validate timestamp (check for reasonable skew)
pub fn validate_timestamp(timestamp: i64, now: i64, max_skew_secs: i64) -> Result<()> {
    let diff = (timestamp - now).abs();
    if diff > max_skew_secs {
        return Err(Error::ValidationError(format!(
            "Timestamp skew {diff} seconds exceeds maximum {max_skew_secs} seconds"
        )));
    }
    Ok(())
}

/// Validate header name (RFC 9421)
pub fn validate_header_name(name: &str, max_length: usize) -> Result<()> {
    if name.is_empty() {
        return Err(Error::ValidationError("Header name cannot be empty".into()));
    }

    if name.len() > max_length {
        return Err(Error::ValidationError(format!(
            "Header name length {} exceeds maximum {}",
            name.len(),
            max_length
        )));
    }

    // Header names must be lowercase, alphanumeric, or hyphens
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::ValidationError(
            "Header name must be lowercase alphanumeric or hyphen".into(),
        ));
    }

    Ok(())
}

/// Validate header value
pub fn validate_header_value(value: &str, max_length: usize) -> Result<()> {
    if value.len() > max_length {
        return Err(Error::ValidationError(format!(
            "Header value length {} exceeds maximum {}",
            value.len(),
            max_length
        )));
    }

    // Header values must be printable ASCII or whitespace
    if !value
        .chars()
        .all(|c| c.is_ascii() && (c.is_ascii_graphic() || c.is_whitespace()))
    {
        return Err(Error::ValidationError(
            "Header value contains invalid characters".into(),
        ));
    }

    Ok(())
}

/// Validate number of items in a collection
pub fn validate_collection_size(count: usize, max_count: usize, item_type: &str) -> Result<()> {
    if count > max_count {
        return Err(Error::ValidationError(format!(
            "{item_type} count {count} exceeds maximum {max_count}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_message_size() {
        assert!(validate_message_size(&[0u8; 100], 1024).is_ok());
        assert!(validate_message_size(&[0u8; 2000], 1024).is_err());
    }

    #[test]
    fn test_validate_signature_size() {
        assert!(validate_signature_size(&[], 256).is_err()); // Empty
        assert!(validate_signature_size(&[0u8; 64], 256).is_ok());
        assert!(validate_signature_size(&[0u8; 300], 256).is_err());
    }

    #[test]
    fn test_validate_did_format() {
        // Valid DIDs
        assert!(validate_did_format("did:sage:alice", 1024).is_ok());
        assert!(validate_did_format("did:ethr:0x1234", 1024).is_ok());
        assert!(validate_did_format("did:web:example.com", 1024).is_ok());
        assert!(validate_did_format(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            1024
        )
        .is_ok());

        // Invalid DIDs
        assert!(validate_did_format("", 1024).is_err()); // Empty
        assert!(validate_did_format("notadid", 1024).is_err()); // No did: prefix
        assert!(validate_did_format("did:", 1024).is_err()); // No method
        assert!(validate_did_format("did:sage:", 1024).is_err()); // No identifier
        assert!(validate_did_format("did:SAGE:alice", 1024).is_err()); // Uppercase method
        assert!(validate_did_format("did:sa ge:alice", 1024).is_err()); // Space in method
    }

    #[test]
    fn test_validate_key_id() {
        assert!(validate_key_id("key-1", 256).is_ok());
        assert!(validate_key_id("", 256).is_err()); // Empty
        assert!(validate_key_id(&"x".repeat(300), 256).is_err()); // Too long
    }

    #[test]
    fn test_validate_nonce() {
        // Hex nonce
        assert!(validate_nonce("deadbeef", 128).is_ok());
        assert!(validate_nonce("1234567890abcdef", 128).is_ok());

        // Base64 nonce
        assert!(validate_nonce("SGVsbG8gV29ybGQ=", 128).is_ok());

        // Invalid
        assert!(validate_nonce("", 128).is_err()); // Empty
        assert!(validate_nonce("not-hex-or-base64!", 128).is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_timestamp() {
        let now = 1000;
        assert!(validate_timestamp(1000, now, 300).is_ok()); // Exact
        assert!(validate_timestamp(1200, now, 300).is_ok()); // +200s
        assert!(validate_timestamp(800, now, 300).is_ok()); // -200s
        assert!(validate_timestamp(1500, now, 300).is_err()); // +500s (too far)
        assert!(validate_timestamp(400, now, 300).is_err()); // -600s (too far)
    }

    #[test]
    fn test_validate_header_name() {
        assert!(validate_header_name("content-type", 256).is_ok());
        assert!(validate_header_name("x-custom-header", 256).is_ok());
        assert!(validate_header_name("", 256).is_err()); // Empty
        assert!(validate_header_name("Content-Type", 256).is_err()); // Uppercase
        assert!(validate_header_name("invalid_header", 256).is_err()); // Underscore
    }

    #[test]
    fn test_validate_header_value() {
        assert!(validate_header_value("application/json", 8192).is_ok());
        assert!(validate_header_value("text/plain; charset=utf-8", 8192).is_ok());
        assert!(validate_header_value(&"x".repeat(10000), 8192).is_err()); // Too long
    }

    #[test]
    fn test_validate_collection_size() {
        assert!(validate_collection_size(10, 100, "items").is_ok());
        assert!(validate_collection_size(150, 100, "items").is_err());
    }
}
