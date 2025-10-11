//! Message verification service
//!
//! This module provides the VerificationService for validating SAGE messages
//! including signature verification, timestamp checking, and nonce validation.

use crate::core::{Message, VerificationOptions, VerificationResult};
use crate::crypto::keys::PublicKey;
use crate::error::{Error, Result};
use crate::rfc9421::HttpVerifier;

#[cfg(feature = "blockchain")]
use crate::blockchain::NonceTracker;
#[cfg(feature = "blockchain")]
use crate::did::DID;
#[cfg(feature = "blockchain")]
use std::sync::Arc;

/// Service for verifying SAGE messages
#[cfg(not(feature = "blockchain"))]
pub struct VerificationService;

/// Service for verifying SAGE messages with blockchain support
#[cfg(feature = "blockchain")]
pub struct VerificationService<M: ethers::providers::Middleware> {
    /// Optional nonce tracker for on-chain nonce verification
    nonce_tracker: Option<Arc<NonceTracker<M>>>,
}

#[cfg(not(feature = "blockchain"))]
impl VerificationService {
    /// Creates a new VerificationService
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "blockchain")]
impl<M: ethers::providers::Middleware + 'static> VerificationService<M> {
    /// Creates a new VerificationService without nonce tracking
    pub fn new() -> Self {
        Self {
            nonce_tracker: None,
        }
    }

    /// Creates a new VerificationService with nonce tracking
    pub fn with_nonce_tracker(nonce_tracker: Arc<NonceTracker<M>>) -> Self {
        Self {
            nonce_tracker: Some(nonce_tracker),
        }
    }

    /// Returns whether nonce tracking is enabled
    pub fn has_nonce_tracker(&self) -> bool {
        self.nonce_tracker.is_some()
    }
}

#[cfg(not(feature = "blockchain"))]
impl VerificationService {
    /// Verifies a message with the given public key and options
    pub fn verify(
        &self,
        message: &Message,
        public_key: &PublicKey,
        options: &VerificationOptions,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        // Step 1: Verify signature
        result.signature_valid = self.verify_signature(message, public_key)?;
        if !result.signature_valid {
            result.verified = false;
            result.error = Some("Invalid signature".to_string());
            return Ok(result);
        }

        // Step 2: Verify timestamp if requested
        if options.check_timestamp {
            result.timestamp_valid = self.verify_timestamp(message, options)?;
            if !result.timestamp_valid {
                result.verified = false;
                result.error = Some("Invalid or expired timestamp".to_string());
                return Ok(result);
            }
        }

        // Step 3: Verify nonce if requested
        if options.check_nonce {
            result.nonce_valid = self.verify_nonce(message)?;
            if !result.nonce_valid {
                result.verified = false;
                result.error = Some("Invalid nonce".to_string());
                return Ok(result);
            }
        }

        // Step 4: Verify order if requested
        if options.check_order {
            result.order_valid = self.verify_order(message)?;
            if !result.order_valid {
                result.verified = false;
                result.error = Some("Invalid message order".to_string());
                return Ok(result);
            }
        }

        result.verified = true;
        Ok(result)
    }

    /// Verifies the message signature using RFC 9421 HttpVerifier
    fn verify_signature(&self, message: &Message, public_key: &PublicKey) -> Result<bool> {
        // Check if message is signed
        if message.signature.is_empty() || message.signature_input.is_empty() {
            return Ok(false);
        }

        // Reconstruct HTTP Request from Message
        let request = self.reconstruct_http_request(message)?;

        // Create HttpVerifier with public key
        let verifier = HttpVerifier::new(public_key.clone());

        // Verify the request signature
        match verifier.verify_request(&request) {
            Ok(()) => Ok(true),
            Err(e) => {
                // Log verification failure details for debugging
                eprintln!("Signature verification failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Reconstructs an HTTP Request from a Message for verification
    fn reconstruct_http_request(&self, message: &Message) -> Result<http::Request<Vec<u8>>> {
        use base64::Engine;

        // Build request with SAGE headers
        let mut request_builder = http::Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .header("x-sage-agent-did", &message.agent_did)
            .header("x-sage-message-id", &message.message_id)
            .header("x-sage-timestamp", message.timestamp.to_string())
            .header("x-sage-nonce", &message.nonce);

        // Add custom headers from message
        for (key, value) in &message.headers {
            request_builder = request_builder.header(key, value);
        }

        // Add RFC 9421 signature headers
        // Format: "sig1=:base64_signature:"
        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(&message.signature);
        let signature_header = format!("sig1=:{signature_base64}");

        request_builder = request_builder
            .header("signature", signature_header)
            .header("signature-input", &message.signature_input);

        // Build request with body
        request_builder
            .body(message.body.clone())
            .map_err(|e| Error::Other(format!("Failed to reconstruct HTTP request: {e}")))
    }

    /// Verifies the message timestamp
    fn verify_timestamp(&self, message: &Message, options: &VerificationOptions) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let message_time = message.timestamp;

        // Check if message is not from the future
        if message_time > now + 60 {
            // Allow 60 seconds clock skew
            return Ok(false);
        }

        // Check if message is not too old
        if let Some(max_age) = options.max_age_secs {
            let age = now - message_time;
            if age > max_age as i64 {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verifies the nonce is valid and not reused
    fn verify_nonce(&self, message: &Message) -> Result<bool> {
        // TODO: Implement nonce storage and checking in Phase 3
        // For now, just check if nonce is not empty
        Ok(!message.nonce.is_empty())
    }

    /// Verifies message ordering
    fn verify_order(&self, _message: &Message) -> Result<bool> {
        // TODO: Implement order checking in Phase 3
        // For now, just return true
        Ok(true)
    }
}

#[cfg(not(feature = "blockchain"))]
impl Default for VerificationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "blockchain")]
impl<M: ethers::providers::Middleware + 'static> Default for VerificationService<M> {
    fn default() -> Self {
        Self::new()
    }
}

/// Blockchain-enabled verification methods
#[cfg(feature = "blockchain")]
impl<M: ethers::providers::Middleware + 'static> VerificationService<M> {
    /// Verifies a message with the given public key and options (async version)
    pub async fn verify_async(
        &self,
        message: &Message,
        public_key: &PublicKey,
        options: &VerificationOptions,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        // Step 1: Verify signature
        result.signature_valid = self.verify_signature(message, public_key)?;
        if !result.signature_valid {
            result.verified = false;
            result.error = Some("Invalid signature".to_string());
            return Ok(result);
        }

        // Step 2: Verify timestamp if requested
        if options.check_timestamp {
            result.timestamp_valid = self.verify_timestamp(message, options)?;
            if !result.timestamp_valid {
                result.verified = false;
                result.error = Some("Invalid or expired timestamp".to_string());
                return Ok(result);
            }
        }

        // Step 3: Verify nonce if requested (with blockchain)
        if options.check_nonce {
            result.nonce_valid = self.verify_nonce_async(message).await?;
            if !result.nonce_valid {
                result.verified = false;
                result.error = Some("Invalid or reused nonce".to_string());
                return Ok(result);
            }
        }

        // Step 4: Verify order if requested
        if options.check_order {
            result.order_valid = self.verify_order(message)?;
            if !result.order_valid {
                result.verified = false;
                result.error = Some("Invalid message order".to_string());
                return Ok(result);
            }
        }

        result.verified = true;
        Ok(result)
    }

    /// Verifies the message signature using RFC 9421 HttpVerifier
    fn verify_signature(&self, message: &Message, public_key: &PublicKey) -> Result<bool> {
        // Check if message is signed
        if message.signature.is_empty() || message.signature_input.is_empty() {
            return Ok(false);
        }

        // Reconstruct HTTP Request from Message
        let request = self.reconstruct_http_request(message)?;

        // Create HttpVerifier with public key
        let verifier = HttpVerifier::new(public_key.clone());

        // Verify the request signature
        match verifier.verify_request(&request) {
            Ok(()) => Ok(true),
            Err(e) => {
                eprintln!("Signature verification failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Reconstructs an HTTP Request from a Message for verification
    fn reconstruct_http_request(&self, message: &Message) -> Result<http::Request<Vec<u8>>> {
        use base64::Engine;

        let mut request_builder = http::Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .header("x-sage-agent-did", &message.agent_did)
            .header("x-sage-message-id", &message.message_id)
            .header("x-sage-timestamp", message.timestamp.to_string())
            .header("x-sage-nonce", &message.nonce);

        for (key, value) in &message.headers {
            request_builder = request_builder.header(key, value);
        }

        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(&message.signature);
        let signature_header = format!("sig1=:{signature_base64}");

        request_builder = request_builder
            .header("signature", signature_header)
            .header("signature-input", &message.signature_input);

        request_builder
            .body(message.body.clone())
            .map_err(|e| Error::Other(format!("Failed to reconstruct HTTP request: {e}")))
    }

    /// Verifies the message timestamp
    fn verify_timestamp(&self, message: &Message, options: &VerificationOptions) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let message_time = message.timestamp;

        if message_time > now + 60 {
            return Ok(false);
        }

        if let Some(max_age) = options.max_age_secs {
            let age = now - message_time;
            if age > max_age as i64 {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verifies the nonce is valid and not reused (async with blockchain)
    async fn verify_nonce_async(&self, message: &Message) -> Result<bool> {
        // Check if nonce is not empty
        if message.nonce.is_empty() {
            return Ok(false);
        }

        // If nonce tracker is available, check on-chain
        if let Some(tracker) = &self.nonce_tracker {
            // Parse DID from message
            let did = DID::parse(&message.agent_did)
                .map_err(|e| Error::Other(format!("Invalid DID: {}", e)))?;

            // Validate nonce (checks if it's NOT used)
            tracker.validate_nonce(&did, &message.nonce).await?;
            Ok(true)
        } else {
            // No tracker, just check if nonce is not empty
            Ok(true)
        }
    }

    /// Verifies message ordering
    fn verify_order(&self, _message: &Message) -> Result<bool> {
        // TODO: Implement order checking
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "blockchain"))]
    use crate::core::message::MessageBuilder;
    #[cfg(not(feature = "blockchain"))]
    use crate::crypto::keys::{KeyPair, KeyType};

    #[cfg(not(feature = "blockchain"))]
    #[test]
    fn test_verification_service_creation() {
        let _service = VerificationService::new();
        // Service created successfully
    }

    #[cfg(not(feature = "blockchain"))]
    #[test]
    fn test_timestamp_verification() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Valid timestamp (current time)
        let msg = MessageBuilder::new()
            .timestamp(now)
            .nonce("test-nonce")
            .body(b"test".to_vec())
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600), // 1 hour
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(is_valid);

        // Expired timestamp
        let old_msg = MessageBuilder::new()
            .timestamp(now - 7200) // 2 hours ago
            .nonce("test-nonce")
            .build()
            .unwrap();

        let is_valid = service.verify_timestamp(&old_msg, &options).unwrap();
        assert!(!is_valid);
    }

    #[cfg(not(feature = "blockchain"))]
    #[test]
    fn test_verify_with_empty_signature() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions::default();
        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Should fail because signature is empty
        assert!(!result.verified);
        assert!(!result.signature_valid);
    }
}
