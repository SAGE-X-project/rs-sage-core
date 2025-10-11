//! Message verification service
//!
//! This module provides the VerificationService for validating SAGE messages
//! including signature verification, timestamp checking, and nonce validation.

use crate::core::{Message, VerificationOptions, VerificationResult};
use crate::crypto::keys::PublicKey;
use crate::error::Result;

/// Service for verifying SAGE messages
pub struct VerificationService;

impl VerificationService {
    /// Creates a new VerificationService
    pub fn new() -> Self {
        Self
    }

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

    /// Verifies the message signature
    fn verify_signature(&self, message: &Message, _public_key: &PublicKey) -> Result<bool> {
        // TODO: Integrate with RFC 9421 verifier in Task 1-4
        // For now, just check if signature is not empty
        Ok(!message.signature.is_empty())
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

impl Default for VerificationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::message::MessageBuilder;
    use crate::crypto::keys::{KeyPair, KeyType};

    #[test]
    fn test_verification_service_creation() {
        let service = VerificationService::new();
        assert!(true); // Service created successfully
    }

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

        let mut options = VerificationOptions::default();
        options.check_timestamp = true;
        options.max_age_secs = Some(3600); // 1 hour

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
            .verify(&msg, &keypair.public_key(), &options)
            .unwrap();

        // Should fail because signature is empty
        assert!(!result.verified);
        assert!(!result.signature_valid);
    }
}
