//! Message verification service
//!
//! This module provides the VerificationService for validating SAGE messages
//! including signature verification, timestamp checking, and nonce validation.

use crate::core::{Message, VerificationOptions, VerificationResult};
use crate::crypto::keys::PublicKey;
use crate::error::{Error, Result};
use crate::rfc9421::HttpVerifier;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

// DEPRECATED: Old blockchain imports
// #[cfg(feature = "blockchain")]
// use crate::blockchain::NonceTracker;
// #[cfg(feature = "blockchain")]
// use crate::did::DID;
// #[cfg(feature = "blockchain")]
// use std::sync::Arc;

/// Simple in-memory nonce store for replay protection
#[derive(Debug, Clone)]
struct NonceStore {
    used_nonces: Arc<Mutex<HashSet<String>>>,
}

impl NonceStore {
    fn new() -> Self {
        Self {
            used_nonces: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn check_and_store(&self, nonce: &str) -> bool {
        let mut nonces = self.used_nonces.lock().unwrap();
        if nonces.contains(nonce) {
            false // Nonce already used
        } else {
            nonces.insert(nonce.to_string());
            true // Nonce is new
        }
    }
}

/// Message order tracker for ensuring message sequence
#[derive(Debug, Clone)]
struct OrderTracker {
    /// Maps agent DID to last seen timestamp
    last_timestamps: Arc<Mutex<HashMap<String, i64>>>,
}

impl OrderTracker {
    fn new() -> Self {
        Self {
            last_timestamps: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn check_and_update(&self, agent_did: &str, timestamp: i64) -> bool {
        let mut timestamps = self.last_timestamps.lock().unwrap();

        if let Some(&last_ts) = timestamps.get(agent_did) {
            // Message must have a newer timestamp than the last one
            if timestamp <= last_ts {
                return false; // Out of order
            }
        }

        // Update the last timestamp for this agent
        timestamps.insert(agent_did.to_string(), timestamp);
        true
    }
}

/// Service for verifying SAGE messages
pub struct VerificationService {
    nonce_store: NonceStore,
    order_tracker: OrderTracker,
}

// DEPRECATED: Old blockchain struct using ethers (replaced with alloy)
// /// Service for verifying SAGE messages with blockchain support
// #[cfg(feature = "blockchain")]
// pub struct VerificationService<M: ethers::providers::Middleware> {
//     /// Optional nonce tracker for on-chain nonce verification
//     nonce_tracker: Option<Arc<NonceTracker<M>>>,
// }

impl VerificationService {
    /// Creates a new VerificationService
    pub fn new() -> Self {
        Self {
            nonce_store: NonceStore::new(),
            order_tracker: OrderTracker::new(),
        }
    }
}

// DEPRECATED: Old blockchain impl using ethers (replaced with alloy)
// impl<M: ethers::providers::Middleware + 'static> VerificationService<M> {
//     /// Creates a new VerificationService without nonce tracking
//     pub fn new() -> Self {
//         Self {
//             nonce_tracker: None,
//         }
//     }
//
//     /// Creates a new VerificationService with nonce tracking
//     pub fn with_nonce_tracker(nonce_tracker: Arc<NonceTracker<M>>) -> Self {
//         Self {
//             nonce_tracker: Some(nonce_tracker),
//         }
//     }
//
//     /// Returns whether nonce tracking is enabled
//     pub fn has_nonce_tracker(&self) -> bool {
//         self.nonce_tracker.is_some()
//     }
// }

impl VerificationService {
    /// Verifies a message with the given public key and options
    pub fn verify(
        &self,
        message: &Message,
        public_key: &PublicKey,
        options: &VerificationOptions,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult {
            signature_valid: false,
            timestamp_valid: false,
            nonce_valid: false,
            order_valid: false,
            verified: false,
            error: None,
            metadata: std::collections::HashMap::new(),
        };

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
        } else {
            result.timestamp_valid = true;
        }

        // Step 3: Verify nonce if requested
        if options.check_nonce {
            result.nonce_valid = self.verify_nonce(message)?;
            if !result.nonce_valid {
                result.verified = false;
                result.error = Some("Invalid nonce".to_string());
                return Ok(result);
            }
        } else {
            result.nonce_valid = true;
        }

        // Step 4: Verify order if requested
        if options.check_order {
            result.order_valid = self.verify_order(message)?;
            if !result.order_valid {
                result.verified = false;
                result.error = Some("Invalid message order".to_string());
                return Ok(result);
            }
        } else {
            result.order_valid = true;
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
                eprintln!("Signature verification failed: {e}");
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
            .uri("https://example.com/message")
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
        let signature_base64 = base64::engine::general_purpose::STANDARD.encode(&message.signature);
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
        // Check if nonce is not empty
        if message.nonce.is_empty() {
            return Ok(false);
        }

        // Check if nonce has been used before (replay protection)
        Ok(self.nonce_store.check_and_store(&message.nonce))
    }

    /// Verifies message ordering
    fn verify_order(&self, message: &Message) -> Result<bool> {
        // Check message order based on timestamp per agent DID
        Ok(self
            .order_tracker
            .check_and_update(&message.agent_did, message.timestamp))
    }
}

impl Default for VerificationService {
    fn default() -> Self {
        Self::new()
    }
}

// DEPRECATED: Old blockchain implementation using ethers (replaced with alloy)
// #[cfg(feature = "blockchain")]
// impl<M: ethers::providers::Middleware + 'static> Default for VerificationService<M> {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// DEPRECATED: Old blockchain implementation using ethers (replaced with alloy in blockchain module)
// #[cfg(feature = "blockchain")]
// impl<M: ethers::providers::Middleware + 'static> VerificationService<M> {
//     /// Verifies a message with the given public key and options (async version)
//     pub async fn verify_async(
//         &self,
//         message: &Message,
//         public_key: &PublicKey,
//         options: &VerificationOptions,
//     ) -> Result<VerificationResult> {
//         let mut result = VerificationResult::success();
//
//         // Step 1: Verify signature
//         result.signature_valid = self.verify_signature(message, public_key)?;
//         if !result.signature_valid {
//             result.verified = false;
//             result.error = Some("Invalid signature".to_string());
//             return Ok(result);
//         }
//
//         // Step 2: Verify timestamp if requested
//         if options.check_timestamp {
//             result.timestamp_valid = self.verify_timestamp(message, options)?;
//             if !result.timestamp_valid {
//                 result.verified = false;
//                 result.error = Some("Invalid or expired timestamp".to_string());
//                 return Ok(result);
//             }
//         }
//
//         // Step 3: Verify nonce if requested (with blockchain)
//         if options.check_nonce {
//             result.nonce_valid = self.verify_nonce_async(message).await?;
//             if !result.nonce_valid {
//                 result.verified = false;
//                 result.error = Some("Invalid or reused nonce".to_string());
//                 return Ok(result);
//             }
//         }
//
//         // Step 4: Verify order if requested
//         if options.check_order {
//             result.order_valid = self.verify_order(message)?;
//             if !result.order_valid {
//                 result.verified = false;
//                 result.error = Some("Invalid message order".to_string());
//                 return Ok(result);
//             }
//         }
//
//         result.verified = true;
//         Ok(result)
//     }
//
//     /// Verifies the message signature using RFC 9421 HttpVerifier
//     fn verify_signature(&self, message: &Message, public_key: &PublicKey) -> Result<bool> {
//         // Check if message is signed
//         if message.signature.is_empty() || message.signature_input.is_empty() {
//             return Ok(false);
//         }
//
//         // Reconstruct HTTP Request from Message
//         let request = self.reconstruct_http_request(message)?;
//
//         // Create HttpVerifier with public key
//         let verifier = HttpVerifier::new(public_key.clone());
//
//         // Verify the request signature
//         match verifier.verify_request(&request) {
//             Ok(()) => Ok(true),
//             Err(e) => {
//                 eprintln!("Signature verification failed: {}", e);
//                 Ok(false)
//             }
//         }
//     }
//
//     /// Reconstructs an HTTP Request from a Message for verification
//     fn reconstruct_http_request(&self, message: &Message) -> Result<http::Request<Vec<u8>>> {
//         use base64::Engine;
//
//         let mut request_builder = http::Request::builder()
//             .method("POST")
//             .uri("/message")
//             .header("content-type", "application/json")
//             .header("x-sage-agent-did", &message.agent_did)
//             .header("x-sage-message-id", &message.message_id)
//             .header("x-sage-timestamp", message.timestamp.to_string())
//             .header("x-sage-nonce", &message.nonce);
//
//         for (key, value) in &message.headers {
//             request_builder = request_builder.header(key, value);
//         }
//
//         let signature_base64 =
//             base64::engine::general_purpose::STANDARD.encode(&message.signature);
//         let signature_header = format!("sig1=:{signature_base64}");
//
//         request_builder = request_builder
//             .header("signature", signature_header)
//             .header("signature-input", &message.signature_input);
//
//         request_builder
//             .body(message.body.clone())
//             .map_err(|e| Error::Other(format!("Failed to reconstruct HTTP request: {e}")))
//     }
//
//     /// Verifies the message timestamp
//     fn verify_timestamp(&self, message: &Message, options: &VerificationOptions) -> Result<bool> {
//         let now = chrono::Utc::now().timestamp();
//         let message_time = message.timestamp;
//
//         if message_time > now + 60 {
//             return Ok(false);
//         }
//
//         if let Some(max_age) = options.max_age_secs {
//             let age = now - message_time;
//             if age > max_age as i64 {
//                 return Ok(false);
//             }
//         }
//
//         Ok(true)
//     }
//
//     /// Verifies the nonce is valid and not reused (async with blockchain)
//     async fn verify_nonce_async(&self, message: &Message) -> Result<bool> {
//         // Check if nonce is not empty
//         if message.nonce.is_empty() {
//             return Ok(false);
//         }
//
//         // If nonce tracker is available, check on-chain
//         if let Some(tracker) = &self.nonce_tracker {
//             // Parse DID from message
//             let did = DID::parse(&message.agent_did)
//                 .map_err(|e| Error::Other(format!("Invalid DID: {}", e)))?;
//
//             // Validate nonce (checks if it's NOT used)
//             tracker.validate_nonce(&did, &message.nonce).await?;
//             Ok(true)
//         } else {
//             // No tracker, just check if nonce is not empty
//             Ok(true)
//         }
//     }
//
//     /// Verifies message ordering (replaced with OrderTracker implementation above)
//     fn verify_order(&self, _message: &Message) -> Result<bool> {
//         Ok(true)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::message::MessageBuilder;
    use crate::crypto::keys::{KeyPair, KeyType};

    // ===== Service Creation Tests =====

    #[test]
    fn test_verification_service_creation() {
        let _service = VerificationService::new();
        // Service created successfully
    }

    #[test]
    fn test_verification_service_default() {
        let _service = VerificationService::default();
        // Service created successfully via Default trait
    }

    // ===== Timestamp Verification Tests =====

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

    #[test]
    fn test_timestamp_future_message() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Message from future (beyond clock skew)
        let future_msg = MessageBuilder::new()
            .timestamp(now + 120) // 2 minutes in future
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&future_msg, &options).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_timestamp_within_clock_skew() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Message within clock skew (30 seconds in future)
        let msg = MessageBuilder::new()
            .timestamp(now + 30)
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_timestamp_no_max_age() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Very old message but no max_age set
        let old_msg = MessageBuilder::new()
            .timestamp(now - 86400) // 1 day ago
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: None,
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&old_msg, &options).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_timestamp_exact_boundary() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Message exactly at max age boundary
        let msg = MessageBuilder::new()
            .timestamp(now - 3600) // Exactly 1 hour ago
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(is_valid); // Should be valid at the boundary
    }

    // ===== Nonce Verification Tests =====

    #[test]
    fn test_verify_nonce_valid() {
        let service = VerificationService::new();

        let msg = MessageBuilder::new()
            .nonce("valid-nonce-123")
            .build()
            .unwrap();

        let is_valid = service.verify_nonce(&msg).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_nonce_empty() {
        let service = VerificationService::new();

        let msg = MessageBuilder::new().nonce("").build().unwrap();

        let is_valid = service.verify_nonce(&msg).unwrap();
        assert!(!is_valid);
    }

    // ===== Order Verification Tests =====

    #[test]
    fn test_verify_order() {
        let service = VerificationService::new();

        let msg = MessageBuilder::new().nonce("test-nonce").build().unwrap();

        // Currently returns true (stub implementation)
        let is_valid = service.verify_order(&msg).unwrap();
        assert!(is_valid);
    }

    // ===== Signature Verification Tests =====

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

    #[test]
    fn test_verify_signature_empty() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_missing_input() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        // Message with signature but no signature_input
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        msg.signature = vec![1, 2, 3, 4]; // Some signature
        msg.signature_input = String::new(); // Empty input

        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    // ===== HTTP Request Reconstruction Tests =====

    #[test]
    fn test_reconstruct_http_request() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:ethereum:0x1234")
            .message_id("msg-123")
            .timestamp(now)
            .nonce("nonce-456")
            .body(b"test body".to_vec())
            .build()
            .unwrap();

        // Add signature and signature_input
        msg.signature = vec![1, 2, 3, 4];
        msg.signature_input = "(@method @path);created=123".to_string();

        // Add custom header
        msg.headers
            .insert("x-custom".to_string(), "value".to_string());

        let request = service.reconstruct_http_request(&msg).unwrap();

        // Verify request properties
        assert_eq!(request.method(), "POST");
        assert_eq!(request.uri(), "https://example.com/message");
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            request.headers().get("x-sage-agent-did").unwrap(),
            "did:sage:ethereum:0x1234"
        );
        assert_eq!(
            request.headers().get("x-sage-message-id").unwrap(),
            "msg-123"
        );
        assert_eq!(
            request.headers().get("x-sage-timestamp").unwrap(),
            &now.to_string()
        );
        assert_eq!(request.headers().get("x-sage-nonce").unwrap(), "nonce-456");
        assert_eq!(request.headers().get("x-custom").unwrap(), "value");
        assert!(request.headers().contains_key("signature"));
        assert!(request.headers().contains_key("signature-input"));
        assert_eq!(request.body(), b"test body");
    }

    #[test]
    fn test_reconstruct_http_request_base64_signature() {
        let service = VerificationService::new();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        msg.signature = vec![0x01, 0x02, 0x03, 0x04];
        msg.signature_input = "test-input".to_string();

        let request = service.reconstruct_http_request(&msg).unwrap();

        // Verify signature is base64 encoded
        let signature_header = request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(signature_header.starts_with("sig1=:"));
        assert!(signature_header.contains("AQIDBA")); // Base64 of [1,2,3,4]
    }

    // ===== Combined Verification Tests =====

    #[test]
    fn test_verify_with_all_options_disabled() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: false,
            check_nonce: false,
            check_order: false,
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Should fail due to empty signature
        assert!(!result.verified);
        assert!(!result.signature_valid);
    }

    #[test]
    fn test_verify_timestamp_check_enabled() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        // Old message
        let old_msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp() - 7200)
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&old_msg, keypair.public_key(), &options)
            .unwrap();

        // Should fail due to expired timestamp (signature check happens first but we test flow)
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_nonce_check_enabled() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        // Create message with valid signature but empty nonce
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("")
            .build()
            .unwrap();

        // Add dummy signature to pass signature check
        msg.signature = vec![1, 2, 3];
        msg.signature_input = "test".to_string();

        let options = VerificationOptions {
            check_nonce: true,
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Will fail at signature verification first
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_order_check_enabled() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_order: true,
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Will fail at signature verification
        assert!(!result.verified);
    }

    // ===== Error Message Tests =====

    #[test]
    fn test_verify_error_invalid_signature() {
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

        assert!(!result.verified);
        assert_eq!(result.error, Some("Invalid signature".to_string()));
    }

    #[test]
    fn test_verify_error_invalid_timestamp() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        // Very old message
        let old_msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(0) // Unix epoch
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&old_msg, keypair.public_key(), &options)
            .unwrap();

        assert!(!result.verified);
        // Will fail at signature first, but structure is correct
    }

    // ===== Algorithm-Specific Tests =====

    #[test]
    fn test_verify_signature_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let service = VerificationService::new();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Empty signature should fail
        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_p256() {
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let service = VerificationService::new();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Empty signature should fail
        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_secp256k1() {
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let service = VerificationService::new();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Empty signature should fail
        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    // ===== Additional Edge Case Tests =====

    #[test]
    fn test_reconstruct_http_request_multiple_custom_headers() {
        let service = VerificationService::new();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        msg.signature = vec![1, 2, 3];
        msg.signature_input = "test".to_string();

        // Add multiple custom headers
        msg.headers
            .insert("x-header-1".to_string(), "value1".to_string());
        msg.headers
            .insert("x-header-2".to_string(), "value2".to_string());
        msg.headers
            .insert("x-header-3".to_string(), "value3".to_string());

        let request = service.reconstruct_http_request(&msg).unwrap();

        // Verify all custom headers are present
        assert_eq!(request.headers().get("x-header-1").unwrap(), "value1");
        assert_eq!(request.headers().get("x-header-2").unwrap(), "value2");
        assert_eq!(request.headers().get("x-header-3").unwrap(), "value3");
    }

    #[test]
    fn test_reconstruct_http_request_empty_body() {
        let service = VerificationService::new();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .body(vec![])
            .build()
            .unwrap();

        msg.signature = vec![1];
        msg.signature_input = "test".to_string();

        let request = service.reconstruct_http_request(&msg).unwrap();

        assert_eq!(request.body(), &Vec::<u8>::new());
    }

    #[test]
    fn test_reconstruct_http_request_large_body() {
        let service = VerificationService::new();

        let large_body = vec![0u8; 10000]; // 10KB body
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .body(large_body.clone())
            .build()
            .unwrap();

        msg.signature = vec![1];
        msg.signature_input = "test".to_string();

        let request = service.reconstruct_http_request(&msg).unwrap();

        assert_eq!(request.body(), &large_body);
    }

    #[test]
    fn test_reconstruct_http_request_special_chars_in_did() {
        let service = VerificationService::new();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:ethereum:0xABCD1234_test-agent")
            .nonce("test-nonce")
            .build()
            .unwrap();

        msg.signature = vec![1];
        msg.signature_input = "test".to_string();

        let request = service.reconstruct_http_request(&msg).unwrap();

        assert_eq!(
            request.headers().get("x-sage-agent-did").unwrap(),
            "did:sage:ethereum:0xABCD1234_test-agent"
        );
    }

    #[test]
    fn test_timestamp_verification_zero_max_age() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        let msg = MessageBuilder::new()
            .timestamp(now - 1) // 1 second ago
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(0), // Zero max age
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(!is_valid); // Should be invalid
    }

    #[test]
    fn test_timestamp_verification_very_large_max_age() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        let msg = MessageBuilder::new()
            .timestamp(now - 86400) // 1 day ago
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(604800), // 1 week
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_with_nonce_only() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("valid-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: false,
            check_nonce: false, // Nonce check disabled
            check_order: false,
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Will fail due to empty signature
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_with_order_only() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: false,
            check_nonce: false,
            check_order: true, // Only order check
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Will fail due to empty signature
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_with_all_options_enabled() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            check_nonce: true,
            check_order: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Will fail due to empty signature
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_nonce_with_various_formats() {
        let service = VerificationService::new();

        // UUID format
        let msg1 = MessageBuilder::new()
            .nonce("550e8400-e29b-41d4-a716-446655440000")
            .build()
            .unwrap();
        assert!(service.verify_nonce(&msg1).unwrap());

        // Hex format
        let msg2 = MessageBuilder::new()
            .nonce("0123456789abcdef")
            .build()
            .unwrap();
        assert!(service.verify_nonce(&msg2).unwrap());

        // Base64 format
        let msg3 = MessageBuilder::new().nonce("YWJjZGVm").build().unwrap();
        assert!(service.verify_nonce(&msg3).unwrap());
    }

    #[test]
    fn test_verify_signature_with_only_signature_no_input() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Only signature, no signature_input
        msg.signature = vec![1, 2, 3, 4];
        msg.signature_input = String::new();

        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_with_only_input_no_signature() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Only signature_input, no signature
        msg.signature = vec![];
        msg.signature_input = "(@method);created=123".to_string();

        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_reconstruct_request_with_long_message_id() {
        let service = VerificationService::new();

        let long_id = "a".repeat(200);
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .message_id(&long_id)
            .nonce("test-nonce")
            .build()
            .unwrap();

        msg.signature = vec![1];
        msg.signature_input = "test".to_string();

        let request = service.reconstruct_http_request(&msg).unwrap();

        assert_eq!(
            request.headers().get("x-sage-message-id").unwrap(),
            &long_id
        );
    }

    #[test]
    fn test_reconstruct_request_with_binary_body() {
        let service = VerificationService::new();

        let binary_body = vec![0, 1, 2, 255, 254, 253]; // Binary data
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .body(binary_body.clone())
            .build()
            .unwrap();

        msg.signature = vec![1];
        msg.signature_input = "test".to_string();

        let request = service.reconstruct_http_request(&msg).unwrap();

        assert_eq!(request.body(), &binary_body);
    }

    #[test]
    fn test_timestamp_at_clock_skew_boundary() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Message exactly at 60 seconds in future (at boundary)
        let msg = MessageBuilder::new()
            .timestamp(now + 60)
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(is_valid); // Should be valid at boundary
    }

    #[test]
    fn test_timestamp_just_beyond_clock_skew() {
        let service = VerificationService::new();
        let now = chrono::Utc::now().timestamp();

        // Message just beyond clock skew (61 seconds in future)
        let msg = MessageBuilder::new()
            .timestamp(now + 61)
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let is_valid = service.verify_timestamp(&msg, &options).unwrap();
        assert!(!is_valid); // Should be invalid
    }

    // ===== Integration Tests with Real Signatures =====

    #[test]
    fn test_verify_with_valid_signature_and_timestamp() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let now = chrono::Utc::now().timestamp();

        // Create a message
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .message_id("test-msg-123")
            .timestamp(now)
            .nonce("test-nonce-456")
            .body(b"test body".to_vec())
            .build()
            .unwrap();

        // Create and sign an HTTP request
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        // Extract signature from signed request
        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        // Extract base64 signature (format: "sig1=:base64" or "sig1=:base64:")
        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        // Verify with all options disabled except signature
        let options = VerificationOptions {
            check_timestamp: false,
            check_nonce: false,
            check_order: false,
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();
        assert!(result.verified);
        assert!(result.signature_valid);
    }

    #[test]
    fn test_verify_with_valid_signature_timestamp_check_pass() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let now = chrono::Utc::now().timestamp();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now)
            .nonce("test-nonce")
            .body(b"test".to_vec())
            .build()
            .unwrap();

        // Sign the message
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        // Verify with timestamp check enabled
        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            check_nonce: false,
            check_order: false,
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();
        assert!(result.verified);
        assert!(result.signature_valid);
        assert!(result.timestamp_valid);
    }

    #[test]
    fn test_verify_with_valid_signature_but_expired_timestamp() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let now = chrono::Utc::now().timestamp();

        // Create message with old timestamp
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now - 7200) // 2 hours ago
            .nonce("test-nonce")
            .body(b"test".to_vec())
            .build()
            .unwrap();

        // Sign the message (signature will be valid)
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        // Verify with timestamp check (max_age = 1 hour)
        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();
        assert!(!result.verified);
        assert!(result.signature_valid); // Signature is valid
        assert!(!result.timestamp_valid); // But timestamp is expired
        assert_eq!(
            result.error,
            Some("Invalid or expired timestamp".to_string())
        );
    }

    #[test]
    fn test_verify_full_flow_with_all_checks_passing() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let now = chrono::Utc::now().timestamp();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now)
            .nonce("valid-nonce-123")
            .body(b"test body".to_vec())
            .build()
            .unwrap();

        // Sign the message
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        // Verify with all checks enabled
        let options = VerificationOptions {
            check_timestamp: true,
            check_nonce: true,
            check_order: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();
        assert!(result.verified);
        assert!(result.signature_valid);
        assert!(result.timestamp_valid);
        assert!(result.nonce_valid);
        assert!(result.order_valid);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_verify_signature_with_wrong_public_key() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap(); // Different key

        let now = chrono::Utc::now().timestamp();
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now)
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Sign with keypair1
        let signer = HttpSigner::new(keypair1.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        // Verify with keypair2 (wrong key)
        let options = VerificationOptions::default();
        let result = service
            .verify(&msg, keypair2.public_key(), &options)
            .unwrap();

        assert!(!result.verified);
        assert!(!result.signature_valid);
        assert_eq!(result.error, Some("Invalid signature".to_string()));
    }

    #[test]
    fn test_verify_with_different_algorithms() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let algorithms = vec![KeyType::Ed25519, KeyType::P256, KeyType::Secp256k1];

        for algo in algorithms {
            let keypair = KeyPair::generate(algo).unwrap();
            let now = chrono::Utc::now().timestamp();

            let mut msg = MessageBuilder::new()
                .agent_did("did:sage:test")
                .timestamp(now)
                .nonce("test-nonce")
                .build()
                .unwrap();

            // Sign the message
            let signer = HttpSigner::new(keypair.clone());
            let request = service.reconstruct_http_request(&msg).unwrap();
            let signed_request = signer.sign_request(request).unwrap();

            let signature_header = signed_request
                .headers()
                .get("signature")
                .unwrap()
                .to_str()
                .unwrap();
            let signature_input = signed_request
                .headers()
                .get("signature-input")
                .unwrap()
                .to_str()
                .unwrap();

            let sig_start = signature_header.find(':').unwrap() + 1;
            let sig_base64 = if signature_header.ends_with(':') {
                &signature_header[sig_start..signature_header.len() - 1]
            } else {
                &signature_header[sig_start..]
            };
            msg.signature = base64::engine::general_purpose::STANDARD
                .decode(sig_base64)
                .unwrap();
            msg.signature_input = signature_input.to_string();

            let options = VerificationOptions::default();
            let result = service
                .verify(&msg, keypair.public_key(), &options)
                .unwrap();

            assert!(result.verified, "Failed to verify with {algo:?}");
            assert!(result.signature_valid);
        }
    }

    #[test]
    fn test_verify_timestamp_at_max_age_boundary() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let now = chrono::Utc::now().timestamp();

        // Message exactly at max_age boundary (1 hour ago)
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now - 3600)
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Sign the message
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();
        assert!(result.verified); // Should be valid at boundary
        assert!(result.timestamp_valid);
    }

    #[test]
    fn test_verify_timestamp_just_past_max_age() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::P256).unwrap();
        let now = chrono::Utc::now().timestamp();

        // Message just past max_age (1 hour + 1 second)
        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now - 3601)
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Sign the message
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        let options = VerificationOptions {
            check_timestamp: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();
        assert!(!result.verified); // Should fail
        assert!(!result.timestamp_valid);
        assert_eq!(
            result.error,
            Some("Invalid or expired timestamp".to_string())
        );
    }

    #[test]
    fn test_verify_with_custom_headers() {
        use crate::rfc9421::HttpSigner;
        use base64::Engine;

        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let now = chrono::Utc::now().timestamp();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(now)
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Add custom headers
        msg.headers
            .insert("x-custom-1".to_string(), "value1".to_string());
        msg.headers
            .insert("x-custom-2".to_string(), "value2".to_string());

        // Sign the message
        let signer = HttpSigner::new(keypair.clone());
        let request = service.reconstruct_http_request(&msg).unwrap();
        let signed_request = signer.sign_request(request).unwrap();

        let signature_header = signed_request
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap();
        let signature_input = signed_request
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();

        let sig_start = signature_header.find(':').unwrap() + 1;
        let sig_base64 = if signature_header.ends_with(':') {
            &signature_header[sig_start..signature_header.len() - 1]
        } else {
            &signature_header[sig_start..]
        };
        msg.signature = base64::engine::general_purpose::STANDARD
            .decode(sig_base64)
            .unwrap();
        msg.signature_input = signature_input.to_string();

        let options = VerificationOptions::default();
        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        assert!(result.verified);
        assert!(result.signature_valid);
    }

    #[test]
    fn test_verify_result_fields_on_signature_failure() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .timestamp(chrono::Utc::now().timestamp())
            .nonce("test-nonce")
            .build()
            .unwrap();

        let options = VerificationOptions {
            check_timestamp: true,
            check_nonce: true,
            check_order: true,
            max_age_secs: Some(3600),
            ..Default::default()
        };

        let result = service
            .verify(&msg, keypair.public_key(), &options)
            .unwrap();

        // Verify all fields are set correctly on signature failure
        assert!(!result.verified);
        assert!(!result.signature_valid);
        assert!(!result.timestamp_valid);
        assert!(!result.nonce_valid);
        assert!(!result.order_valid);
        assert_eq!(result.error, Some("Invalid signature".to_string()));
    }

    #[test]
    fn test_verify_signature_returns_false_on_verification_error() {
        let service = VerificationService::new();
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let mut msg = MessageBuilder::new()
            .agent_did("did:sage:test")
            .nonce("test-nonce")
            .build()
            .unwrap();

        // Add invalid signature that will fail verification
        msg.signature = vec![1, 2, 3, 4, 5];
        msg.signature_input = "sig1=(@method);created=123".to_string();

        let is_valid = service
            .verify_signature(&msg, keypair.public_key())
            .unwrap();
        assert!(!is_valid);
    }
}
