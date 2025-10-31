//! Handshake Server (Responder)
//!
//! This module implements the handshake responder that handles incoming
//! handshake requests and completes the 4-phase protocol.

use crate::crypto::KeyPair;
use crate::error::{Error, Result};
use crate::handshake::types::*;
use crate::hpke::HpkeServer;
use base64::Engine;
use chrono::Utc;
use rand::Rng;
use std::sync::Arc;

/// Handshake server configuration
#[derive(Debug, Clone)]
pub struct HandshakeServerConfig {
    /// Maximum allowed time skew for timestamp validation (seconds)
    pub max_time_skew_secs: i64,
    /// Session timeout (seconds)
    pub session_timeout_secs: i64,
}

impl Default for HandshakeServerConfig {
    fn default() -> Self {
        Self {
            max_time_skew_secs: 300,  // 5 minutes
            session_timeout_secs: 3600, // 1 hour
        }
    }
}

/// Handshake server for responding to secure session requests
pub struct HandshakeServer {
    /// DID of this server
    did: String,
    /// Signing keypair for message authentication
    signing_keypair: KeyPair,
    /// HPKE server for key exchange
    #[allow(dead_code)]
    hpke_server: Arc<HpkeServer>,
    /// Configuration
    config: HandshakeServerConfig,
    /// Event handler
    events: Arc<dyn HandshakeEvents>,
    /// Current sequence number
    sequence: u64,
}

impl HandshakeServer {
    /// Create a new handshake server
    pub fn new(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        hpke_server: Arc<HpkeServer>,
    ) -> Self {
        Self::with_config(
            did,
            signing_keypair,
            hpke_server,
            HandshakeServerConfig::default(),
            Arc::new(NoopEvents),
        )
    }

    /// Create a new handshake server with custom configuration
    pub fn with_config(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        hpke_server: Arc<HpkeServer>,
        config: HandshakeServerConfig,
        events: Arc<dyn HandshakeEvents>,
    ) -> Self {
        Self {
            did: did.into(),
            signing_keypair,
            hpke_server,
            config,
            events,
            sequence: 0,
        }
    }

    /// Phase 1: Handle invitation from peer
    pub fn handle_invitation(
        &self,
        invitation: InvitationMessage,
    ) -> Result<()> {
        // Validate invitation
        self.validate_invitation(&invitation)?;

        // Notify event handler
        self.events
            .on_invitation(&invitation.base.session_id.clone(), invitation)?;

        Ok(())
    }

    /// Phase 2: Handle request and generate response
    pub fn handle_request(
        &mut self,
        request: RequestMessage,
        ephemeral_jwk: serde_json::Value,
        key_id: String,
    ) -> Result<ResponseMessage> {
        // Validate request
        self.validate_request(&request)?;

        // Extract ephemeral key from request
        let _eph_c = self.extract_ephemeral_key(&request.ephemeral_pub_key)?;

        // Notify event handler
        let sender_pub = self.signing_keypair.public_key().clone();
        self.events
            .on_request(&request.base.session_id, request.clone(), sender_pub)?;

        self.sequence += 1;

        // Generate response
        let response = ResponseMessage {
            base: BaseMessage {
                session_id: request.base.session_id.clone(),
                from: self.did.clone(),
                to: request.base.from.clone(),
            },
            control: MessageControlHeader {
                sequence: self.sequence,
                nonce: self.generate_nonce(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: ephemeral_jwk,
            keyid: Some(key_id),
            ack: true,
        };

        Ok(response)
    }

    /// Phase 4: Handle complete message
    pub fn handle_complete(
        &self,
        complete: CompleteMessage,
        session_params: SessionParams,
    ) -> Result<()> {
        // Validate complete message
        self.validate_complete(&complete)?;

        // Notify event handler
        let _sender_pub = self.signing_keypair.public_key().clone();
        self.events
            .on_complete(&complete.base.session_id.clone(), complete, session_params)?;

        Ok(())
    }

    /// Validate invitation message
    fn validate_invitation(&self, invitation: &InvitationMessage) -> Result<()> {
        // Verify recipient is us
        if invitation.base.to != self.did {
            return Err(Error::ValidationError(format!(
                "Invitation not addressed to us: expected {}, got {}",
                self.did, invitation.base.to
            )));
        }

        // Verify timestamp is within acceptable skew
        let now = Utc::now();
        let time_diff = (now - invitation.control.timestamp)
            .num_seconds()
            .abs();

        if time_diff > self.config.max_time_skew_secs {
            return Err(Error::ValidationError(format!(
                "Timestamp skew too large: {time_diff} seconds"
            )));
        }

        Ok(())
    }

    /// Validate request message
    fn validate_request(&self, request: &RequestMessage) -> Result<()> {
        // Verify recipient is us
        if request.base.to != self.did {
            return Err(Error::ValidationError(format!(
                "Request not addressed to us: expected {}, got {}",
                self.did, request.base.to
            )));
        }

        // Verify timestamp is within acceptable skew
        let now = Utc::now();
        let time_diff = (now - request.control.timestamp)
            .num_seconds()
            .abs();

        if time_diff > self.config.max_time_skew_secs {
            return Err(Error::ValidationError(format!(
                "Timestamp skew too large: {time_diff} seconds"
            )));
        }

        // Verify ephemeral key exists
        if request.ephemeral_pub_key.is_null() {
            return Err(Error::ValidationError(
                "Missing ephemeral public key".into(),
            ));
        }

        Ok(())
    }

    /// Validate complete message
    fn validate_complete(&self, complete: &CompleteMessage) -> Result<()> {
        // Verify recipient is us
        if complete.base.to != self.did {
            return Err(Error::ValidationError(format!(
                "Complete message not addressed to us: expected {}, got {}",
                self.did, complete.base.to
            )));
        }

        // Verify timestamp is within acceptable skew
        let now = Utc::now();
        let time_diff = (now - complete.control.timestamp)
            .num_seconds()
            .abs();

        if time_diff > self.config.max_time_skew_secs {
            return Err(Error::ValidationError(format!(
                "Timestamp skew too large: {time_diff} seconds"
            )));
        }

        Ok(())
    }

    /// Extract ephemeral key bytes from JWK
    fn extract_ephemeral_key(&self, jwk: &serde_json::Value) -> Result<Vec<u8>> {
        // Try to extract 'x' parameter from JWK (X25519 public key)
        if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| Error::ParseError(format!("Failed to decode JWK x parameter: {e}")))
        } else {
            Err(Error::ParseError(
                "No 'x' parameter found in JWK".into(),
            ))
        }
    }

    /// Generate a random nonce
    fn generate_nonce(&self) -> String {
        let nonce: [u8; 16] = rand::thread_rng().gen();
        hex::encode(nonce)
    }

    /// Reset sequence number (for new session)
    pub fn reset_sequence(&mut self) {
        self.sequence = 0;
    }

    /// Get current sequence number
    pub fn get_sequence(&self) -> u64 {
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;
    use crate::did::resolver::MockDIDResolver;

    fn create_test_server() -> HandshakeServer {
        let signing_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let kem_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = "did:sage:server".to_string();
        let resolver = Arc::new(MockDIDResolver::new());

        let hpke_server = Arc::new(
            HpkeServer::new(did.clone(), signing_keypair.clone(), kem_keypair, resolver).unwrap(),
        );

        HandshakeServer::new(did, signing_keypair, hpke_server)
    }

    #[test]
    fn test_server_creation() {
        let server = create_test_server();
        assert_eq!(server.sequence, 0);
    }

    #[test]
    fn test_handle_invitation() {
        let server = create_test_server();

        let invitation = InvitationMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:client".to_string(),
                to: "did:sage:server".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
        };

        assert!(server.handle_invitation(invitation).is_ok());
    }

    #[test]
    fn test_handle_request() {
        let mut server = create_test_server();

        let request = RequestMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:client".to_string(),
                to: "did:sage:server".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: serde_json::json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": "test-key"
            }),
        };

        let ephemeral_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "server-key"
        });

        let response = server
            .handle_request(request, ephemeral_jwk, "key-1".to_string())
            .unwrap();

        assert_eq!(response.base.session_id, "session-1");
        assert_eq!(response.base.from, "did:sage:server");
        assert_eq!(response.base.to, "did:sage:client");
        assert!(response.ack);
        assert_eq!(response.keyid, Some("key-1".to_string()));
        assert_eq!(server.sequence, 1);
    }

    #[test]
    fn test_validate_invitation_wrong_recipient() {
        let server = create_test_server();

        let invitation = InvitationMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:client".to_string(),
                to: "did:sage:other".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
        };

        assert!(server.validate_invitation(&invitation).is_err());
    }

    #[test]
    fn test_validate_request_missing_ephemeral_key() {
        let server = create_test_server();

        let request = RequestMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:client".to_string(),
                to: "did:sage:server".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: serde_json::Value::Null,
        };

        assert!(server.validate_request(&request).is_err());
    }

    #[test]
    fn test_handle_complete() {
        let server = create_test_server();

        let complete = CompleteMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:client".to_string(),
                to: "did:sage:server".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
        };

        let session_params = SessionParams {
            session_id: "session-1".to_string(),
            key_id: "key-1".to_string(),
            initiator_did: "did:sage:client".to_string(),
            responder_did: "did:sage:server".to_string(),
            combined_secret: vec![0u8; 32],
            is_initiator: false,
        };

        assert!(server.handle_complete(complete, session_params).is_ok());
    }

    #[test]
    fn test_sequence_increment() {
        let mut server = create_test_server();
        assert_eq!(server.get_sequence(), 0);

        let request = RequestMessage {
            base: BaseMessage {
                session_id: "session-1".to_string(),
                from: "did:sage:client".to_string(),
                to: "did:sage:server".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: serde_json::json!({"x": "test"}),
        };

        server
            .handle_request(request, serde_json::json!({}), "key-1".to_string())
            .unwrap();
        assert_eq!(server.get_sequence(), 1);

        server.reset_sequence();
        assert_eq!(server.get_sequence(), 0);
    }

    #[test]
    fn test_generate_nonce() {
        let server = create_test_server();
        let nonce1 = server.generate_nonce();
        let nonce2 = server.generate_nonce();

        assert_eq!(nonce1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(nonce1, nonce2);
    }
}
