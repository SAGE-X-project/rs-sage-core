//! Handshake Client (Initiator)
//!
//! This module implements the handshake initiator that drives the 4-phase
//! protocol to establish a secure session with a peer.

use crate::crypto::KeyPair;
use crate::error::{Error, Result};
use crate::handshake::types::*;
use crate::hpke::HpkeClient;
use base64::Engine;
use chrono::Utc;
use rand::Rng;
use std::sync::Arc;

/// Handshake client configuration
#[derive(Debug, Clone)]
pub struct HandshakeClientConfig {
    /// Maximum allowed time skew for timestamp validation (seconds)
    pub max_time_skew_secs: i64,
    /// Session timeout (seconds)
    pub session_timeout_secs: i64,
}

impl Default for HandshakeClientConfig {
    fn default() -> Self {
        Self {
            max_time_skew_secs: 300,  // 5 minutes
            session_timeout_secs: 3600, // 1 hour
        }
    }
}

/// Handshake client for initiating secure sessions
pub struct HandshakeClient {
    /// DID of this client
    did: String,
    /// Signing keypair for message authentication
    signing_keypair: KeyPair,
    /// HPKE client for key exchange
    #[allow(dead_code)]
    hpke_client: Arc<HpkeClient>,
    /// Configuration
    config: HandshakeClientConfig,
    /// Event handler
    events: Arc<dyn HandshakeEvents>,
    /// Current sequence number
    sequence: u64,
}

impl HandshakeClient {
    /// Create a new handshake client
    pub fn new(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        hpke_client: Arc<HpkeClient>,
    ) -> Self {
        Self::with_config(
            did,
            signing_keypair,
            hpke_client,
            HandshakeClientConfig::default(),
            Arc::new(NoopEvents),
        )
    }

    /// Create a new handshake client with custom configuration
    pub fn with_config(
        did: impl Into<String>,
        signing_keypair: KeyPair,
        hpke_client: Arc<HpkeClient>,
        config: HandshakeClientConfig,
        events: Arc<dyn HandshakeEvents>,
    ) -> Self {
        Self {
            did: did.into(),
            signing_keypair,
            hpke_client,
            config,
            events,
            sequence: 0,
        }
    }

    /// Phase 1: Send invitation to peer
    pub fn send_invitation(&mut self, session_id: &str, peer_did: &str) -> Result<InvitationMessage> {
        self.sequence += 1;

        let invitation = InvitationMessage {
            base: BaseMessage {
                session_id: session_id.to_string(),
                from: self.did.clone(),
                to: peer_did.to_string(),
            },
            control: MessageControlHeader {
                sequence: self.sequence,
                nonce: self.generate_nonce(),
                timestamp: Utc::now(),
            },
        };

        // Notify event handler
        self.events.on_invitation(&invitation.base.session_id, invitation.clone())?;

        Ok(invitation)
    }

    /// Phase 2: Send request with ephemeral key
    pub fn send_request(
        &mut self,
        session_id: &str,
        peer_did: &str,
        ephemeral_jwk: serde_json::Value,
    ) -> Result<RequestMessage> {
        self.sequence += 1;

        let request = RequestMessage {
            base: BaseMessage {
                session_id: session_id.to_string(),
                from: self.did.clone(),
                to: peer_did.to_string(),
            },
            control: MessageControlHeader {
                sequence: self.sequence,
                nonce: self.generate_nonce(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: ephemeral_jwk,
        };

        Ok(request)
    }

    /// Phase 3: Handle response from peer
    pub fn handle_response(
        &self,
        session_id: &str,
        response: ResponseMessage,
    ) -> Result<SessionParams> {
        // Validate response
        self.validate_response(session_id, &response)?;

        // Extract ephemeral key from response
        let _eph_s = self.extract_ephemeral_key(&response.ephemeral_pub_key)?;

        // Build session parameters (before moving response)
        let session_params = SessionParams {
            session_id: session_id.to_string(),
            key_id: response.keyid.clone().unwrap_or_default(),
            initiator_did: self.did.clone(),
            responder_did: response.base.from.clone(),
            combined_secret: vec![0u8; 32], // Placeholder - would come from HPKE
            is_initiator: true,
        };

        // Notify event handler
        // Note: sender_pub would come from signature verification in real implementation
        let sender_pub = self.signing_keypair.public_key().clone();
        self.events
            .on_response(session_id, response, sender_pub)?;

        Ok(session_params)
    }

    /// Phase 4: Send complete message to confirm session
    pub fn send_complete(
        &mut self,
        session_id: &str,
        peer_did: &str,
        session_params: &SessionParams,
    ) -> Result<CompleteMessage> {
        self.sequence += 1;

        let complete = CompleteMessage {
            base: BaseMessage {
                session_id: session_id.to_string(),
                from: self.did.clone(),
                to: peer_did.to_string(),
            },
            control: MessageControlHeader {
                sequence: self.sequence,
                nonce: self.generate_nonce(),
                timestamp: Utc::now(),
            },
        };

        // Notify event handler
        self.events
            .on_complete(&complete.base.session_id, complete.clone(), session_params.clone())?;

        Ok(complete)
    }

    /// Validate response message
    fn validate_response(&self, session_id: &str, response: &ResponseMessage) -> Result<()> {
        // Verify session ID matches
        if response.base.session_id != session_id {
            return Err(Error::ValidationError(format!(
                "Session ID mismatch: expected {}, got {}",
                session_id, response.base.session_id
            )));
        }

        // Verify recipient is us
        if response.base.to != self.did {
            return Err(Error::ValidationError(format!(
                "Message not addressed to us: expected {}, got {}",
                self.did, response.base.to
            )));
        }

        // Verify timestamp is within acceptable skew
        let now = Utc::now();
        let time_diff = (now - response.control.timestamp)
            .num_seconds()
            .abs();

        if time_diff > self.config.max_time_skew_secs {
            return Err(Error::ValidationError(format!(
                "Timestamp skew too large: {time_diff} seconds"
            )));
        }

        // Verify acknowledgment flag
        if !response.ack {
            return Err(Error::ValidationError(
                "Response acknowledgment flag is false".into(),
            ));
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

    fn create_test_client() -> HandshakeClient {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let did = "did:sage:client".to_string();
        let resolver = Arc::new(MockDIDResolver::new());
        let hpke_client = Arc::new(HpkeClient::new(did.clone(), keypair.clone(), resolver));

        HandshakeClient::new(did, keypair, hpke_client)
    }

    #[test]
    fn test_client_creation() {
        let client = create_test_client();
        assert_eq!(client.sequence, 0);
    }

    #[test]
    fn test_send_invitation() {
        let mut client = create_test_client();
        let session_id = "session-1";
        let peer_did = "did:sage:peer";

        let invitation = client.send_invitation(session_id, peer_did).unwrap();

        assert_eq!(invitation.base.session_id, session_id);
        assert_eq!(invitation.base.from, "did:sage:client");
        assert_eq!(invitation.base.to, peer_did);
        assert_eq!(invitation.control.sequence, 1);
        assert_eq!(client.sequence, 1);
    }

    #[test]
    fn test_send_request() {
        let mut client = create_test_client();
        let session_id = "session-1";
        let peer_did = "did:sage:peer";
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "test-key"
        });

        let request = client.send_request(session_id, peer_did, jwk).unwrap();

        assert_eq!(request.base.session_id, session_id);
        assert_eq!(request.control.sequence, 1);
        assert!(request.ephemeral_pub_key.is_object());
    }

    #[test]
    fn test_validate_response_success() {
        let client = create_test_client();
        let session_id = "session-1";

        let response = ResponseMessage {
            base: BaseMessage {
                session_id: session_id.to_string(),
                from: "did:sage:peer".to_string(),
                to: "did:sage:client".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: serde_json::json!({"x": "test"}),
            keyid: Some("key-1".to_string()),
            ack: true,
        };

        assert!(client.validate_response(session_id, &response).is_ok());
    }

    #[test]
    fn test_validate_response_wrong_session() {
        let client = create_test_client();
        let session_id = "session-1";

        let response = ResponseMessage {
            base: BaseMessage {
                session_id: "wrong-session".to_string(),
                from: "did:sage:peer".to_string(),
                to: "did:sage:client".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: serde_json::json!({"x": "test"}),
            keyid: Some("key-1".to_string()),
            ack: true,
        };

        assert!(client.validate_response(session_id, &response).is_err());
    }

    #[test]
    fn test_validate_response_no_ack() {
        let client = create_test_client();
        let session_id = "session-1";

        let response = ResponseMessage {
            base: BaseMessage {
                session_id: session_id.to_string(),
                from: "did:sage:peer".to_string(),
                to: "did:sage:client".to_string(),
            },
            control: MessageControlHeader {
                sequence: 1,
                nonce: "nonce-123".to_string(),
                timestamp: Utc::now(),
            },
            ephemeral_pub_key: serde_json::json!({"x": "test"}),
            keyid: Some("key-1".to_string()),
            ack: false,
        };

        assert!(client.validate_response(session_id, &response).is_err());
    }

    #[test]
    fn test_sequence_increment() {
        let mut client = create_test_client();
        assert_eq!(client.get_sequence(), 0);

        client.send_invitation("session-1", "did:sage:peer").unwrap();
        assert_eq!(client.get_sequence(), 1);

        client.send_request("session-1", "did:sage:peer", serde_json::json!({})).unwrap();
        assert_eq!(client.get_sequence(), 2);

        client.reset_sequence();
        assert_eq!(client.get_sequence(), 0);
    }

    #[test]
    fn test_generate_nonce() {
        let client = create_test_client();
        let nonce1 = client.generate_nonce();
        let nonce2 = client.generate_nonce();

        assert_eq!(nonce1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(nonce1, nonce2);
    }
}
