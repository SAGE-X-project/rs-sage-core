//! Secure Session Implementation
//!
//! This module provides the SecureSession implementation with AES-GCM encryption,
//! MAC generation, and lifecycle management.

use crate::error::{Error, Result};
use crate::hpke::derive_traffic_keys;
use crate::session::types::*;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Secure session with encryption and authentication
pub struct SecureSession {
    /// Session ID
    id: String,
    /// Session keys (C2S and S2C)
    keys: Arc<RwLock<SessionKeys>>,
    /// Creation timestamp
    created_at: DateTime<Utc>,
    /// Last used timestamp
    last_used_at: Arc<RwLock<DateTime<Utc>>>,
    /// Message counter
    message_count: Arc<RwLock<usize>>,
    /// Session status
    status: Arc<RwLock<SessionStatus>>,
    /// Configuration
    config: SessionConfig,
    /// Whether this party is the initiator
    is_initiator: bool,
}

/// Session keys derived from combined secret
struct SessionKeys {
    /// Client-to-Server key
    c2s_key: Zeroizing<Vec<u8>>,
    /// Client-to-Server IV
    #[allow(dead_code)]
    c2s_iv: Vec<u8>,
    /// Server-to-Client key
    s2c_key: Zeroizing<Vec<u8>>,
    /// Server-to-Client IV
    #[allow(dead_code)]
    s2c_iv: Vec<u8>,
    /// Channel binding value
    channel_binding: Vec<u8>,
}

impl SecureSession {
    /// Create a new secure session from combined secret
    pub fn new(
        session_id: String,
        combined_secret: &[u8],
        is_initiator: bool,
        config: SessionConfig,
    ) -> Result<Self> {
        // Derive traffic keys from combined secret
        let traffic_keys = derive_traffic_keys(combined_secret)?;

        let keys = SessionKeys {
            c2s_key: Zeroizing::new(traffic_keys.c2s_key.to_vec()),
            c2s_iv: traffic_keys.c2s_iv.to_vec(),
            s2c_key: Zeroizing::new(traffic_keys.s2c_key.to_vec()),
            s2c_iv: traffic_keys.s2c_iv.to_vec(),
            channel_binding: traffic_keys.channel_binding.to_vec(),
        };

        let now = Utc::now();

        Ok(Self {
            id: session_id,
            keys: Arc::new(RwLock::new(keys)),
            created_at: now,
            last_used_at: Arc::new(RwLock::new(now)),
            message_count: Arc::new(RwLock::new(0)),
            status: Arc::new(RwLock::new(SessionStatus::Active)),
            config,
            is_initiator,
        })
    }

    /// Get channel binding value
    pub fn get_channel_binding(&self) -> Vec<u8> {
        let keys = self.keys.read().unwrap();
        keys.channel_binding.clone()
    }

    /// Check if session should expire based on timestamps
    fn check_expiration(&self) -> bool {
        let now = Utc::now();
        let last_used = *self.last_used_at.read().unwrap();

        // Check absolute expiration
        if now - self.created_at > self.config.max_age {
            return true;
        }

        // Check idle timeout
        if now - last_used > self.config.idle_timeout {
            return true;
        }

        false
    }

    /// Increment message counter
    fn increment_message_count(&self) -> Result<()> {
        let mut count = self.message_count.write().unwrap();
        *count += 1;

        if *count > self.config.max_messages {
            return Err(Error::Other("Message limit exceeded".into()));
        }

        Ok(())
    }

    /// Get encryption key (based on direction)
    fn get_encryption_key(&self) -> Zeroizing<Vec<u8>> {
        let keys = self.keys.read().unwrap();
        if self.is_initiator {
            keys.c2s_key.clone()
        } else {
            keys.s2c_key.clone()
        }
    }

    /// Get decryption key (based on direction)
    fn get_decryption_key(&self) -> Zeroizing<Vec<u8>> {
        let keys = self.keys.read().unwrap();
        if self.is_initiator {
            keys.s2c_key.clone()
        } else {
            keys.c2s_key.clone()
        }
    }

    /// Generate nonce from message counter
    ///
    /// Creates a unique 96-bit (12-byte) nonce for each message using the message counter.
    /// This ensures nonce uniqueness which is critical for AES-GCM security.
    fn generate_nonce(&self) -> Result<[u8; 12]> {
        let count = *self.message_count.read().unwrap();

        // Use session ID hash + counter for nonce uniqueness
        let mut nonce = [0u8; 12];

        // First 4 bytes: session ID hash
        let id_bytes = self.id.as_bytes();
        let id_hash = sha2::Sha256::digest(id_bytes);
        nonce[0..4].copy_from_slice(&id_hash[0..4]);

        // Next 8 bytes: message counter (big-endian)
        nonce[4..12].copy_from_slice(&(count as u64).to_be_bytes());

        Ok(nonce)
    }

    /// AES-GCM encryption
    ///
    /// Uses AES-256-GCM with unique nonce per message.
    /// The nonce is prepended to the ciphertext for decryption.
    fn aes_gcm_encrypt(&self, plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Ensure key is 32 bytes for AES-256
        if key.len() != 32 {
            return Err(Error::CryptoError("Invalid key length for AES-256-GCM".into()));
        }

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {e}")))?;

        // Generate unique nonce
        let nonce_array = self.generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_array);

        // Encrypt with AAD
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| Error::CryptoError(format!("Encryption failed: {e}")))?;

        // Prepend nonce to ciphertext for decryption
        // Format: [nonce (12 bytes)][ciphertext + tag]
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_array);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// AES-GCM decryption
    ///
    /// Extracts nonce from ciphertext and decrypts using AES-256-GCM.
    fn aes_gcm_decrypt(&self, ciphertext_with_nonce: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Ensure key is 32 bytes for AES-256
        if key.len() != 32 {
            return Err(Error::CryptoError("Invalid key length for AES-256-GCM".into()));
        }

        // Check minimum length (nonce + tag)
        if ciphertext_with_nonce.len() < 28 {  // 12 (nonce) + 16 (GCM tag)
            return Err(Error::CryptoError("Ciphertext too short".into()));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {e}")))?;

        // Decrypt with AAD
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| Error::CryptoError(format!("Decryption failed: {e}")))?;

        Ok(plaintext)
    }
}

impl Session for SecureSession {
    fn get_id(&self) -> &str {
        &self.id
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn get_last_used_at(&self) -> DateTime<Utc> {
        *self.last_used_at.read().unwrap()
    }

    fn get_status(&self) -> SessionStatus {
        *self.status.read().unwrap()
    }

    fn is_expired(&self) -> bool {
        if self.check_expiration() {
            let mut status = self.status.write().unwrap();
            *status = SessionStatus::Expired;
            true
        } else {
            matches!(self.get_status(), SessionStatus::Expired | SessionStatus::Closed)
        }
    }

    fn update_last_used(&mut self) {
        let mut last_used = self.last_used_at.write().unwrap();
        *last_used = Utc::now();
    }

    fn close(&mut self) -> Result<()> {
        let mut status = self.status.write().unwrap();
        *status = SessionStatus::Closed;
        Ok(())
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.is_expired() {
            return Err(Error::Other("Session expired".into()));
        }

        self.increment_message_count()?;

        let key = self.get_encryption_key();
        // Use empty AAD for simple encryption
        self.aes_gcm_encrypt(plaintext, &key, b"")
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.is_expired() {
            return Err(Error::Other("Session expired".into()));
        }

        self.increment_message_count()?;

        let key = self.get_decryption_key();
        // Use empty AAD for simple decryption
        self.aes_gcm_decrypt(ciphertext, &key, b"")
    }

    fn encrypt_and_sign(&self, plaintext: &[u8], covered: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.is_expired() {
            return Err(Error::Other("Session expired".into()));
        }

        self.increment_message_count()?;

        let key = self.get_encryption_key();
        // Use covered data as AAD for authenticated encryption
        // AES-GCM will authenticate both the plaintext and AAD
        let ciphertext = self.aes_gcm_encrypt(plaintext, &key, covered)?;

        // For backward compatibility, also generate a separate MAC
        // In production, you could rely solely on AES-GCM's authentication
        let mac = self.sign_covered(covered);

        Ok((ciphertext, mac))
    }

    fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        covered: &[u8],
        mac: &[u8],
    ) -> Result<Vec<u8>> {
        if self.is_expired() {
            return Err(Error::Other("Session expired".into()));
        }

        // Verify separate MAC for backward compatibility
        self.verify_covered(covered, mac)?;

        self.increment_message_count()?;

        let key = self.get_decryption_key();
        // AES-GCM will also verify the AAD during decryption
        self.aes_gcm_decrypt(ciphertext, &key, covered)
    }

    fn sign_covered(&self, covered: &[u8]) -> Vec<u8> {
        let key = self.get_encryption_key();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC key size");
        mac.update(covered);
        mac.finalize().into_bytes().to_vec()
    }

    fn verify_covered(&self, covered: &[u8], signature: &[u8]) -> Result<()> {
        let key = self.get_decryption_key();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)
            .map_err(|e| Error::CryptoError(format!("HMAC error: {e}")))?;
        mac.update(covered);

        mac.verify_slice(signature)
            .map_err(|_| Error::ValidationError("MAC verification failed".into()))
    }

    fn get_message_count(&self) -> usize {
        *self.message_count.read().unwrap()
    }

    fn get_config(&self) -> &SessionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_session() -> SecureSession {
        let combined_secret = vec![0x42u8; 32];
        let config = SessionConfig {
            max_age: Duration::seconds(60),
            idle_timeout: Duration::seconds(30),
            max_messages: 100,
        };

        SecureSession::new("test-session".to_string(), &combined_secret, true, config).unwrap()
    }

    #[test]
    fn test_session_creation() {
        let session = create_test_session();
        assert_eq!(session.get_id(), "test-session");
        assert_eq!(session.get_status(), SessionStatus::Active);
        assert_eq!(session.get_message_count(), 0);
    }

    #[test]
    fn test_encrypt_decrypt() {
        // Create two sessions with same secret - one initiator, one responder
        let combined_secret = vec![0x42u8; 32];
        let config = SessionConfig {
            max_age: Duration::seconds(60),
            idle_timeout: Duration::seconds(30),
            max_messages: 100,
        };

        let initiator = SecureSession::new(
            "test-session".to_string(),
            &combined_secret,
            true,
            config.clone(),
        )
        .unwrap();

        let responder = SecureSession::new(
            "test-session".to_string(),
            &combined_secret,
            false,
            config,
        )
        .unwrap();

        let plaintext = b"Hello, World!";

        // Initiator encrypts
        let ciphertext = initiator.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Responder decrypts
        let decrypted = responder.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Responder encrypts
        let ciphertext2 = responder.encrypt(plaintext).unwrap();

        // Initiator decrypts
        let decrypted2 = initiator.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_sign_verify() {
        // Create two sessions - initiator and responder
        let combined_secret = vec![0x42u8; 32];
        let config = SessionConfig {
            max_age: Duration::seconds(60),
            idle_timeout: Duration::seconds(30),
            max_messages: 100,
        };

        let initiator = SecureSession::new(
            "test-session".to_string(),
            &combined_secret,
            true,
            config.clone(),
        )
        .unwrap();

        let responder = SecureSession::new(
            "test-session".to_string(),
            &combined_secret,
            false,
            config,
        )
        .unwrap();

        let data = b"test data";

        // Initiator signs
        let signature = initiator.sign_covered(data);
        assert!(!signature.is_empty());

        // Responder verifies
        assert!(responder.verify_covered(data, &signature).is_ok());

        // Verify fails with wrong data
        assert!(responder.verify_covered(b"wrong data", &signature).is_err());
    }

    #[test]
    fn test_encrypt_and_sign() {
        // Create two sessions - initiator and responder
        let combined_secret = vec![0x42u8; 32];
        let config = SessionConfig {
            max_age: Duration::seconds(60),
            idle_timeout: Duration::seconds(30),
            max_messages: 100,
        };

        let initiator = SecureSession::new(
            "test-session".to_string(),
            &combined_secret,
            true,
            config.clone(),
        )
        .unwrap();

        let responder = SecureSession::new(
            "test-session".to_string(),
            &combined_secret,
            false,
            config,
        )
        .unwrap();

        let plaintext = b"secret message";
        let covered = b"additional data";

        // Initiator encrypts and signs
        let (ciphertext, mac) = initiator.encrypt_and_sign(plaintext, covered).unwrap();

        // Responder decrypts and verifies
        let decrypted = responder
            .decrypt_and_verify(&ciphertext, covered, &mac)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_message_count() {
        let session = create_test_session();
        assert_eq!(session.get_message_count(), 0);

        session.encrypt(b"test").unwrap();
        assert_eq!(session.get_message_count(), 1);

        session.encrypt(b"test2").unwrap();
        assert_eq!(session.get_message_count(), 2);
    }

    #[test]
    fn test_session_close() {
        let mut session = create_test_session();
        assert_eq!(session.get_status(), SessionStatus::Active);

        session.close().unwrap();
        assert_eq!(session.get_status(), SessionStatus::Closed);

        // Closed session cannot encrypt
        assert!(session.encrypt(b"test").is_err());
    }

    #[test]
    fn test_channel_binding() {
        let session = create_test_session();
        let cb = session.get_channel_binding();
        assert_eq!(cb.len(), 32);
    }

    #[test]
    fn test_update_last_used() {
        let mut session = create_test_session();
        let initial = session.get_last_used_at();

        std::thread::sleep(std::time::Duration::from_millis(10));
        session.update_last_used();

        let updated = session.get_last_used_at();
        assert!(updated > initial);
    }
}
