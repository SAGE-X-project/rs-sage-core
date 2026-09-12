//! Session Manager
//!
//! This module provides the SessionManager for managing multiple secure sessions,
//! key ID binding, and session lifecycle.

use crate::error::{Error, Result};
use crate::session::secure_session::SecureSession;
use crate::session::types::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Session manager configuration
#[derive(Debug, Clone)]
pub struct SessionManagerConfig {
    /// Cleanup interval for expired sessions
    pub cleanup_interval: Duration,
    /// Default session configuration
    pub default_session_config: SessionConfig,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(60), // 1 minute
            default_session_config: SessionConfig::default(),
        }
    }
}

/// Session manager for handling multiple secure sessions
pub struct SessionManager {
    /// Active sessions (session_id -> SecureSession)
    sessions: Arc<DashMap<String, Arc<SecureSession>>>,
    /// Key ID to session ID mapping
    key_to_session: Arc<DashMap<String, String>>,
    /// Configuration
    config: SessionManagerConfig,
    /// Cleanup task handle
    cleanup_handle: Option<JoinHandle<()>>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: SessionManagerConfig) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            key_to_session: Arc::new(DashMap::new()),
            config,
            cleanup_handle: None,
        }
    }

    /// Create a session from combined secret (exporter)
    pub fn ensure_session_from_exporter_with_role(
        &self,
        exporter: &[u8],
        info: &str,
        is_initiator: bool,
        opts: Option<SessionOpts>,
    ) -> Result<(Arc<SecureSession>, String, Vec<u8>)> {
        let opts = opts.unwrap_or_default();

        // Generate session ID if not provided
        let session_id = opts
            .session_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Derive session key from exporter using info as context
        let session_key = self.derive_session_key(exporter, info)?;

        // Create secure session
        let session =
            SecureSession::new(session_id.clone(), &session_key, is_initiator, opts.config)?;

        let session = Arc::new(session);

        // Store session
        self.sessions.insert(session_id.clone(), session.clone());

        Ok((session, session_id, session_key))
    }

    /// Bind a key ID to a session ID
    pub fn bind_key_id(&self, key_id: &str, session_id: &str) {
        self.key_to_session
            .insert(key_id.to_string(), session_id.to_string());
    }

    /// Get session by session ID
    pub fn get_session(&self, session_id: &str) -> Option<Arc<SecureSession>> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    /// Get session by key ID
    pub fn get_by_key_id(&self, key_id: &str) -> Option<Arc<SecureSession>> {
        self.key_to_session
            .get(key_id)
            .and_then(|sid| self.sessions.get(sid.value()).map(|s| s.clone()))
    }

    /// Remove session by session ID
    pub fn remove_session(&self, session_id: &str) -> Option<Arc<SecureSession>> {
        self.sessions.remove(session_id).map(|(_, s)| s)
    }

    /// Remove key ID binding
    pub fn remove_key_binding(&self, key_id: &str) {
        self.key_to_session.remove(key_id);
    }

    /// Get number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get number of key bindings
    pub fn key_binding_count(&self) -> usize {
        self.key_to_session.len()
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(mut self) -> Self {
        let sessions = Arc::clone(&self.sessions);
        let interval = self.config.cleanup_interval;

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                Self::cleanup_expired_sessions(&sessions);
            }
        });

        self.cleanup_handle = Some(handle);
        self
    }

    /// Stop cleanup task
    pub fn stop_cleanup_task(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }

    /// Cleanup expired sessions (internal)
    fn cleanup_expired_sessions(sessions: &DashMap<String, Arc<SecureSession>>) {
        sessions.retain(|_, session| !session.is_expired());
    }

    /// Manually trigger cleanup
    pub fn cleanup_expired(&self) {
        Self::cleanup_expired_sessions(&self.sessions);
    }

    /// Clear all sessions
    pub fn clear_all(&self) {
        self.sessions.clear();
        self.key_to_session.clear();
    }

    /// Derive session key from exporter using HKDF
    fn derive_session_key(&self, exporter: &[u8], info: &str) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, exporter);
        let mut okm = vec![0u8; 32];
        hkdf.expand(info.as_bytes(), &mut okm)
            .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))?;

        Ok(okm)
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        self.stop_cleanup_task();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_manager_creation() {
        let config = SessionManagerConfig::default();
        let manager = SessionManager::new(config);
        assert_eq!(manager.session_count(), 0);
        assert_eq!(manager.key_binding_count(), 0);
    }

    #[test]
    fn test_ensure_session_from_exporter() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        let result =
            manager.ensure_session_from_exporter_with_role(&exporter, "test-context", true, None);

        assert!(result.is_ok());
        let (session, session_id, key) = result.unwrap();

        assert_eq!(session.get_id(), session_id);
        assert_eq!(key.len(), 32);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_bind_key_id() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        let (_, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
            .unwrap();

        let key_id = "test-key-1";
        manager.bind_key_id(key_id, &session_id);

        assert_eq!(manager.key_binding_count(), 1);

        let session = manager.get_by_key_id(key_id);
        assert!(session.is_some());
        assert_eq!(session.unwrap().get_id(), session_id);
    }

    #[test]
    fn test_get_session() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        let (_, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
            .unwrap();

        let session = manager.get_session(&session_id);
        assert!(session.is_some());
        assert_eq!(session.unwrap().get_id(), session_id);

        let missing = manager.get_session("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_remove_session() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        let (_, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
            .unwrap();

        assert_eq!(manager.session_count(), 1);

        let removed = manager.remove_session(&session_id);
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_remove_key_binding() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        let (_, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
            .unwrap();

        let key_id = "test-key";
        manager.bind_key_id(key_id, &session_id);
        assert_eq!(manager.key_binding_count(), 1);

        manager.remove_key_binding(key_id);
        assert_eq!(manager.key_binding_count(), 0);
    }

    #[test]
    fn test_clear_all() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        // Create multiple sessions
        for i in 0..3 {
            let (_, session_id, _) = manager
                .ensure_session_from_exporter_with_role(&exporter, &format!("test-{i}"), true, None)
                .unwrap();
            manager.bind_key_id(&format!("key-{i}"), &session_id);
        }

        assert_eq!(manager.session_count(), 3);
        assert_eq!(manager.key_binding_count(), 3);

        manager.clear_all();

        assert_eq!(manager.session_count(), 0);
        assert_eq!(manager.key_binding_count(), 0);
    }

    #[test]
    fn test_custom_session_opts() {
        let manager = SessionManager::new(SessionManagerConfig::default());
        let exporter = vec![0x42u8; 32];

        let custom_id = "custom-session-id";
        let opts = SessionOpts {
            session_id: Some(custom_id.to_string()),
            config: SessionConfig::default(),
            metadata: std::collections::HashMap::new(),
        };

        let (session, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, "test", true, Some(opts))
            .unwrap();

        assert_eq!(session_id, custom_id);
        assert_eq!(session.get_id(), custom_id);
    }
}
