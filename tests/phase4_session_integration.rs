//! Phase 4 Session Integration Tests
//!
//! Tests the session management system:
//! - Session creation from HPKE exporter secrets
//! - Session pool management with key bindings
//! - Session expiration and cleanup
//! - Concurrent session access
//!
//! Note: Encryption/decryption functionality is tested in unit tests

use sage_crypto_core::hpke::common::derive_traffic_keys;
use sage_crypto_core::session::{
    Session, SessionConfig, SessionManager, SessionManagerConfig, SessionOpts,
};
use std::sync::Arc;
use std::time::Duration;

/// Test session creation from exporter secret
#[test]
fn test_session_creation_from_exporter() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let info = "test-session-info";

    let result = manager.ensure_session_from_exporter_with_role(&exporter, info, true, None);

    assert!(result.is_ok());
    let (session, session_id, key) = result.unwrap();

    // Verify session properties
    assert_eq!(session.get_id(), session_id);
    assert_eq!(key.len(), 32);
    assert!(!session.is_expired());
    assert_eq!(manager.session_count(), 1);
}

/// Test session manager key binding
#[test]
fn test_session_manager_key_binding() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    let (_, session_id, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
        .unwrap();

    // Bind key ID to session
    let key_id = "test-key-123";
    manager.bind_key_id(key_id, &session_id);

    assert_eq!(manager.key_binding_count(), 1);

    // Retrieve session by key ID
    let session = manager.get_by_key_id(key_id);
    assert!(session.is_some());
    assert_eq!(session.unwrap().get_id(), session_id);

    // Remove key binding
    manager.remove_key_binding(key_id);
    assert_eq!(manager.key_binding_count(), 0);
}

/// Test session manager with multiple sessions
#[test]
fn test_multiple_sessions() {
    let manager = SessionManager::new(SessionManagerConfig::default());

    // Create multiple sessions
    let mut session_ids = Vec::new();
    for i in 0..10 {
        let exporter = vec![i as u8; 32];
        let (_, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, &format!("test-{i}"), true, None)
            .unwrap();
        session_ids.push(session_id);
    }

    assert_eq!(manager.session_count(), 10);

    // Verify all sessions can be retrieved
    for session_id in &session_ids {
        let session = manager.get_session(session_id);
        assert!(session.is_some());
        assert_eq!(session.unwrap().get_id(), session_id);
    }

    // Remove some sessions
    for session_id in session_ids.iter().take(5) {
        manager.remove_session(session_id);
    }

    assert_eq!(manager.session_count(), 5);
}

/// Test session with custom ID
#[test]
fn test_session_custom_id() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    let custom_id = "my-custom-session-id";
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

/// Test session clear all
#[test]
fn test_session_clear_all() {
    let manager = SessionManager::new(SessionManagerConfig::default());

    // Create multiple sessions with key bindings
    for i in 0..5 {
        let exporter = vec![i as u8; 32];
        let (_, session_id, _) = manager
            .ensure_session_from_exporter_with_role(&exporter, &format!("test-{i}"), true, None)
            .unwrap();
        manager.bind_key_id(&format!("key-{i}"), &session_id);
    }

    assert_eq!(manager.session_count(), 5);
    assert_eq!(manager.key_binding_count(), 5);

    // Clear all
    manager.clear_all();

    assert_eq!(manager.session_count(), 0);
    assert_eq!(manager.key_binding_count(), 0);
}

/// Test concurrent session access
#[test]
fn test_concurrent_session_access() {
    let manager = Arc::new(SessionManager::new(SessionManagerConfig::default()));
    let exporter = vec![0x42u8; 32];

    let (_, session_id, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
        .unwrap();

    // Spawn multiple threads accessing the same session
    let mut handles = vec![];
    for i in 0..10 {
        let manager = Arc::clone(&manager);
        let session_id = session_id.clone();

        let handle = std::thread::spawn(move || {
            let session = manager.get_session(&session_id);
            assert!(session.is_some());
            // Just accessing the session
            let _ = i;
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify session still exists
    let session = manager.get_session(&session_id).unwrap();
    assert_eq!(session.get_id(), session_id);
}

/// Test session manager remove by key binding
#[test]
fn test_remove_session_with_key_binding() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    let (_, session_id, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
        .unwrap();

    let key_id = "test-key";
    manager.bind_key_id(key_id, &session_id);

    assert_eq!(manager.session_count(), 1);
    assert_eq!(manager.key_binding_count(), 1);

    // Remove session
    manager.remove_session(&session_id);

    assert_eq!(manager.session_count(), 0);
    // Key binding still exists (not automatically removed)
    assert_eq!(manager.key_binding_count(), 1);

    // But trying to get by key ID returns None
    assert!(manager.get_by_key_id(key_id).is_none());
}

/// Test traffic key derivation consistency
#[test]
fn test_traffic_key_consistency() {
    let exporter = vec![0x42u8; 32];

    // Derive traffic keys multiple times
    let keys1 = derive_traffic_keys(&exporter).unwrap();
    let keys2 = derive_traffic_keys(&exporter).unwrap();

    // Should be identical
    assert_eq!(keys1.c2s_key, keys2.c2s_key);
    assert_eq!(keys1.c2s_iv, keys2.c2s_iv);
    assert_eq!(keys1.s2c_key, keys2.s2c_key);
    assert_eq!(keys1.s2c_iv, keys2.s2c_iv);
    assert_eq!(keys1.channel_binding, keys2.channel_binding);
}

/// Test session creation with different roles
#[test]
fn test_session_roles() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    // Create initiator session
    let (initiator_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test-initiator", true, None)
        .unwrap();

    // Create responder session
    let (responder_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test-responder", false, None)
        .unwrap();

    // Both should be created successfully
    assert!(!initiator_session.is_expired());
    assert!(!responder_session.is_expired());
}

/// Test multiple key bindings to same session
#[test]
fn test_multiple_key_bindings_same_session() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    let (_, session_id, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
        .unwrap();

    // Bind multiple keys to same session
    manager.bind_key_id("key1", &session_id);
    manager.bind_key_id("key2", &session_id);
    manager.bind_key_id("key3", &session_id);

    assert_eq!(manager.key_binding_count(), 3);

    // All keys should resolve to same session
    let session1 = manager.get_by_key_id("key1").unwrap();
    let session2 = manager.get_by_key_id("key2").unwrap();
    let session3 = manager.get_by_key_id("key3").unwrap();

    assert_eq!(session1.get_id(), session_id);
    assert_eq!(session2.get_id(), session_id);
    assert_eq!(session3.get_id(), session_id);
}

/// Test session manager with custom config
#[test]
fn test_session_manager_custom_config() {
    let mut config = SessionManagerConfig {
        cleanup_interval: Duration::from_secs(120),
        ..Default::default()
    };
    config.default_session_config.max_age = chrono::Duration::hours(1);

    let manager = SessionManager::new(config);
    let exporter = vec![0x42u8; 32];

    let (session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
        .unwrap();

    // Session should not be expired with 1 hour TTL
    assert!(!session.is_expired());
}

/// Test session removal
#[test]
fn test_session_removal() {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    let (_, session_id, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "test", true, None)
        .unwrap();

    assert_eq!(manager.session_count(), 1);

    // Remove session
    let removed = manager.remove_session(&session_id);
    assert!(removed.is_some());
    assert_eq!(manager.session_count(), 0);

    // Try to get removed session
    assert!(manager.get_session(&session_id).is_none());
}
