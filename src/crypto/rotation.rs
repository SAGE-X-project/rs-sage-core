//! Key Rotation Infrastructure
//!
//! This module provides key rotation functionality with history tracking,
//! automatic rotation, and configurable policies.
//!
//! # Features
//!
//! - Manual key rotation with atomic operations
//! - Automatic key rotation based on time intervals
//! - Rotation history tracking
//! - Configurable key retention policies
//! - Concurrent-safe operations
//!
//! # Example
//!
//! ```ignore
//! use sage_crypto_core::crypto::rotation::{DefaultKeyRotator, KeyRotationConfig};
//! use std::time::Duration;
//!
//! let config = KeyRotationConfig {
//!     rotation_interval: Duration::from_secs(86400), // 24 hours
//!     max_key_age: Duration::from_secs(604800),      // 7 days
//!     keep_old_keys: true,
//! };
//!
//! let mut rotator = DefaultKeyRotator::new(storage);
//! rotator.set_rotation_config(config);
//!
//! // Manual rotation
//! let new_key = rotator.rotate("my-key-id")?;
//!
//! // View history
//! let history = rotator.get_rotation_history("my-key-id")?;
//! ```

use crate::crypto::keys::KeyPair;
use crate::crypto::storage::KeyStorage;
use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Configuration for key rotation behavior
///
/// This struct defines the policy for when and how keys should be rotated.
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    /// Time interval between automatic rotations
    ///
    /// If set, the key will be automatically rotated after this duration
    /// has elapsed since the last rotation.
    pub rotation_interval: Duration,

    /// Maximum age a key can reach before it must be rotated
    ///
    /// This is a hard limit. Keys older than this will be flagged for
    /// immediate rotation.
    pub max_key_age: Duration,

    /// Whether to keep old keys after rotation
    ///
    /// - `true`: Old keys are retained in storage with a special prefix
    /// - `false`: Old keys are deleted during rotation
    pub keep_old_keys: bool,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(86400 * 30), // 30 days
            max_key_age: Duration::from_secs(86400 * 90),       // 90 days
            keep_old_keys: true,
        }
    }
}

/// Event representing a key rotation occurrence
///
/// Each rotation creates an event that is stored in the rotation history.
#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    /// When the rotation occurred
    pub timestamp: DateTime<Utc>,

    /// ID of the key that was rotated out
    pub old_key_id: String,

    /// ID of the new key that replaced it
    pub new_key_id: String,

    /// Reason for the rotation
    ///
    /// Examples: "manual", "scheduled", "max_age_exceeded", "security_incident"
    pub reason: String,
}

impl KeyRotationEvent {
    /// Create a new rotation event
    pub fn new(old_key_id: String, new_key_id: String, reason: String) -> Self {
        Self {
            timestamp: Utc::now(),
            old_key_id,
            new_key_id,
            reason,
        }
    }
}

/// Trait for key rotation functionality
///
/// Implement this trait to provide custom key rotation behavior.
pub trait KeyRotator: Send + Sync {
    /// Rotate a key, generating a new key of the same type
    ///
    /// This operation should be atomic - either the rotation succeeds completely
    /// or it fails without modifying the storage.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the key to rotate
    ///
    /// # Returns
    ///
    /// The newly generated key pair
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` if the key doesn't exist
    /// - `Error::CryptoError` if key generation fails
    /// - `Error::StorageError` if storage operations fail
    fn rotate(&self, id: &str) -> Result<KeyPair>;

    /// Update the rotation configuration
    ///
    /// This affects future rotations and auto-rotation behavior.
    ///
    /// # Arguments
    ///
    /// * `config` - The new rotation configuration
    fn set_rotation_config(&mut self, config: KeyRotationConfig);

    /// Get the rotation configuration
    ///
    /// # Returns
    ///
    /// The current rotation configuration
    fn get_rotation_config(&self) -> KeyRotationConfig;

    /// Get the rotation history for a specific key
    ///
    /// # Arguments
    ///
    /// * `id` - The key ID to get history for
    ///
    /// # Returns
    ///
    /// A vector of rotation events, ordered from oldest to newest
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` if no history exists for this key
    fn get_rotation_history(&self, id: &str) -> Result<Vec<KeyRotationEvent>>;

    /// Get the last rotation time for a key
    ///
    /// # Arguments
    ///
    /// * `id` - The key ID to check
    ///
    /// # Returns
    ///
    /// The timestamp of the last rotation, or None if never rotated
    fn get_last_rotation_time(&self, id: &str) -> Result<Option<DateTime<Utc>>> {
        let history = self.get_rotation_history(id)?;
        Ok(history.last().map(|event| event.timestamp))
    }

    /// Check if a key needs rotation based on the current config
    ///
    /// # Arguments
    ///
    /// * `id` - The key ID to check
    ///
    /// # Returns
    ///
    /// `true` if the key should be rotated
    fn needs_rotation(&self, id: &str) -> Result<bool> {
        let config = self.get_rotation_config();

        if let Some(last_rotation) = self.get_last_rotation_time(id)? {
            let age = Utc::now().signed_duration_since(last_rotation);
            let age_duration = Duration::from_secs(age.num_seconds().max(0) as u64);

            // Check if max age exceeded
            if age_duration >= config.max_key_age {
                return Ok(true);
            }

            // Check if rotation interval exceeded
            if age_duration >= config.rotation_interval {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Default implementation of KeyRotator
///
/// This implementation provides:
/// - Atomic key rotation
/// - In-memory rotation history
/// - Configurable retention policies
/// - Thread-safe operations using DashMap
/// - Automatic rotation with background tasks
pub struct DefaultKeyRotator {
    /// Key storage backend
    storage: Arc<dyn KeyStorage>,

    /// Rotation configuration
    config: Arc<RwLock<KeyRotationConfig>>,

    /// Rotation history per key ID
    /// Map<key_id, Vec<KeyRotationEvent>>
    history: Arc<DashMap<String, Vec<KeyRotationEvent>>>,

    /// Auto-rotation task handle
    auto_rotation_task: Arc<parking_lot::RwLock<Option<JoinHandle<()>>>>,

    /// Flag to stop auto-rotation
    stop_flag: Arc<AtomicBool>,

    /// Keys to monitor for auto-rotation
    /// Map<key_id, ()>
    monitored_keys: Arc<DashMap<String, ()>>,
}

impl DefaultKeyRotator {
    /// Create a new DefaultKeyRotator with the given storage backend
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage backend to use for key persistence
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sage_crypto_core::crypto::storage::MemoryKeyStorage;
    /// use sage_crypto_core::crypto::rotation::DefaultKeyRotator;
    /// use std::sync::Arc;
    ///
    /// let storage = Arc::new(MemoryKeyStorage::new());
    /// let rotator = DefaultKeyRotator::new(storage);
    /// ```
    pub fn new(storage: Arc<dyn KeyStorage>) -> Self {
        Self {
            storage,
            config: Arc::new(RwLock::new(KeyRotationConfig::default())),
            history: Arc::new(DashMap::new()),
            auto_rotation_task: Arc::new(RwLock::new(None)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            monitored_keys: Arc::new(DashMap::new()),
        }
    }

    /// Create a new DefaultKeyRotator with custom configuration
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage backend to use
    /// * `config` - Initial rotation configuration
    pub fn with_config(storage: Arc<dyn KeyStorage>, config: KeyRotationConfig) -> Self {
        Self {
            storage,
            config: Arc::new(RwLock::new(config)),
            history: Arc::new(DashMap::new()),
            auto_rotation_task: Arc::new(RwLock::new(None)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            monitored_keys: Arc::new(DashMap::new()),
        }
    }

    /// Handle old key based on retention policy (blocking version for sync contexts)
    ///
    /// If `keep_old_keys` is true, the old key is moved to an archived location.
    /// Otherwise, it is deleted (actually, when false, we do nothing since the old key
    /// has already been overwritten by the new key in storage).
    fn handle_old_key_sync(&self, id: &str, old_key: &KeyPair, keep_old: bool) -> Result<()> {
        if keep_old {
            // Archive old key with timestamp suffix
            let timestamp = Utc::now().timestamp();
            let archived_id = format!("{id}.old.{timestamp}");
            self.storage.store(&archived_id, old_key)?;
        }
        // When keep_old is false, we don't need to do anything - the old key
        // has already been overwritten by the new key in storage
        Ok(())
    }

    /// Record a rotation event in history
    ///
    /// # Arguments
    ///
    /// * `storage_id` - The storage ID (not the key's internal ID)
    /// * `event` - The rotation event to record
    fn record_event(&self, storage_id: &str, event: KeyRotationEvent) {
        self.history
            .entry(storage_id.to_string())
            .or_default()
            .push(event);
    }

    /// Add a key to the auto-rotation monitoring list
    ///
    /// Keys in this list will be checked periodically and rotated automatically
    /// if they meet the rotation criteria defined in the config.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The storage ID of the key to monitor
    ///
    /// # Example
    ///
    /// ```ignore
    /// rotator.add_monitored_key("my-signing-key");
    /// rotator.start_auto_rotation().await?;
    /// ```
    pub fn add_monitored_key(&self, key_id: &str) {
        self.monitored_keys.insert(key_id.to_string(), ());
    }

    /// Remove a key from the auto-rotation monitoring list
    ///
    /// # Arguments
    ///
    /// * `key_id` - The storage ID of the key to stop monitoring
    pub fn remove_monitored_key(&self, key_id: &str) {
        self.monitored_keys.remove(key_id);
    }

    /// Start automatic key rotation in the background
    ///
    /// This spawns a background tokio task that periodically checks all monitored
    /// keys and rotates them if they meet the rotation criteria.
    ///
    /// # Returns
    ///
    /// An error if auto-rotation is already running
    ///
    /// # Example
    ///
    /// ```ignore
    /// let rotator = DefaultKeyRotator::new(storage);
    /// rotator.add_monitored_key("key1");
    /// rotator.add_monitored_key("key2");
    /// rotator.start_auto_rotation().await?;
    ///
    /// // Later...
    /// rotator.stop_auto_rotation().await?;
    /// ```
    pub async fn start_auto_rotation(&self) -> Result<()> {
        let mut task_guard = self.auto_rotation_task.write();

        if task_guard.is_some() {
            return Err(Error::Other("Auto-rotation is already running".to_string()));
        }

        // Reset stop flag
        self.stop_flag.store(false, Ordering::Relaxed);

        // Clone Arc references for the background task
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let stop_flag = Arc::clone(&self.stop_flag);
        let monitored_keys = Arc::clone(&self.monitored_keys);
        let history = Arc::clone(&self.history);

        // Spawn background task
        let handle = tokio::spawn(async move {
            loop {
                // Check if we should stop
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                // Read config
                let (check_interval, rotation_interval, max_key_age, keep_old_keys) = {
                    let cfg = config.read();
                    (
                        cfg.rotation_interval / 10, // Check 10x per interval
                        cfg.rotation_interval,
                        cfg.max_key_age,
                        cfg.keep_old_keys,
                    )
                }; // cfg is dropped here

                // Check all monitored keys
                for entry in monitored_keys.iter() {
                    let key_id = entry.key().clone();

                    // Check if rotation is needed
                    let needs_rotation = if let Some(events) = history.get(&key_id) {
                        if let Some(last_event) = events.last() {
                            let age = Utc::now().signed_duration_since(last_event.timestamp);
                            // Use milliseconds for sub-second precision
                            let age_duration =
                                Duration::from_millis(age.num_milliseconds().max(0) as u64);

                            age_duration >= rotation_interval || age_duration >= max_key_age
                        } else {
                            false
                        }
                    } else {
                        false // No history, probably newly added
                    };

                    if needs_rotation {
                        // Perform rotation
                        if let Ok(old_key) = storage.load(&key_id) {
                            let old_key_id = old_key.key_id().to_string();
                            let key_type = old_key.key_type();

                            if let Ok(new_key) = KeyPair::generate(key_type) {
                                let new_key_id = new_key.key_id().to_string();

                                // Store new key
                                if storage.store(&key_id, &new_key).is_ok() {
                                    // Handle old key
                                    if keep_old_keys {
                                        let timestamp = Utc::now().timestamp();
                                        let archived_id = format!("{key_id}.old.{timestamp}");
                                        let _ = storage.store(&archived_id, &old_key);
                                    }

                                    // Record event
                                    let event = KeyRotationEvent::new(
                                        old_key_id,
                                        new_key_id,
                                        "auto".to_string(),
                                    );

                                    history.entry(key_id.clone()).or_default().push(event);
                                }
                            }
                        }
                    }
                }

                // Sleep before next check
                tokio::time::sleep(check_interval).await;
            }
        });

        *task_guard = Some(handle);
        Ok(())
    }

    /// Stop automatic key rotation
    ///
    /// This gracefully stops the background rotation task.
    ///
    /// # Example
    ///
    /// ```ignore
    /// rotator.stop_auto_rotation().await?;
    /// ```
    pub async fn stop_auto_rotation(&self) -> Result<()> {
        // Set stop flag
        self.stop_flag.store(true, Ordering::Relaxed);

        // Wait for task to finish
        let handle = self.auto_rotation_task.write().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Check if auto-rotation is currently running
    pub fn is_auto_rotation_running(&self) -> bool {
        self.auto_rotation_task.read().is_some()
    }
}

impl KeyRotator for DefaultKeyRotator {
    fn rotate(&self, id: &str) -> Result<KeyPair> {
        // Step 1: Load the existing key
        let old_key = self.storage.load(id)?;
        let old_key_id = old_key.key_id().to_string();

        // Step 2: Generate new key of the same type
        let key_type = old_key.key_type();
        let new_key = KeyPair::generate(key_type)?;
        let new_key_id = new_key.key_id().to_string();

        // Step 3: Store new key (atomic operation)
        self.storage.store(id, &new_key)?;

        // Step 4: Handle old key based on retention policy
        let keep_old = self.config.read().keep_old_keys;
        self.handle_old_key_sync(id, &old_key, keep_old)?;

        // Step 5: Record rotation event
        let event = KeyRotationEvent::new(old_key_id, new_key_id, "manual".to_string());
        self.record_event(id, event);

        Ok(new_key)
    }

    fn set_rotation_config(&mut self, config: KeyRotationConfig) {
        *self.config.write() = config;
    }

    fn get_rotation_config(&self) -> KeyRotationConfig {
        self.config.read().clone()
    }

    fn get_rotation_history(&self, id: &str) -> Result<Vec<KeyRotationEvent>> {
        self.history
            .get(id)
            .map(|entry| entry.clone())
            .ok_or_else(|| Error::NotFound(format!("No rotation history for key: {id}")))
    }

    fn get_last_rotation_time(&self, id: &str) -> Result<Option<DateTime<Utc>>> {
        match self.get_rotation_history(id) {
            Ok(history) => Ok(history.last().map(|event| event.timestamp)),
            Err(Error::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn needs_rotation(&self, id: &str) -> Result<bool> {
        let config = self.get_rotation_config();

        match self.get_last_rotation_time(id)? {
            Some(last_rotation) => {
                let age = Utc::now().signed_duration_since(last_rotation);
                // Use milliseconds for sub-second precision
                let age_duration = Duration::from_millis(age.num_milliseconds().max(0) as u64);

                // Check if max age exceeded
                if age_duration >= config.max_key_age {
                    return Ok(true);
                }

                // Check if rotation interval exceeded
                if age_duration >= config.rotation_interval {
                    return Ok(true);
                }

                Ok(false)
            }
            None => {
                // No history means key was never rotated, so it doesn't need rotation yet
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyType;
    use crate::crypto::storage::MemoryKeyStorage;

    #[test]
    fn test_default_config() {
        let config = KeyRotationConfig::default();
        assert_eq!(config.rotation_interval, Duration::from_secs(86400 * 30));
        assert_eq!(config.max_key_age, Duration::from_secs(86400 * 90));
        assert!(config.keep_old_keys);
    }

    #[test]
    fn test_rotation_event_creation() {
        let event = KeyRotationEvent::new(
            "old-key".to_string(),
            "new-key".to_string(),
            "test".to_string(),
        );

        assert_eq!(event.old_key_id, "old-key");
        assert_eq!(event.new_key_id, "new-key");
        assert_eq!(event.reason, "test");
        assert!(event.timestamp <= Utc::now());
    }

    #[test]
    fn test_default_key_rotator_creation() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage);

        let config = rotator.get_rotation_config();
        assert_eq!(config.rotation_interval, Duration::from_secs(86400 * 30));
    }

    #[test]
    fn test_default_key_rotator_with_config() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let custom_config = KeyRotationConfig {
            rotation_interval: Duration::from_secs(3600),
            max_key_age: Duration::from_secs(7200),
            keep_old_keys: false,
        };

        let rotator = DefaultKeyRotator::with_config(storage, custom_config.clone());
        let config = rotator.get_rotation_config();

        assert_eq!(config.rotation_interval, Duration::from_secs(3600));
        assert_eq!(config.max_key_age, Duration::from_secs(7200));
        assert!(!config.keep_old_keys);
    }

    #[test]
    fn test_manual_rotation() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // Generate and store initial key
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        let key_id = key.key_id().to_string();
        storage.store("test-key", &key).unwrap();

        // Rotate the key
        let new_key = rotator.rotate("test-key").unwrap();

        // Verify new key was stored
        let loaded_key = storage.load("test-key").unwrap();
        assert_eq!(loaded_key.key_id(), new_key.key_id());
        assert_ne!(loaded_key.key_id(), key_id);

        // Verify history was recorded
        let history = rotator.get_rotation_history("test-key").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].old_key_id, key_id);
        assert_eq!(history[0].new_key_id, new_key.key_id());
        assert_eq!(history[0].reason, "manual");
    }

    #[test]
    fn test_rotation_preserves_key_type() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // Test with Ed25519
        let ed_key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("ed-key", &ed_key).unwrap();
        let new_ed_key = rotator.rotate("ed-key").unwrap();
        assert_eq!(new_ed_key.key_type(), KeyType::Ed25519);

        // Test with Secp256k1
        let secp_key = KeyPair::generate(KeyType::Secp256k1).unwrap();
        storage.store("secp-key", &secp_key).unwrap();
        let new_secp_key = rotator.rotate("secp-key").unwrap();
        assert_eq!(new_secp_key.key_type(), KeyType::Secp256k1);
    }

    #[test]
    fn test_rotation_not_found() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage);

        let result = rotator.rotate("nonexistent-key");
        assert!(result.is_err());
        // MemoryKeyStorage returns InvalidInput for missing keys
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidInput(_) | Error::NotFound(_)
        ));
    }

    #[test]
    fn test_get_rotation_history_not_found() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage);

        let result = rotator.get_rotation_history("nonexistent-key");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NotFound(_)));
    }

    #[test]
    fn test_multiple_rotations() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // Initial key
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("multi-key", &key).unwrap();

        // Rotate multiple times
        rotator.rotate("multi-key").unwrap();
        rotator.rotate("multi-key").unwrap();
        rotator.rotate("multi-key").unwrap();

        // Verify history
        let history = rotator.get_rotation_history("multi-key").unwrap();
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_set_rotation_config() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let mut rotator = DefaultKeyRotator::new(storage);

        let new_config = KeyRotationConfig {
            rotation_interval: Duration::from_secs(1800),
            max_key_age: Duration::from_secs(3600),
            keep_old_keys: false,
        };

        rotator.set_rotation_config(new_config.clone());
        let config = rotator.get_rotation_config();

        assert_eq!(config.rotation_interval, Duration::from_secs(1800));
        assert_eq!(config.max_key_age, Duration::from_secs(3600));
        assert!(!config.keep_old_keys);
    }

    #[test]
    fn test_needs_rotation_no_history() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // Key with no history doesn't need rotation
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();

        let needs = rotator.needs_rotation("test-key").unwrap();
        assert!(!needs);
    }

    #[test]
    fn test_needs_rotation_interval_exceeded() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let config = KeyRotationConfig {
            rotation_interval: Duration::from_secs(1),
            max_key_age: Duration::from_secs(100),
            keep_old_keys: true,
        };
        let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

        // Create key and rotate it
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();
        rotator.rotate("test-key").unwrap();

        // Wait for interval to pass
        std::thread::sleep(Duration::from_secs(2));

        // Should need rotation now
        let needs = rotator.needs_rotation("test-key").unwrap();
        assert!(needs);
    }

    #[test]
    fn test_needs_rotation_max_age_exceeded() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let config = KeyRotationConfig {
            rotation_interval: Duration::from_secs(100),
            max_key_age: Duration::from_secs(1),
            keep_old_keys: true,
        };
        let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

        // Create key and rotate it
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();
        rotator.rotate("test-key").unwrap();

        // Wait for max age to pass
        std::thread::sleep(Duration::from_secs(2));

        // Should need rotation now
        let needs = rotator.needs_rotation("test-key").unwrap();
        assert!(needs);
    }

    #[test]
    fn test_get_last_rotation_time() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // No history - should return None
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();

        let last_time = rotator.get_last_rotation_time("test-key").unwrap();
        assert!(last_time.is_none());

        // Rotate and check
        let before_rotation = Utc::now();
        rotator.rotate("test-key").unwrap();
        let after_rotation = Utc::now();

        let last_time = rotator.get_last_rotation_time("test-key").unwrap();
        assert!(last_time.is_some());
        let timestamp = last_time.unwrap();
        assert!(timestamp >= before_rotation);
        assert!(timestamp <= after_rotation);
    }

    #[test]
    fn test_add_remove_monitored_key() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage);

        // Add keys
        rotator.add_monitored_key("key1");
        rotator.add_monitored_key("key2");
        rotator.add_monitored_key("key3");

        // Verify they're added
        assert!(rotator.monitored_keys.contains_key("key1"));
        assert!(rotator.monitored_keys.contains_key("key2"));
        assert!(rotator.monitored_keys.contains_key("key3"));

        // Remove one
        rotator.remove_monitored_key("key2");
        assert!(rotator.monitored_keys.contains_key("key1"));
        assert!(!rotator.monitored_keys.contains_key("key2"));
        assert!(rotator.monitored_keys.contains_key("key3"));
    }

    #[tokio::test]
    async fn test_auto_rotation_start_stop() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage);

        // Initially not running
        assert!(!rotator.is_auto_rotation_running());

        // Start auto-rotation
        rotator.start_auto_rotation().await.unwrap();
        assert!(rotator.is_auto_rotation_running());

        // Try to start again - should fail
        let result = rotator.start_auto_rotation().await;
        assert!(result.is_err());

        // Stop auto-rotation
        rotator.stop_auto_rotation().await.unwrap();
        assert!(!rotator.is_auto_rotation_running());
    }

    #[tokio::test]
    async fn test_auto_rotation_performs_rotation() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let config = KeyRotationConfig {
            rotation_interval: Duration::from_millis(100),
            max_key_age: Duration::from_millis(200),
            keep_old_keys: true,
        };
        let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

        // Create a key and do initial rotation to establish history
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();
        let first_key = rotator.rotate("test-key").unwrap();
        let first_key_id = first_key.key_id().to_string();

        // Add to monitored keys
        rotator.add_monitored_key("test-key");

        // Start auto-rotation
        rotator.start_auto_rotation().await.unwrap();

        // Wait for rotation to occur - with 100ms interval and check every 10ms,
        // rotation should happen after ~100ms. Wait 500ms to be very safe.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Stop auto-rotation
        rotator.stop_auto_rotation().await.unwrap();

        // Load the key - should be different from first rotation
        let current_key = storage.load("test-key").unwrap();
        let current_key_id = current_key.key_id().to_string();
        assert_ne!(
            current_key_id,
            first_key_id,
            "Auto-rotation did not change the key after waiting. History: {:?}",
            rotator.get_rotation_history("test-key").unwrap_or_default()
        );

        // Check history - should have at least 2 rotations (manual + auto)
        let history = rotator.get_rotation_history("test-key").unwrap();
        assert!(
            history.len() >= 2,
            "Expected at least 2 rotation events, got {}",
            history.len()
        );

        // Last rotation should be auto
        let last_event = history.last().unwrap();
        assert_eq!(last_event.reason, "auto");
    }

    #[test]
    fn test_concurrent_rotations() {
        use std::thread;

        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = Arc::new(DefaultKeyRotator::new(storage.clone()));

        // Create initial keys
        for i in 0..5 {
            let key = KeyPair::generate(KeyType::Ed25519).unwrap();
            storage.store(&format!("key-{i}"), &key).unwrap();
        }

        // Spawn multiple threads to rotate concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let rotator_clone = Arc::clone(&rotator);
            let handle = thread::spawn(move || {
                for _ in 0..3 {
                    let _ = rotator_clone.rotate(&format!("key-{i}"));
                    thread::sleep(Duration::from_millis(10));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all keys have history
        for i in 0..5 {
            let history = rotator.get_rotation_history(&format!("key-{i}")).unwrap();
            assert_eq!(history.len(), 3);
        }
    }

    #[test]
    fn test_rotation_with_keep_old_keys_false() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let config = KeyRotationConfig {
            rotation_interval: Duration::from_secs(3600),
            max_key_age: Duration::from_secs(7200),
            keep_old_keys: false,
        };
        let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

        // Create and store key
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();

        // Rotate
        rotator.rotate("test-key").unwrap();

        // List all keys - should not have archived old key
        let all_keys = storage.list().unwrap();
        assert_eq!(all_keys.len(), 1);
        assert_eq!(all_keys[0], "test-key");
    }

    #[test]
    fn test_rotation_with_keep_old_keys_true() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let config = KeyRotationConfig {
            rotation_interval: Duration::from_secs(3600),
            max_key_age: Duration::from_secs(7200),
            keep_old_keys: true,
        };
        let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

        // Create and store key
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();

        // Rotate
        rotator.rotate("test-key").unwrap();

        // List all keys - should have both current and archived
        let all_keys = storage.list().unwrap();
        assert_eq!(all_keys.len(), 2);
        assert!(all_keys.contains(&"test-key".to_string()));
        assert!(all_keys.iter().any(|k| k.starts_with("test-key.old.")));
    }

    #[test]
    fn test_multiple_rotations_history_order() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // Create initial key
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("test-key", &key).unwrap();

        // Perform multiple rotations with delays
        let mut timestamps = vec![];
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(10));
            rotator.rotate("test-key").unwrap();
            timestamps.push(Utc::now());
        }

        // Check history order
        let history = rotator.get_rotation_history("test-key").unwrap();
        assert_eq!(history.len(), 3);

        // Verify events are in chronological order
        for i in 0..history.len() - 1 {
            assert!(history[i].timestamp <= history[i + 1].timestamp);
        }
    }

    #[test]
    fn test_rotation_preserves_storage_id() {
        let storage = Arc::new(MemoryKeyStorage::new());
        let rotator = DefaultKeyRotator::new(storage.clone());

        // Create key with specific ID
        let key = KeyPair::generate(KeyType::Ed25519).unwrap();
        storage.store("my-special-key", &key).unwrap();

        // Rotate multiple times
        for _ in 0..5 {
            rotator.rotate("my-special-key").unwrap();
        }

        // The storage ID should still be the same
        let loaded_key = storage.load("my-special-key").unwrap();
        assert!(loaded_key.key_id() != key.key_id()); // Key changed

        // History should use storage ID
        let history = rotator.get_rotation_history("my-special-key").unwrap();
        assert_eq!(history.len(), 5);
    }
}
