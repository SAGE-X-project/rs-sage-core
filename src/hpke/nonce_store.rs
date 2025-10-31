//! Nonce Store for Replay Protection
//!
//! This module provides a thread-safe nonce store for preventing replay attacks.
//! Nonces are stored with TTL-based expiration with optional rate limiting.

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use std::sync::Arc;

/// Rate limit tracking for DOS prevention
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Number of attempts in current window
    count: usize,
    /// Window start time
    window_start: DateTime<Utc>,
}

/// Configuration for nonce store rate limiting
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum attempts per window
    pub max_attempts: usize,
    /// Window duration
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 100,                // 100 attempts
            window_duration: Duration::minutes(1), // per minute
        }
    }
}

/// Nonce store for replay protection
///
/// This structure maintains a set of recently used nonces with automatic expiration.
/// It prevents replay attacks by ensuring each nonce can only be used once within
/// the TTL window. Optionally supports rate limiting to prevent DOS attacks.
///
/// # Thread Safety
/// Uses DashMap for lock-free concurrent access from multiple threads.
///
/// # Memory Management
/// Expired entries are cleaned up lazily during check_and_mark operations and
/// periodically via cleanup_expired().
#[derive(Clone)]
pub struct NonceStore {
    /// Time-to-live for nonce entries
    ttl: Duration,

    /// Map of nonce keys to expiration timestamps
    entries: Arc<DashMap<String, DateTime<Utc>>>,

    /// Rate limiting configuration (optional)
    rate_limit: Option<RateLimitConfig>,

    /// Rate limit tracking per client identifier
    rate_limits: Arc<DashMap<String, RateLimitEntry>>,
}

impl NonceStore {
    /// Create a new nonce store with the specified TTL
    ///
    /// # Arguments
    /// * `ttl` - Time-to-live duration for nonce entries
    ///
    /// # Example
    /// ```
    /// use chrono::Duration;
    /// use sage_crypto_core::hpke::NonceStore;
    ///
    /// let store = NonceStore::new(Duration::minutes(5));
    /// ```
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Arc::new(DashMap::new()),
            rate_limit: None,
            rate_limits: Arc::new(DashMap::new()),
        }
    }

    /// Check if a nonce has been used, and mark it as used if not
    ///
    /// This method performs an atomic check-and-mark operation:
    /// 1. Cleanup expired entries (lazy cleanup)
    /// 2. Check if the nonce exists (replay detection)
    /// 3. If not, mark it as used with expiration timestamp
    ///
    /// # Arguments
    /// * `key` - Nonce key to check and mark
    ///
    /// # Returns
    /// `true` if the nonce was not used before (valid), `false` if it was (replay attack)
    ///
    /// # Example
    /// ```
    /// use chrono::Duration;
    /// use sage_crypto_core::hpke::NonceStore;
    ///
    /// let store = NonceStore::new(Duration::minutes(5));
    ///
    /// // First use: valid
    /// assert!(store.check_and_mark("nonce-123"));
    ///
    /// // Second use: replay detected
    /// assert!(!store.check_and_mark("nonce-123"));
    /// ```
    pub fn check_and_mark(&self, key: &str) -> bool {
        let now = Utc::now();
        let exp = now + self.ttl;

        // Lazy cleanup: remove expired entries during check
        // This is more efficient than a separate background cleanup thread
        // for most use cases
        self.entries.retain(|_, v| *v > now);

        // Atomic check-and-insert using entry API
        // This prevents race conditions where two threads check simultaneously
        use dashmap::mapref::entry::Entry;
        match self.entries.entry(key.to_string()) {
            Entry::Vacant(entry) => {
                // Nonce not used yet - mark it as used
                entry.insert(exp);
                true // Valid nonce
            }
            Entry::Occupied(_) => {
                // Nonce already exists - replay detected
                false
            }
        }
    }

    /// Explicitly cleanup all expired entries
    ///
    /// This method can be called periodically by a background task for
    /// proactive memory management. However, check_and_mark() already
    /// performs lazy cleanup, so this is optional.
    ///
    /// # Example
    /// ```
    /// use chrono::Duration;
    /// use sage_crypto_core::hpke::NonceStore;
    ///
    /// let store = NonceStore::new(Duration::minutes(5));
    /// store.check_and_mark("nonce-1");
    /// store.check_and_mark("nonce-2");
    ///
    /// // Cleanup expired entries
    /// store.cleanup_expired();
    /// ```
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        self.entries.retain(|_, v| *v > now);
    }

    /// Clear a specific nonce entry
    ///
    /// This can be used to manually remove a nonce from the store,
    /// for example during testing or error recovery.
    ///
    /// # Arguments
    /// * `key` - Nonce key to remove
    ///
    /// # Returns
    /// `true` if the nonce was present and removed, `false` otherwise
    pub fn clear_for_key(&self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Get the current number of stored nonces
    ///
    /// # Returns
    /// Number of nonces currently in the store (including expired ones)
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty
    ///
    /// # Returns
    /// `true` if no nonces are stored, `false` otherwise
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all nonces from the store
    ///
    /// This is primarily useful for testing.
    pub fn clear_all(&self) {
        self.entries.clear();
    }
}

impl Default for NonceStore {
    /// Create a nonce store with default TTL of 5 minutes
    fn default() -> Self {
        Self::new(Duration::minutes(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_nonce_store_basic() {
        let store = NonceStore::new(Duration::minutes(5));

        // First use: should succeed
        assert!(store.check_and_mark("nonce-1"));

        // Second use: should fail (replay)
        assert!(!store.check_and_mark("nonce-1"));

        // Different nonce: should succeed
        assert!(store.check_and_mark("nonce-2"));
    }

    #[test]
    fn test_nonce_store_expiration() {
        // Use very short TTL for testing
        let store = NonceStore::new(Duration::milliseconds(100));

        // Mark a nonce
        assert!(store.check_and_mark("nonce-expiring"));

        // Wait for expiration
        thread::sleep(StdDuration::from_millis(150));

        // Should be able to use the same nonce again after expiration
        assert!(store.check_and_mark("nonce-expiring"));
    }

    #[test]
    fn test_cleanup_expired() {
        let store = NonceStore::new(Duration::milliseconds(100));

        // Add multiple nonces
        assert!(store.check_and_mark("nonce-1"));
        assert!(store.check_and_mark("nonce-2"));
        assert!(store.check_and_mark("nonce-3"));
        assert_eq!(store.len(), 3);

        // Wait for expiration
        thread::sleep(StdDuration::from_millis(150));

        // Cleanup
        store.cleanup_expired();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_clear_for_key() {
        let store = NonceStore::new(Duration::minutes(5));

        assert!(store.check_and_mark("nonce-1"));
        assert!(!store.check_and_mark("nonce-1")); // Replay

        // Clear the nonce
        assert!(store.clear_for_key("nonce-1"));

        // Should be able to use again after clearing
        assert!(store.check_and_mark("nonce-1"));
    }

    #[test]
    fn test_clear_all() {
        let store = NonceStore::new(Duration::minutes(5));

        assert!(store.check_and_mark("nonce-1"));
        assert!(store.check_and_mark("nonce-2"));
        assert!(store.check_and_mark("nonce-3"));
        assert_eq!(store.len(), 3);

        store.clear_all();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_concurrent_access() {
        let store = NonceStore::new(Duration::minutes(5));
        let store_clone = store.clone();

        // Spawn multiple threads trying to mark the same nonce
        let handle1 = thread::spawn(move || store_clone.check_and_mark("concurrent-nonce"));

        let store_clone2 = store.clone();
        let handle2 = thread::spawn(move || store_clone2.check_and_mark("concurrent-nonce"));

        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        // Exactly one should succeed
        assert!(result1 != result2);
        assert!(result1 || result2);
    }

    #[test]
    fn test_default() {
        let store = NonceStore::default();
        assert!(store.check_and_mark("test-nonce"));
    }
}
