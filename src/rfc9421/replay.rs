//! Nonce replay protection for RFC 9421 verification: a nonce may be
//! accepted once per key id within the verifier's freshness window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Records nonces per scope (the signer's `keyid`).
pub trait ReplayGuard: Send + Sync {
    /// Returns `true` when the nonce was not seen before under `scope`
    /// and records it.
    fn check_and_mark(&self, scope: &str, nonce: &str) -> bool;
}

/// In-memory guard with a TTL per entry.
pub struct MemoryReplayGuard {
    ttl: Duration,
    seen: Mutex<HashMap<(String, String), Instant>>,
}

impl MemoryReplayGuard {
    /// Create a guard that forgets nonces after `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Number of live entries (after sweeping expired ones).
    pub fn len(&self) -> usize {
        let mut seen = self.seen.lock().unwrap();
        let now = Instant::now();
        seen.retain(|_, t| now.duration_since(*t) < self.ttl);
        seen.len()
    }

    /// Whether the guard holds no live entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn check_and_mark(&self, scope: &str, nonce: &str) -> bool {
        let mut seen = self.seen.lock().unwrap();
        let now = Instant::now();
        if seen.len() > 4096 {
            seen.retain(|_, t| now.duration_since(*t) < self.ttl);
        }
        let key = (scope.to_string(), nonce.to_string());
        match seen.get(&key) {
            Some(t) if now.duration_since(*t) < self.ttl => false,
            _ => {
                seen.insert(key, now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn once_per_scope() {
        let g = MemoryReplayGuard::new(Duration::from_secs(60));
        assert!(g.check_and_mark("a", "n1"));
        assert!(!g.check_and_mark("a", "n1"));
        assert!(g.check_and_mark("b", "n1"));
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn expires() {
        let g = MemoryReplayGuard::new(Duration::from_millis(1));
        assert!(g.check_and_mark("a", "n1"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(g.check_and_mark("a", "n1"));
    }
}
