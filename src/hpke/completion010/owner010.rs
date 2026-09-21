//! Exclusive ownership of unused non-HTTP sessions for trusted protocol adapters.
use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// An exclusively owned non-HTTP session. This handle has no Clone, restore,
/// HTTP binding or inner-session export. It grants neither MCP readiness nor
/// dispatch authority. Keep it inside the trusted host's protocol adapter.
pub struct NonHTTPOwner010 {
    session: AuthenticatedCompletion010,
    sampled: Stamp,
}

impl AuthenticatedCompletion010 {
    /// Consume an unused non-HTTP session. Failure also consumes and erases it.
    /// The endpoint must be the original live handshake endpoint. Rust moves
    /// invalidate the original handle; transferring never resets keys or history.
    ///
    /// ```compile_fail
    /// use sage_crypto_core::hpke::completion010::{AuthenticatedCompletion010, CompletionEndpoint010};
    /// fn cannot_reuse(session: AuthenticatedCompletion010, endpoint: &CompletionEndpoint010) {
    ///     let _owner = session.into_non_http(endpoint);
    ///     let _ = session.state(); // moved, no usable old alias
    /// }
    /// ```
    pub fn into_non_http(mut self, e: &CompletionEndpoint010) -> Result<NonHTTPOwner010> {
        if self.closed
            || self.record_used
            || !self.http_target.is_empty()
            || !self.sent.is_empty()
            || !self.received.is_empty()
            || self.endpoint != e.identity
            || e.signing.is_none()
        {
            self.close();
            return Err(bad());
        }
        let sampled = e.last.unwrap_or(self.created);
        Ok(NonHTTPOwner010 {
            session: self,
            sampled,
        })
    }
}

impl NonHTTPOwner010 {
    /// Immutable handshake role, not authorization to send or dispatch.
    pub fn initiator(&self) -> bool {
        self.session.initiator
    }
    /// Original trusted monotonic creation time in milliseconds.
    pub fn created_mono_ms(&self) -> i64 {
        self.session.created.mono_ms
    }
    /// Immutable authenticated local and peer identities, not current authority.
    pub fn participants(&self) -> Result<(String, String)> {
        self.session.participants()
    }
    /// Revoke this owner's record operations and erase its keys.
    pub fn close(&mut self) {
        self.session.close();
    }

    // Providers may unwind; fail closed before propagating a uniform error.
    // This cannot catch aborting panics or force a blocked provider to return.
    fn guarded<T>(
        &mut self,
        e: &mut CompletionEndpoint010,
        action: impl FnOnce(&mut AuthenticatedCompletion010, &mut CompletionEndpoint010) -> Result<T>,
    ) -> Result<T> {
        match catch_unwind(AssertUnwindSafe(|| action(&mut self.session, e))) {
            Ok(result) => result,
            Err(_) => {
                self.close();
                Err(bad())
            }
        }
    }
    /// Sample only the trusted local clock, without registry or transport work.
    /// Clock access remains exclusive through the endpoint; this method alone is
    /// not a background scheduler or a cancellation path around blocked providers.
    pub fn local_now(&mut self, e: &mut CompletionEndpoint010) -> Result<i64> {
        let previous = self.sampled;
        let sampled = self.guarded(e, |s, e| {
            if s.endpoint != e.identity || e.signing.is_none() {
                return Err(bad());
            }
            let t = e.clock.now().map_err(|_| bad())?;
            if t.mono_ms < previous.mono_ms
                || t.unix < previous.unix
                || e.last
                    .is_some_and(|p| t.mono_ms < p.mono_ms || t.unix < p.unix)
                || t.mono_ms > i64::MAX / 1_000_000
                || t.unix > 9007199254740691
                || !pinned_live(t.unix, &s.a, &s.b)
                || s.record_live(t).is_err()
            {
                return Err(bad());
            }
            e.last = Some(t);
            Ok(t)
        });
        match sampled {
            Ok(t) => {
                self.sampled = t;
                Ok(t.mono_ms)
            }
            Err(e) => {
                self.close();
                Err(e)
            }
        }
    }
    /// Return the start of a fresh registry validation, never a portable permit.
    pub fn observe(&mut self, e: &mut CompletionEndpoint010) -> Result<i64> {
        // Preserve the local sampling watermark before registry work as well.
        self.local_now(e)?;
        self.guarded(e, |s, e| s.check_current(e).map(|t| t.mono_ms))
    }
    /// Seal a request with the existing signed record protocol.
    pub fn seal_request(
        &mut self,
        e: &mut CompletionEndpoint010,
        raw: &[u8],
        ttl: i64,
    ) -> Result<Vec<u8>> {
        self.local_now(e)?;
        self.guarded(e, |s, e| s.seal_request(e, raw, ttl))
    }
    /// Authenticate a request before returning plaintext; consumes existing replay state.
    pub fn open_request(&mut self, e: &mut CompletionEndpoint010, wire: &[u8]) -> Result<Vec<u8>> {
        self.local_now(e)?;
        self.guarded(e, |s, e| s.open_request(e, wire))
    }
    /// Seal a response correlated to an accepted request.
    pub fn seal_response(
        &mut self,
        e: &mut CompletionEndpoint010,
        id: &str,
        raw: &[u8],
        error: Option<&str>,
        ttl: i64,
    ) -> Result<Vec<u8>> {
        self.local_now(e)?;
        self.guarded(e, |s, e| s.seal_response(e, id, raw, error, ttl))
    }
    /// Open only a cryptographically correlated response.
    pub fn open_response(
        &mut self,
        e: &mut CompletionEndpoint010,
        wire: &[u8],
    ) -> Result<SessionResponse010> {
        self.local_now(e)?;
        self.guarded(e, |s, e| s.open_response(e, wire))
    }
}
impl Drop for NonHTTPOwner010 {
    fn drop(&mut self) {
        self.close();
    }
}
