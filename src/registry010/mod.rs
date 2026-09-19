//! Operation-scoped checks over a trusted validating source and durable store.
//! This is not a network resolver, proof verifier, or authenticated session manager.
mod journal;
use crate::error::{Error, Result};
pub use journal::{Journal, Watermark};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub(crate) fn rejected() -> Error {
    Error::ValidationError("record.rejected".into())
}
pub(crate) fn stale() -> Error {
    Error::ValidationError("record.stale".into())
}
pub(crate) fn unreachable() -> Error {
    Error::ValidationError("record.unreachable".into())
}
pub(crate) fn hex32(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
/// Trusted local time. Clock failures must be returned as errors.
#[derive(Clone, Copy)]
pub struct Stamp {
    /// Local monotonic milliseconds; shared with Source acquisition stamps.
    pub mono_ms: i64,
    /// Trusted Unix seconds.
    pub unix: i64,
}
/// Local trusted clock, never timestamps asserted by a remote peer.
pub trait Clock {
    /// Read the current trusted time, or fail closed.
    fn now(&mut self) -> Result<Stamp>;
}
/// Trusted local deployment configuration, never received from a peer.
#[derive(Clone)]
pub struct Config {
    /// Configured authoritative source identity.
    pub source: String,
    /// Exact registry identity.
    pub registry: String,
    /// Configured chain/network binding.
    pub network: String,
    /// Require one finalized block for records and keys.
    pub blockchain: bool,
}
/// Projection of an already cryptographically validated registry key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Key {
    /// Immutable ASCII registry name.
    pub name: String,
    /// Supported profile algorithm: ed25519 or x25519.
    pub alg: String,
    /// Canonical lowercase hex public bytes, not a wire record encoding.
    pub material: String,
    /// accepted or revoked.
    pub state: String,
    /// Optional immutable expiry in trusted Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}
/// Returned only by a trusted Source. Complete syntax, cryptography, proofs,
/// identity, finality and readiness must be verified there, not inferred from
/// remote JSON flags. Keys and digest describe the same complete record.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Authenticated source identity.
    pub source: String,
    /// Observed registry binding.
    pub registry: String,
    /// Observed network binding.
    pub network: String,
    /// Exact record DID.
    pub did: String,
    /// Canonical nonzero decimal uint64 version.
    pub version: String,
    /// created, active, or deactivated.
    pub state: String,
    /// SHA256 of the entire validated canonical record.
    pub digest: String,
    /// Source readiness was established for this read.
    pub ready: bool,
    /// Complete record and proof validation succeeded at the trusted source.
    pub validated: bool,
    /// Finality policy succeeded; unfinalized observations only deny this operation.
    pub finalized: bool,
    /// Inconsistent source state was observed.
    pub conflicting: bool,
    /// Actual acquisition in the local Clock's monotonic domain.
    pub acquired_ms: i64,
    /// Finalized record block hash.
    pub block_hash: String,
    /// Block hash used to read all dependent keys.
    pub keys_block_hash: String,
    /// Validated sorted key projections.
    pub keys: Vec<Key>,
}
/// Each call must perform a new authoritative read and readiness check.
/// A cached positive record or a remote "latest" claim is insufficient.
pub trait Source {
    /// Return an owned validated observation or an error.
    fn read(&mut self, did: &str) -> Result<Snapshot>;
}
/// Persistent state is partitioned by exact registry and record.
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Registry identifier.
    pub registry: String,
    /// Record identifier.
    pub did: String,
}
/// Enforce monotonic versions, equal-version content equality and terminal
/// deactivation atomically; durably commit before returning success.
pub trait Store {
    /// Persist denial/rollback state, never positive authority.
    fn advance(&mut self, scope: Scope, version: u64, digest: String, terminal: bool)
        -> Result<()>;
}
/// One owner serializes operations; each method obtains a new observation.
pub struct RegistryGate<S: Source + ?Sized, C: Clock + ?Sized, T: Store + ?Sized> {
    cfg: Config,
    source: Box<S>,
    clock: Box<C>,
    store: Box<T>,
    last: Option<Stamp>,
}
/// A gate with existing single-threaded trusted dependencies.
pub type Gate = RegistryGate<dyn Source, dyn Clock, dyn Store>;
/// A gate whose trusted dependencies can move into a serialized Guard owner.
pub type SendGate = RegistryGate<dyn Source + Send, dyn Clock + Send, dyn Store + Send>;
impl Gate {
    /// Construct with explicitly trusted dependencies. No default positive cache.
    pub fn new(
        cfg: Config,
        source: Box<dyn Source>,
        clock: Box<dyn Clock>,
        store: Box<dyn Store>,
    ) -> Result<Self> {
        Self::from_parts(cfg, source, clock, store)
    }
}
impl SendGate {
    /// Construct a movable gate without changing existing single-threaded clients.
    pub fn new_send(
        cfg: Config,
        source: Box<dyn Source + Send>,
        clock: Box<dyn Clock + Send>,
        store: Box<dyn Store + Send>,
    ) -> Result<Self> {
        Self::from_parts(cfg, source, clock, store)
    }
}
impl<S: Source + ?Sized, C: Clock + ?Sized, T: Store + ?Sized> RegistryGate<S, C, T> {
    fn from_parts(cfg: Config, source: Box<S>, clock: Box<C>, store: Box<T>) -> Result<Self> {
        if [&cfg.source, &cfg.registry, &cfg.network]
            .iter()
            .any(|v| v.is_empty() || v.len() > 256 || v.contains(['\0', '\r', '\n']))
        {
            return Err(rejected());
        }
        Ok(Self {
            cfg,
            source,
            clock,
            store,
            last: None,
        })
    }
    fn sample(&mut self) -> Result<Stamp> {
        let t = self.clock.now().map_err(|_| unreachable())?;
        if t.mono_ms < 0 || t.unix < 0 || t.unix > 9007199254740991 {
            return Err(unreachable());
        }
        if self
            .last
            .is_some_and(|p| t.mono_ms < p.mono_ms || t.unix < p.unix)
        {
            return Err(stale());
        }
        self.last = Some(t);
        Ok(t)
    }
    fn valid_did(&self, did: &str) -> bool {
        did.len() <= 256
            && did
                .strip_prefix(&format!("did:sage:{}:", self.cfg.registry))
                .is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s != "."
                        && s != ".."
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                })
    }
    fn read(&mut self, did: &str) -> Result<(Snapshot, Stamp)> {
        if !self.valid_did(did) {
            return Err(rejected());
        }
        let start = self.sample()?;
        let s = self.source.read(did).map_err(|_| unreachable())?;
        let now = self.sample()?;
        if !s.ready
            || s.source != self.cfg.source
            || s.registry != self.cfg.registry
            || s.network != self.cfg.network
        {
            return Err(unreachable());
        }
        if !s.validated
            || s.conflicting
            || s.did != did
            || !s.finalized
            || !fresh(start, now, s.acquired_ms)
        {
            return Err(stale());
        }
        if self.cfg.blockchain && (!hex32(&s.block_hash) || s.keys_block_hash != s.block_hash) {
            return Err(stale());
        }
        let version = s.version.parse::<u64>().map_err(|_| rejected())?;
        if version == 0
            || version.to_string() != s.version
            || !hex32(&s.digest)
            || !["created", "active", "deactivated"].contains(&s.state.as_str())
            || s.keys.is_empty()
            || s.keys.len() > 128
        {
            return Err(rejected());
        }
        let mut previous = "";
        let mut materials = HashSet::new();
        for k in &s.keys {
            if k.name.is_empty()
                || k.name.len() > 32
                || !k
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                || k.name.as_str() <= previous
                || !materials.insert(&k.material)
                || !hex32(&k.material)
                || !["ed25519", "x25519"].contains(&k.alg.as_str())
                || !["accepted", "revoked"].contains(&k.state.as_str())
                || k.expires
                    .is_some_and(|v| !(0..=9007199254740991).contains(&v))
            {
                return Err(rejected());
            }
            previous = &k.name;
        }
        self.store.advance(
            Scope {
                registry: self.cfg.registry.clone(),
                did: did.into(),
            },
            version,
            s.digest.clone(),
            s.state == "deactivated",
        )?;
        // Storage may block. Recheck immediately before returning any grant.
        let now = self.sample()?;
        if !fresh(start, now, s.acquired_ms) {
            return Err(stale());
        }
        Ok((s, now))
    }
    /// Read without granting authority; inactive records remain readable.
    /// Stale results require a new authoritative read before a deferred decision.
    pub fn observe(&mut self, did: &str) -> Result<Snapshot> {
        self.read(did).map(|(s, _)| s)
    }
    /// Exact signing URL, with optional first usable ASCII-ordered X25519 selection.
    /// No trial verification or substitution of another signing key.
    pub fn select(&mut self, did: &str, signing_url: &str, require_kem: bool) -> Result<Pinned> {
        self.select_with_time(did, signing_url, require_kem)
            .map(|(p, _)| p)
    }
    /// Return selected keys and final trusted observation time for this operation.
    /// Neither value authorizes a later operation without a new read.
    pub fn select_with_time(
        &mut self,
        did: &str,
        signing_url: &str,
        require_kem: bool,
    ) -> Result<(Pinned, Stamp)> {
        let (s, now) = self.read(did)?;
        if s.state != "active" {
            return Err(rejected());
        }
        let signing = s
            .keys
            .iter()
            .find(|k| {
                usable(k, now.unix)
                    && k.alg == "ed25519"
                    && signing_url == format!("{did}#{}", k.name)
            })
            .cloned()
            .ok_or_else(rejected)?;
        let kem = if require_kem {
            Some(
                s.keys
                    .iter()
                    .find(|k| usable(k, now.unix) && k.alg == "x25519")
                    .cloned()
                    .ok_or_else(rejected)?,
            )
        } else {
            None
        };
        Ok((
            Pinned {
                did: did.into(),
                registry: self.cfg.registry.clone(),
                signing,
                kem,
            },
            now,
        ))
    }
    /// Revalidate original keys without changing selection. A session owner must
    /// close its session on failure. This check does not itself own session state.
    pub fn check_pinned(&mut self, p: &Pinned) -> Result<()> {
        if p.registry != self.cfg.registry {
            return Err(rejected());
        }
        let (s, now) = self.read(&p.did)?;
        if s.state != "active" {
            return Err(rejected());
        }
        for wanted in std::iter::once(&p.signing).chain(p.kem.iter()) {
            if !s
                .keys
                .iter()
                .any(|k| same_key(k, wanted) && usable(k, now.unix))
            {
                return Err(rejected());
            }
        }
        Ok(())
    }
}
fn fresh(start: Stamp, now: Stamp, acquired: i64) -> bool {
    acquired >= start.mono_ms && acquired <= now.mono_ms && now.mono_ms - acquired <= 5000
}
fn usable(k: &Key, now: i64) -> bool {
    k.state == "accepted" && k.expires.is_none_or(|e| now < e)
}
fn same_key(a: &Key, b: &Key) -> bool {
    a.name == b.name && a.alg == b.alg && a.material == b.material && a.expires == b.expires
}
/// Immutable selected keys, not a reusable authorization token.
#[derive(Clone)]
pub struct Pinned {
    did: String,
    registry: String,
    signing: Key,
    kem: Option<Key>,
}
impl Pinned {
    /// The bound record DID.
    pub fn did(&self) -> &str {
        &self.did
    }
    /// Exact originally selected signing material.
    pub fn signing(&self) -> &Key {
        &self.signing
    }
    /// Exact originally selected KEM material, if requested.
    pub fn kem(&self) -> Option<&Key> {
        self.kem.as_ref()
    }
}

#[cfg(test)]
mod tests;
