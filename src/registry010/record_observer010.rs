//! Complete registry observations for informational DID projections.
use super::web_record_proofs010::{
    check_record_proofs_010, check_web_registry_proofs_with_policy_010,
};
use super::web_record_shape010::{check_record_shape_010, field, object, string};
use super::{check_config, fresh, hex32, stale, unreachable, Clock, Config, Scope, Stamp, Store};
use crate::{
    did::parse_did_010,
    error::{Error, Result},
    jcs,
};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Locally authenticated origin of a complete observation, never a wire assertion.
#[derive(Clone)]
pub enum RecordOrigin {
    /// One finalized eip155 block for the complete record and dependent arrays.
    FinalizedBlock {
        /// Canonical lowercase hexadecimal block identity without 0x.
        block_hash: String,
        /// Block used for record members.
        record_block_hash: String,
        /// Block used for every key, including tombstones.
        keys_block_hash: String,
        /// Block used for the complete service array.
        services_block_hash: String,
        /// The configured finality policy has been verified by the reader.
        finalized: bool,
    },
    /// A REG-08 envelope from the configured authenticated TLS origin. The
    /// reader must enforce bounded framing/media, destinations and no caching.
    AuthenticatedWeb,
}
/// Complete trusted read. Eip155 data is a REG-01 record; web data is a REG-08
/// envelope. Reader booleans are local obligations, not peer-supplied evidence.
#[derive(Clone)]
pub struct RecordSnapshot {
    /// Configured source identity.
    pub source: String,
    /// Exact configured registry.
    pub registry: String,
    /// Exact configured network.
    pub network: String,
    /// Complete encoded bytes, including all proofs.
    pub data: Vec<u8>,
    /// Source-specific provenance from this read.
    pub origin: RecordOrigin,
    /// Acquisition in the observer's monotonic clock domain.
    pub acquired_ms: i64,
    /// Source readiness established for this read.
    pub ready: bool,
    /// Complete immutable history and authority checked by the trusted reader.
    pub validated: bool,
    /// Conflicting source observations deny resolution.
    pub conflicting: bool,
}
/// Must acquire a fresh authenticated observation on every call. Actual RPC/ABI
/// and TLS bindings are explicit caller obligations, never selected by peers.
pub trait RecordReader {
    /// Read the exact DID or fail; an error does not prove authenticated absence.
    fn read_record(&mut self, did: &str) -> Result<RecordSnapshot>;
}
/// An owned validated record for display, never a protected-operation grant.
pub struct ObservedRecord {
    record: Vec<u8>,
    pub(crate) view: serde_json::Value,
    source: String,
    completed: Stamp,
    observed_at: serde_json::Value,
}
impl ObservedRecord {
    /// Borrow the complete record; mutation cannot bypass its observation checks.
    pub fn record_json(&self) -> &[u8] {
        &self.record
    }
    /// Authenticated source identity configured locally.
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Local trusted completion sample, not a peer timestamp.
    pub fn completed(&self) -> Stamp {
        self.completed
    }
    /// Finalized block string or REG-08 issued integer.
    pub fn observed_at(&self) -> &serde_json::Value {
        &self.observed_at
    }
}
/// A serialized complete reader for public DID views. Protected operations
/// still use their own fresh RegistryGate; views are not reusable authority.
pub struct RecordObserver {
    cfg: Config,
    reader: Box<dyn RecordReader>,
    clock: Box<dyn Clock>,
    store: Box<dyn Store>,
    last: Option<Stamp>,
}
fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}
impl RecordObserver {
    /// Require explicit local trust, a protected clock and durable continuity.
    pub fn new(
        cfg: Config,
        reader: Box<dyn RecordReader>,
        clock: Box<dyn Clock>,
        store: Box<dyn Store>,
    ) -> Result<Self> {
        check_config(&cfg)?;
        let p = parse_did_010(&format!("did:sage:{}:a", cfg.registry))?;
        if !cfg.source.is_ascii() || cfg.blockchain != (p.kind == "eip155") {
            return Err(invalid());
        }
        Ok(Self {
            cfg,
            reader,
            clock,
            store,
            last: None,
        })
    }
    fn sample(&mut self) -> Result<Stamp> {
        let t = self.clock.now().map_err(|_| unreachable())?;
        if t.mono_ms < 0 || !(0..=9007199254740991).contains(&t.unix) {
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
    /// Read and validate a complete current record, commit finalized continuity,
    /// then recheck freshness before returning display data. Missing state is
    /// never defaulted. Known local validation codes survive reader failures; transport or unknown
    /// failures mean unreachable, not invented absence.
    pub fn observe(&mut self, did: &str) -> Result<ObservedRecord> {
        let p = parse_did_010(did)?;
        if format!("{}:{}", p.kind, p.locator) != self.cfg.registry {
            return Err(invalid());
        }
        let start = self.sample()?;
        let s = self.reader.read_record(did).map_err(|e| match e {
            Error::ValidationError(ref code)
                if matches!(
                    code.as_str(),
                    "size.exceeded" | "record.invalid" | "record.stale"
                ) =>
            {
                e
            }
            _ => unreachable(),
        })?;
        let limit = if self.cfg.blockchain { 65536 } else { 69632 };
        if s.data.len() > limit {
            return Err(Error::ValidationError("size.exceeded".into()));
        }
        let now = self.sample()?;
        if !s.ready
            || s.source != self.cfg.source
            || s.registry != self.cfg.registry
            || s.network != self.cfg.network
        {
            return Err(unreachable());
        }
        if !s.validated || s.conflicting || !fresh(start, now, s.acquired_ms) {
            return Err(stale());
        }
        let (raw, at) = match &s.origin {
            RecordOrigin::FinalizedBlock {
                block_hash,
                record_block_hash,
                keys_block_hash,
                services_block_hash,
                finalized,
            } if self.cfg.blockchain => {
                if !finalized
                    || !hex32(block_hash)
                    || record_block_hash != block_hash
                    || keys_block_hash != block_hash
                    || services_block_hash != block_hash
                {
                    return Err(stale());
                }
                (
                    s.data.clone(),
                    serde_json::Value::String(block_hash.clone()),
                )
            }
            RecordOrigin::AuthenticatedWeb if !self.cfg.blockchain => {
                check_web_registry_proofs_with_policy_010(&s.data, did, now.unix, false)?;
                let env: BTreeMap<String, Box<RawValue>> =
                    serde_json::from_slice(&s.data).map_err(|_| invalid())?;
                let issued = jcs::parse(env.get("issued").ok_or_else(invalid)?.get())?;
                let issued = super::web_envelope010::exact_integer(&issued).ok_or_else(invalid)?;
                if issued < 0 {
                    return Err(invalid());
                }
                (
                    env.get("record")
                        .ok_or_else(invalid)?
                        .get()
                        .as_bytes()
                        .to_vec(),
                    serde_json::json!(issued),
                )
            }
            _ => return Err(stale()),
        };
        check_record_shape_010(&raw, did, now.unix, false)?;
        let text = std::str::from_utf8(&raw).map_err(|_| invalid())?;
        let record = jcs::parse(text).map_err(|_| invalid())?;
        let fields = object(&record)?;
        if self.cfg.blockchain {
            let controller = string(field(fields, "controller")?)?;
            if controller.len() != 42
                || !controller.starts_with("0x")
                || !controller.as_bytes()[2..]
                    .iter()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            {
                return Err(invalid());
            }
            check_record_proofs_010(&record, did)?;
        }
        let version = string(field(fields, "version")?)?
            .parse::<u64>()
            .map_err(|_| invalid())?;
        let terminal = string(field(fields, "state")?)? == "deactivated";
        let canonical = jcs::canonical(&raw).map_err(|_| invalid())?;
        // Cache normalized JSON only after exact numeric and proof validation.
        // This avoids parsing validated literals again in each projection.
        let view = serde_json::from_slice(&canonical).map_err(|_| invalid())?;
        self.store.advance(
            Scope {
                registry: self.cfg.registry.clone(),
                did: did.into(),
            },
            version,
            hex::encode(Sha256::digest(&canonical)),
            terminal,
        )?;
        let completed = self.sample()?;
        if !fresh(start, completed, s.acquired_ms) {
            return Err(stale());
        }
        // A web envelope must still be live at the final gate after storage.
        if !self.cfg.blockchain {
            super::check_web_registry_envelope_010(&s.data, completed.unix)?;
        }
        Ok(ObservedRecord {
            record: raw,
            view,
            source: s.source,
            completed,
            observed_at: at,
        })
    }
}
