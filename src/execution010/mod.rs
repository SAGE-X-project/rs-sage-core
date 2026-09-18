//! Durable execution identities and immutable outcomes on trusted local storage.
//! This module does not authenticate envelopes, authorize calls or dispatch tools.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const HEADER: &[u8] = b"sage-execution-ledger|0.10.0\n";
const MAX_SIZE: u64 = 64 * 1024 * 1024;
const MAX_ROWS: usize = 4096;

/// Invalid transitions, identities, exhausted storage, or unavailable storage.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid identity, state transition or capacity.
    #[error("execution ledger denied")]
    Denied,
    /// Closed, failed or unrecoverable journal.
    #[error("execution ledger unavailable")]
    Unavailable,
    /// Local storage failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
/// Exact caller-validated canonical envelopes and trusted identity projections.
/// No expiry-based pruning occurs. Result bytes are not verified by this store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Authenticated issuer from the intent.
    pub issuer: String,
    /// Authenticated executor from the intent.
    pub recipient: String,
    /// Issuer-scoped call identity.
    pub call_id: String,
    /// Issuer/recipient-scoped freshness identity.
    pub nonce: String,
    /// Signed intent expiry; enforcing current time is a caller duty.
    pub expires: i64,
    /// Exact canonical intent envelope in lowercase hex, at most 1 MiB decoded.
    pub intent_hex: String,
    /// RESERVED, EXECUTING, COMPLETED, REJECTED or UNKNOWN.
    pub state: String,
    /// Exact signed terminal envelope hex; empty for unresolved uncertainty.
    pub result_hex: String,
}
type Call = (String, String);
type Nonce = (String, String, String);
/// Single writer ledger. Share under a mutex for concurrent callers. No automatic
/// Drop unlock: a crash or unclean owner drop leaves the lock for administration.
/// Only Linux/macOS initialization is supported; filesystem integrity is trusted.
pub struct Ledger {
    file: Option<File>,
    lock: PathBuf,
    entries: BTreeMap<Call, Entry>,
    nonces: BTreeMap<Nonce, Call>,
    size: u64,
    rows: usize,
    failed: bool,
}
fn atom(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|c| (33..=126).contains(&c) && !b"\"\\<>&".contains(&c))
}
fn envelope(s: &str, empty: bool) -> bool {
    if s.is_empty() {
        return empty;
    }
    s.len() <= 2 * 1024 * 1024
        && s.len() % 2 == 0
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid(e: &Entry) -> bool {
    if ![&e.issuer, &e.recipient, &e.call_id, &e.nonce]
        .iter()
        .all(|v| atom(v))
        || !(0..=9007199254740991).contains(&e.expires)
        || !envelope(&e.intent_hex, false)
    {
        return false;
    }
    match e.state.as_str() {
        "RESERVED" | "EXECUTING" => e.result_hex.is_empty(),
        "UNKNOWN" => envelope(&e.result_hex, true),
        "COMPLETED" | "REJECTED" => envelope(&e.result_hex, false),
        _ => false,
    }
}
fn identity(a: &Entry, b: &Entry) -> bool {
    a.issuer == b.issuer
        && a.recipient == b.recipient
        && a.call_id == b.call_id
        && a.nonce == b.nonce
        && a.expires == b.expires
        && a.intent_hex == b.intent_hex
}
impl Ledger {
    fn check(&self, e: &Entry) -> Result<bool, Error> {
        if !valid(e) {
            return Err(Error::Denied);
        }
        let k = (e.issuer.clone(), e.call_id.clone());
        let n = (e.issuer.clone(), e.recipient.clone(), e.nonce.clone());
        if self.nonces.get(&n).is_some_and(|owner| owner != &k) {
            return Err(Error::Denied);
        }
        let Some(old) = self.entries.get(&k) else {
            return if e.state == "RESERVED" || e.state == "REJECTED" {
                Ok(true)
            } else {
                Err(Error::Denied)
            };
        };
        if !identity(old, e) {
            return Err(Error::Denied);
        }
        if old == e {
            return Ok(false);
        }
        let allowed = match old.state.as_str() {
            "RESERVED" => matches!(e.state.as_str(), "EXECUTING" | "REJECTED" | "UNKNOWN"),
            "EXECUTING" => matches!(e.state.as_str(), "COMPLETED" | "UNKNOWN"),
            "UNKNOWN" => {
                old.result_hex.is_empty() && e.state == "UNKNOWN" && !e.result_hex.is_empty()
            }
            _ => false,
        };
        if allowed {
            Ok(true)
        } else {
            Err(Error::Denied)
        }
    }
    fn remember(&mut self, e: Entry) {
        let key = (e.issuer.clone(), e.call_id.clone());
        self.nonces.insert(
            (e.issuer.clone(), e.recipient.clone(), e.nonce.clone()),
            key.clone(),
        );
        self.entries.insert(key, e);
    }
    fn append(&mut self, e: Entry) -> Result<(), Error> {
        if self.rows >= MAX_ROWS {
            return Err(Error::Denied);
        }
        let mut bytes = serde_json::to_vec(&e).map_err(|_| Error::Denied)?;
        bytes.push(b'\n');
        if self.size + bytes.len() as u64 > MAX_SIZE {
            return Err(Error::Denied);
        }
        let f = self.file.as_mut().ok_or(Error::Unavailable)?;
        if f.write_all(&bytes).and_then(|_| f.sync_all()).is_err() {
            self.failed = true;
            return Err(Error::Unavailable);
        }
        self.size += bytes.len() as u64;
        self.rows += 1;
        self.remember(e);
        Ok(())
    }
    /// Initialize only for a new isolated scope with no outstanding grants. Reopen
    /// never recreates missing state. Recovery durably marks all unresolved calls
    /// UNKNOWN before exposing the handle, without ever invoking a tool.
    /// Trusted administration must prove exclusive ownership before clearing a
    /// leftover lock. Malicious disk rollback and policy rollout are external.
    pub fn open(path: &Path, create: bool) -> Result<Self, Error> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(Error::Unavailable);
        }
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        drop(options.open(&lock)?);
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(create);
        #[cfg(unix)]
        options.mode(0o600);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(e) => {
                let _ = fs::remove_file(&lock);
                return Err(e.into());
            }
        };
        let mut l = Self {
            file: Some(file),
            lock,
            entries: BTreeMap::new(),
            nonces: BTreeMap::new(),
            size: 0,
            rows: 0,
            failed: false,
        };
        if let Err(e) = l.load(path, create) {
            let _ = l.close();
            return Err(e);
        }
        Ok(l)
    }
    fn load(&mut self, path: &Path, create: bool) -> Result<(), Error> {
        let f = self.file.as_mut().ok_or(Error::Unavailable)?;
        if create {
            f.write_all(HEADER)?;
            f.sync_all()?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        f.seek(SeekFrom::Start(0))?;
        let mut raw = Vec::new();
        f.take(MAX_SIZE + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_SIZE || !raw.starts_with(HEADER) || !raw.ends_with(b"\n") {
            return Err(Error::Unavailable);
        }
        self.size = raw.len() as u64;
        let body = &raw[HEADER.len()..];
        if !body.is_empty() {
            for line in body[..body.len() - 1].split(|b| *b == b'\n') {
                let entry: Entry = serde_json::from_slice(line).map_err(|_| Error::Unavailable)?;
                if serde_json::to_vec(&entry).map_err(|_| Error::Unavailable)? != line
                    || !self.check(&entry)?
                    || self.rows >= MAX_ROWS
                {
                    return Err(Error::Unavailable);
                }
                self.rows += 1;
                self.remember(entry);
            }
        }
        let pending: Vec<_> = self
            .entries
            .values()
            .filter(|e| e.state == "RESERVED" || e.state == "EXECUTING")
            .cloned()
            .collect();
        for mut e in pending {
            e.state = "UNKNOWN".into();
            self.append(e)?;
        }
        Ok(())
    }
    /// Atomically persist identity, nonce and state. False means an identical
    /// retry, never permission to execute again. Durable EXECUTING must precede
    /// effects. Current authorization and retirement need a separate shared gate.
    /// Terminal envelopes must already be signed and bound by the caller.
    pub fn commit(&mut self, e: Entry) -> Result<bool, Error> {
        if self.failed || self.file.is_none() {
            return Err(Error::Unavailable);
        }
        let changed = self.check(&e)?;
        if changed {
            self.append(e)?;
        }
        Ok(changed)
    }
    /// Read storage state only. Freshness, live identity/policy and result expiry
    /// must be checked by the caller before each authenticated retrieval.
    pub fn lookup(&self, issuer: &str, call: &str) -> Result<Option<Entry>, Error> {
        if self.failed || self.file.is_none() {
            return Err(Error::Unavailable);
        }
        Ok(self.entries.get(&(issuer.into(), call.into())).cloned())
    }
    /// Release a healthy writer lock. Poisoned handles retain their lock for
    /// explicit administrative recovery. No implicit unlock occurs on Drop.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.file.take().is_some() {
            if self.failed {
                return Err(Error::Unavailable);
            }
            fs::remove_file(&self.lock)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
