//! Single-DID local reference journal for complete web Registry writes.

use super::web_transition010::web_write_journal_step_010;
use super::{
    rejected, unreachable, WebRegistryAdminAuthority010, WebRegistryWriteSnapshot010,
    WebRegistryWriteState010, WebRegistryWriteStore010,
};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const HEADER: &[u8] = b"sage-web-registry-writes|0.10.0\n";
const LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    did: String,
    source: String,
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

fn refresh(raw: &[u8], now: i64) -> Result<Vec<u8>> {
    if !(0..=9_007_199_254_740_986).contains(&now) {
        return Err(rejected());
    }
    let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| rejected())?;
    let record = value.get("record").ok_or_else(rejected)?;
    serde_json::to_vec(&serde_json::json!({
        "record": record, "issued": now, "expires": now + 5,
    }))
    .map_err(|_| rejected())
}

/// Single-writer, single-DID local reference store. Paths, source identity,
/// actor authentication and delegation state come from trusted deployment
/// configuration. A crash or uncertain I/O leaves the exclusive lock in place;
/// an operator must establish ownership and inspect the journal before recovery.
/// Malicious disk rollback and deployed source/credential binding are outside
/// this type's guarantee.
pub struct WebRegistryWriteJournal010<'a> {
    file: Option<File>,
    lock: PathBuf,
    did: String,
    source: String,
    authority: &'a dyn WebRegistryAdminAuthority010,
    state: WebRegistryWriteState010,
    size: u64,
    failed: bool,
}

impl<'a> WebRegistryWriteJournal010<'a> {
    /// Initialize only when `create` is true. Ordinary restart requires an
    /// existing complete journal and no writer lock.
    pub fn open(
        path: &Path,
        did: &str,
        source: &str,
        authority: &'a dyn WebRegistryAdminAuthority010,
        create: bool,
    ) -> Result<Self> {
        if did.is_empty() || source.is_empty() {
            return Err(rejected());
        }
        let lock = lock_path(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let guard = options.open(&lock)?;
        drop(guard);
        if let Err(error) = sync_parent(&lock) {
            let _ = fs::remove_file(&lock);
            return Err(error);
        }
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(create);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_file(&lock);
                return Err(error.into());
            }
        };
        if create {
            let initialize = (|| -> Result<()> {
                file.write_all(HEADER)?;
                let binding = serde_json::to_vec(&Binding {
                    did: did.to_owned(),
                    source: source.to_owned(),
                })
                .map_err(|_| rejected())?;
                file.write_all(&binding)?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                sync_parent(path)?;
                Ok(())
            })();
            if initialize.is_err() {
                // A partial or unsynced initialization may be on disk.
                drop(file);
                return Err(unreachable());
            }
        }
        let load = (|| -> Result<(WebRegistryWriteState010, u64)> {
            let size = file.metadata()?.len();
            if size > LIMIT {
                return Err(unreachable());
            }
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            if !bytes.starts_with(HEADER) || !bytes.ends_with(b"\n") {
                return Err(rejected());
            }
            let mut lines = bytes[HEADER.len()..].split_inclusive(|byte| *byte == b'\n');
            let first = lines.next().ok_or_else(rejected)?;
            let binding: Binding = serde_json::from_slice(first).map_err(|_| rejected())?;
            if binding.did != did || binding.source != source {
                return Err(rejected());
            }
            let mut state = WebRegistryWriteState010 {
                source: source.to_owned(),
                envelope: Vec::new(),
                history: Vec::new(),
                tombstoned: false,
            };
            for line in lines {
                let next: WebRegistryWriteState010 =
                    serde_json::from_slice(line).map_err(|_| rejected())?;
                web_write_journal_step_010(&state, &next, source, did)?;
                state = next;
            }
            Ok((state, size))
        })();
        let (state, size) = match load {
            Ok(value) => value,
            Err(error) => {
                drop(file);
                let _ = fs::remove_file(&lock);
                return Err(error);
            }
        };
        Ok(Self {
            file: Some(file),
            lock,
            did: did.to_owned(),
            source: source.to_owned(),
            authority,
            state,
            size,
            failed: false,
        })
    }

    /// Inspect local test state without granting write authority.
    pub fn inspect(&self) -> WebRegistryWriteState010 {
        self.state.clone()
    }

    /// Release a clean writer lock. A quarantined store retains its lock.
    pub fn close(&mut self) -> Result<()> {
        if self.failed {
            self.file.take();
            return Err(unreachable());
        }
        if self.file.take().is_some() {
            fs::remove_file(&self.lock)?;
            sync_parent(&self.lock)?;
        }
        Ok(())
    }
}

impl WebRegistryWriteStore010 for WebRegistryWriteJournal010<'_> {
    fn update(
        &mut self,
        did: &str,
        now: i64,
        decide: &mut dyn for<'a> FnMut(
            WebRegistryWriteSnapshot010<'a>,
        ) -> Result<WebRegistryWriteState010>,
    ) -> Result<()> {
        if self.failed || self.file.is_none() || did != self.did {
            return Err(unreachable());
        }
        let mut snapshot = self.state.clone();
        if !snapshot.envelope.is_empty() {
            snapshot.envelope = refresh(&snapshot.envelope, now)?;
        }
        let next = decide(WebRegistryWriteSnapshot010 {
            state: snapshot,
            authority: self.authority,
        })?;
        web_write_journal_step_010(&self.state, &next, &self.source, &self.did)?;
        let mut line = serde_json::to_vec(&next).map_err(|_| unreachable())?;
        line.push(b'\n');
        if self.size + line.len() as u64 > LIMIT {
            return Err(unreachable());
        }
        let file = self.file.as_mut().ok_or_else(unreachable)?;
        if file.write_all(&line).and_then(|_| file.sync_all()).is_err() {
            self.failed = true;
            return Err(unreachable());
        }
        self.size += line.len() as u64;
        self.state = next;
        Ok(())
    }
}

impl Drop for WebRegistryWriteJournal010<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    struct Authority;
    impl WebRegistryAdminAuthority010 for Authority {
        fn authenticated_actor(&self) -> Result<String> {
            Ok("operator".into())
        }
        fn delegated(
            &self,
            _controller: &str,
            _actor: &str,
            _did: &str,
            _operation: &str,
            _expected_version: &str,
        ) -> Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn uncertain_write_keeps_exclusive_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writes.log");
        let authority = Authority;
        let mut store = WebRegistryWriteJournal010::open(
            &path,
            "did:sage:web:agents.example.com:billing-bot",
            "trusted-web-origin",
            &authority,
            true,
        )
        .unwrap();
        store.failed = true; // deterministic I/O-failure state
        assert!(matches!(store.close(), Err(Error::ValidationError(_))));
        assert!(lock_path(&path).exists());
        assert!(WebRegistryWriteJournal010::open(
            &path,
            "did:sage:web:agents.example.com:billing-bot",
            "trusted-web-origin",
            &authority,
            false,
        )
        .is_err());
    }
}
