use super::{hex32, rejected, stale, unreachable, Scope, Store};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
const HEADER: &[u8] = b"sage-registry-watermarks|0.10.0\n";
/// Persistent denial/rollback state, never a positive grant.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    /// Exact registry/record partition.
    pub scope: Scope,
    /// Highest finalized version observed.
    pub version: u64,
    /// Full validated record commitment.
    pub digest: String,
    /// Confirmed permanent deactivation.
    pub terminal: bool,
}
/// Single-writer durable append log on trusted local storage. The lock file is
/// removed only on clean close. After a crash an operator must establish exclusive
/// ownership before removing the lock; never automatically recover lost state.
pub struct Journal {
    file: Option<File>,
    lock: PathBuf,
    values: HashMap<Scope, Watermark>,
    failed: bool,
    size: u64,
}
impl Journal {
    /// Create only with create=true; ordinary restart requires an existing complete
    /// journal. Path integrity and protection from malicious disk rollback are
    /// deployment obligations. A second writer or partial journal fails closed.
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let guard = options.open(&lock)?;
        drop(guard);
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(create);
        #[cfg(unix)]
        options.mode(0o600);
        let opened = options.open(path);
        let file = match opened {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_file(&lock);
                return Err(e.into());
            }
        };
        let mut j = Self {
            file: Some(file),
            lock,
            values: HashMap::new(),
            failed: false,
            size: 0,
        };
        let file = j.file.as_mut().ok_or_else(unreachable)?;
        if create {
            file.write_all(HEADER)?;
            file.sync_all()?
        }
        j.size = file.metadata()?.len();
        if j.size > 64 * 1024 * 1024 {
            return Err(unreachable());
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if !bytes.starts_with(HEADER) || !bytes.ends_with(b"\n") {
            return Err(rejected());
        }
        for line in bytes[HEADER.len()..].split_inclusive(|b| *b == b'\n') {
            let w: Watermark = serde_json::from_slice(line).map_err(|_| rejected())?;
            j.check(&w)?;
            j.values.insert(w.scope.clone(), w);
        }
        Ok(j)
    }
    fn check(&self, w: &Watermark) -> Result<()> {
        if w.scope.registry.is_empty()
            || w.scope.did.is_empty()
            || w.version == 0
            || !hex32(&w.digest)
        {
            return Err(rejected());
        }
        if let Some(old) = self.values.get(&w.scope) {
            if w.version < old.version
                || (old.terminal && !w.terminal)
                || (w.version == old.version
                    && (w.digest != old.digest || w.terminal != old.terminal))
            {
                return Err(stale());
            }
        } else if self.values.len() >= 4096 {
            return Err(unreachable());
        }
        Ok(())
    }
    /// Inspect denial state without obtaining authority.
    pub fn get(&self, scope: &Scope) -> Option<Watermark> {
        self.values.get(scope).cloned()
    }
    /// Close the journal and release the writer lock.
    pub fn close(&mut self) -> Result<()> {
        if self.file.take().is_some() {
            fs::remove_file(&self.lock)?
        }
        Ok(())
    }
}
impl Store for Journal {
    fn advance(
        &mut self,
        scope: Scope,
        version: u64,
        digest: String,
        terminal: bool,
    ) -> Result<()> {
        if self.failed || self.file.is_none() {
            return Err(unreachable());
        }
        let w = Watermark {
            scope,
            version,
            digest,
            terminal,
        };
        self.check(&w)?;
        if self.values.get(&w.scope) == Some(&w) {
            return Ok(());
        }
        let mut bytes = serde_json::to_vec(&w).map_err(|_| rejected())?;
        bytes.push(b'\n');
        if self.size + bytes.len() as u64 > 64 * 1024 * 1024 {
            return Err(unreachable());
        }
        let file = self.file.as_mut().ok_or_else(unreachable)?;
        if file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            self.failed = true;
            return Err(unreachable());
        }
        self.size += bytes.len() as u64;
        self.values.insert(w.scope.clone(), w);
        Ok(())
    }
}
impl Store for Arc<Mutex<Journal>> {
    fn advance(
        &mut self,
        scope: Scope,
        version: u64,
        digest: String,
        terminal: bool,
    ) -> Result<()> {
        self.lock()
            .map_err(|_| unreachable())?
            .advance(scope, version, digest, terminal)
    }
}
impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
