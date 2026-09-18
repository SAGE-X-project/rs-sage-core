//! Bounded persistent replay denial state, never an acceptance or session snapshot.
use super::{bad, Replay010, ReplayStore010};
use crate::{
    error::Result,
    registry010::{Clock, Stamp},
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const HEADER: &[u8] = b"sage-replay-denials|0.10.0\n";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    at: i64,
    sender: String,
    recipient: String,
    id: String,
    nonce: String,
    context: String,
    expires: i64,
}
fn text(v: &str) -> bool {
    v.len() <= 1024
        && v.bytes()
            .all(|c| (33..=126).contains(&c) && !b"\"\\<>&".contains(&c))
}
impl Row {
    fn valid(&self) -> bool {
        [&self.sender, &self.recipient, &self.id, &self.nonce]
            .iter()
            .all(|v| !v.is_empty() && text(v))
            && text(&self.context)
            && (0..=9007199254740000).contains(&self.at)
            && self.expires >= self.at - 30
            && self.expires <= self.at + 330
    }
    fn keys(&self) -> Vec<[String; 4]> {
        let mut k = vec![
            [
                self.sender.clone(),
                self.recipient.clone(),
                "id".into(),
                self.id.clone(),
            ],
            [
                self.sender.clone(),
                self.recipient.clone(),
                "nonce".into(),
                self.nonce.clone(),
            ],
        ];
        if !self.context.is_empty() {
            k.push([
                self.sender.clone(),
                String::new(),
                "context".into(),
                self.context.clone(),
            ]);
        }
        k
    }
}
/// Single-writer bounded denial journal on trusted Linux/macOS storage. Missing
/// or partial state fails closed. No session restoration or hostile disk rollback
/// protection is claimed. A crash leaves a lock requiring operator recovery.
pub struct ReplayJournal010 {
    file: Option<File>,
    lock: PathBuf,
    clock: Box<dyn Clock>,
    start: Stamp,
    last: Stamp,
    recovered: bool,
    failed: bool,
    rows: usize,
    size: usize,
    seen: HashMap<[String; 4], i64>,
}
impl ReplayJournal010 {
    /// Explicit creation imposes 360 seconds of BOTH UTC and monotonic quarantine.
    /// Empty reopen restarts quarantine; complete nonempty recovery permits immediate
    /// use with nondecreasing UTC. Paths and clock are trusted deployment inputs.
    pub fn open(path: &Path, create: bool, mut clock: Box<dyn Clock>) -> Result<Self> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(bad());
        }
        let now = clock.now()?;
        if !(0..=9007199254740000).contains(&now.unix) || now.mono_ms < 0 {
            return Err(bad());
        }
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        o.mode(0o600);
        drop(o.open(&lock)?);
        let mut o = OpenOptions::new();
        o.read(true).append(true).create_new(create);
        #[cfg(unix)]
        o.mode(0o600);
        let file = match o.open(path) {
            Ok(f) => f,
            Err(e) => {
                let _ = fs::remove_file(&lock);
                return Err(e.into());
            }
        };
        let mut j = Self {
            file: Some(file),
            lock,
            clock,
            start: now,
            last: now,
            recovered: false,
            failed: false,
            rows: 0,
            size: 0,
            seen: HashMap::new(),
        };
        let opened = (|| -> Result<()> {
            let f = j.file.as_mut().ok_or_else(bad)?;
            if create {
                f.write_all(HEADER)?;
                f.sync_all()?;
                File::open(
                    path.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                )?
                .sync_all()?;
            }
            f.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            f.take(1048577).read_to_end(&mut bytes)?;
            if bytes.len() > 1048576 || !bytes.starts_with(HEADER) || !bytes.ends_with(b"\n") {
                return Err(bad());
            }
            let mut previous = 0;
            for line in bytes[HEADER.len()..].split_inclusive(|b| *b == b'\n') {
                let line = &line[..line.len() - 1];
                let v: Row = serde_json::from_slice(line).map_err(|_| bad())?;
                if serde_json::to_vec(&v).map_err(|_| bad())? != line
                    || !v.valid()
                    || v.at < previous
                    || v.at > now.unix
                    || j.rows >= 4096
                    || j.duplicate(&v, v.at)
                {
                    return Err(bad());
                }
                previous = v.at;
                j.remember(&v);
                j.rows += 1;
            }
            j.size = bytes.len();
            j.recovered = j.rows > 0;
            Ok(())
        })();
        if let Err(e) = opened {
            let _ = j.close();
            return Err(e);
        }
        Ok(j)
    }
    fn sample(&mut self) -> Result<Stamp> {
        if self.failed || self.file.is_none() {
            return Err(bad());
        }
        let t = match self.clock.now() {
            Ok(v) => v,
            Err(e) => {
                self.failed = true;
                return Err(e);
            }
        };
        if t.unix < self.last.unix || t.mono_ms < self.last.mono_ms || t.unix > 9007199254740000 {
            self.failed = true;
            return Err(bad());
        }
        self.last = t;
        Ok(t)
    }
    fn ready_at(&self, t: Stamp) -> bool {
        self.recovered
            || (t.unix - self.start.unix >= 360 && t.mono_ms - self.start.mono_ms >= 360000)
    }
    /// Sample trusted clock and report admission readiness without peer overrides.
    pub fn ready(&mut self) -> bool {
        self.sample().is_ok_and(|t| self.ready_at(t))
    }
    fn duplicate(&self, v: &Row, at: i64) -> bool {
        v.keys().iter().any(|k| {
            self.seen
                .get(k)
                .is_some_and(|until| k[2] == "context" || at <= *until)
        })
    }
    fn remember(&mut self, v: &Row) {
        for k in v.keys() {
            self.seen.insert(k, v.expires + 30);
        }
    }
    fn stage(&mut self, v: Replay010) -> Result<()> {
        let now = self.sample()?;
        if !self.ready_at(now) {
            return Err(bad());
        }
        let row = Row {
            at: now.unix,
            sender: v.sender,
            recipient: v.recipient,
            id: v.id,
            nonce: v.nonce,
            context: v.context,
            expires: v.expires,
        };
        if !row.valid() || self.rows >= 4096 || self.duplicate(&row, now.unix) {
            return Err(bad());
        }
        let mut data = serde_json::to_vec(&row).map_err(|_| bad())?;
        data.push(b'\n');
        if self.size + data.len() > 1048576 {
            return Err(bad());
        }
        self.failed = true;
        let f = self.file.as_mut().ok_or_else(bad)?;
        f.write_all(&data)?;
        f.sync_all()?;
        self.remember(&row);
        self.rows += 1;
        self.size += data.len();
        self.failed = false;
        self.sample()?;
        Ok(())
    }
    /// Clean close releases the exclusive lock. Unclean process exit does not.
    pub fn close(&mut self) -> Result<()> {
        if let Some(f) = self.file.take() {
            drop(f);
            fs::remove_file(&self.lock)?;
        }
        Ok(())
    }
}
impl ReplayStore010 for ReplayJournal010 {
    fn reserve(&mut self, v: Replay010) -> Result<()> {
        self.stage(v)
    }
    fn reserve_record(
        &mut self,
        v: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if !v.context.is_empty() {
            return Err(bad());
        }
        self.stage(v)?;
        validate()
    }
}
// Deliberately no Drop unlink: explicit close proves clean ownership release.

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[derive(Clone)]
    struct Time(Rc<RefCell<Stamp>>);
    impl Clock for Time {
        fn now(&mut self) -> Result<Stamp> {
            Ok(*self.0.borrow())
        }
    }
    fn entry(v: &serde_json::Value) -> Replay010 {
        let text = |k: &str, default: &str| v[k].as_str().unwrap_or(default).to_owned();
        Replay010 {
            sender: "alice".into(),
            recipient: text("recipient", "bob"),
            id: text("id", "id"),
            nonce: text("nonce", "nonce"),
            context: text("context", ""),
            expires: v["expires"].as_i64().unwrap_or(760),
        }
    }
    #[test]
    fn vectors() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/replay-journal010.json"
        ))
        .unwrap();
        for case in f["cases"].as_array().unwrap() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("replay");
            let time = Time(Rc::new(RefCell::new(Stamp {
                unix: 0,
                mono_ms: 0,
            })));
            let mut store: Option<ReplayJournal010> = None;
            for (i, s) in case["steps"].as_array().unwrap().iter().enumerate() {
                *time.0.borrow_mut() = Stamp {
                    unix: s["unix"].as_i64().unwrap(),
                    mono_ms: s["mono_ms"].as_i64().unwrap(),
                };
                let mut calls = 0;
                let ok = match s["action"].as_str().unwrap() {
                    "open" => {
                        let r = ReplayJournal010::open(
                            &path,
                            s["create"].as_bool().unwrap_or(false),
                            Box::new(time.clone()),
                        );
                        let ok = r.is_ok();
                        store = r.ok();
                        ok
                    }
                    "close" => store.as_mut().unwrap().close().is_ok(),
                    "ready" => store.as_mut().unwrap().ready(),
                    "reserve" => store.as_mut().unwrap().reserve(entry(s)).is_ok(),
                    "record" => store
                        .as_mut()
                        .unwrap()
                        .reserve_record(entry(s), &mut || {
                            calls += 1;
                            if s["gate"].as_bool().unwrap_or(false) {
                                Ok(())
                            } else {
                                Err(bad())
                            }
                        })
                        .is_ok(),
                    _ => panic!("action"),
                };
                assert_eq!(ok, s["ok"].as_bool().unwrap(), "{} step {}", case["id"], i);
                assert_eq!(calls, s["calls"].as_u64().unwrap_or(0));
            }
            if let Some(mut j) = store {
                j.close().unwrap();
            }
        }
    }
    #[test]
    fn faults() {
        for kind in ["lock", "partial", "blank", "capacity", "io"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("replay");
            let time = Time(Rc::new(RefCell::new(Stamp {
                unix: 100,
                mono_ms: 0,
            })));
            let mut j = ReplayJournal010::open(&path, true, Box::new(time.clone())).unwrap();
            *time.0.borrow_mut() = Stamp {
                unix: 460,
                mono_ms: 360000,
            };
            match kind {
                "lock" => {
                    assert!(ReplayJournal010::open(&path, false, Box::new(time.clone())).is_err())
                }
                "partial" | "blank" => {
                    j.close().unwrap();
                    OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(if kind == "partial" { b"{" } else { b"\n" })
                        .unwrap();
                    assert!(ReplayJournal010::open(&path, false, Box::new(time.clone())).is_err());
                }
                "capacity" => {
                    j.rows = 4096;
                    assert!(j.reserve(entry(&serde_json::json!({}))).is_err());
                }
                "io" => {
                    j.file = Some(File::open(&path).unwrap());
                    let mut calls = 0;
                    assert!(j
                        .reserve_record(entry(&serde_json::json!({})), &mut || {
                            calls += 1;
                            Ok(())
                        })
                        .is_err());
                    assert_eq!(calls, 0);
                    assert!(j.failed);
                }
                _ => unreachable!(),
            }
            j.close().unwrap();
        }
    }
}

// A caller can retain this handle, pass Box::new(handle.clone()) to endpoints,
// then explicitly close the journal after all endpoints/sessions are closed.
impl ReplayStore010 for std::rc::Rc<std::cell::RefCell<ReplayJournal010>> {
    fn reserve(&mut self, v: Replay010) -> Result<()> {
        self.try_borrow_mut().map_err(|_| bad())?.reserve(v)
    }
    fn reserve_record(
        &mut self,
        v: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.try_borrow_mut()
            .map_err(|_| bad())?
            .reserve_record(v, validate)
    }
}
