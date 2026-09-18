use super::dispatch::*;
use super::fixtures_test::Fixture;
use super::*;
use std::fs;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

fn fixture() -> Value {
    let suite: Value = serde_json::from_str(include_str!("testdata/guard-records.json")).unwrap();
    suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "intent-valid")
        .unwrap()["input"]
        .clone()
}
fn raw() -> Vec<u8> {
    hex::decode(text(&fixture(), "envelope_hex")).unwrap()
}
struct Services {
    fixture: Fixture,
    keys: usize,
    policies: usize,
    clocks: usize,
    fail_key: usize,
    fail_policy: usize,
    expire: usize,
}
impl Services {
    fn new(fail_key: usize, fail_policy: usize, expire: usize) -> Self {
        Self {
            fixture: Fixture(fixture()),
            keys: 0,
            policies: 0,
            clocks: 0,
            fail_key,
            fail_policy,
            expire,
        }
    }
}
impl Authority for Services {
    fn now(&mut self) -> Result<i64> {
        self.clocks += 1;
        if self.clocks == self.expire {
            Ok(1700000300)
        } else {
            self.fixture.now()
        }
    }
    fn active_key(&mut self, i: &str, k: &str) -> Result<[u8; 32]> {
        self.keys += 1;
        ensure(self.keys != self.fail_key)?;
        self.fixture.active_key(i, k)
    }
}
impl IntentPolicy for Services {
    fn bindings(&mut self, i: &str, r: &str) -> Result<Bindings> {
        self.fixture.bindings(i, r)
    }
    fn authorize(&mut self, i: &str, t: &str, a: &[u8]) -> Result<()> {
        self.policies += 1;
        ensure(self.policies != self.fail_policy)?;
        self.fixture.authorize(i, t, a)
    }
}
#[derive(Default)]
struct Observed {
    completion: Option<Completion>,
    commits: usize,
    checks: usize,
    envelope: Vec<u8>,
    arguments: Vec<u8>,
    digest: String,
}
struct Sink {
    path: std::path::PathBuf,
    observed: Arc<Mutex<Observed>>,
    fail_check: usize,
    panic_check: usize,
    fail_commit: bool,
    panic_commit: bool,
    block: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}
impl Sink {
    fn new(path: &std::path::Path, observed: Arc<Mutex<Observed>>) -> Self {
        Self {
            path: path.into(),
            observed,
            fail_check: 0,
            panic_check: 0,
            fail_commit: false,
            panic_commit: false,
            block: None,
        }
    }
}
impl Component for Sink {
    fn check(&mut self, manifest: &str, tool: &str) -> Result<()> {
        let count = {
            let mut o = self.observed.lock().unwrap();
            o.checks += 1;
            o.checks
        };
        assert_ne!(count, self.panic_check, "fixture check uncertainty");
        ensure(count != self.fail_check)?;
        let bytes = serde_json::to_vec(&fixture()["approved_manifest"]).unwrap();
        let digest = verify_manifest(
            &bytes,
            &[
                Artifact {
                    path: "engine.bin".into(),
                    bytes: b"public pinned evaluator".to_vec(),
                },
                Artifact {
                    path: "rules.json".into(),
                    bytes: br#"{"allow":["read"]}"#.to_vec(),
                },
            ],
        )?;
        ensure(digest == manifest && tool == "read")
    }
    fn commit(&mut self, i: &Invocation) -> Result<()> {
        let bytes = fs::read_to_string(&self.path).unwrap();
        let row: Value = serde_json::from_str(bytes.lines().last().unwrap()).unwrap();
        ensure(row["state"] == "EXECUTING")?;
        {
            let mut o = self.observed.lock().unwrap();
            o.commits += 1;
            o.completion = Some(i.completion());
            o.envelope = i.canonical_intent().into();
            o.arguments = i.arguments().into();
            o.digest = i.intent_digest().into();
        }
        ensure(
            i.tool() == "read"
                && i.manifest_digest()
                    == text(
                        &serde_json::from_slice::<Value>(&raw()).unwrap()["intent"],
                        "manifest_digest",
                    ),
        )?;
        if let Some((entered, release)) = &self.block {
            entered.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        assert!(!self.panic_commit, "fixture commit uncertainty");
        ensure(!self.fail_commit)
    }
}
fn open(path: &std::path::Path, a: Services, p: Services, s: Sink) -> DispatchGate {
    DispatchGate::open(
        path,
        true,
        text(&fixture(), "expected_recipient"),
        Box::new(a),
        Box::new(p),
        Box::new(s),
    )
    .unwrap()
}
fn state(path: &std::path::Path) -> String {
    let text = fs::read_to_string(path).unwrap();
    let line = text.lines().last().unwrap();
    if line.starts_with("sage-") {
        return String::new();
    };
    serde_json::from_str::<Value>(line).unwrap()["state"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn dispatch_exactly_once_and_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let o = Arc::new(Mutex::new(Observed::default()));
    let gate = open(
        &path,
        Services::new(0, 0, 0),
        Services::new(0, 0, 0),
        Sink::new(&path, o.clone()),
    );
    let r = gate.dispatch(&raw()).unwrap();
    assert!(r.created() && r.committed());
    assert_eq!(r.state(), "EXECUTING");
    {
        let o = o.lock().unwrap();
        assert_eq!(o.commits, 1);
        assert_eq!(o.checks, 2);
        assert_eq!(o.envelope, raw());
        assert_eq!(o.arguments, br#"{"path":"public.txt"}"#);
        assert_eq!(o.digest, r.intent_digest());
    }
    let before = fs::read(&path).unwrap();
    let r = gate.dispatch(&raw()).unwrap();
    assert!(!r.created() && !r.committed());
    assert_eq!(before, fs::read(&path).unwrap());
    gate.close().unwrap();
    let o2 = Arc::new(Mutex::new(Observed::default()));
    let recovered = DispatchGate::open(
        &path,
        false,
        text(&fixture(), "expected_recipient"),
        Box::new(Services::new(0, 0, 0)),
        Box::new(Services::new(0, 0, 0)),
        Box::new(Sink::new(&path, o2.clone())),
    )
    .unwrap();
    let r = recovered.dispatch(&raw()).unwrap();
    assert_eq!(r.state(), "UNKNOWN");
    assert!(!r.committed());
    assert_eq!(o2.lock().unwrap().commits, 0);
    recovered.close().unwrap();
}
#[test]
fn final_denials_and_commit_uncertainty_never_retry() {
    for kind in [
        "key",
        "policy",
        "expiry",
        "component",
        "panic-check",
        "commit-error",
        "commit-panic",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let o = Arc::new(Mutex::new(Observed::default()));
        let mut sink = Sink::new(&path, o.clone());
        let a = Services::new(
            if kind == "key" { 2 } else { 0 },
            0,
            if kind == "expiry" { 7 } else { 0 },
        );
        let p = Services::new(0, if kind == "policy" { 2 } else { 0 }, 0);
        match kind {
            "component" => sink.fail_check = 2,
            "panic-check" => sink.panic_check = 2,
            "commit-error" => sink.fail_commit = true,
            "commit-panic" => sink.panic_commit = true,
            _ => (),
        }
        let gate = open(&path, a, p, sink);
        assert!(gate.dispatch(&raw()).is_err(), "{kind}");
        assert_eq!(state(&path), "UNKNOWN", "{kind}");
        let count = usize::from(kind.starts_with("commit-"));
        assert_eq!(o.lock().unwrap().commits, count, "{kind}");
        let r = gate.dispatch(&raw());
        if kind.contains("panic") {
            assert!(r.is_err())
        } else {
            let r = r.unwrap();
            assert_eq!(r.state(), "UNKNOWN");
            assert!(!r.committed())
        };
        assert_eq!(o.lock().unwrap().commits, count);
        gate.close().unwrap();
    }
}
#[test]
fn retirement_and_replacement_serialize_with_commit() {
    for replace in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let o = Arc::new(Mutex::new(Observed::default()));
        let mut sink = Sink::new(&path, o.clone());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        sink.block = Some((entered_tx, release_rx));
        let gate = Arc::new(open(
            &path,
            Services::new(0, 0, 0),
            Services::new(0, 0, 0),
            sink,
        ));
        let g = gate.clone();
        let dispatch = std::thread::spawn(move || g.dispatch(&raw()).unwrap().committed());
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let g = gate.clone();
        let replacement = Arc::new(Mutex::new(Observed::default()));
        let sink = Sink::new(&path, replacement.clone());
        let update = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let r = if replace {
                g.replace(
                    Box::new(Services::new(0, 0, 0)),
                    Box::new(Services::new(0, 0, 0)),
                    Box::new(sink),
                )
            } else {
                g.retire()
            };
            done_tx.send(r).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
        release_tx.send(()).unwrap();
        assert!(dispatch.join().unwrap());
        done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        update.join().unwrap();
        let r = gate.dispatch(&raw());
        if replace {
            assert!(!r.unwrap().committed())
        } else {
            assert!(r.is_err());
            assert!(gate
                .replace(
                    Box::new(Services::new(0, 0, 0)),
                    Box::new(Services::new(0, 0, 0)),
                    Box::new(Sink::new(&path, replacement.clone()))
                )
                .is_err())
        };
        assert_eq!(o.lock().unwrap().commits, 1);
        assert_eq!(replacement.lock().unwrap().commits, 0);
        gate.close().unwrap();
    }
}
#[test]
fn early_retirement_component_denial_and_replacement_have_zero_effects() {
    for kind in ["retire", "component", "replace", "closed"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let o = Arc::new(Mutex::new(Observed::default()));
        let mut sink = Sink::new(&path, o.clone());
        if kind == "component" {
            sink.fail_check = 1
        };
        let gate = open(&path, Services::new(0, 0, 0), Services::new(0, 0, 0), sink);
        match kind {
            "retire" => gate.retire().unwrap(),
            "replace" => gate
                .replace(
                    Box::new(Services::new(0, 0, 0)),
                    Box::new(Services::new(0, 1, 0)),
                    Box::new(Sink::new(&path, o.clone())),
                )
                .unwrap(),
            "closed" => gate.close().unwrap(),
            _ => (),
        }
        let before = fs::read(&path).unwrap();
        assert!(gate.dispatch(&raw()).is_err());
        assert_eq!(o.lock().unwrap().commits, 0);
        assert_eq!(before, fs::read(&path).unwrap());
        gate.close().unwrap();
    }
}
#[test]
fn concurrent_identical_dispatches_commit_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let o = Arc::new(Mutex::new(Observed::default()));
    let gate = Arc::new(open(
        &path,
        Services::new(0, 0, 0),
        Services::new(0, 0, 0),
        Sink::new(&path, o.clone()),
    ));
    let joins: Vec<_> = (0..16)
        .map(|_| {
            let g = gate.clone();
            std::thread::spawn(move || g.dispatch(&raw()).unwrap().committed())
        })
        .collect();
    assert_eq!(
        joins
            .into_iter()
            .map(|j| usize::from(j.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(o.lock().unwrap().commits, 1);
    gate.close().unwrap();
}

#[test]
fn independent_intent_denials_never_commit() {
    let suite: Value = serde_json::from_str(include_str!("testdata/guard-records.json")).unwrap();
    for case in suite["cases"].as_array().unwrap() {
        if case["operation"] != "sage.guard.intent.verify" {
            continue;
        };
        let f = &case["input"];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let o = Arc::new(Mutex::new(Observed::default()));
        let gate = DispatchGate::open(
            &path,
            true,
            text(f, "expected_recipient"),
            Box::new(Fixture(f.clone())),
            Box::new(Fixture(f.clone())),
            Box::new(Sink::new(&path, o.clone())),
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let r = gate.dispatch(&hex::decode(text(f, "envelope_hex")).unwrap());
        if case["expected"]["verdict"] == "ACCEPT" {
            assert!(r.unwrap().committed());
            assert_eq!(o.lock().unwrap().commits, 1)
        } else {
            assert!(r.is_err(), "{}", case["id"]);
            assert_eq!(o.lock().unwrap().commits, 0);
            assert_eq!(before, fs::read(&path).unwrap())
        };
        gate.close().unwrap();
    }
}

#[test]
fn storage_capacity_failure_retires_gate() {
    for rows in [4094, 4095] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut bytes = b"sage-execution-ledger|0.10.0\n".to_vec();
        // Owned offline storage fixture; these opaque terminal bytes are not signed results.
        for n in 0..rows {
            let e = crate::execution010::Entry {
                issuer: "fixture".into(),
                recipient: "fixture".into(),
                call_id: n.to_string(),
                nonce: n.to_string(),
                expires: 1700000300,
                intent_hex: "7b7d".into(),
                state: "REJECTED".into(),
                result_hex: "7b7d".into(),
            };
            bytes.extend_from_slice(serde_json::to_string(&e).unwrap().as_bytes());
            bytes.push(b'\n');
        }
        fs::write(&path, bytes).unwrap();
        let o = Arc::new(Mutex::new(Observed::default()));
        let mut sink = Sink::new(&path, o.clone());
        if rows == 4094 {
            sink.fail_check = 2
        };
        let gate = DispatchGate::open(
            &path,
            false,
            text(&fixture(), "expected_recipient"),
            Box::new(Services::new(0, 0, 0)),
            Box::new(Services::new(0, 0, 0)),
            Box::new(sink),
        )
        .unwrap();
        assert!(gate.dispatch(&raw()).is_err());
        assert_eq!(o.lock().unwrap().commits, 0);
        let before = fs::read(&path).unwrap();
        assert!(gate
            .replace(
                Box::new(Services::new(0, 0, 0)),
                Box::new(Services::new(0, 0, 0)),
                Box::new(Sink::new(&path, o.clone()))
            )
            .is_err());
        assert!(gate.dispatch(&raw()).is_err());
        assert_eq!(before, fs::read(&path).unwrap());
        assert_eq!(o.lock().unwrap().commits, 0);
        gate.close().unwrap();
    }
}

mod publication_tests;
