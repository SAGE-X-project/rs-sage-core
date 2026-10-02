use super::*;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Controls(Rc<RefCell<(Value, usize)>>);
impl Clock for Controls {
    fn now(&mut self) -> Result<Stamp> {
        let mut c = self.0.borrow_mut();
        if c.0["clock_ok"] != true {
            return Err(unreachable());
        }
        let times = c.0["times"].as_array().ok_or_else(unreachable)?;
        let t = times
            .get(c.1.min(times.len().saturating_sub(1)))
            .ok_or_else(unreachable)?;
        let stamp = Stamp {
            mono_ms: t["mono_ms"].as_i64().unwrap(),
            unix: t["unix"].as_i64().unwrap(),
        };
        c.1 += 1;
        Ok(stamp)
    }
}
impl Source for Controls {
    fn read(&mut self, _: &str) -> Result<Snapshot> {
        let c = self.0.borrow();
        if c.0["source_ok"] != true {
            return Err(unreachable());
        }
        serde_json::from_value(c.0["snapshot"].clone()).map_err(|_| rejected())
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/registry010.json")).unwrap()
}
fn config(v: &Value) -> Config {
    Config {
        source: v["source"].as_str().unwrap().into(),
        registry: v["registry"].as_str().unwrap().into(),
        network: v["network"].as_str().unwrap().into(),
        blockchain: v["blockchain"].as_bool().unwrap(),
    }
}
#[test]
fn independent_scenarios() {
    let f = fixture();
    assert_eq!(f["cases"].as_array().unwrap().len(), 39);
    for case in f["cases"].as_array().unwrap() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state");
        let mut journal = Arc::new(Mutex::new(Journal::open(&path, true).unwrap()));
        let control = Controls(Rc::new(RefCell::new((Value::Null, 0))));
        let cfg = config(&f["config"]);
        let make = |j: Arc<Mutex<Journal>>| {
            Gate::new(
                cfg.clone(),
                Box::new(control.clone()),
                Box::new(control.clone()),
                Box::new(j),
            )
            .unwrap()
        };
        let mut gate = make(journal.clone());
        let mut pinned = None;
        for step in case["steps"].as_array().unwrap() {
            let q = &step["request"];
            *control.0.borrow_mut() = (q.clone(), 0);
            let mut out = json!({});
            let did = q["did"].as_str().unwrap_or("");
            let result = match q["action"].as_str().unwrap() {
                "observe" => gate.observe(did).map(|s| {out = json!({"state": s.state, "version": s.version});}),
                "select" => gate.select(did, q["signing_url"].as_str().unwrap(), q["require_kem"].as_bool().unwrap()).map(|p| {
                    out = json!({"signing_keyid": format!("{}#{}",p.did(),p.signing().name),
                        "kem_keyid": p.kem().map(|k|format!("{}#{}",p.did(),k.name)).unwrap_or_default()}); pinned = Some(p);
                }),
                "check" => pinned.as_ref().ok_or_else(rejected).and_then(|p|gate.check_pinned(p)).map(|()| {out=json!({"valid":true});}),
                "inspect" => {
                    let w=journal.lock().unwrap().get(&Scope{registry:cfg.registry.clone(),did:did.into()});
                    out=json!({"highest_finalized_version":w.as_ref().map(|w|w.version.to_string()).unwrap_or_else(||"0".into()),
                        "tombstone":w.is_some_and(|w|w.terminal)}); Ok(())
                },
                "restart" => {journal.lock().unwrap().close().unwrap();journal=Arc::new(Mutex::new(Journal::open(&path,false).unwrap()));gate=make(journal.clone());pinned=None;Ok(())},
                _ => panic!("unknown action"),
            };
            let verdict = if result.is_ok() {
                "ACCEPT"
            } else {
                out = json!({});
                "REJECT"
            };
            assert_eq!(
                json!({"verdict":verdict,"output":out}),
                step["expected"],
                "{}: {} {:?}",
                case["id"],
                q["action"],
                result.err()
            );
        }
        journal.lock().unwrap().close().unwrap();
    }
}
#[test]
fn journal_rejects_second_writer_partial_and_missing_state() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("state");
    let mut j = Journal::open(&path, true).unwrap();
    assert!(Journal::open(&path, false).is_err());
    let scope = Scope {
        registry: "r".into(),
        did: "d".into(),
    };
    j.advance(scope.clone(), 2, "aa".repeat(32), false).unwrap();
    j.close().unwrap();
    let mut j = Journal::open(&path, false).unwrap();
    assert!(j.advance(scope.clone(), 1, "aa".repeat(32), false).is_err());
    j.close().unwrap();
    assert!(j.advance(scope, 3, "aa".repeat(32), false).is_err());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"scope\":")
        .unwrap();
    assert!(Journal::open(&path, false).is_err());
    assert!(Journal::open(&tmp.path().join("missing"), false).is_err());
}
#[test]
fn blank_journal_row_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("state");
    Journal::open(&path, true).unwrap().close().unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(Journal::open(&path, false).is_err());
}

#[test]
fn rejects_noncanonical_identity_before_source_read() {
    #[derive(Clone)]
    struct Counter(Rc<RefCell<(usize, usize)>>);
    impl Clock for Counter {
        fn now(&mut self) -> Result<Stamp> {
            self.0.borrow_mut().0 += 1;
            Ok(Stamp {
                mono_ms: 1,
                unix: 1,
            })
        }
    }
    impl Source for Counter {
        fn read(&mut self, _: &str) -> Result<Snapshot> {
            self.0.borrow_mut().1 += 1;
            Err(unreachable())
        }
    }
    let valid = "did:sage:eip155:1:0xabababababababababababababababababababab:alice";
    let registry = "eip155:1:0xabababababababababababababababababababab";
    for (name, identity, key_url, observe) in [
        ("legacy kind", "did:sage:chain:x:alice", "", true),
        (
            "noncanonical chain",
            "did:sage:eip155:01:0xabababababababababababababababababababab:alice",
            "",
            true,
        ),
        (
            "different registry",
            "did:sage:web:agents.example.com:alice",
            "",
            true,
        ),
        ("missing fragment", valid, valid, false),
        (
            "extra fragment",
            valid,
            "did:sage:eip155:1:0xabababababababababababababababababababab:alice#signing-1#other",
            false,
        ),
        (
            "other sender",
            valid,
            "did:sage:eip155:1:0xabababababababababababababababababababab:bob#signing-1",
            false,
        ),
    ] {
        let counts = Rc::new(RefCell::new((0, 0)));
        let counter = Counter(counts.clone());
        let temp = tempfile::tempdir().unwrap();
        let mut gate = Gate::new(
            Config {
                source: "fixture".into(),
                registry: registry.into(),
                network: "1".into(),
                blockchain: true,
            },
            Box::new(counter.clone()),
            Box::new(counter),
            Box::new(Journal::open(&temp.path().join("state"), true).unwrap()),
        )
        .unwrap();
        let error = if observe {
            gate.observe(identity).err()
        } else {
            gate.select(identity, key_url, false).err()
        };
        assert!(
            error.is_some_and(|e| e.to_string().contains("record.rejected")),
            "{name}"
        );
        assert_eq!(*counts.borrow(), (0, 0), "{name}");
    }
    for registry in [
        "eip155:01:0xabababababababababababababababababababab",
        "web:Agents.example.com",
        "solana:mainnet",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let counter = Counter(Rc::new(RefCell::new((0, 0))));
        let gate = Gate::new(
            Config {
                source: "fixture".into(),
                registry: registry.into(),
                network: "local".into(),
                blockchain: false,
            },
            Box::new(counter.clone()),
            Box::new(counter),
            Box::new(Journal::open(&temp.path().join("state"), true).unwrap()),
        );
        assert!(gate.is_err(), "{registry}");
    }
}
