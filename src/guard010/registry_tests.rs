use super::fixtures_test::Fixture;
use super::*;
use crate::registry010 as r;
use std::sync::{Arc, Mutex};
#[derive(Clone)]
struct Controls(Arc<Mutex<State>>);
struct State {
    snapshot: r::Snapshot,
    mono: i64,
    delay: i64,
    reads: usize,
    fail: bool,
    clock_fail: bool,
    checks: usize,
    effects: usize,
}
impl r::Clock for Controls {
    fn now(&mut self) -> crate::error::Result<r::Stamp> {
        let c = self.0.lock().unwrap();
        if c.clock_fail {
            return Err(r::unreachable());
        }
        Ok(r::Stamp {
            mono_ms: c.mono,
            unix: 1700000000,
        })
    }
}
impl r::Source for Controls {
    fn read(&mut self, _: &str) -> crate::error::Result<r::Snapshot> {
        let mut c = self.0.lock().unwrap();
        c.reads += 1;
        if c.fail {
            return Err(r::unreachable());
        }
        let mut s = c.snapshot.clone();
        s.acquired_ms = c.mono;
        Ok(s)
    }
}
impl r::Store for Controls {
    fn advance(&mut self, _: r::Scope, _: u64, _: String, _: bool) -> crate::error::Result<()> {
        let mut c = self.0.lock().unwrap();
        c.mono += c.delay;
        Ok(())
    }
}
fn setup() -> (RegistryAuthority, Controls, Value) {
    let all: Value = serde_json::from_str(include_str!("testdata/guard-records.json")).unwrap();
    let f = all["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "intent-valid")
        .unwrap()["input"]
        .clone();
    let env: Value =
        serde_json::from_slice(&hex::decode(text(&f, "envelope_hex")).unwrap()).unwrap();
    let issuer = text(&env["intent"], "issuer");
    let kid = text(&env["intent"], "keyid");
    let registry = issuer
        .strip_prefix("did:sage:")
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .0;
    let c = Controls(Arc::new(Mutex::new(State {
        snapshot: r::Snapshot {
            source: "fixture".into(),
            registry: registry.into(),
            network: "fixture".into(),
            did: issuer.into(),
            version: "1".into(),
            state: "active".into(),
            digest: "a".repeat(64),
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: 0,
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys: vec![r::Key {
                name: kid.split_once('#').unwrap().1.into(),
                alg: "ed25519".into(),
                material: text(&f, "public_key_hex").into(),
                state: "accepted".into(),
                expires: None,
            }],
        },
        mono: 100,
        delay: 0,
        reads: 0,
        fail: false,
        clock_fail: false,
        checks: 0,
        effects: 0,
    })));
    let gate = r::SendGate::new_send(
        r::Config {
            source: "fixture".into(),
            registry: registry.into(),
            network: "fixture".into(),
            blockchain: false,
        },
        Box::new(c.clone()),
        Box::new(c.clone()),
        Box::new(c.clone()),
    )
    .unwrap();
    (RegistryAuthority::new(gate, issuer, kid).unwrap(), c, f)
}
struct Sink {
    control: Controls,
    mode: &'static str,
}
impl Component for Sink {
    fn check(&mut self, _: &str, _: &str) -> Result<()> {
        let mut c = self.control.0.lock().unwrap();
        c.checks += 1;
        if c.checks == 2 {
            match self.mode {
                "revoked" => c.snapshot.keys[0].state = "revoked".into(),
                "unready" => c.snapshot.ready = false,
                "source" => c.fail = true,
                "clock" => c.clock_fail = true,
                "stale" => c.delay = 5001,
                "boundary" => c.delay = 5000,
                "rollback" => c.mono = 0,
                _ => (),
            }
        }
        Ok(())
    }
    fn commit(&mut self, i: &Invocation) -> Result<()> {
        ensure(i.arguments() == br#"{"path":"public.txt"}"#)?;
        self.control.0.lock().unwrap().effects += 1;
        Ok(())
    }
}
#[test]
fn registry_authority_fresh_reads_and_pin() {
    let (mut a, c, _) = setup();
    assert!(a.now().is_ok());
    assert!(a.now().is_ok());
    assert_eq!(c.0.lock().unwrap().reads, 2);
    assert!(a.active_key("wrong", "wrong").is_err());
    assert_eq!(c.0.lock().unwrap().reads, 2);
    c.0.lock().unwrap().snapshot.keys[0].material = "00".repeat(32);
    assert!(a.now().is_err());
}
#[test]
fn registry_authority_final_dispatch() {
    for mode in [
        "valid", "boundary", "revoked", "unready", "source", "clock", "stale", "rollback",
    ] {
        let (a, c, f) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let opened = DispatchGate::open(
            &path,
            true,
            text(&f, "expected_recipient"),
            Box::new(a),
            Box::new(Fixture(f.clone())),
            Box::new(Sink {
                control: c.clone(),
                mode,
            }),
        );
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(
                opened.is_err(),
                "unsupported durable storage must deny setup"
            );
            assert_eq!(c.0.lock().unwrap().effects, 0);
            assert!(!path.exists());
            continue;
        }
        let gate = opened.unwrap();
        let result = gate.dispatch(&hex::decode(text(&f, "envelope_hex")).unwrap());
        let want = mode == "valid" || mode == "boundary";
        assert_eq!(result.is_ok(), want, "{mode}");
        let state = c.0.lock().unwrap();
        assert_eq!(state.effects, usize::from(want), "{mode}");
        if want {
            assert!(result.unwrap().committed());
            assert_eq!(state.reads, 9)
        } else {
            let raw = std::fs::read_to_string(&path).unwrap();
            let last: Value = serde_json::from_str(raw.lines().last().unwrap()).unwrap();
            assert_eq!(last["state"], "UNKNOWN")
        };
        gate.close().unwrap();
    }
}
