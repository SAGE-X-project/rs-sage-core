use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(Clone)]
struct Signing {
    now: i64,
    active: bool,
    fail: bool,
    corrupt: bool,
    kid: String,
    signs: Arc<AtomicUsize>,
    clocks: usize,
    expire_at: usize,
}
fn signer() -> Signing {
    Signing {
        now: 1700000000,
        active: true,
        fail: false,
        corrupt: false,
        kid: "did:sage:web:agents.example.com:executor#signing-1".into(),
        signs: Arc::new(AtomicUsize::new(0)),
        clocks: 0,
        expire_at: 0,
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(b"public Guard fixture executor").into())
}
impl Authority for Signing {
    fn now(&mut self) -> Result<i64> {
        self.clocks += 1;
        Ok(if self.clocks == self.expire_at {
            self.now + 300
        } else {
            self.now
        })
    }
    fn active_key(&mut self, i: &str, k: &str) -> Result<[u8; 32]> {
        ensure(self.active && i == "did:sage:web:agents.example.com:executor" && k == self.kid)?;
        Ok(key().verifying_key().to_bytes())
    }
}
impl ResultSigner for Signing {
    fn key_id(&mut self) -> Result<String> {
        Ok(self.kid.clone())
    }
    fn sign(&mut self, kid: &str, b: &[u8]) -> Result<Vec<u8>> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        ensure(!self.fail && kid == self.kid)?;
        let mut p = key().sign(b).to_bytes().to_vec();
        if self.corrupt {
            p[0] ^= 1
        };
        Ok(p)
    }
}
fn count(s: &Signing) -> usize {
    s.signs.load(Ordering::SeqCst)
}
fn setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    DispatchGate,
    Arc<Mutex<Observed>>,
) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("journal");
    let o = Arc::new(Mutex::new(Observed::default()));
    let g = open(
        &p,
        Services::new(0, 0, 0),
        Services::new(0, 0, 0),
        Sink::new(&p, o.clone()),
    );
    (d, p, g, o)
}
fn token(o: &Arc<Mutex<Observed>>) -> Completion {
    o.lock().unwrap().completion.clone().unwrap()
}
fn status(b: &[u8]) -> String {
    serde_json::from_slice::<Value>(b).unwrap()["result"]["status"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn pending_then_finish_is_one_reply_and_terminal_is_immutable() {
    let (_d, p, g, o) = setup();
    let mut r = g.dispatch(&raw()).unwrap();
    let mut s = signer();
    assert_eq!(status(&g.reply(&mut r, &mut s).unwrap()), "pending");
    assert!(g.reply(&mut r, &mut s).is_err());
    g.finish(&token(&o), br#"{"value":"ok"}"#, &mut s).unwrap();
    assert!(g.reply(&mut r, &mut s).is_err());
    let b = g.reply(&mut g.dispatch(&raw()).unwrap(), &mut s).unwrap();
    assert_eq!(status(&b), "completed");
    let before = fs::read(&p).unwrap();
    let n = count(&s);
    g.finish(&token(&o), b"{\n\"value\":\"ok\"}", &mut s)
        .unwrap();
    assert_eq!(
        b,
        g.reply(&mut g.dispatch(&raw()).unwrap(), &mut s).unwrap()
    );
    assert_eq!(count(&s), n);
    assert_eq!(before, fs::read(&p).unwrap());
    assert!(g
        .finish(&token(&o), br#"{"value":"other"}"#, &mut s)
        .is_err());
    assert_eq!(o.lock().unwrap().commits, 1);
    g.close().unwrap();
}
#[test]
fn late_accepted_response_and_expired_new_retrieval() {
    let (_d, _p, g, o) = setup();
    let mut r = g.dispatch(&raw()).unwrap();
    let mut s = signer();
    s.now = 1700000301;
    let mut late = fixture();
    late["now"] = json!(1700000301);
    g.replace(
        Box::new(Fixture(late.clone())),
        Box::new(Fixture(late)),
        Box::new(Sink::new(&_p, o.clone())),
    )
    .unwrap();
    g.finish(&token(&o), br#"{"late":true}"#, &mut s).unwrap();
    assert_eq!(status(&g.reply(&mut r, &mut s).unwrap()), "completed");
    assert!(g.dispatch(&raw()).is_err());
    g.close().unwrap();
}
#[test]
fn signer_failures_never_replace_terminal_bytes() {
    for kind in ["unavailable", "wrong-key", "corrupt", "revoked", "expired"] {
        let (_d, p, g, o) = setup();
        let mut r = g.dispatch(&raw()).unwrap();
        let mut s = signer();
        if matches!(kind, "revoked" | "expired") {
            g.finish(&token(&o), b"{}", &mut s).unwrap();
            let before = fs::read(&p).unwrap();
            let n = count(&s);
            if kind == "revoked" {
                s.active = false
            } else {
                s.now += 300
            };
            assert!(g.reply(&mut r, &mut s).is_err());
            assert_eq!(count(&s), n);
            assert_eq!(before, fs::read(&p).unwrap());
        } else {
            match kind {
                "unavailable" => s.fail = true,
                "wrong-key" => s.kid = "did:sage:web:agents.example.com:other#signing-1".into(),
                "corrupt" => s.corrupt = true,
                _ => (),
            };
            let before = fs::read(&p).unwrap();
            assert!(g.finish(&token(&o), b"{}", &mut s).is_err());
            assert_eq!(before, fs::read(&p).unwrap());
            s.fail = false;
            s.corrupt = false;
            s.kid = signer().kid;
            g.finish(&token(&o), b"{}", &mut s).unwrap();
        };
        g.close().unwrap();
    }
}
#[test]
fn expiry_during_storage_keeps_terminal_without_refresh() {
    let (_d, p, g, o) = setup();
    let mut r = g.dispatch(&raw()).unwrap();
    let mut s = signer();
    s.expire_at = 5;
    assert!(g.finish(&token(&o), b"{}", &mut s).is_err());
    assert_eq!(state(&p), "COMPLETED");
    let before = fs::read(&p).unwrap();
    s.now += 300;
    s.expire_at = 0;
    assert!(g.reply(&mut r, &mut s).is_err());
    assert_eq!(count(&s), 1);
    assert_eq!(before, fs::read(&p).unwrap());
    g.close().unwrap();
}
#[test]
fn rejection_reserves_identity_and_never_overwrites_execution() {
    let (_d, p, g, o) = setup();
    let mut s = signer();
    let mut r = g.reject(&raw(), &mut s).unwrap();
    let b = g.reply(&mut r, &mut s).unwrap();
    assert_eq!(status(&b), "rejected");
    let before = fs::read(&p).unwrap();
    assert_eq!(
        b,
        g.reply(&mut g.dispatch(&raw()).unwrap(), &mut s).unwrap()
    );
    assert_eq!(count(&s), 1);
    assert_eq!(o.lock().unwrap().commits, 0);
    assert_eq!(before, fs::read(&p).unwrap());
    g.close().unwrap();
    let (_d, p, g, o) = setup();
    g.dispatch(&raw()).unwrap();
    let before = fs::read(&p).unwrap();
    assert!(g.reject(&raw(), &mut s).is_err());
    assert_eq!(before, fs::read(&p).unwrap());
    assert_eq!(o.lock().unwrap().commits, 1);
    g.close().unwrap();
}
#[test]
fn unknown_recovery_and_foreign_tokens_fail_closed() {
    let (_d, p, g, o) = setup();
    let mut old = g.dispatch(&raw()).unwrap();
    let t = token(&o);
    g.close().unwrap();
    let recovered = Arc::new(Mutex::new(Observed::default()));
    let g = DispatchGate::open(
        &p,
        false,
        text(&fixture(), "expected_recipient"),
        Box::new(Services::new(0, 0, 0)),
        Box::new(Services::new(0, 0, 0)),
        Box::new(Sink::new(&p, recovered.clone())),
    )
    .unwrap();
    let mut s = signer();
    assert!(g.finish(&t, b"{}", &mut s).is_err());
    assert!(g.reply(&mut old, &mut s).is_err());
    let mut r = g.dispatch(&raw()).unwrap();
    s.fail = true;
    let before = fs::read(&p).unwrap();
    assert!(g.reply(&mut r, &mut s).is_err());
    assert_eq!(before, fs::read(&p).unwrap());
    s.fail = false;
    let b = g.reply(&mut g.dispatch(&raw()).unwrap(), &mut s).unwrap();
    assert_eq!(status(&b), "unknown");
    let n = count(&s);
    assert_eq!(
        b,
        g.reply(&mut g.dispatch(&raw()).unwrap(), &mut s).unwrap()
    );
    assert_eq!(n, count(&s));
    assert_eq!(recovered.lock().unwrap().commits, 0);
    g.close().unwrap();
}
#[test]
fn concurrent_finish_signs_once() {
    let (_d, _p, g, o) = setup();
    g.dispatch(&raw()).unwrap();
    let g = Arc::new(g);
    let s = signer();
    let t = token(&o);
    let joins: Vec<_> = (0..8)
        .map(|_| {
            let g = g.clone();
            let mut s = s.clone();
            let t = t.clone();
            std::thread::spawn(move || g.finish(&t, b"{}", &mut s))
        })
        .collect();
    for j in joins {
        j.join().unwrap().unwrap()
    }
    assert_eq!(count(&s), 1);
    g.close().unwrap();
}

#[test]
fn capacity_cannot_publish_unpersisted_completion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let mut bytes = b"sage-execution-ledger|0.10.0\n".to_vec();
    // Owned offline capacity fixture; opaque filler is not cryptographic evidence.
    for n in 0..4094 {
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
        bytes.extend(serde_json::to_vec(&e).unwrap());
        bytes.push(b'\n');
    }
    fs::write(&path, bytes).unwrap();
    let o = Arc::new(Mutex::new(Observed::default()));
    let gate = DispatchGate::open(
        &path,
        false,
        text(&fixture(), "expected_recipient"),
        Box::new(Services::new(0, 0, 0)),
        Box::new(Services::new(0, 0, 0)),
        Box::new(Sink::new(&path, o.clone())),
    )
    .unwrap();
    let mut receipt = gate.dispatch(&raw()).unwrap();
    let token = o.lock().unwrap().completion.clone().unwrap();
    let before = fs::read(&path).unwrap();
    let mut signer = signer();
    assert!(gate.finish(&token, b"{}", &mut signer).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    if let Ok(result) = gate.reply(&mut receipt, &mut signer) {
        assert_eq!(
            serde_json::from_slice::<Value>(&result).unwrap()["result"]["status"],
            "pending"
        );
    }
    assert!(gate.dispatch(&raw()).is_err());
    gate.close().unwrap();
}
#[test]
fn malformed_output_does_not_sign_or_write() {
    let (dir, _path, gate, o) = setup();
    let _r = gate.dispatch(&raw()).unwrap();
    let token = o.lock().unwrap().completion.clone().unwrap();
    let mut signer = signer();
    let before = fs::read(dir.path().join("journal")).unwrap();
    for output in [
        br"[]".as_slice(),
        br"null",
        br#"{"x":1,"x":2}"#,
        br#"{"x":-0}"#,
    ] {
        assert!(gate.finish(&token, output, &mut signer).is_err());
    }
    assert_eq!(signer.signs.load(Ordering::SeqCst), 0);
    assert_eq!(before, fs::read(dir.path().join("journal")).unwrap());
    gate.close().unwrap();
}

#[test]
fn unknown_and_reject_capacity_never_release_terminal() {
    for unknown in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut bytes = b"sage-execution-ledger|0.10.0\n".to_vec();
        let mut write = |e: crate::execution010::Entry| {
            bytes.extend(serde_json::to_vec(&e).unwrap());
            bytes.push(b'\n');
        };
        for n in 0..if unknown { 4094 } else { 4096 } {
            write(crate::execution010::Entry {
                issuer: "fixture".into(),
                recipient: "fixture".into(),
                call_id: n.to_string(),
                nonce: n.to_string(),
                expires: 1700000300,
                intent_hex: "7b7d".into(),
                state: "REJECTED".into(),
                result_hex: "7b7d".into(),
            });
        }
        if unknown {
            let env: Value = serde_json::from_slice(&raw()).unwrap();
            let i = &env["intent"];
            let mut e = crate::execution010::Entry {
                issuer: text(i, "issuer").into(),
                recipient: text(i, "recipient").into(),
                call_id: text(i, "call_id").into(),
                nonce: text(i, "nonce").into(),
                expires: i["expires"].as_i64().unwrap(),
                intent_hex: hex::encode(raw()),
                state: "RESERVED".into(),
                result_hex: String::new(),
            };
            write(e.clone());
            e.state = "UNKNOWN".into();
            write(e);
        }
        fs::write(&path, bytes).unwrap();
        let o = Arc::new(Mutex::new(Observed::default()));
        let gate = DispatchGate::open(
            &path,
            false,
            text(&fixture(), "expected_recipient"),
            Box::new(Services::new(0, 0, 0)),
            Box::new(Services::new(0, 0, 0)),
            Box::new(Sink::new(&path, o.clone())),
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let mut s = signer();
        if unknown {
            let mut r = gate.dispatch(&raw()).unwrap();
            assert!(gate.reply(&mut r, &mut s).is_err());
        } else {
            assert!(gate.reject(&raw(), &mut s).is_err());
        }
        assert_eq!(before, fs::read(&path).unwrap());
        assert_eq!(o.lock().unwrap().commits, 0);
        gate.close().unwrap();
    }
}
