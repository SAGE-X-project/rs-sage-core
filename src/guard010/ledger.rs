//! Authenticated reservation bridge; no dispatch or result-release authority.
use super::*;
use crate::execution010::{Entry, Ledger};
use std::path::Path;

/// Owns the storage handle. Share under a mutex for concurrent host callers.
/// Each reservation freshly verifies the envelope. No raw Entry API is exposed.
pub struct GuardLedger {
    store: Ledger,
    recipient: String,
}
/// Authenticated storage observation, not execution permission or tool output.
pub struct Reservation {
    created: bool,
    state: String,
    digest: String,
}
impl Reservation {
    /// True only when this operation durably inserted the identity.
    pub fn created(&self) -> bool {
        self.created
    }
    /// Stored state, never a signed protocol result.
    pub fn state(&self) -> &str {
        &self.state
    }
    /// Commitment to the complete canonical authenticated intent.
    pub fn intent_digest(&self) -> &str {
        &self.digest
    }
}
impl GuardLedger {
    /// Initialize only a new isolated scope when create is explicit. Normal reopen
    /// never recreates missing state. Storage paths and initialization are trusted.
    pub fn open(path: &Path, create: bool, recipient: &str) -> Result<Self> {
        ensure(did(recipient))?;
        Ok(Self {
            store: Ledger::open(path, create).map_err(|_| Invalid)?,
            recipient: recipient.into(),
        })
    }
    /// Reauthenticate even existing calls, then atomically reserve call and nonce
    /// or return the unchanged state. Terminal bytes are deliberately not exposed.
    /// This is not a dispatch/retirement gate. Host callbacks need bounded deadlines.
    /// Expiry during storage denies the response but retains any durable reservation.
    pub fn reserve(
        &mut self,
        raw: &[u8],
        a: &mut dyn Authority,
        p: &mut dyn IntentPolicy,
    ) -> Result<Reservation> {
        let verified = verify_intent(raw, &self.recipient, a, p)?;
        let entry = reservation_entry(&verified)?;
        let (stored, created) = self.store.reserve(entry).map_err(|_| Invalid)?;
        let (e, _) = intent_envelope(&verified.canonical)?;
        times(&e["intent"], a.now()?)?;
        Ok(Reservation {
            created,
            state: stored.state,
            digest: verified.digest(),
        })
    }
    /// Release a healthy handle; poisoned storage retains its administrative lock.
    pub fn close(&mut self) -> Result<()> {
        self.store.close().map_err(|_| Invalid)
    }
}
fn reservation_entry(v: &VerifiedIntent) -> Result<Entry> {
    let (e, _) = intent_envelope(&v.canonical)?;
    let i = &e["intent"];
    Ok(Entry {
        issuer: text(i, "issuer").into(),
        recipient: text(i, "recipient").into(),
        call_id: text(i, "call_id").into(),
        nonce: text(i, "nonce").into(),
        expires: number(i, "expires")?,
        intent_hex: hex::encode(&v.canonical),
        state: "RESERVED".into(),
        result_hex: String::new(),
    })
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::super::fixtures_test::Fixture;
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::fs;
    use std::sync::{Arc, Mutex};
    fn cases() -> Vec<Value> {
        serde_json::from_str::<Value>(include_str!("testdata/guard-records.json")).unwrap()["cases"]
            .as_array()
            .unwrap()
            .clone()
    }
    fn fixture() -> Value {
        cases()
            .into_iter()
            .find(|c| c["id"] == "intent-valid")
            .unwrap()["input"]
            .clone()
    }
    fn raw(f: &Value) -> Vec<u8> {
        hex::decode(text(f, "envelope_hex")).unwrap()
    }
    fn reserve(l: &mut GuardLedger, f: &Value) -> Result<Reservation> {
        l.reserve(&raw(f), &mut Fixture(f.clone()), &mut Fixture(f.clone()))
    }
    fn signed(f: &mut Value, field: &str, value: Value, rotate: bool) -> Vec<u8> {
        let mut e: Value = serde_json::from_slice(&raw(f)).unwrap();
        if !field.is_empty() {
            e["intent"][field] = value
        }
        let mut seed: [u8; 32] = Sha256::digest(b"public Guard fixture issuer").into();
        if rotate {
            seed[0] ^= 1
        };
        let key = SigningKey::from_bytes(&seed);
        let b = encode(&e["intent"]).unwrap();
        e["proof"] = json!(B64.encode(
            key.sign(&[b"sage-execution-intent|0.10.0\0".as_slice(), &b].concat())
                .to_bytes()
        ));
        f["public_key_hex"] = json!(hex::encode(key.verifying_key().to_bytes()));
        serde_json::to_vec(&e).unwrap()
    }
    #[test]
    fn independent_intents_do_not_write_on_denial() {
        for c in cases() {
            if c["operation"] != "sage.guard.intent.verify" {
                continue;
            };
            let f = &c["input"];
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("journal");
            let mut l = GuardLedger::open(&path, true, text(f, "expected_recipient")).unwrap();
            let before = fs::read(&path).unwrap();
            let r = reserve(&mut l, f);
            assert_eq!(
                r.is_ok(),
                c["expected"]["verdict"] == "ACCEPT",
                "{}",
                c["id"]
            );
            if let Ok(r) = r {
                assert!(r.created());
                assert_eq!(r.state(), "RESERVED")
            } else {
                assert_eq!(fs::read(&path).unwrap(), before)
            };
            l.close().unwrap();
        }
    }
    #[test]
    fn retries_reauthenticate_and_recovery_never_reserves_again() {
        let mut f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut l = GuardLedger::open(&path, true, text(&f, "expected_recipient")).unwrap();
        let r = reserve(&mut l, &f).unwrap();
        assert!(r.created());
        let before = fs::read(&path).unwrap();
        let e: Value = serde_json::from_slice(&raw(&f)).unwrap();
        let pretty = serde_json::to_vec_pretty(&e).unwrap();
        let r = l
            .reserve(&pretty, &mut Fixture(f.clone()), &mut Fixture(f.clone()))
            .unwrap();
        assert!(!r.created());
        assert_eq!(r.state(), "RESERVED");
        assert_eq!(fs::read(&path).unwrap(), before);
        for k in ["active_key", "policy_allow", "clock_trusted"] {
            f[k] = json!(false);
            assert!(reserve(&mut l, &f).is_err());
            f[k] = json!(true);
            assert_eq!(fs::read(&path).unwrap(), before)
        }
        l.close().unwrap();
        let mut l = GuardLedger::open(&path, false, text(&f, "expected_recipient")).unwrap();
        let r = reserve(&mut l, &f).unwrap();
        assert!(!r.created());
        assert_eq!(r.state(), "UNKNOWN");
        let before = fs::read(&path).unwrap();
        f["now"] = json!(1700000300);
        assert!(reserve(&mut l, &f).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        l.close().unwrap();
    }
    #[test]
    fn valid_signed_conflicts_preserve_storage() {
        for (field, value) in [
            ("arguments", json!({"path":"other.txt"})),
            ("nonce", json!("AQECAwQFBgcICQoLDA0ODw")),
            ("call_id", json!("00000000-0000-4000-8000-000000000004")),
            ("", Value::Null),
        ] {
            let mut f = fixture();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("journal");
            let mut l = GuardLedger::open(&path, true, text(&f, "expected_recipient")).unwrap();
            reserve(&mut l, &f).unwrap();
            let before = fs::read(&path).unwrap();
            let raw = signed(&mut f, field, value, field.is_empty());
            assert!(verify_intent(
                &raw,
                text(&f, "expected_recipient"),
                &mut Fixture(f.clone()),
                &mut Fixture(f.clone())
            )
            .is_ok());
            assert!(l
                .reserve(&raw, &mut Fixture(f.clone()), &mut Fixture(f.clone()))
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
            l.close().unwrap();
        }
    }
    #[test]
    fn concurrent_identical_reservations_are_single() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let l = Arc::new(Mutex::new(
            GuardLedger::open(&path, true, text(&f, "expected_recipient")).unwrap(),
        ));
        let mut joins = Vec::new();
        for _ in 0..16 {
            let l = l.clone();
            let f = f.clone();
            joins.push(std::thread::spawn(move || {
                reserve(&mut l.lock().unwrap(), &f).unwrap().created()
            }))
        }
        let count = joins
            .into_iter()
            .map(|j| usize::from(j.join().unwrap()))
            .sum::<usize>();
        assert_eq!(count, 1);
        assert_eq!(
            fs::read(&path)
                .unwrap()
                .iter()
                .filter(|b| **b == b'\n')
                .count(),
            2
        );
        l.lock().unwrap().close().unwrap();
    }
    #[test]
    fn concurrent_calls_cannot_share_nonce() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let l = Arc::new(Mutex::new(
            GuardLedger::open(&path, true, text(&f, "expected_recipient")).unwrap(),
        ));
        let mut joins = Vec::new();
        for id in [
            "00000000-0000-4000-8000-000000000004",
            "00000000-0000-4000-8000-000000000005",
        ] {
            let mut f = fixture();
            let raw = signed(&mut f, "call_id", json!(id), false);
            assert!(verify_intent(
                &raw,
                text(&f, "expected_recipient"),
                &mut Fixture(f.clone()),
                &mut Fixture(f.clone())
            )
            .is_ok());
            let l = l.clone();
            joins.push(std::thread::spawn(move || {
                l.lock()
                    .unwrap()
                    .reserve(&raw, &mut Fixture(f.clone()), &mut Fixture(f))
                    .is_ok()
            }));
        }
        assert_eq!(
            joins
                .into_iter()
                .filter_map(|j| j.join().ok())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(
            fs::read(&path)
                .unwrap()
                .iter()
                .filter(|b| **b == b'\n')
                .count(),
            2
        );
        l.lock().unwrap().close().unwrap();
    }
    struct Expiry {
        fixture: Fixture,
        calls: usize,
    }
    impl Authority for Expiry {
        fn now(&mut self) -> Result<i64> {
            self.calls += 1;
            if self.calls == 4 {
                Ok(1700000300)
            } else {
                self.fixture.now()
            }
        }
        fn active_key(&mut self, i: &str, k: &str) -> Result<[u8; 32]> {
            self.fixture.active_key(i, k)
        }
    }
    #[test]
    fn expiry_during_storage_keeps_committed_denial() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut l = GuardLedger::open(&path, true, text(&f, "expected_recipient")).unwrap();
        assert!(l
            .reserve(
                &raw(&f),
                &mut Expiry {
                    fixture: Fixture(f.clone()),
                    calls: 0
                },
                &mut Fixture(f.clone())
            )
            .is_err());
        assert!(!reserve(&mut l, &f).unwrap().created());
        l.close().unwrap();
    }
    #[test]
    fn missing_exclusive_and_closed_storage_deny() {
        let f = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        assert!(GuardLedger::open(&path, false, text(&f, "expected_recipient")).is_err());
        let mut l = GuardLedger::open(&path, true, text(&f, "expected_recipient")).unwrap();
        assert!(GuardLedger::open(&path, false, text(&f, "expected_recipient")).is_err());
        l.close().unwrap();
        assert!(reserve(&mut l, &f).is_err());
    }
}
