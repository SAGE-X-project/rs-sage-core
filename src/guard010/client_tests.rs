use super::fixtures_test::Fixture;
use super::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct Services(Arc<Mutex<Value>>);
impl ClientClock for Services {
    fn sample(&mut self) -> Result<(i64, i64)> {
        let s = self.0.lock().unwrap();
        ensure(s["clock_ok"] == true)?;
        Ok((
            s["utc"].as_i64().ok_or(Invalid)?,
            s["mono"].as_i64().ok_or(Invalid)?,
        ))
    }
}
impl Authority for Services {
    fn now(&mut self) -> Result<i64> {
        Ok(self.sample()?.0 / 1000)
    }
    fn active_key(&mut self, issuer: &str, kid: &str) -> Result<[u8; 32]> {
        let s = self.0.lock().unwrap();
        if issuer == "did:sage:web:agents.example.com:executor" {
            ensure(s["result_active"] == true && kid == format!("{issuer}#signing-1"))?;
            hex::decode(text(&s, "public"))
                .map_err(|_| Invalid)?
                .try_into()
                .map_err(|_| Invalid)
        } else {
            Fixture(s["input"].clone()).active_key(issuer, kid)
        }
    }
}
impl IntentPolicy for Services {
    fn bindings(&mut self, i: &str, r: &str) -> Result<Bindings> {
        Fixture(self.0.lock().unwrap()["input"].clone()).bindings(i, r)
    }
    fn authorize(&mut self, i: &str, t: &str, a: &[u8]) -> Result<()> {
        Fixture(self.0.lock().unwrap()["input"].clone()).authorize(i, t, a)
    }
}
impl ClientSender for Services {
    fn commit(&mut self, id: &str, raw: &[u8]) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        s["handoffs"] = json!(s["handoffs"].as_u64().unwrap_or(0) + 1);
        s["sent_id"] = json!(id);
        s["sent_intent"] = json!(hex::encode(raw));
        let delay = s["send_delay"].as_i64().unwrap_or(0);
        let u = s["utc"].as_i64().unwrap();
        let m = s["mono"].as_i64().unwrap();
        s["utc"] = json!(u + delay);
        s["mono"] = json!(m + delay);
        ensure(s["send_fail"] != true)
    }
}
impl Services {
    pub(super) fn config(&self) -> ClientServices {
        ClientServices {
            intent_authority: Box::new(self.clone()),
            policy: Box::new(self.clone()),
            result_authority: Box::new(self.clone()),
            clock: Box::new(self.clone()),
            sender: Box::new(self.clone()),
        }
    }
}
fn suite() -> Value {
    serde_json::from_str(include_str!("testdata/guard-client.json")).unwrap()
}
pub(super) fn setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Client,
    Services,
    Value,
) {
    let v = suite();
    let services = Services(Arc::new(Mutex::new(
        json!({"input":v["input"],"public":v["public_key_hex"],"clock_ok":true,"result_active":true,"utc":1700000000000_i64,"mono":0}),
    )));
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("journal");
    let raw = hex::decode(text(&v["input"], "envelope_hex")).unwrap();
    let c = Client::open(&p, true, &raw, services.config()).unwrap();
    (d, p, c, services, v)
}
fn outer(n: i64) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn result(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v["results"][name].as_str().unwrap()).unwrap()
}
fn observation() -> Value {
    json!({"ok":true,"id":"","intent_hex":"","status":"","first":false,"ignored":false,"output_hex":"","handoffs":0})
}
fn apply(
    c: &Client,
    s: &Services,
    tickets: &mut std::collections::BTreeMap<String, ClientInvocation>,
    q: &Value,
    v: &Value,
) -> Value {
    let mut o = observation();
    let id = text(q, "id");
    match text(q, "action") {
        "tick" => {
            let mut s = s.0.lock().unwrap();
            s["utc"] = q["utc"].clone();
            s["mono"] = q["mono"].clone()
        }
        "set" => {
            let mut s = s.0.lock().unwrap();
            match text(q, "field") {
                "intent_active" => s["input"]["active_key"] = q["value"].clone(),
                "policy_allow" => s["input"]["policy_allow"] = q["value"].clone(),
                field => s[field] = q["value"].clone(),
            }
        }
        "begin" => match c.begin(id) {
            Ok(t) => {
                o["id"] = json!(t.id());
                o["intent_hex"] = json!(hex::encode(t.intent()));
                tickets.insert(id.into(), t);
            }
            Err(_) => o["ok"] = json!(false),
        },
        "accept" => {
            let r = tickets
                .get(id)
                .ok_or(Invalid)
                .and_then(|t| c.accept(t, &result(v, text(q, "result"))));
            match r {
                Ok(d) => {
                    o["status"] = json!(d.status());
                    o["first"] = json!(d.first_terminal());
                    o["ignored"] = json!(d.ignored());
                    o["output_hex"] = json!(hex::encode(d.output()));
                }
                Err(_) => o["ok"] = json!(false),
            }
        }
        "failed" => {
            o["ok"] = json!(tickets
                .get(id)
                .ok_or(Invalid)
                .and_then(|t| c.failed(t))
                .is_ok())
        }
        "close" => o["ok"] = json!(c.close().is_ok()),
        _ => panic!("fixture action"),
    };
    o["handoffs"] = json!(s.0.lock().unwrap()["handoffs"].as_u64().unwrap_or(0));
    o
}
#[test]
fn independent_client_scenarios() {
    for case in suite()["cases"].as_array().unwrap() {
        let (_d, _p, c, s, v) = setup();
        let mut tickets = std::collections::BTreeMap::new();
        for (step, q) in case["steps"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                apply(&c, &s, &mut tickets, q, &v),
                q["expected"],
                "{} step {step}",
                case["id"]
            );
        }
        let _ = c.close();
    }
}
#[test]
fn concurrent_terminal_consumption() {
    let (_d, _p, c, s, v) = setup();
    let c = Arc::new(c);
    let mut tickets = Vec::new();
    for n in 1..=8 {
        let mut state = s.0.lock().unwrap();
        state["utc"] = json!(1700000000000_i64 + n * 1000);
        state["mono"] = json!(n * 1000);
        drop(state);
        tickets.push(c.begin(&outer(n)).unwrap());
    }
    let handles: Vec<_> = tickets
        .into_iter()
        .map(|t| {
            let c = c.clone();
            let raw = result(&v, "completed");
            std::thread::spawn(move || c.accept(&t, &raw).unwrap())
        })
        .collect();
    let mut count = 0;
    for h in handles {
        let d = h.join().unwrap();
        if d.first_terminal() {
            count += 1;
            assert!(!d.output().is_empty())
        } else {
            assert!(d.ignored() && d.output().is_empty())
        }
    }
    assert_eq!(count, 1);
    c.close().unwrap();
}
#[test]
fn restart_preserves_polling_and_consumption() {
    let (_d, p, c, s, v) = setup();
    let raw = hex::decode(text(&v["input"], "envelope_hex")).unwrap();
    let old = c.begin(&outer(1)).unwrap();
    c.close().unwrap();
    s.0.lock().unwrap()["utc"] = json!(1700000001000_i64);
    let c = Client::open(&p, false, &raw, s.config()).unwrap();
    assert!(c.begin(&outer(2)).is_err());
    s.0.lock().unwrap()["mono"] = json!(1000);
    assert!(c.begin(&outer(1)).is_err());
    assert!(c.accept(&old, &result(&v, "completed")).is_err());
    let next = c.begin(&outer(2)).unwrap();
    assert!(c
        .accept(&next, &result(&v, "completed"))
        .unwrap()
        .first_terminal());
    c.close().unwrap();
    let c = Client::open(&p, false, &raw, s.config()).unwrap();
    {
        let mut s = s.0.lock().unwrap();
        s["utc"] = json!(1700000002000_i64);
        s["mono"] = json!(2000);
    }
    assert!(c.begin(&outer(3)).is_err());
    assert!(c.accept(&next, &result(&v, "completed")).is_err());
    c.close().unwrap();
}
#[test]
fn missing_exclusive_and_corrupt_storage() {
    let (_d, p, c, s, v) = setup();
    let raw = hex::decode(text(&v["input"], "envelope_hex")).unwrap();
    assert!(Client::open(&p, false, &raw, s.config()).is_err());
    assert!(Client::open(&p.with_extension("missing"), false, &raw, s.config()).is_err());
    c.close().unwrap();
    let mut bytes = std::fs::read(&p).unwrap();
    bytes.pop();
    std::fs::write(&p, bytes).unwrap();
    assert!(Client::open(&p, false, &raw, s.config()).is_err());
}

#[test]
fn handoff_duration_and_uncertain_transmission() {
    for fail in [false, true] {
        let (_d, _p, c, s, _v) = setup();
        {
            let mut state = s.0.lock().unwrap();
            state["send_delay"] = json!(500);
            state["send_fail"] = json!(fail);
        }
        assert_eq!(c.begin(&outer(1)).is_err(), fail);
        {
            let mut state = s.0.lock().unwrap();
            state["send_delay"] = json!(0);
            state["send_fail"] = json!(false);
            state["utc"] = json!(1700000001499_i64);
            state["mono"] = json!(1499);
        }
        assert!(c.begin(&outer(2)).is_err());
        assert_eq!(s.0.lock().unwrap()["sent_id"], outer(1));
        {
            let mut state = s.0.lock().unwrap();
            state["utc"] = json!(1700000001500_i64);
            state["mono"] = json!(1500);
        }
        assert!(c.begin(&outer(2)).is_ok());
        c.close().unwrap();
    }
}
