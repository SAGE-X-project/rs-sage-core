use super::*;
use crate::registry010::{Config, Journal, Snapshot, Source};
use std::{cell::RefCell, collections::HashSet, rc::Rc};
const ALICE: &str = "did:sage:web:agent.example:alice";
const BOB: &str = "did:sage:web:agent.example:bob";
#[derive(Default)]
struct Control {
    records: u64,
    expiry: i64,
    mono: i64,
    utc: i64,
    mode: String,
}
#[derive(Clone)]
struct Controls(Rc<RefCell<Control>>);
impl Clock for Controls {
    fn now(&mut self) -> Result<Stamp> {
        let c = self.0.borrow();
        if c.mode == "clock-error" {
            return Err(bad());
        }
        Ok(Stamp {
            mono_ms: c.mono,
            unix: c.utc,
        })
    }
}
impl Source for Controls {
    fn read(&mut self, did: &str) -> Result<Snapshot> {
        let c = self.0.borrow();
        if c.mode == "source-error" {
            return Err(bad());
        }
        let n = if did == BOB { 2 } else { 1 };
        let mut k = Key {
            name: "signing-1".into(),
            alg: "ed25519".into(),
            material: hex::encode(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()),
            state: "accepted".into(),
            expires: None,
        };
        let mut keys = Vec::new();
        if did == BOB {
            keys.push(Key {
                name: "kem-1".into(),
                alg: "x25519".into(),
                material: hex::encode(x25519([3; 32], X25519_BASEPOINT_BYTES)),
                state: if c.mode == "revoke-kem" {
                    "revoked"
                } else {
                    "accepted"
                }
                .into(),
                expires: None,
            });
        }
        if (c.mode == "revoke-init" && did == ALICE) || (c.mode == "revoke-resp" && did == BOB) {
            k.state = "revoked".into()
        }
        if c.mode == "changed-material" && did == BOB {
            k.material = hex::encode(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes())
        }
        keys.push(k.clone());
        let version = if c.mode.starts_with("revoke")
            || ["changed-material", "unrelated"].contains(&c.mode.as_str())
        {
            "3"
        } else {
            "2"
        };
        if c.mode == "unrelated" {
            k.name = "z-extra".into();
            k.material = hex::encode(SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes());
            keys.push(k)
        }
        if c.expiry != 0 {
            for k in &mut keys {
                k.expires = Some(c.expiry);
            }
        }
        let digest = hex::encode(Sha256::digest(canonical(&keys)));
        Ok(Snapshot {
            source: "fixture-authority".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            did: did.into(),
            version: version.into(),
            state: "active".into(),
            digest,
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: c.mono,
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys,
        })
    }
}
struct Replay {
    control: Controls,
    seen: HashSet<String>,
}
impl ReplayStore010 for Replay {
    fn reserve_record(
        &mut self,
        r: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let prefix = format!("{}|{}", r.sender, r.recipient);
        let ids = [
            format!("{prefix}|id|{}", r.id),
            format!("{prefix}|nonce|{}", r.nonce),
        ];
        if self.control.0.borrow().mode == "transport-id" {
            self.seen.insert(ids[0].clone());
        }
        if self.control.0.borrow().mode == "transport-nonce" {
            self.seen.insert(ids[1].clone());
        }
        if ids.iter().any(|id| self.seen.contains(id)) {
            return Err(bad());
        }
        {
            let mut c = self.control.0.borrow_mut();
            if c.mode == "store-error" {
                return Err(bad());
            }
            if c.mode == "utc-delay" {
                c.utc += 1;
                c.mono += 1000
            }
            if c.mode == "store-delay" {
                c.mono += 5001
            }
        }
        validate()?;
        self.seen.extend(ids);
        self.control.0.borrow_mut().records += 1;
        Ok(())
    }

    fn reserve(&mut self, r: Replay010) -> Result<()> {
        let mut c = self.control.0.borrow_mut();
        if c.mode == "store-error" {
            return Err(bad());
        }
        let prefix = format!("{}|{}", r.sender, r.recipient);
        let mut ids = vec![
            format!("{prefix}|id|{}", r.id),
            format!("{prefix}|nonce|{}", r.nonce),
        ];
        if !r.context.is_empty() {
            ids.push(format!("{}|ctx|{}", r.sender, r.context))
        }
        if ids.iter().any(|id| self.seen.contains(id)) {
            return Err(bad());
        }
        self.seen.extend(ids);
        if c.mode == "utc-delay" {
            c.utc += 1;
            c.mono += 1000;
        }
        if c.mode == "store-delay" {
            c.mono += 5001
        }
        Ok(())
    }
}
fn pair() -> (
    CompletionEndpoint010,
    CompletionEndpoint010,
    Controls,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let controls = Controls(Rc::new(RefCell::new(Control {
        utc: 100,
        ..Default::default()
    })));
    let make = |did: &str, n: u8| {
        let gate = Gate::new(
            Config {
                source: "fixture-authority".into(),
                registry: "web:agent.example".into(),
                network: "local".into(),
                blockchain: false,
            },
            Box::new(controls.clone()),
            Box::new(controls.clone()),
            Box::new(Journal::open(&tmp.path().join(n.to_string()), true).unwrap()),
        )
        .unwrap();
        CompletionEndpoint010::new(
            did,
            &format!("{did}#signing-1"),
            &[n; 32],
            if n == 2 { &[3; 32] } else { &[] },
            gate,
            Box::new(controls.clone()),
            Box::new(Replay {
                control: controls.clone(),
                seen: HashSet::new(),
            }),
        )
        .unwrap()
    };
    (make(ALICE, 1), make(BOB, 2), controls, tmp)
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../tests/fixtures/completion010.json")).unwrap()
}
fn changed(request: &[u8], response: &[u8], kind: &str) -> Vec<u8> {
    if kind.is_empty() {
        return response.to_vec();
    }
    let mut w: Value = serde_json::from_slice(response).unwrap();
    let q: Value = serde_json::from_slice(request).unwrap();
    let mut body = B64.decode(w["data"].as_str().unwrap()).unwrap();
    let mut c: Value = serde_json::from_slice(&body).unwrap();
    let key = SigningKey::from_bytes(&[2; 32]);
    let mut inner = false;
    match kind {
        "outer-signature" => {
            w["signature"] = json!(B64.encode([0; 64]));
            return canonical(&w);
        }
        "inner-signature" => c["sigB64"] = json!(B64.encode([0; 64])),
        "ack" => {
            c["ackTagB64"] = json!(B64.encode([0; 32]));
            inner = true
        }
        "echo" => {
            c["transcript"]["ctx"] = json!("11111111-1111-4111-8111-111111111111");
            inner = true
        }
        "request-hash" => w["request_hash"] = json!(B64.encode([0; 32])),
        "message-id" => w["message_id"] = json!("11111111-1111-4111-8111-111111111111"),
        "recipient" => w["recipient"] = json!(BOB),
        "signing-key" => w["kid"] = json!(format!("{BOB}#different")),
        "response-nonce" => w["nonce"] = q["nonce"].clone(),
        "unknown-wire" => w["extra"] = json!("value"),
        "unknown-completion" => c["extra"] = json!("value"),
        "duplicate-wire" => {
            let mut out = response[..response.len() - 1].to_vec();
            out.extend(b",\"version\":\"0.10.0\"}");
            return out;
        }
        "duplicate-completion" => {
            body.pop();
            body.extend(b",\"v\":\"0.10.0\"}")
        }
        "duplicate-transcript" => {
            let t = String::from_utf8(canonical(&c["transcript"])).unwrap();
            let dup = format!("{},\"v\":\"0.10.0\"}}", &t[..t.len() - 1]);
            body = String::from_utf8(body)
                .unwrap()
                .replace(
                    &format!("\"transcript\":{t}"),
                    &format!("\"transcript\":{dup}"),
                )
                .into_bytes()
        }
        "null-transcript" => c["transcript"] = Value::Null,
        "trailing-wire" => {
            let mut out = response.to_vec();
            out.extend(b" {}");
            return out;
        }
        "noncanonical-completion" => body.insert(0, b' '),
        _ => panic!("unknown mutation"),
    }
    if inner {
        c.as_object_mut().unwrap().remove("sigB64");
        let mut data = b"sage-hpke-complete|0.10.0\n".to_vec();
        data.extend(canonical(&c));
        c["sigB64"] = json!(B64.encode(key.sign(&data).to_bytes()))
    }
    if ![
        "duplicate-completion",
        "duplicate-transcript",
        "noncanonical-completion",
    ]
    .contains(&kind)
    {
        body = canonical(&c)
    }
    w["data"] = json!(B64.encode(body));
    w.as_object_mut().unwrap().remove("signature");
    signed(w, b"sage-wire-response|0.10.0\n", &key)
}
#[test]
fn completion_scenarios() {
    let f = fixture();
    assert_eq!(f["cases"].as_array().unwrap().len(), 36);
    for n in [1, 2] {
        assert_eq!(
            hex::encode(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()),
            f["public_keys"][n.to_string()]
        )
    }
    for case in f["cases"].as_array().unwrap() {
        let (mut a, mut b, c, _tmp) = pair();
        let (mut p, request) = a
            .start(
                BOB,
                &format!("{BOB}#signing-1"),
                case["init_ttl"].as_i64().unwrap_or(300),
            )
            .unwrap();
        let (mut r, response) = b
            .respond(&request, case["response_ttl"].as_i64().unwrap_or(300))
            .unwrap();
        assert_eq!(r.state(), "RESPONSE_SENT");
        let response = changed(&request, &response, case["mutation"].as_str().unwrap_or(""));
        {
            let mut v = c.0.borrow_mut();
            v.mode = case["mode"].as_str().unwrap_or("").into();
            v.mono = case["mono_ms"].as_i64().unwrap_or(0);
            v.utc = case["unix"].as_i64().unwrap_or(100);
        }
        if case["abandon"] == true {
            p.close()
        }
        if case["endpoint_close"] == true {
            a.close()
        }
        let result = p.complete(&mut a, &response);
        assert_eq!(
            result.is_ok(),
            case["accept"].as_bool().unwrap(),
            "{}: {:?}",
            case["id"],
            result.as_ref().err()
        );
        assert_eq!(p.state(), "CLOSED");
        if let Ok(mut s) = result {
            assert_eq!(s.state(), "ESTABLISHED");
            assert_eq!(s.tuple(), r.tuple());
            let mut copy = s.tuple();
            copy.insert("sid".into(), "changed".into());
            assert_ne!(s.tuple(), copy);
            s.close();
        }
        assert!(p.complete(&mut a, &response).is_err());
        r.close();
    }
}
#[test]
fn lifecycle() {
    for mode in [
        "revoke-init",
        "revoke-resp",
        "revoke-kem",
        "source-error",
        "unrelated",
        "expiry",
        "closed",
    ] {
        let (mut a, mut b, c, _tmp) = pair();
        let (mut p, request) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        let (mut r, response) = b.respond(&request, 300).unwrap();
        assert!(b.respond(&request, 300).is_err());
        let mut s = p.complete(&mut a, &response).unwrap();
        c.0.borrow_mut().mode = mode.into();
        if mode == "expiry" {
            c.0.borrow_mut().utc = 400;
            c.0.borrow_mut().mono = 300000
        }
        if mode == "closed" {
            r.close()
        }
        let result = r.check(&mut b);
        if mode == "unrelated" {
            assert!(result.is_ok());
            assert_eq!(r.state(), "RESPONSE_SENT")
        } else {
            assert!(result.is_err(), "{mode}");
            assert_eq!(r.state(), "CLOSED")
        }
        if !["expiry", "closed"].contains(&mode) {
            assert_eq!(s.check(&mut a).is_ok(), mode == "unrelated")
        }
    }
}

#[test]
fn key_expires_during_commit() {
    let (mut a, mut b, c, _tmp) = pair();
    c.0.borrow_mut().expiry = 101;
    let (mut p, request) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
    let (mut r, response) = b.respond(&request, 300).unwrap();
    c.0.borrow_mut().mode = "utc-delay".into();
    assert!(p.complete(&mut a, &response).is_err());
    assert_eq!(p.state(), "CLOSED");
    r.close();
}

#[test]
fn authenticated_record_scenarios() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/authenticated-record010.json"
    ))
    .unwrap();
    for case in f["cases"].as_array().unwrap() {
        let kind = case.as_str().unwrap();
        let (mut a, mut b, c, _tmp) = pair();
        if kind == "key-expiry-during-commit" {
            c.0.borrow_mut().expiry = 101
        }
        let (mut pending, q) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        let (mut server, r) = b.respond(&q, 300).unwrap();
        let mut client = pending.complete(&mut a, &r).unwrap();
        assert!(server.seal_request(&mut b, b"denied", 300).is_err());
        assert_eq!(server.state(), "RESPONSE_SENT");
        let first = client.seal_request(&mut a, b"first", 300).unwrap();
        let mut w = first.clone();
        let mut want = b"first".to_vec();
        if ["nonzero-first", "out-of-order"].contains(&kind) {
            w = client.seal_request(&mut a, b"second", 300).unwrap();
            want = b"second".to_vec()
        }
        let good = w.clone();
        let mut m: Value = serde_json::from_slice(&w).unwrap();
        let mut mutated = true;
        match kind {
            "signature" => {
                m["signature"] = json!(B64.encode([0; 64]));
                w = canonical(&m);
                mutated = false
            }
            "tag" => {
                let mut v = B64.decode(m["payload"].as_str().unwrap()).unwrap();
                *v.last_mut().unwrap() ^= 1;
                m["payload"] = json!(B64.encode(v));
            }
            "did" => m[kind] = json!(BOB),
            "recipient" => m[kind] = json!(ALICE),
            "kid" => m[kind] = json!(format!("{ALICE}#different")),
            "role" => m[kind] = json!("responder"),
            "context_id" => m[kind] = json!("11111111-1111-4111-8111-111111111111"),
            "session_id" => m[kind] = json!(B64.encode([0; 16])),
            "version" => m[kind] = json!("0.9.0"),
            "unknown-field" => m["extra"] = json!("value"),
            "duplicate-field" => {
                w.pop();
                w.extend(br#", "version":"0.10.0"}"#);
                mutated = false
            }
            _ => mutated = false,
        }
        if mutated {
            m.as_object_mut().unwrap().remove("signature");
            w = signed(
                m,
                b"sage-wire-request|0.10.0\n",
                a.signing.as_ref().unwrap(),
            )
        }
        let mut accept = false;
        let mut closed = false;
        match kind {
            "valid" | "nonzero-first" | "out-of-order" | "application-reject" | "unrelated" => {
                accept = true;
                if kind == "unrelated" {
                    c.0.borrow_mut().mode = kind.into()
                }
            }
            "duplicate" | "idle-expiry" => {
                server.open_request(&mut b, &w).unwrap();
                if kind == "idle-expiry" {
                    c.0.borrow_mut().mono = 600000;
                    closed = true
                }
            }
            "store-error" | "transport-id" | "transport-nonce" => {
                c.0.borrow_mut().mode = kind.into()
            }
            "store-delay" | "revoke-init" | "revoke-resp" | "revoke-kem" | "changed-material"
            | "source-error" | "clock-error" => {
                c.0.borrow_mut().mode = kind.into();
                closed = true
            }
            "pending-mono-expiry" => {
                c.0.borrow_mut().mono = 300000;
                closed = true
            }
            "pending-utc-expiry" => {
                c.0.borrow_mut().utc = 400;
                closed = true
            }
            "key-expiry-during-commit" => {
                c.0.borrow_mut().mode = "utc-delay".into();
                closed = true
            }
            "closed" => {
                server.close();
                closed = true
            }
            _ => {}
        }
        let before = c.0.borrow().records;
        let result = server.open_request(&mut b, &w);
        assert_eq!(result.is_ok(), accept, "{kind}");
        if accept {
            assert_eq!(result.unwrap(), want);
            assert_eq!(server.state(), "ESTABLISHED");
            assert_eq!(c.0.borrow().records, before + 1);
            assert!(server.open_request(&mut b, &w).is_err());
            if kind == "out-of-order" {
                assert_eq!(server.open_request(&mut b, &first).unwrap(), b"first")
            }
            let reverse = server.seal_request(&mut b, b"rejection", 300).unwrap();
            assert_eq!(client.open_request(&mut a, &reverse).unwrap(), b"rejection");
        } else {
            assert_eq!(c.0.borrow().records, before, "{kind}: partial acceptance");
            if closed {
                assert_eq!(server.state(), "CLOSED", "{kind}")
            } else if !["duplicate", "transport-id", "transport-nonce"].contains(&kind) {
                assert_eq!(server.state(), "RESPONSE_SENT");
                c.0.borrow_mut().mode.clear();
                assert_eq!(
                    server.open_request(&mut b, &good).unwrap(),
                    want,
                    "{kind}: consumed sequence"
                );
            }
        }
    }
}

#[test]
fn authenticated_record_lifetime_and_bounds() {
    for kind in ["absolute", "idle", "bounds"] {
        let (mut a, mut b, c, _tmp) = pair();
        let (mut p, q) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        let (mut server, r) = b.respond(&q, 300).unwrap();
        let mut client = p.complete(&mut a, &r).unwrap();
        if kind == "absolute" {
            c.0.borrow_mut().mono = 200000
        }
        if kind == "bounds" {
            assert!(client.seal_request(&mut a, &vec![0; 16349], 300).is_err());
            let w = client.seal_request(&mut a, &vec![0; 16348], 300).unwrap();
            assert_eq!(server.open_request(&mut b, &w).unwrap().len(), 16348);
            continue;
        }
        let w = client.seal_request(&mut a, b"first", 300).unwrap();
        server.open_request(&mut b, &w).unwrap();
        if kind == "absolute" {
            for now in (500000..=3500000).step_by(500000) {
                c.0.borrow_mut().mono = now;
                server.seal_request(&mut b, b"traffic", 300).unwrap();
            }
            c.0.borrow_mut().mono = 3600000;
            assert!(server.seal_request(&mut b, b"", 300).is_err());
        } else {
            c.0.borrow_mut().mono = 599999;
            let mut m: Value = serde_json::from_slice(&w).unwrap();
            m["signature"] = json!(B64.encode([0; 64]));
            assert!(server.open_request(&mut b, &canonical(&m)).is_err());
            c.0.borrow_mut().mono = 600000;
            assert!(server.check(&mut b).is_err());
        }
        assert_eq!(server.state(), "CLOSED");
    }
}

fn response_mutation(
    raw: &[u8],
    request: &[u8],
    kind: &str,
    other: &str,
    e: &CompletionEndpoint010,
) -> Vec<u8> {
    let mut w: Value = serde_json::from_slice(raw).unwrap();
    let q: Value = serde_json::from_slice(request).unwrap();
    match kind {
        "request-hash" => w["request_hash"] = json!(B64.encode([0; 32])),
        "message-id" => w["message_id"] = json!("11111111-1111-4111-8111-111111111111"),
        "cross-request" => w["message_id"] = json!(other),
        "same-id" => w["id"] = q["id"].clone(),
        "same-nonce" => w["nonce"] = q["nonce"].clone(),
        "recipient" => w[kind] = json!(BOB),
        "did" => w[kind] = json!(ALICE),
        "kid" => w[kind] = json!(format!("{BOB}#different")),
        "role" => w[kind] = json!("initiator"),
        "context_id" => w[kind] = json!("11111111-1111-4111-8111-111111111111"),
        "session_id" => w[kind] = json!(B64.encode([0; 16])),
        "signature" => {
            w[kind] = json!(B64.encode([0; 64]));
            return canonical(&w);
        }
        "tag" => {
            let mut v = B64.decode(w["data"].as_str().unwrap()).unwrap();
            *v.last_mut().unwrap() ^= 1;
            w["data"] = json!(B64.encode(v))
        }
        "missing-error" => {
            w["success"] = json!(false);
            w.as_object_mut().unwrap().remove("error");
        }
        "unknown-error" => {
            w["success"] = json!(false);
            w["error"] = json!("other")
        }
        "success-error" => {
            w["success"] = json!(true);
            w["error"] = json!("policy_denied")
        }
        "success-type" => w["success"] = json!("true"),
        "unknown-field" => w["extra"] = json!("value"),
        "plain-encoding" => w["encoding"] = json!("plain"),
        "duplicate-field" => {
            let mut v = raw[..raw.len() - 1].to_vec();
            v.extend(br#", "success":true}"#);
            return v;
        }
        _ => return raw.to_vec(),
    }
    w.as_object_mut().unwrap().remove("signature");
    signed(
        w,
        b"sage-wire-response|0.10.0\n",
        e.signing.as_ref().unwrap(),
    )
}
#[test]
fn session_response_scenarios() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/session-response010.json"
    ))
    .unwrap();
    for case in f["cases"].as_array().unwrap() {
        let kind = case.as_str().unwrap();
        let (mut a, mut b, c, _tmp) = pair();
        if kind == "key-expiry-during-commit" {
            c.0.borrow_mut().expiry = 101
        }
        let (mut p, q) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        let (mut server, r) = b.respond(&q, 300).unwrap();
        let mut client = p.complete(&mut a, &r).unwrap();
        let mut request = client.seal_request(&mut a, b"request", 300).unwrap();
        server.open_request(&mut b, &request).unwrap();
        if kind == "reverse" {
            std::mem::swap(&mut a, &mut b);
            std::mem::swap(&mut client, &mut server);
            request = client.seal_request(&mut a, b"reverse", 300).unwrap();
            server.open_request(&mut b, &request).unwrap();
        }
        let q: Value = serde_json::from_slice(&request).unwrap();
        let id = q["id"].as_str().unwrap();
        let error = if [
            "authentication_failed",
            "policy_denied",
            "operation_failed",
            "unavailable",
        ]
        .contains(&kind)
        {
            Some(kind)
        } else {
            None
        };
        let data = if kind == "empty-data" {
            b"".as_slice()
        } else {
            b"result".as_slice()
        };
        let response = server.seal_response(&mut b, id, data, error, 300).unwrap();
        assert!(server.seal_response(&mut b, id, data, error, 300).is_err());
        let mut other_id = String::new();
        let mut other_response = Vec::new();
        if ["cross-request", "out-of-order"].contains(&kind) {
            let other = client.seal_request(&mut a, b"other", 300).unwrap();
            server.open_request(&mut b, &other).unwrap();
            let m: Value = serde_json::from_slice(&other).unwrap();
            other_id = m["id"].as_str().unwrap().into();
            other_response = server
                .seal_response(&mut b, &other_id, b"other-result", None, 300)
                .unwrap();
        }
        let changed = response_mutation(&response, &request, kind, &other_id, &b);
        let accept =
            error.is_some() || ["valid", "empty-data", "reverse", "out-of-order"].contains(&kind);
        let mut closed = false;
        match kind {
            "duplicate-terminal" => {
                client.open_response(&mut a, &response).unwrap();
            }
            "out-of-order" => assert_eq!(
                client.open_response(&mut a, &other_response).unwrap().data,
                b"other-result"
            ),
            "store-error" => c.0.borrow_mut().mode = kind.into(),
            "store-delay" | "revoke-init" | "revoke-resp" | "revoke-kem" | "source-error" => {
                c.0.borrow_mut().mode = kind.into();
                closed = true
            }
            "key-expiry-during-commit" => {
                c.0.borrow_mut().mode = "utc-delay".into();
                closed = true
            }
            "closed" => {
                client.close();
                closed = true
            }
            "expired" => c.0.borrow_mut().utc = 400,
            _ => {}
        }
        let before = c.0.borrow().records;
        let result = client.open_response(&mut a, &changed);
        assert_eq!(result.is_ok(), accept, "{kind}");
        if accept {
            let r = result.unwrap();
            assert_eq!(r.message_id, id);
            assert_eq!(r.success, error.is_none());
            assert_eq!(r.error, error.unwrap_or(""));
            assert_eq!(r.data, data);
            assert!(client.open_response(&mut a, &response).is_err());
        } else {
            assert_eq!(c.0.borrow().records, before, "{kind}: partial replay");
            if closed {
                assert_eq!(client.state(), "CLOSED", "{kind}")
            } else if !["duplicate-terminal", "expired"].contains(&kind) {
                c.0.borrow_mut().mode.clear();
                assert_eq!(
                    client.open_response(&mut a, &response).unwrap().data,
                    data,
                    "{kind}: consumed pending/sequence"
                )
            }
        }
    }
}

#[test]
fn session_response_retained_copy_and_admission() {
    let (mut a, mut b, _c, _tmp) = pair();
    let (mut p, q) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
    let (mut server, r) = b.respond(&q, 300).unwrap();
    let mut client = p.complete(&mut a, &r).unwrap();
    let mut q = client.seal_request(&mut a, b"request", 300).unwrap();
    assert!(server
        .seal_response(
            &mut b,
            "11111111-1111-4111-8111-111111111111",
            b"",
            None,
            300
        )
        .is_err());
    server.open_request(&mut b, &q).unwrap();
    let m: Value = serde_json::from_slice(&q).unwrap();
    let id = m["id"].as_str().unwrap();
    q.fill(0);
    for code in ["", "unknown"] {
        assert!(server
            .seal_response(&mut b, id, b"", Some(code), 300)
            .is_err())
    }
    assert!(server
        .seal_response(&mut b, id, &vec![0; 16349], None, 300)
        .is_err());
    let r = server
        .seal_response(&mut b, id, &vec![0; 16348], None, 300)
        .unwrap();
    assert_eq!(client.open_response(&mut a, &r).unwrap().data.len(), 16348);
}

fn mutate_http(m: &HTTPMessage010, kind: &str) -> HTTPMessage010 {
    let mut m = m.clone();
    match kind {
        "request-method" => m.method = "GET".into(),
        "request-target" => m.target.push_str("?other=1"),
        "request-authority" => m.authority = "other.example".into(),
        "response-status" => m.status = 204,
        "response-status-tamper" => m.status = 201,
        "body-digest" => m.body.push(b' '),
        "duplicate-signature"
        | "duplicate-input"
        | "duplicate-digest"
        | "duplicate-type"
        | "duplicate-sage" => {
            let k = match kind {
                "duplicate-signature" => "signature",
                "duplicate-input" => "signature-input",
                "duplicate-digest" => "content-digest",
                "duplicate-type" => "content-type",
                _ => "x-sage-did",
            };
            let p = m.headers.iter().find(|p| p[0] == k).unwrap();
            m.headers.push([k.to_uppercase(), p[1].clone()]);
        }
        _ => {
            let set = match kind {
                "content-type" => Some(("content-type", "application/json; charset=utf-8")),
                "content-encoding" => Some(("content-encoding", "identity")),
                "transfer-encoding" => Some(("transfer-encoding", "chunked")),
                "trailer" => Some(("trailer", "signature")),
                "content-length" => Some(("content-length", "1")),
                "header-control" => Some(("extra", "a\nb")),
                "version" => Some(("x-sage-version", "1.0")),
                "did" => Some(("x-sage-did", "did:sage:web:agent.example:other")),
                "projection" => Some(("x-sage-context-id", "other")),
                "metadata" => Some(("x-sage-meta-key", "value")),
                _ => None,
            };
            if let Some((k, v)) = set {
                if let Some(p) = m.headers.iter_mut().find(|p| p[0] == k) {
                    p[1] = v.into()
                } else {
                    m.headers.push([k.into(), v.into()])
                }
            }
            for p in &mut m.headers {
                if p[0] == "signature" {
                    match kind {
                        "signature" => p[1] = format!("sig1=:{}==:", "A".repeat(86)),
                        "multiple-signatures" => p[1] = format!("{}, {}", p[1], p[1]),
                        "noncanonical-base64" => p[1] = p[1].replace("=:", ":"),
                        _ => {}
                    }
                }
                if p[0] == "signature-input" {
                    p[1] = match kind {
                        "unknown-parameter" => format!("{};extra=1", p[1]),
                        "duplicate-parameter" => format!("{};tag=\"sage-0.10.0\"", p[1]),
                        "wrong-tag" => p[1].replace("sage-0.10.0", "sage-1.0"),
                        "wrong-keyid" => p[1].replace("#signing-1", "#other"),
                        "wrong-nonce" => p[1].replace(";nonce=\"", ";nonce=\"A"),
                        "wrong-created" => p[1].replace(";created=100", ";created=101"),
                        "wrong-alg" => p[1].replace("ed25519", "rsa-pss-sha512"),
                        "coverage" => p[1].replace("\"@method\"", "\"@path\""),
                        _ => p[1].clone(),
                    };
                }
            }
        }
    }
    m
}
#[test]
fn http_session_scenarios() {
    let f: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/http-session010.json")).unwrap();
    for v in f["cases"].as_array().unwrap() {
        let kind = v.as_str().unwrap();
        let (mut a, mut b, c, _tmp) = pair();
        let (mut p, q) = a.start(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        let (mut server, r) = b.respond(&q, 300).unwrap();
        let mut client = p.complete(&mut a, &r).unwrap();
        client.bind_http("https://agent.example/messages").unwrap();
        server.bind_http("https://agent.example/messages").unwrap();
        let mut q = client.seal_http_request(&mut a, b"request", 300).unwrap();
        let invalid = kind.starts_with("request-")
            || kind.starts_with("duplicate-")
            || kind.starts_with("wrong-")
            || kind.starts_with("content-")
            || [
                "body-digest",
                "header-control",
                "unknown-parameter",
                "transfer-encoding",
                "trailer",
                "version",
                "did",
                "projection",
                "metadata",
                "signature",
                "multiple-signatures",
                "noncanonical-base64",
                "coverage",
            ]
            .contains(&kind);
        if invalid {
            assert!(
                server
                    .open_http_request(&mut b, &mutate_http(&q, kind))
                    .is_err(),
                "{kind}"
            );
            assert_eq!(server.state(), "RESPONSE_SENT");
        }
        if kind == "bare-bypass" {
            assert!(server.open_request(&mut b, &q.body).is_err());
            assert!(client.seal_request(&mut a, b"", 300).is_err());
        }
        assert_eq!(server.open_http_request(&mut b, &q).unwrap(), b"request");
        assert!(server.open_http_request(&mut b, &q).is_err());
        if kind == "reverse" {
            std::mem::swap(&mut a, &mut b);
            std::mem::swap(&mut client, &mut server);
            q = client.seal_http_request(&mut a, b"request", 300).unwrap();
            server.open_http_request(&mut b, &q).unwrap();
        }
        let w: Value = serde_json::from_slice(&q.body).unwrap();
        let id = w["id"].as_str().unwrap();
        let data = if kind == "empty" {
            b"".as_slice()
        } else {
            b"result".as_slice()
        };
        let error = if kind == "error" {
            Some("policy_denied")
        } else {
            None
        };
        let mut r = server
            .seal_http_response(&mut b, id, data, error, 300, 200)
            .unwrap();
        assert!(server
            .seal_http_response(&mut b, id, data, error, 300, 200)
            .is_err());
        if kind == "response-status" || kind == "response-status-tamper" {
            assert!(client
                .open_http_response(&mut a, &mutate_http(&r, kind))
                .is_err());
        }
        if kind == "reordered-parameters" {
            for p in &mut r.headers {
                if p[0] == "signature-input" {
                    let (prefix, rest) = p[1].split_once(");").unwrap();
                    let fields: Vec<_> = rest.split(';').rev().collect();
                    p[1] = format!("{prefix});{}", fields.join(";"));
                }
            }
            record010::http010::resign_test(&mut r, &b, Some(&q));
        }
        if kind == "inner-signature" {
            let mut bad = r.clone();
            let mut body: Value = serde_json::from_slice(&bad.body).unwrap();
            body["signature"] = json!("A".repeat(86));
            bad.body = canonical(&body);
            record010::http010::resign_test(&mut bad, &b, Some(&q));
            assert!(client.open_http_response(&mut a, &bad).is_err());
        }
        if kind == "response-request-signature" {
            let mut altered = q.clone();
            altered
                .headers
                .iter_mut()
                .find(|p| p[0] == "signature")
                .unwrap()[1]
                .push_str("wrong");
            let mut bad = r.clone();
            record010::http010::resign_test(&mut bad, &b, Some(&altered));
            assert!(client.open_http_response(&mut a, &bad).is_err());
        }
        if ["store-error", "store-delay", "revoke-resp"].contains(&kind) {
            c.0.borrow_mut().mode = kind.into();
            assert!(client.open_http_response(&mut a, &r).is_err());
            c.0.borrow_mut().mode.clear();
            if kind != "store-error" {
                assert_eq!(client.state(), "CLOSED");
                continue;
            }
        }
        if kind == "expired" {
            c.0.borrow_mut().utc = 400;
            assert!(client.open_http_response(&mut a, &r).is_err());
            continue;
        }
        let v = client.open_http_response(&mut a, &r).unwrap();
        assert_eq!(v.message_id, id);
        assert_eq!(v.success, error.is_none());
        assert_eq!(v.error, error.unwrap_or(""));
        assert_eq!(v.data, data);
        assert!(client.open_http_response(&mut a, &r).is_err());
    }
}

const HTTP_TARGET: &str = "https://localhost:8443/messages";
#[test]
fn http_handshake_scenarios() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/http-handshake010.json"
    ))
    .unwrap();
    for kind in f["cases"].as_array().unwrap() {
        let kind = kind.as_str().unwrap();
        let (mut a, mut b, c, _tmp) = pair();
        a.bind_http(HTTP_TARGET).unwrap();
        b.bind_http(HTTP_TARGET).unwrap();
        let (mut p, q) = a.start_http(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
        if kind == "bare-bypass" {
            assert!(a.start(BOB, &format!("{BOB}#signing-1"), 300).is_err());
            assert!(b.respond(&q.body, 300).is_err());
        }
        if kind.starts_with("request-") {
            let name = match kind {
                "request-signature" => "signature",
                "request-digest" => "body-digest",
                "request-duplicate" => "duplicate-signature",
                _ => kind,
            };
            assert!(b.respond_http(&mutate_http(&q, name), 300).is_err());
        }
        let raw = encode_http_010(&q, HTTP_TARGET).unwrap();
        let parsed = parse_http_010(&raw, HTTP_TARGET, false).unwrap();
        let (mut server, mut r) = b.respond_http(&parsed, 300).unwrap();
        if kind == "first-record" {
            assert!(server.seal_http_request(&mut b, b"", 300).is_err());
        }
        if kind == "duplicate-initiation" {
            assert!(b.respond_http(&q, 300).is_err());
        }
        if kind == "bare-bypass" {
            assert!(p.complete(&mut a, &r.body).is_err());
        }
        let mut reject = false;
        match kind {
            "response-signature" => {
                r = mutate_http(&r, "signature");
                reject = true
            }
            "response-status" => {
                r = mutate_http(&r, "response-status-tamper");
                reject = true
            }
            "response-digest" => {
                r = mutate_http(&r, "body-digest");
                reject = true
            }
            "response-request-signature" => {
                let mut other = q.clone();
                other
                    .headers
                    .iter_mut()
                    .find(|p| p[0] == "signature")
                    .unwrap()[1]
                    .push_str("different");
                record010::http010::resign_test(&mut r, &b, Some(&other));
                reject = true
            }
            "inner-completion" => {
                r.body = changed(&q.body, &r.body, "inner-signature");
                record010::http010::resign_test(&mut r, &b, Some(&q));
                reject = true
            }
            "revoke-resp" | "store-delay" | "store-error" => {
                c.0.borrow_mut().mode = kind.into();
                reject = true
            }
            "expired" => {
                c.0.borrow_mut().utc = 400;
                reject = true
            }
            "closed-pending" => {
                p.close();
                reject = true
            }
            _ => {}
        }
        let result = p.complete_http(&mut a, &r);
        if reject {
            assert!(result.is_err(), "{kind}");
            assert_eq!(p.state(), "CLOSED");
            continue;
        }
        let mut client = result.unwrap();
        assert!(p.complete_http(&mut a, &r).is_err());
        assert!(client.seal_request(&mut a, b"", 300).is_err());
        let request = client.seal_http_request(&mut a, b"request", 300).unwrap();
        assert!(server.open_request(&mut b, &request.body).is_err());
        assert_eq!(
            server.open_http_request(&mut b, &request).unwrap(),
            b"request"
        );
        assert_eq!(server.state(), "ESTABLISHED");
        let w: Value = serde_json::from_slice(&request.body).unwrap();
        let code = if kind == "error-response" {
            Some("operation_failed")
        } else {
            None
        };
        let response = server
            .seal_http_response(&mut b, w["id"].as_str().unwrap(), b"result", code, 300, 200)
            .unwrap();
        let raw = encode_http_010(&response, HTTP_TARGET).unwrap();
        let parsed = parse_http_010(&raw, HTTP_TARGET, true).unwrap();
        let result = client.open_http_response(&mut a, &parsed).unwrap();
        assert_eq!(result.success, code.is_none());
        assert_eq!(result.data, b"result");
    }
}
#[test]
fn http_framing_rejections() {
    let (mut a, _b, _c, _tmp) = pair();
    a.bind_http(HTTP_TARGET).unwrap();
    let (_p, m) = a.start_http(BOB, &format!("{BOB}#signing-1"), 300).unwrap();
    let original = String::from_utf8(encode_http_010(&m, HTTP_TARGET).unwrap()).unwrap();
    let (head, body) = original.split_once("\r\n\r\n").unwrap();
    let length = head
        .split("\r\n")
        .find(|l| l.starts_with("Content-Length:"))
        .unwrap();
    let first = head.split_once("\r\n").unwrap().0;
    let padding = 32768 - (head.len() - first.len()) - 10;
    let exact = format!("{head}\r\nPadding:{}", " ".repeat(padding));
    assert!(parse_http_010(
        format!("{exact}\r\n\r\n{body}").as_bytes(),
        HTTP_TARGET,
        false
    )
    .is_ok());
    assert!(parse_http_010(
        format!("{exact} \r\n\r\n{body}").as_bytes(),
        HTTP_TARGET,
        false
    )
    .is_err());
    let mut cases = vec![
        format!("{head}\r\n{length}"),
        format!("{head}\r\nContent-Length: 1"),
        head.replace(&format!("\r\n{length}"), ""),
        head.replace("Content-Length: ", "Content-Length: 0"),
        head.replace("\r\nHost: localhost:8443", ""),
        head.replace("Host: localhost:8443", "Host: other.example"),
        head.replace("POST /messages", &format!("POST {HTTP_TARGET}")),
        head.replace("POST /messages", "POST /other"),
        head.replace("HTTP/1.1", "HTTP/1.0"),
        head.replace("Connection: close", "Connection: keep-alive"),
    ];
    for h in [
        "Transfer-Encoding: chunked",
        "Trailer: signature",
        "Content-Encoding: identity",
        "HOST: localhost:8443",
        " continued",
        "Name : value",
        "Name: a\tb",
        "Upgrade: websocket",
        "Expect: 100-continue",
    ] {
        cases.push(format!("{head}\r\n{h}"));
    }
    for h in cases {
        assert!(
            parse_http_010(format!("{h}\r\n\r\n{body}").as_bytes(), HTTP_TARGET, false).is_err()
        );
    }
    for raw in [
        original[..original.len() - 1].to_owned(),
        format!("{original}x"),
        original.replace("\r\n", "\n"),
    ] {
        assert!(parse_http_010(raw.as_bytes(), HTTP_TARGET, false).is_err());
    }
    let mut duplicate = m.clone();
    duplicate.headers.push(m.headers[5].clone());
    assert!(encode_http_010(&duplicate, HTTP_TARGET).is_err());
    let mut injection = m;
    injection
        .headers
        .push(["extra".into(), "value\r\nInjected: yes".into()]);
    assert!(encode_http_010(&injection, HTTP_TARGET).is_err());
}
