use super::fixtures_test::Fixture;
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Services(Arc<Mutex<Value>>);
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
    fn active_key(&mut self, i: &str, k: &str) -> Result<[u8; 32]> {
        ensure(k == format!("{i}#signing-1"))?;
        Fixture(self.0.lock().unwrap()["input"].clone()).active_key(i, k)
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
impl IssuancePolicy for Services {
    fn approve_intent(&mut self, body: &[u8]) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        s["approvals"] = json!(s["approvals"].as_u64().unwrap_or(0) + 1);
        let panics = s["panic_policy"] == true;
        let intent: Value = serde_json::from_slice(body).map_err(|_| Invalid)?;
        let approved = s["deny"] != true
            && intent["recipient"] == s["input"]["expected_recipient"]
            && intent["alg"] == "ed25519";
        drop(s);
        if panics {
            panic!("bounded fixture evaluator failure")
        };
        ensure(approved)
    }
}
impl IntentMeasurement for Services {
    fn check(&mut self, manifest: &str, tool: &str) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        s["measures"] = json!(s["measures"].as_u64().unwrap_or(0) + 1);
        ensure(
            s["changed"] != true
                && s["measures"] != s["fail_measure_at"]
                && manifest_commitment(
                    &serde_json::to_vec(&s["input"]["approved_manifest"]).unwrap(),
                )? == manifest
                && tool == "read",
        )
    }
}
impl IntentSigner for Services {
    fn sign(&mut self, kid: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut s = self.0.lock().unwrap();
        s["signs"] = json!(s["signs"].as_u64().unwrap_or(0) + 1);
        ensure(
            s["approvals"].as_u64().unwrap_or(0) > 0
                && s["measures"].as_u64().unwrap_or(0) > 0
                && kid == format!("{}#signing-1", text(&s["input"], "expected_issuer"))
                && body.starts_with(b"sage-execution-intent|0.10.0\0"),
        )?;
        ensure(
            Path::new(&format!("{}.issuance", text(&s, "path"))).exists() && s["fail_sign"] != true,
        )?;
        let seed: [u8; 32] = Sha256::digest(if s["wrong_sign"] == true {
            b"public unrelated fixture signer".as_slice()
        } else {
            b"public Guard fixture issuer".as_slice()
        })
        .into();
        let proof = SigningKey::from_bytes(&seed).sign(body).to_bytes().to_vec();
        if s["change_after_sign"] == true {
            s["changed"] = json!(true);
        }
        Ok(proof)
    }
}
impl ClientSender for Services {
    fn commit(&mut self, id: &str, raw: &[u8]) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        s["sends"] = json!(s["sends"].as_u64().unwrap_or(0) + 1);
        s["sent_id"] = json!(id);
        s["sent_intent"] = json!(hex::encode(raw));
        Ok(())
    }
}
impl HopParent for Services {
    fn authorized(&mut self, _: &[u8]) -> Result<()> {
        ensure(self.0.lock().unwrap()["parent_allowed"] != false)
    }
}
impl Services {
    fn new() -> Self {
        let mut v: Value =
            serde_json::from_str(include_str!("testdata/guard-client.json")).unwrap();
        v["input"]["original_digest"] =
            json!(original_commitment(&[b"trusted root input".to_vec()]).unwrap());
        Self(Arc::new(Mutex::new(
            json!({"input":v["input"],"utc":1700000000000_i64,"mono":0,"clock_ok":true}),
        )))
    }
    fn set(&self, k: &str, v: Value) {
        self.0.lock().unwrap()[k] = v;
    }
    fn count(&self, k: &str) -> u64 {
        self.0.lock().unwrap()[k].as_u64().unwrap_or(0)
    }
    fn config(&self) -> IssuerServices {
        let s = self.0.lock().unwrap();
        let issuer = text(&s["input"], "expected_issuer").to_owned();
        let recipient = text(&s["input"], "expected_recipient").to_owned();
        drop(s);
        IssuerServices {
            client: ClientServices {
                intent_authority: Box::new(self.clone()),
                policy: Box::new(self.clone()),
                result_authority: Box::new(self.clone()),
                clock: Box::new(self.clone()),
                sender: Box::new(self.clone()),
                expected_issuer: issuer.clone(),
                expected_recipient: recipient,
            },
            policy: Box::new(self.clone()),
            signer: Box::new(self.clone()),
            measurement: Box::new(self.clone()),
            key_id: format!("{issuer}#signing-1"),
        }
    }
    fn issuer(&self) -> IntentIssuer {
        IntentIssuer::new(
            RootCapture::new(
                &[b"trusted root input".to_vec()],
                "00000000-0000-4000-8000-000000000002",
            )
            .unwrap(),
            self.config(),
        )
        .unwrap()
    }
    fn path(&self, dir: &Path) -> PathBuf {
        let path = dir.join("operation");
        self.set("path", json!(path));
        path
    }
}
fn proposal() -> IntentProposal {
    IntentProposal {
        tool: "read".into(),
        arguments: br#"{"path":"notes.txt"}"#.to_vec(),
        lifetime_seconds: 300,
    }
}

#[test]
fn issuer_journals_and_resumes_without_new_signature() {
    let f = Services::new();
    let directory = tempfile::tempdir().unwrap();
    let path = f.path(directory.path());
    let mut issuer = f.issuer();
    let mut token = issuer.authorize(proposal()).unwrap();
    assert_eq!(f.count("signs"), 0);
    assert_eq!(f.count("sends"), 0);
    let client = issuer.issue(&path, &mut token).unwrap();
    assert_eq!(f.count("signs"), 1);
    assert_eq!(f.count("sends"), 0);
    let invocation = client
        .begin("00000000-0000-4000-8000-000000000020")
        .unwrap();
    let raw = invocation.intent().to_vec();
    let recipient = text(&f.0.lock().unwrap()["input"], "expected_recipient").to_owned();
    let verified = verify_intent(&raw, &recipient, &mut f.clone(), &mut f.clone()).unwrap();
    assert_eq!(verified.canonical(), raw);
    assert_eq!(
        intent_envelope(&raw).unwrap().0["intent"]["arguments"]["path"],
        "notes.txt"
    );
    client.close().unwrap();
    let resumed = f.issuer().reopen(&path).unwrap();
    f.set("utc", json!(1700000001000_i64));
    f.set("mono", json!(1000));
    let retry = resumed
        .begin("00000000-0000-4000-8000-000000000021")
        .unwrap();
    assert_eq!(retry.intent(), raw);
    assert_eq!(f.count("signs"), 1);
    assert_eq!(f.count("sends"), 2);
    resumed.close().unwrap();
}
#[test]
fn issuer_denies_changed_authority_before_key_use() {
    for mode in [
        "policy",
        "epoch",
        "original",
        "measurement",
        "key",
        "expiry",
        "retirement",
    ] {
        let f = Services::new();
        let directory = tempfile::tempdir().unwrap();
        let path = f.path(directory.path());
        let mut issuer = f.issuer();
        let mut token = issuer.authorize(proposal()).unwrap();
        match mode {
            "policy" => f.set("deny", json!(true)),
            "epoch" => {
                f.0.lock().unwrap()["input"]["approved_policy"]["epoch"] =
                    json!("00000000-0000-4000-8000-000000000099")
            }
            "original" => {
                f.0.lock().unwrap()["input"]["original_digest"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000")
            }
            "measurement" => f.set("changed", json!(true)),
            "key" => f.0.lock().unwrap()["input"]["active_key"] = json!(false),
            "expiry" => f.set("utc", json!(1700000300000_i64)),
            _ => issuer.retire().unwrap(),
        }
        assert!(issuer.issue(&path, &mut token).is_err(), "{mode}");
        assert_eq!(f.count("signs"), 0);
        assert_eq!(f.count("sends"), 0);
        assert!(!path.exists());
        f.set("deny", json!(false));
        f.set("changed", json!(false));
        assert!(issuer.issue(&path, &mut token).is_err());
        assert_eq!(f.count("signs"), 0);
    }
}
#[test]
fn issuer_preserves_failure_fence_across_restart() {
    for mode in ["signer-failure", "wrong-proof", "partial-fence"] {
        let f = Services::new();
        let directory = tempfile::tempdir().unwrap();
        let path = f.path(directory.path());
        f.set("fail_sign", json!(mode == "signer-failure"));
        f.set("wrong_sign", json!(mode == "wrong-proof"));
        let fence = directory.path().join("operation.issuance");
        if mode == "partial-fence" {
            std::fs::write(&fence, []).unwrap();
        }
        let mut issuer = f.issuer();
        let mut token = issuer.authorize(proposal()).unwrap();
        assert!(issuer.issue(&path, &mut token).is_err());
        let before = f.count("signs");
        f.set("fail_sign", json!(false));
        f.set("wrong_sign", json!(false));
        let mut restarted = f.issuer();
        let mut fresh = restarted.authorize(proposal()).unwrap();
        assert!(restarted.issue(&path, &mut fresh).is_err());
        assert_eq!(f.count("signs"), before);
        assert!(f.issuer().reopen(&path).is_err());
        assert!(fence.exists());
    }
}
#[test]
fn issuer_enforces_owner_and_one_use() {
    let f = Services::new();
    let directory = tempfile::tempdir().unwrap();
    let path = f.path(directory.path());
    let mut issuer = f.issuer();
    let mut token = issuer.authorize(proposal()).unwrap();
    assert!(f.issuer().issue(&path, &mut token).is_err());
    assert_eq!(f.count("signs"), 0);
    let client = issuer.issue(&path, &mut token).unwrap();
    assert!(issuer.issue(&path, &mut token).is_err());
    assert_eq!(f.count("signs"), 1);
    client.close().unwrap();
}
#[test]
fn issuer_rejects_invalid_proposal_and_retires_after_panic() {
    for (tool, args, lifetime) in [
        ("read", br#"{"path":"x","path":"y"}"#.as_slice(), 300),
        ("sage_secure_call", b"{}".as_slice(), 300),
        ("read", br#"{"path":"x"}"#.as_slice(), 301),
        ("read", br#"{"unexpected":"x"}"#.as_slice(), 300),
    ] {
        let f = Services::new();
        assert!(f
            .issuer()
            .authorize(IntentProposal {
                tool: tool.into(),
                arguments: args.to_vec(),
                lifetime_seconds: lifetime
            })
            .is_err());
        assert_eq!(f.count("signs"), 0);
    }
    let f = Services::new();
    let mut issuer = f.issuer();
    f.set("panic_policy", json!(true));
    assert!(issuer.authorize(proposal()).is_err());
    f.set("panic_policy", json!(false));
    assert!(issuer.authorize(proposal()).is_err());
}
#[test]
fn hop_issuer_requires_admitted_parent_before_signing() {
    for allowed in [true, false] {
        let suite: Value =
            serde_json::from_str(include_str!("testdata/guard-client.json")).unwrap();
        let incoming = hex::decode(text(&suite["input"], "envelope_hex")).unwrap();
        let parent = Services::new();
        parent.0.lock().unwrap()["input"] = suite["input"].clone();
        let child = Services::new();
        let old_issuer = text(&suite["input"], "expected_issuer");
        let issuer = text(&suite["input"], "expected_recipient");
        {
            let mut state = child.0.lock().unwrap();
            state["input"]["expected_issuer"] = json!(issuer);
            state["input"]["expected_recipient"] = json!(old_issuer);
            state["input"]["approved_policy"]["issuer"] = json!(issuer);
            state["input"]["original_digest"] =
                json!(original_commitment(std::slice::from_ref(&incoming)).unwrap());
        }
        let directory = tempfile::tempdir().unwrap();
        let path = child.path(directory.path());
        let capture = RootCapture::new(
            std::slice::from_ref(&incoming),
            "00000000-0000-4000-8000-000000000011",
        )
        .unwrap();
        let mut gate = IntentIssuer::new_hop(
            capture,
            child.config(),
            &incoming,
            HopServices {
                authority: Box::new(parent.clone()),
                policy: Box::new(parent.clone()),
                parent: Box::new(parent.clone()),
            },
        )
        .unwrap();
        let mut token = gate.authorize(proposal()).unwrap();
        parent.set("parent_allowed", json!(allowed));
        let result = gate.issue(&path, &mut token);
        if !allowed {
            assert!(result.is_err());
            assert_eq!(child.count("signs"), 0);
            continue;
        }
        let client = result.unwrap();
        let invocation = client
            .begin("00000000-0000-4000-8000-000000000030")
            .unwrap();
        let envelope = intent_envelope(invocation.intent()).unwrap().0;
        assert_eq!(
            envelope["intent"]["parent_call_id"],
            intent_envelope(&incoming).unwrap().0["intent"]["call_id"]
        );
        client.close().unwrap();
    }
}

#[test]
fn issuer_process_helper() {
    let Some(path) = std::env::var_os("SAGE_INTENT_ISSUANCE_TEST_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let f = Services::new();
    f.set("path", json!(path));
    let mut issuer = f.issuer();
    match std::env::var("SAGE_INTENT_ISSUANCE_TEST_MODE")
        .unwrap()
        .as_str()
    {
        "issue" => {
            let mut token = issuer.authorize(proposal()).unwrap();
            let client = issuer.issue(&path, &mut token).unwrap();
            client
                .begin("00000000-0000-4000-8000-000000000040")
                .unwrap();
            assert_eq!(f.count("signs"), 1);
            client.close().unwrap();
        }
        "reopen" => {
            let client = issuer.reopen(&path).unwrap();
            f.set("utc", json!(1700000001000_i64));
            f.set("mono", json!(1000));
            client
                .begin("00000000-0000-4000-8000-000000000041")
                .unwrap();
            assert_eq!(f.count("signs"), 0);
            client.close().unwrap();
        }
        mode @ ("sign-failure" | "fenced") => {
            f.set("fail_sign", json!(mode == "sign-failure"));
            let mut token = issuer.authorize(proposal()).unwrap();
            assert!(issuer.issue(&path, &mut token).is_err());
            assert_eq!(f.count("signs"), u64::from(mode == "sign-failure"));
        }
        _ => panic!("unknown bounded fixture"),
    }
}
#[test]
fn issuer_process_restart() {
    let run = |path: &Path, mode: &str| {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "guard010::issuance_tests::issuer_process_helper"])
            .env("SAGE_INTENT_ISSUANCE_TEST_PATH", path)
            .env("SAGE_INTENT_ISSUANCE_TEST_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operation");
    run(&path, "issue");
    let before = std::fs::read(&path).unwrap();
    run(&path, "reopen");
    let after = std::fs::read(&path).unwrap();
    assert!(after.starts_with(&before));
    let failed = directory.path().join("failed");
    run(&failed, "sign-failure");
    run(&failed, "fenced");
    assert!(!failed.exists());
}

#[test]
fn issuer_rechecks_after_fence_and_after_signing() {
    for post_sign in [false, true] {
        let f = Services::new();
        let directory = tempfile::tempdir().unwrap();
        let path = f.path(directory.path());
        let mut issuer = f.issuer();
        let mut token = issuer.authorize(proposal()).unwrap();
        if post_sign {
            f.set("change_after_sign", json!(true));
        } else {
            f.set("fail_measure_at", json!(3));
        }
        assert!(issuer.issue(&path, &mut token).is_err());
        assert_eq!(f.count("signs"), u64::from(post_sign));
        assert_eq!(f.count("sends"), 0);
        assert!(!path.exists());
        assert!(directory.path().join("operation.issuance").exists());
    }
}

#[test]
fn issuer_rejects_other_key_role_and_weak_key() {
    for role in ["kem-1", "weak-signing-1", "foreign"] {
        let f = Services::new();
        let mut config = f.config();
        match role {
            "kem-1" => config.key_id = config.key_id.replace("#signing-1", "#kem-1"),
            "weak-signing-1" => {
                f.0.lock().unwrap()["input"]["public_key_hex"] =
                    json!("0000000000000000000000000000000000000000000000000000000000000000")
            }
            _ => config.key_id = "did:sage:web:agents.example.com:other#signing-1".into(),
        }
        let capture = RootCapture::new(
            &[b"trusted root input".to_vec()],
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap();
        if let Ok(mut issuer) = IntentIssuer::new(capture, config) {
            assert!(issuer.authorize(proposal()).is_err(), "{role}");
        }
        assert_eq!(f.count("signs"), 0);
    }
}

#[test]
fn issuer_preserves_quoted_argument_strings() {
    let f = Services::new();
    let directory = tempfile::tempdir().unwrap();
    let path = f.path(directory.path());
    let mut issuer = f.issuer();
    let expected = "notes \"quoted\" \\ folder\nname <>&";
    let mut p = proposal();
    p.arguments = serde_json::to_vec(&json!({"path":expected})).unwrap();
    let mut token = issuer.authorize(p).unwrap();
    let client = issuer.issue(&path, &mut token).unwrap();
    let invocation = client
        .begin("00000000-0000-4000-8000-000000000050")
        .unwrap();
    assert_eq!(
        intent_envelope(invocation.intent()).unwrap().0["intent"]["arguments"]["path"],
        expected
    );
    let recipient = text(&f.0.lock().unwrap()["input"], "expected_recipient").to_owned();
    verify_intent(
        invocation.intent(),
        &recipient,
        &mut f.clone(),
        &mut f.clone(),
    )
    .unwrap();
    client.close().unwrap();
}

#[test]
fn journaled_intent_snapshot_does_not_use_authority_or_transport() {
    let f = Services::new();
    let directory = tempfile::tempdir().unwrap();
    let path = f.path(directory.path());
    let mut issuer = f.issuer();
    let mut token = issuer.authorize(proposal()).unwrap();
    let client = issuer.issue(&path, &mut token).unwrap();
    let before = std::fs::read(&path).unwrap();
    let original = client.journaled_intent().unwrap();
    let mut altered = original.clone();
    altered[0] ^= 1;
    assert_eq!(client.journaled_intent().unwrap(), original);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(f.count("signs"), 1);
    assert_eq!(f.count("sends"), 0);
    client.close().unwrap();
    assert!(client.journaled_intent().is_err());
    let resumed = f.issuer().reopen(&path).unwrap();
    assert_eq!(resumed.journaled_intent().unwrap(), original);
    assert_eq!(f.count("signs"), 1);
    assert_eq!(f.count("sends"), 0);
    resumed.close().unwrap();
}
