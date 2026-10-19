use super::fixtures_test::Fixture;
use super::*;
use serde_json::Value;

fn valid_intent() -> (Value, Vec<u8>) {
    let c: Value = serde_json::from_str::<Value>(include_str!("testdata/guard-records.json"))
        .unwrap()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "intent-valid")
        .unwrap()
        .clone();
    let raw = hex::decode(c["input"]["envelope_hex"].as_str().unwrap()).unwrap();
    (c["input"].clone(), raw)
}

/// Receiver administration for one provisioned commitment. It knows the
/// descriptors but never the original request.
struct Mapping {
    issuer: String,
    digest: String,
    policy: Vec<u8>,
    manifest: Vec<u8>,
    deny: bool,
    retired: bool,
    seen: Option<(String, String)>,
}
impl ReceiverMapping for Mapping {
    fn approved(&mut self, issuer: &str, digest: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        self.seen = Some((issuer.into(), digest.into()));
        if self.retired || issuer != self.issuer || digest != self.digest {
            return Err(Invalid);
        }
        Ok((self.policy.clone(), self.manifest.clone()))
    }
    fn authorize(&mut self, issuer: &str, tool: &str, args: &[u8]) -> Result<()> {
        if self.deny || issuer != self.issuer || tool.is_empty() || args.is_empty() {
            return Err(Invalid);
        }
        Ok(())
    }
}

type Change = Box<dyn Fn(&mut Mapping)>;

fn mapping(f: &Value) -> Mapping {
    let policy = canonicalize(&serde_json::to_vec(&f["approved_policy"]).unwrap()).unwrap();
    Mapping {
        issuer: f["expected_issuer"].as_str().unwrap().into(),
        digest: policy_commitment(&policy).unwrap(),
        policy,
        manifest: serde_json::to_vec(&f["approved_manifest"]).unwrap(),
        deny: false,
        retired: false,
        seen: None,
    }
}

fn recipient(f: &Value) -> String {
    f["expected_recipient"].as_str().unwrap().into()
}

#[test]
fn receiver_mapping_verifies_without_original() {
    let (f, raw) = valid_intent();
    let mut p = ReceiverPolicy::new(mapping(&f));
    let v = verify_received_intent(&raw, &recipient(&f), &mut Fixture(f.clone()), &mut p).unwrap();
    assert!(!v.digest().is_empty());
    let seen = p.mapping.seen.clone().unwrap();
    assert_eq!(seen.0, f["expected_issuer"].as_str().unwrap());
    assert_eq!(seen.1, p.mapping.digest);
    // The ordinary policy path is unchanged at a receiver.
    assert!(verify_received_intent(
        &raw,
        &recipient(&f),
        &mut Fixture(f.clone()),
        &mut Fixture(f.clone())
    )
    .is_ok());
}

#[test]
fn receiver_mapping_refusals() {
    let (f, raw) = valid_intent();
    let other_epoch = |m: &mut Mapping| {
        let mut p: Value = serde_json::from_slice(&m.policy).unwrap();
        p["epoch"] = "00000000-0000-4000-8000-0000000000ff".into();
        m.policy = canonicalize(&serde_json::to_vec(&p).unwrap()).unwrap();
    };
    let cases: Vec<(&str, Change)> = vec![
        (
            "unknown-commitment",
            Box::new(|m: &mut Mapping| m.digest = format!("00{}", &m.digest[2..])),
        ),
        ("retired", Box::new(|m: &mut Mapping| m.retired = true)),
        (
            "other-issuer",
            Box::new(|m: &mut Mapping| m.issuer = "did:sage:web:other.example:x".into()),
        ),
        ("other-descriptor", Box::new(other_epoch)),
        (
            "other-manifest",
            Box::new(|m: &mut Mapping| m.manifest = br#"{"files":[],"version":"0.10.0"}"#.to_vec()),
        ),
        (
            "denied-arguments",
            Box::new(|m: &mut Mapping| m.deny = true),
        ),
    ];
    for (name, change) in cases {
        let mut m = mapping(&f);
        change(&mut m);
        let mut p = ReceiverPolicy::new(m);
        assert!(
            verify_received_intent(&raw, &recipient(&f), &mut Fixture(f.clone()), &mut p).is_err(),
            "{name} accepted"
        );
    }
    let mut p = ReceiverPolicy::new(mapping(&f));
    assert!(verify_received_intent(
        &raw,
        "did:sage:web:agent.example:other",
        &mut Fixture(f.clone()),
        &mut p
    )
    .is_err());
    let mut tampered = raw.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    assert!(
        verify_received_intent(&tampered, &recipient(&f), &mut Fixture(f.clone()), &mut p).is_err()
    );
}

#[test]
fn receiver_policy_is_receiver_only() {
    let (f, raw) = valid_intent();
    let mut p = ReceiverPolicy::new(mapping(&f));
    assert!(verify_intent(&raw, &recipient(&f), &mut Fixture(f.clone()), &mut p).is_err());
    assert!(p
        .bindings(f["expected_issuer"].as_str().unwrap(), "x")
        .is_err());
    // Strict original comparison remains for an ordinary policy at a receiver.
    let mut wrong = f.clone();
    let original = f["original_digest"].as_str().unwrap();
    wrong["original_digest"] = format!("00{}", &original[2..]).into();
    assert!(verify_received_intent(
        &raw,
        &recipient(&f),
        &mut Fixture(f.clone()),
        &mut Fixture(wrong)
    )
    .is_err());
}
