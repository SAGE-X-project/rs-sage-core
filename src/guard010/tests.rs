use super::*;
use serde_json::json;
fn cases() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("testdata/guard-records.json")).unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}
#[test]
fn frozen_independent_vectors() {
    let mut count = 0;
    for c in cases() {
        let op = c["operation"].as_str().unwrap();
        if !op.starts_with("sage.guard.") {
            continue;
        }
        let (verdict, output) = super::fixtures_test::observe(op, c["input"].clone()).unwrap();
        assert_eq!(
            json!({"verdict":verdict,"output":output}),
            c["expected"],
            "{}",
            c["id"]
        );
        count += 1;
    }
    assert_eq!(count, 94);
}
#[test]
fn strict_json_boundaries() {
    for s in [
        r#"{"a":1,"\u0061":2}"#,
        r#""\ud800""#,
        r#""\udc00""#,
        r#"{"x":-0}"#,
        r#"{"x":-1e-999}"#,
        r#"{"x":1e999}"#,
        "{}{}",
        "\u{feff}{}",
    ] {
        assert!(canonicalize(s.as_bytes()).is_err(), "{s}")
    }
    assert!(canonicalize(b"\xff").is_err());
    assert!(canonicalize(br#"{"x":"\ud83d\ude00"}"#).is_ok());
    assert!(canonicalize(br#"{"x":"\\ud800"}"#).is_ok());
    for n in [32, 33] {
        let raw = format!("{}0{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(canonicalize(raw.as_bytes()).is_ok(), n == 32)
    }
    for s in [
        "9007199254740990.1",
        "1.00000000000000000001",
        "1e-999",
        "9007199254740992",
    ] {
        assert!(exact_integer(s).is_err(), "{s}")
    }
    for s in ["1700000000.0", "170000000000e-2", "1.7e9"] {
        assert_eq!(exact_integer(s), Ok(1700000000))
    }
    assert!(!did("did:sage:web:example.com:.."));
    assert!(!did("did:sage:web:EXAMPLE.com:a"));
    assert!(!did("did:sage:solana:chain:a"));
}
struct NoAuthority;
impl Authority for NoAuthority {
    fn now(&mut self) -> Result<i64> {
        panic!("malformed input reached authority")
    }
    fn active_key(&mut self, _: &str, _: &str) -> Result<[u8; 32]> {
        panic!("malformed input reached key service")
    }
}
struct NoPolicy;
impl IntentPolicy for NoPolicy {
    fn bindings(&mut self, _: &str, _: &str) -> Result<Bindings> {
        panic!("malformed input reached policy")
    }
    fn authorize(&mut self, _: &str, _: &str, _: &[u8]) -> Result<()> {
        panic!("malformed input reached policy")
    }
}
#[test]
fn malformed_protocol_numbers_fail_before_authority() {
    let c = cases()
        .into_iter()
        .find(|c| c["id"] == "intent-valid")
        .unwrap();
    let raw = hex::decode(c["input"]["envelope_hex"].as_str().unwrap()).unwrap();
    let s = String::from_utf8(raw).unwrap();
    for literal in ["1700000000.0000000001", "-0", "9007199254740992"] {
        let s = s.replace("\"created\":1700000000", &format!("\"created\":{literal}"));
        assert!(verify_intent(
            s.as_bytes(),
            "did:sage:web:agents.example.com:executor",
            &mut NoAuthority,
            &mut NoPolicy
        )
        .is_err())
    }
}

#[test]
fn manifest_file_limit() {
    let files: Vec<_> = (0..4097)
        .map(|n| json!({"path":format!("f{n:04}"),"sha256":"0".repeat(64)}))
        .collect();
    for n in [4096, 4097] {
        let raw = serde_json::to_vec(&json!({"version":"0.10.0","files":&files[..n]})).unwrap();
        assert_eq!(manifest_commitment(&raw).is_ok(), n == 4096)
    }
}

#[test]
fn canonical_public_key_encoding() {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    assert!(!canonical_edwards_y(p));
    p[31] |= 0x80;
    assert!(!canonical_edwards_y(p));
    p[0] = 0xec;
    assert!(canonical_edwards_y(p));
}
