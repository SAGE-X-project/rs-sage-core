use super::*;
use serde_json::json;

fn frozen_cases() -> &'static [Value] {
    static CASES: std::sync::OnceLock<Vec<Value>> = std::sync::OnceLock::new();
    CASES.get_or_init(|| {
        serde_json::from_str::<Value>(include_str!("testdata/guard-records.json")).unwrap()["cases"]
            .as_array()
            .unwrap()
            .clone()
    })
}

fn cases() -> Vec<Value> {
    frozen_cases().to_vec()
}

// Keep the complete fixture inventory tied to the individually scheduled tests.
#[test]
fn frozen_independent_vectors() {
    let ids: Vec<_> = frozen_cases()
        .iter()
        .filter(|c| c["operation"].as_str().unwrap().starts_with("sage.guard."))
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 94);
    assert_eq!(ids.as_slice(), FROZEN_GUARD_CASES);
    let unique: std::collections::BTreeSet<_> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len());
}

fn check_frozen_guard_case(id: &str) {
    let c = frozen_cases()
        .iter()
        .find(|c| c["id"] == id && c["operation"].as_str().unwrap().starts_with("sage.guard."))
        .unwrap();
    let op = c["operation"].as_str().unwrap();
    let (verdict, output) = super::fixtures_test::observe(op, c["input"].clone()).unwrap();
    assert_eq!(
        json!({"verdict":verdict,"output":output}),
        c["expected"],
        "{}",
        c["id"]
    );
}

macro_rules! frozen_guard_case_tests {
    ($($name:ident => $case:literal,)*) => {
        const FROZEN_GUARD_CASES: &[&str] = &[$($case,)*];
        $(
            #[test]
            fn $name() {
                check_frozen_guard_case($case);
            }
        )*
    };
}

frozen_guard_case_tests! {
    frozen_guard_case_original_single => "original-single",
    frozen_guard_case_original_bundle => "original-bundle",
    frozen_guard_case_original_space => "original-space",
    frozen_guard_case_original_composed => "original-composed",
    frozen_guard_case_original_decomposed => "original-decomposed",
    frozen_guard_case_original_empty_item => "original-empty-item",
    frozen_guard_case_original_count_max => "original-count-max",
    frozen_guard_case_original_count_over => "original-count-over",
    frozen_guard_case_original_bytes_max => "original-bytes-max",
    frozen_guard_case_original_bytes_over => "original-bytes-over",
    frozen_guard_case_manifest_valid => "manifest-valid",
    frozen_guard_case_manifest_parent => "manifest-parent",
    frozen_guard_case_manifest_dot => "manifest-dot",
    frozen_guard_case_manifest_empty => "manifest-empty",
    frozen_guard_case_manifest_absolute => "manifest-absolute",
    frozen_guard_case_manifest_backslash => "manifest-backslash",
    frozen_guard_case_manifest_nul => "manifest-nul",
    frozen_guard_case_manifest_duplicate => "manifest-duplicate",
    frozen_guard_case_manifest_unsorted => "manifest-unsorted",
    frozen_guard_case_manifest_hash => "manifest-hash",
    frozen_guard_case_policy_members_2044 => "policy-members-2044",
    frozen_guard_case_policy_members_2045 => "policy-members-2045",
    frozen_guard_case_json_bytes_1048576 => "json-bytes-1048576",
    frozen_guard_case_json_bytes_1048577 => "json-bytes-1048577",
    frozen_guard_case_json_depth_32 => "json-depth-32",
    frozen_guard_case_json_depth_33 => "json-depth-33",
    frozen_guard_case_json_members_4096 => "json-members-4096",
    frozen_guard_case_json_members_4097 => "json-members-4097",
    frozen_guard_case_policy_valid => "policy-valid",
    frozen_guard_case_policy_empty => "policy-empty",
    frozen_guard_case_policy_version => "policy-version",
    frozen_guard_case_policy_epoch => "policy-epoch",
    frozen_guard_case_policy_engine => "policy-engine",
    frozen_guard_case_policy_published_example => "policy-published-example",
    frozen_guard_case_intent_valid => "intent-valid",
    frozen_guard_case_intent_last_second => "intent-last-second",
    frozen_guard_case_intent_expiry => "intent-expiry",
    frozen_guard_case_intent_early_limit => "intent-early-limit",
    frozen_guard_case_intent_too_early => "intent-too-early",
    frozen_guard_case_intent_clock => "intent-clock",
    frozen_guard_case_intent_inactive_key => "intent-inactive-key",
    frozen_guard_case_intent_recipient => "intent-recipient",
    frozen_guard_case_intent_original => "intent-original",
    frozen_guard_case_intent_policy_deny => "intent-policy-deny",
    frozen_guard_case_intent_version => "intent-version",
    frozen_guard_case_intent_profile => "intent-profile",
    frozen_guard_case_intent_tool => "intent-tool",
    frozen_guard_case_intent_recursive => "intent-recursive",
    frozen_guard_case_intent_arguments_extra => "intent-arguments-extra",
    frozen_guard_case_intent_arguments_missing => "intent-arguments-missing",
    frozen_guard_case_intent_arguments_type => "intent-arguments-type",
    frozen_guard_case_intent_lifetime => "intent-lifetime",
    frozen_guard_case_intent_policy_self_approved => "intent-policy-self-approved",
    frozen_guard_case_intent_manifest_self_approved => "intent-manifest-self-approved",
    frozen_guard_case_intent_key_binding => "intent-key-binding",
    frozen_guard_case_intent_parent_invalid => "intent-parent-invalid",
    frozen_guard_case_intent_unknown_field => "intent-unknown-field",
    frozen_guard_case_intent_null_arguments => "intent-null-arguments",
    frozen_guard_case_intent_array_arguments => "intent-array-arguments",
    frozen_guard_case_intent_tampered => "intent-tampered",
    frozen_guard_case_result_pending_valid => "result-pending-valid",
    frozen_guard_case_result_pending_unsolicited => "result-pending-unsolicited",
    frozen_guard_case_result_pending_wrong_intent => "result-pending-wrong-intent",
    frozen_guard_case_result_pending_output => "result-pending-output",
    frozen_guard_case_mcp_pending_valid => "mcp-pending-valid",
    frozen_guard_case_mcp_pending_error_flag => "mcp-pending-error-flag",
    frozen_guard_case_mcp_pending_extra_block => "mcp-pending-extra-block",
    frozen_guard_case_mcp_pending_text_mismatch => "mcp-pending-text-mismatch",
    frozen_guard_case_result_completed_valid => "result-completed-valid",
    frozen_guard_case_result_completed_unsolicited => "result-completed-unsolicited",
    frozen_guard_case_result_completed_accepted_invocation_late_result => "result-completed-accepted-invocation-late-result",
    frozen_guard_case_result_completed_expired => "result-completed-expired",
    frozen_guard_case_result_completed_revoked => "result-completed-revoked",
    frozen_guard_case_result_completed_wrong_intent => "result-completed-wrong-intent",
    frozen_guard_case_mcp_completed_valid => "mcp-completed-valid",
    frozen_guard_case_mcp_completed_error_flag => "mcp-completed-error-flag",
    frozen_guard_case_mcp_completed_extra_block => "mcp-completed-extra-block",
    frozen_guard_case_mcp_completed_text_mismatch => "mcp-completed-text-mismatch",
    frozen_guard_case_result_rejected_valid => "result-rejected-valid",
    frozen_guard_case_result_rejected_unsolicited => "result-rejected-unsolicited",
    frozen_guard_case_result_rejected_wrong_intent => "result-rejected-wrong-intent",
    frozen_guard_case_result_rejected_output => "result-rejected-output",
    frozen_guard_case_mcp_rejected_valid => "mcp-rejected-valid",
    frozen_guard_case_mcp_rejected_error_flag => "mcp-rejected-error-flag",
    frozen_guard_case_mcp_rejected_extra_block => "mcp-rejected-extra-block",
    frozen_guard_case_mcp_rejected_text_mismatch => "mcp-rejected-text-mismatch",
    frozen_guard_case_result_unknown_valid => "result-unknown-valid",
    frozen_guard_case_result_unknown_unsolicited => "result-unknown-unsolicited",
    frozen_guard_case_result_unknown_wrong_intent => "result-unknown-wrong-intent",
    frozen_guard_case_result_unknown_output => "result-unknown-output",
    frozen_guard_case_mcp_unknown_valid => "mcp-unknown-valid",
    frozen_guard_case_mcp_unknown_error_flag => "mcp-unknown-error-flag",
    frozen_guard_case_mcp_unknown_extra_block => "mcp-unknown-extra-block",
    frozen_guard_case_mcp_unknown_text_mismatch => "mcp-unknown-text-mismatch",
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

fn manifest_json(n: usize) -> Vec<u8> {
    let files: Vec<_> = (0..n)
        .map(|i| json!({"sha256":"a".repeat(64),"path":format!("f/{i:05}")}))
        .collect();
    serde_json::to_vec(&json!({"version":"0.10.0","files":files})).unwrap()
}

#[test]
fn canonical_manifest_is_what_the_commitment_hashes() {
    for n in [1, 3000] {
        let raw = manifest_json(n);
        let bytes = canonical_manifest(&raw).unwrap();
        assert_eq!(manifest_commitment(&raw).unwrap(), hash(&bytes));
        assert!(bytes.starts_with(br#"{"files":[{"path":"f/00000","sha256":""#));
    }
    // 3000 files exceed the general member limit; only the manifest path accepts them.
    assert!(canonicalize(&manifest_json(3000)).is_err());
}

#[test]
fn canonical_manifest_refuses_invalid_manifests() {
    let d = "a".repeat(64);
    for raw in [
        r#"{"version":"0.10.0","files":[],"files":[]}"#.to_string(),
        r#"{"version":"0.9.0","files":[]}"#.to_string(),
        r#"{"version":"0.10.0","files":[],"x":1}"#.to_string(),
        format!(
            r#"{{"version":"0.10.0","files":[{{"path":"b","sha256":"{d}"}},{{"path":"a","sha256":"{d}"}}]}}"#
        ),
        format!(r#"{{"version":"0.10.0","files":[{{"path":"a/../b","sha256":"{d}"}}]}}"#),
        String::from_utf8(manifest_json(4097)).unwrap(),
        r#"{"version":"#.to_string(),
    ] {
        assert!(canonical_manifest(raw.as_bytes()).is_err(), "{raw:.60}");
    }
}
