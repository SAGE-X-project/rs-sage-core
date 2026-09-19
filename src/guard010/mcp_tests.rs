use super::fixtures_test::Fixture;
use super::*;
use serde_json::json;
#[test]
fn independent_mcp_verification() {
    let suite: Value = serde_json::from_str(include_str!("testdata/guard-mcp.json")).unwrap();
    let cases = suite["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 32);
    for c in cases {
        let f = &c["input"];
        let wire = hex::decode(text(f, "wire_hex")).unwrap();
        let result = parse_mcp_result(text(f, "mcp_version"), &wire)
            .and_then(|raw| verify_result(&raw, &mut Fixture(f.clone()), &mut Fixture(f.clone())));
        assert_eq!(
            result.is_ok(),
            c["accept"].as_bool().unwrap(),
            "{}",
            c["id"]
        );
        if let Ok(v) = result {
            let expected = match v.status() {
                "completed" => (true, ""),
                "pending" => (false, "unavailable"),
                "unknown" => (false, "operation_failed"),
                "rejected" => (false, "policy_denied"),
                _ => panic!("status"),
            };
            assert_eq!(v.carriage().unwrap(), expected);
            let raw = v.mcp_result(MCP_VERSION).unwrap();
            assert_eq!(parse_mcp_result(MCP_VERSION, &raw).unwrap(), v.canonical());
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn mcp_client_consumes_invalid_and_valid_invocations() {
    for valid in [false, true] {
        let (_d, _p, c, _s, v) = super::client_tests::setup();
        let ticket = c.begin("00000000-0000-4000-8000-000000000001").unwrap();
        let raw = hex::decode(text(&v["results"], "completed")).unwrap();
        let envelope: Value = serde_json::from_slice(&raw).unwrap();
        let wire = if valid {
            serde_json::to_vec(&json!({"structuredContent":envelope,"content":[{"type":"text","text":std::str::from_utf8(&raw).unwrap()}],"isError":false})).unwrap()
        } else {
            br#"{"isError":true}"#.to_vec()
        };
        let d = c.accept_mcp(&ticket, MCP_VERSION, &wire);
        assert_eq!(d.is_ok(), valid);
        if let Ok(d) = d {
            assert!(d.first_terminal());
            assert_eq!(d.status(), "completed");
        }
        assert!(c.accept(&ticket, &raw).is_err());
        c.close().unwrap();
    }
}

#[test]
fn mcp_envelope_size_boundary() {
    let mut envelope = json!({"result":{"status":"completed","created":1700000000,"expires":1700000300,"output":{"text":""}},"proof":"test-only"});
    let base = encode(&envelope).unwrap().len();
    for extra in [0, 1] {
        envelope["result"]["output"]["text"] = json!("a".repeat(MAX_BYTES - base + extra));
        let raw = serde_json::to_vec(&envelope).unwrap();
        let text = if extra == 0 {
            canonicalize(&raw).unwrap()
        } else {
            raw
        };
        let wire=serde_json::to_vec(&json!({"structuredContent":envelope,"content":[{"type":"text","text":std::str::from_utf8(&text).unwrap()}],"isError":false})).unwrap();
        assert_eq!(parse_mcp_result(MCP_VERSION, &wire).is_ok(), extra == 0);
    }
}
