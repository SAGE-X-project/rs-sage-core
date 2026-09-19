use super::*;
use serde_json::json;
fn suite() -> Value {
    serde_json::from_str(include_str!("testdata/guard-rpc.json")).unwrap()
}
#[test]
fn independent_rpc_requests() {
    let v = suite();
    assert_eq!(v["requests"].as_array().unwrap().len(), 27);
    for c in v["requests"].as_array().unwrap() {
        let raw = hex::decode(text(c, "wire_hex")).unwrap();
        assert_eq!(
            parse_mcp_request(text(c, "version"), text(&v, "id"), &raw).is_ok(),
            c["parse"].as_bool().unwrap(),
            "{}",
            c["id"]
        );
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn response_consumes_invocation() {
    let v = suite();
    assert_eq!(v["responses"].as_array().unwrap().len(), 22);
    for q in v["responses"].as_array().unwrap() {
        let (_d, _p, c, _s, client) = super::client_tests::setup();
        let ticket = c.begin(text(&v, "id")).unwrap();
        let raw = hex::decode(text(q, "wire_hex")).unwrap();
        let d = c.accept_mcp_response(&ticket, text(q, "version"), &raw);
        assert_eq!(d.is_ok(), q["accept"].as_bool().unwrap(), "{}", q["id"]);
        if let Ok(d) = d {
            assert!(d.first_terminal());
            assert_eq!(d.output(), br#"{"value":"ok"}"#);
        }
        assert!(c
            .accept(
                &ticket,
                &hex::decode(text(&client["results"], "completed")).unwrap()
            )
            .is_err());
        c.close().unwrap();
    }
}
struct Wire(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl MCPWireSender for Wire {
    fn send(&mut self, id: &str, raw: &[u8]) -> Result<()> {
        parse_mcp_request(MCP_VERSION, id, raw)?;
        *self.0.lock().unwrap() = raw.to_vec();
        Ok(())
    }
}
#[test]
fn sender_and_schema() {
    let v = suite();
    let raw = hex::decode(text(&v["input"], "envelope_hex")).unwrap();
    let stored = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut s = MCPClientSender::new(MCP_VERSION, Box::new(Wire(stored.clone()))).unwrap();
    s.commit(text(&v, "id"), &raw).unwrap();
    assert_eq!(
        *stored.lock().unwrap(),
        mcp_request(MCP_VERSION, text(&v, "id"), &raw).unwrap()
    );
    assert!(MCPClientSender::new("2024-11-05", Box::new(Wire(stored))).is_err());
    let tool: Value = serde_json::from_slice(&mcp_tool(MCP_VERSION).unwrap()).unwrap();
    assert_eq!(tool["name"], "sage_secure_call");
    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    assert_eq!(tool["inputSchema"]["required"], json!(["envelope"]));
    assert_eq!(
        tool["inputSchema"]["properties"].as_object().unwrap().len(),
        1
    );
}
