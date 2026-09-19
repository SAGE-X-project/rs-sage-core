use crate::guard010::{self as g, Authority, Bindings, IntentPolicy, Outstanding};
use serde_json::{json, Value};
// Test-only trusted-service seams. These controls are not production authority.
pub(super) struct Fixture(pub(super) Value);
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
impl Authority for Fixture {
    fn now(&mut self) -> g::Result<i64> {
        if self.0["clock_trusted"] != true {
            return Err(g::Invalid);
        };
        self.0["now"].as_i64().ok_or(g::Invalid)
    }
    fn active_key(&mut self, issuer: &str, _kid: &str) -> g::Result<[u8; 32]> {
        if self.0["active_key"] != true
            || (!s(&self.0, "expected_issuer").is_empty()
                && s(&self.0, "expected_issuer") != issuer)
        {
            return Err(g::Invalid);
        };
        hex::decode(s(&self.0, "public_key_hex"))
            .map_err(|_| g::Invalid)?
            .try_into()
            .map_err(|_| g::Invalid)
    }
}
impl IntentPolicy for Fixture {
    fn bindings(&mut self, issuer: &str, _request_id: &str) -> g::Result<Bindings> {
        if issuer != s(&self.0, "expected_issuer") {
            return Err(g::Invalid);
        };
        Ok(Bindings {
            original: s(&self.0, "original_digest").into(),
            policy: serde_json::to_vec(&self.0["approved_policy"]).map_err(|_| g::Invalid)?,
            manifest: serde_json::to_vec(&self.0["approved_manifest"]).map_err(|_| g::Invalid)?,
        })
    }
    fn authorize(&mut self, _issuer: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        let schema = &self.0["tool_schema"];
        if self.0["policy_allow"] != true || s(schema, "tool") != tool {
            return Err(g::Invalid);
        };
        let v: Value = serde_json::from_slice(args).map_err(|_| g::Invalid)?;
        let a = v.as_object().ok_or(g::Invalid)?;
        for k in schema["required"].as_array().ok_or(g::Invalid)? {
            if !a.contains_key(k.as_str().ok_or(g::Invalid)?) {
                return Err(g::Invalid);
            }
        }
        for (k, v) in a {
            if schema["properties"][k] != "string" || !v.is_string() {
                return Err(g::Invalid);
            }
        }
        Ok(())
    }
}
impl Outstanding for Fixture {
    fn intent(&mut self, _request: &str, _call: &str) -> g::Result<Vec<u8>> {
        if self.0["outstanding"] != true {
            return Err(g::Invalid);
        };
        serde_json::to_vec(&self.0["intent_envelope"]).map_err(|_| g::Invalid)
    }
}
pub fn observe(
    op: &str,
    input: Value,
) -> Result<(&'static str, Value), Box<dyn std::error::Error>> {
    let result: g::Result<Value> = match op {
        "sage.guard.mcp.verify" => {
            let wire = hex::decode(s(&input, "wire_hex"))?;
            g::parse_mcp_result(s(&input,"mcp_version"), &wire).and_then(|raw| {
                let v=g::verify_result(&raw,&mut Fixture(input.clone()),&mut Fixture(input.clone()))?;
                let (success,code)=v.carriage()?;
                Ok(json!({"success":success,"error":code,"status":v.status(),"wire_hex":hex::encode(v.mcp_result(s(&input,"mcp_version"))?)}))
            })
        }
        "sage.guard.mcp.result" => {
            let mut blocks = vec![json!({"type":"text","text":input["text"]})];
            if input["extra_block"] == true {
                blocks.push(json!({"type":"text","text":"unsigned"}));
            }
            let raw = serde_json::to_vec(
                &json!({"structuredContent":input["structured"],"content":blocks,"isError":input["isError"]}),
            )?;
            g::parse_mcp_result(g::MCP_VERSION, &raw).map(|_| json!({"valid":true}))
        }
        "sage.guard.original.commit" => {
            let mut items = Vec::new();
            for i in input["items"].as_array().ok_or("items")? {
                items.push(if let Some(h) = i["hex"].as_str() {
                    hex::decode(h)?
                } else {
                    let n = i["length"].as_u64().ok_or("length")?;
                    let b = i["byte"].as_u64().ok_or("byte")?;
                    if n > (1 << 20) + 1 || b > 255 {
                        return Err("fixture bounds".into());
                    };
                    vec![b as u8; n as usize]
                })
            }
            g::original_commitment(&items).map(|d| json!({"original_digest":d}))
        }
        "sage.guard.manifest.verify" => {
            let mut artifacts = Vec::new();
            for i in input["artifacts"].as_array().ok_or("artifacts")? {
                artifacts.push(g::Artifact {
                    path: s(i, "path").into(),
                    bytes: hex::decode(s(i, "bytes_hex"))?,
                });
            }
            g::verify_manifest(&serde_json::to_vec(&input["manifest"])?, &artifacts)
                .map(|d| json!({"manifest_digest":d}))
        }
        "sage.guard.policy.commit" => {
            g::policy_commitment(&serde_json::to_vec(&input["descriptor"])?)
                .map(|d| json!({"policy_digest":d}))
        }
        "sage.guard.json.bounds" => {
            let mut raw = hex::decode(s(&input, "prefix_hex"))?;
            let n = input["repeat_count"].as_u64().ok_or("count")?;
            let b = input["repeat_byte"].as_u64().ok_or("byte")?;
            if n > (1 << 20) + 1 || b > 255 {
                return Err("fixture bounds".into());
            };
            raw.extend(vec![b as u8; n as usize]);
            raw.extend(hex::decode(s(&input, "suffix_hex"))?);
            g::canonicalize(&raw).map(|_| json!({"valid":true}))
        }
        "sage.guard.intent.verify" => g::verify_intent(
            &hex::decode(s(&input, "envelope_hex"))?,
            s(&input, "expected_recipient"),
            &mut Fixture(input.clone()),
            &mut Fixture(input.clone()),
        )
        .map(|_| json!({"valid":true})),
        "sage.guard.result.verify" => g::verify_result(
            &hex::decode(s(&input, "envelope_hex"))?,
            &mut Fixture(input.clone()),
            &mut Fixture(input.clone()),
        )
        .map(|_| json!({"valid":true})),
        _ => return Ok(("UNSUPPORTED", json!({}))),
    };
    Ok(match result {
        Ok(v) => ("ACCEPT", v),
        Err(_) => ("REJECT", json!({})),
    })
}
