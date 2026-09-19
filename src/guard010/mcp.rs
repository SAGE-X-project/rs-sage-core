//! Strict structured-result carriage; negotiation provenance belongs to the host.
use super::*;
use serde_json::json;

/// Explicitly supported structured-result version; do not assume future compatibility.
pub const MCP_VERSION: &str = "2025-06-18";
/// Check local support. The host must authenticate negotiation before protected calls.
pub fn check_mcp_version(version: &str) -> Result<()> {
    ensure(version == MCP_VERSION)
}

/// Validate representations and mapping only. These returned bytes remain
/// UNAUTHENTICATED; use verify_result or Client::accept_mcp before consumption.
/// The 8 MiB wrapper allows escaping a 1 MiB envelope; inner limits remain intact.
pub fn parse_mcp_result(version: &str, raw: &[u8]) -> Result<Vec<u8>> {
    check_mcp_version(version)?;
    let canonical = canonicalize_bounds(raw, 4104, 8 * MAX_BYTES, 34)?;
    // Validate the original structured bytes, including exact protocol integers,
    // before binary64 canonicalization can round them or shrink oversized input.
    let fields: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(raw).map_err(|_| Invalid)?;
    let structured = fields.get("structuredContent").ok_or(Invalid)?;
    let (_, structured_bytes) = object(structured.get().as_bytes())?;
    let root: Value = serde_json::from_slice(&canonical).map_err(|_| Invalid)?;
    ensure(closed(&root, "structuredContent content isError"))?;
    let blocks = root["content"].as_array().ok_or(Invalid)?;
    ensure(
        blocks.len() == 1 && closed(&blocks[0], "type text") && text(&blocks[0], "type") == "text",
    )?;
    let raw_text = blocks[0]["text"].as_str().ok_or(Invalid)?;
    let (envelope, bytes) = object(raw_text.as_bytes())?;
    ensure(closed(&envelope, "result proof") && bytes == raw_text.as_bytes())?;
    // Compare canonical structured content independently to canonical text.
    ensure(structured_bytes == bytes)?;
    let success = mapping(text(&envelope["result"], "status"))?.0;
    ensure(root["isError"].as_bool().ok_or(Invalid)? != success)?;
    Ok(bytes)
}
fn mapping(status: &str) -> Result<(bool, &'static str)> {
    match status {
        "completed" => Ok((true, "")),
        "pending" => Ok((false, "unavailable")),
        "unknown" => Ok((false, "operation_failed")),
        "rejected" => Ok((false, "policy_denied")),
        _ => Err(Invalid),
    }
}
impl VerifiedResult {
    /// Format an authenticated snapshot without signing or extending its lifetime.
    /// Publishers still need their response permit and protected transport; clients
    /// freshly verify the response and consume their own invocation.
    pub fn mcp_result(&self, version: &str) -> Result<Vec<u8>> {
        check_mcp_version(version)?;
        let envelope: Value = serde_json::from_slice(&self.canonical).map_err(|_| Invalid)?;
        let raw = serde_json::to_vec(&json!({"structuredContent":envelope,
   "content":[{"type":"text","text":std::str::from_utf8(&self.canonical).map_err(|_| Invalid)?}],
   "isError": self.status != "completed"}))
        .map_err(|_| Invalid)?;
        parse_mcp_result(version, &raw)?;
        Ok(raw)
    }
    /// Map authenticated status to chapter 08 success/error; not polling authority.
    pub fn carriage(&self) -> Result<(bool, &'static str)> {
        mapping(&self.status)
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Client {
    /// Consume this invocation even on malformed MCP data or unsupported version,
    /// then apply durable first-terminal acceptance before releasing output.
    pub fn accept_mcp(
        &self,
        t: &ClientInvocation,
        version: &str,
        raw: &[u8],
    ) -> Result<ClientDelivery> {
        match parse_mcp_result(version, raw) {
            Ok(envelope) => self.accept(t, &envelope),
            Err(_) => {
                let _ = self.failed(t);
                Err(Invalid)
            }
        }
    }
}
