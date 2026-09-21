//! Non-HTTP MCP binding to existing authenticated signed AEAD record sessions.
use super::*;
use crate::hpke::completion010::{AuthenticatedCompletion010, CompletionEndpoint010};

/// One invocation and one response permit; cannot be cloned or publicly created.
/// The host owns authenticated negotiation and exclusive protected dispatch.
/// This does not claim HTTP payload mapping, Guard signature validation or isolation.
pub struct MCPSessionCall {
    version: String,
    id: String,
    message_id: String,
    sid: String,
    local: String,
    peer: String,
    request: Vec<u8>,
    intent: Vec<u8>,
    inbound: bool,
    used: bool,
}
fn field(raw: &[u8], key: &str) -> String {
    serde_json::from_slice::<Value>(raw)
        .ok()
        .and_then(|v| v[key].as_str().map(str::to_owned))
        .unwrap_or_default()
}
pub(super) fn request(
    version: &str,
    id: &str,
    raw: &[u8],
    issuer: &str,
    recipient: &str,
) -> Result<Vec<u8>> {
    ensure(raw.len() <= 16348)?;
    let intent = parse_mcp_request(version, id, raw)?;
    let (e, _) = intent_envelope(&intent)?;
    ensure(text(&e["intent"], "issuer") == issuer && text(&e["intent"], "recipient") == recipient)?;
    Ok(intent)
}
pub(super) fn response(
    version: &str,
    id: &str,
    raw: &[u8],
    intent: &[u8],
    issuer: &str,
    recipient: &str,
) -> Result<Option<&'static str>> {
    ensure(raw.len() <= 16348)?;
    let bytes = super::mcp_rpc::response(version, id, raw)?;
    let (e, _) = object(&bytes)?;
    let m = &e["result"];
    let (q, _) = intent_envelope(intent)?;
    let q = &q["intent"];
    ensure(
        text(m, "issuer") == issuer
            && text(m, "recipient") == recipient
            && text(m, "intent_digest") == hash(intent)
            && text(m, "request_id") == text(q, "request_id")
            && text(m, "call_id") == text(q, "call_id"),
    )?;
    match text(m, "status") {
        "completed" => Ok(None),
        "pending" => Ok(Some("unavailable")),
        "rejected" => Ok(Some("policy_denied")),
        "unknown" => Ok(Some("operation_failed")),
        _ => Err(Invalid),
    }
}
/// Protect exact RPC bytes from the authorized client handoff. The existing record
/// plaintext limit (16348 bytes) applies; no fragmentation or new wire fields.
pub fn seal_mcp_session_request(
    s: &mut AuthenticatedCompletion010,
    e: &mut CompletionEndpoint010,
    version: &str,
    id: &str,
    raw: &[u8],
    ttl: i64,
) -> Result<(Vec<u8>, MCPSessionCall)> {
    let (local, peer) = s.participants().map_err(|_| Invalid)?;
    let intent = request(version, id, raw, &local, &peer)?;
    let wire = s.seal_request(e, raw, ttl).map_err(|_| Invalid)?;
    let call = MCPSessionCall {
        version: version.into(),
        id: id.into(),
        message_id: field(&wire, "id"),
        sid: s.tuple()["sid"].clone(),
        local,
        peer,
        request: raw.into(),
        intent,
        inbound: false,
        used: false,
    };
    Ok((wire, call))
}
/// Authenticate identity, all RPC bytes and outer replay before inner validation.
/// Application rejection does not undo cryptographic request acceptance.
pub fn open_mcp_session_request(
    s: &mut AuthenticatedCompletion010,
    e: &mut CompletionEndpoint010,
    version: &str,
    wire: &[u8],
) -> Result<MCPSessionCall> {
    check_mcp_version(version)?;
    let (local, peer) = s.participants().map_err(|_| Invalid)?;
    let raw = s.open_request(e, wire).map_err(|_| Invalid)?;
    let id = field(&raw, "id");
    let intent = request(version, &id, &raw, &peer, &local)?;
    Ok(MCPSessionCall {
        version: version.into(),
        id,
        message_id: field(wire, "id"),
        sid: s.tuple()["sid"].clone(),
        local,
        peer,
        request: raw,
        intent,
        inbound: true,
        used: false,
    })
}
impl MCPSessionCall {
    /// Authenticated RPC ID, separate from the outer message ID.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Exact authenticated RPC bytes for endpoint dispatch; empty for outgoing calls.
    pub fn request(&self) -> &[u8] {
        if self.inbound {
            &self.request
        } else {
            &[]
        }
    }
    fn bound(&self, s: &AuthenticatedCompletion010) -> Result<()> {
        let (local, peer) = s.participants().map_err(|_| Invalid)?;
        ensure(s.tuple().get("sid") == Some(&self.sid) && local == self.local && peer == self.peer)
    }
    /// Protect one signed endpoint reply. An invalid application reply consumes
    /// this permit; the client still independently verifies the Guard signature.
    pub fn seal_reply(
        &mut self,
        s: &mut AuthenticatedCompletion010,
        e: &mut CompletionEndpoint010,
        raw: &[u8],
        ttl: i64,
    ) -> Result<Vec<u8>> {
        self.bound(s)?;
        ensure(self.inbound && !self.used)?;
        self.used = true;
        let code = response(
            &self.version,
            &self.id,
            raw,
            &self.intent,
            &self.local,
            &self.peer,
        )?;
        s.seal_response(e, &self.message_id, raw, code, ttl)
            .map_err(|_| Invalid)
    }
    /// Open only this outgoing call's correlated response. Pass returned bytes to
    /// Client::accept_mcp_response for Guard verification and durable consumption.
    pub fn open_reply(
        &mut self,
        s: &mut AuthenticatedCompletion010,
        e: &mut CompletionEndpoint010,
        wire: &[u8],
    ) -> Result<Vec<u8>> {
        self.bound(s)?;
        ensure(!self.inbound && !self.used)?;
        // Untrusted ID is an early rejection filter, never authentication.
        ensure(wire.len() <= 32768)?;
        ensure(field(wire, "message_id") == self.message_id)?;
        let r = s.open_response(e, wire).map_err(|_| Invalid)?;
        self.used = true;
        let code = response(
            &self.version,
            &self.id,
            &r.data,
            &self.intent,
            &self.peer,
            &self.local,
        )?;
        ensure(
            r.message_id == self.message_id
                && r.success == code.is_none()
                && r.error == code.unwrap_or(""),
        )?;
        Ok(r.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_identity_and_exact_binding() {
        let v: Value = serde_json::from_str(include_str!("testdata/guard-rpc.json")).unwrap();
        let id = text(&v, "id");
        let bytes = |name: &str| {
            hex::decode(text(
                v[name]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|q| q["id"] == "valid")
                    .unwrap(),
                "wire_hex",
            ))
            .unwrap()
        };
        let req = bytes("requests");
        let resp = bytes("responses");
        let intent = hex::decode(text(&v["input"], "envelope_hex")).unwrap();
        let (e, _) = intent_envelope(&intent).unwrap();
        let issuer = text(&e["intent"], "issuer");
        let recipient = text(&e["intent"], "recipient");
        assert!(request("2025-06-18", id, &req, issuer, recipient).is_ok());
        assert!(response("2025-06-18", id, &resp, &intent, recipient, issuer).is_ok());
        for (version, id, i, r) in [
            ("unsupported", id, issuer, recipient),
            ("2025-06-18", "wrong", issuer, recipient),
            ("2025-06-18", id, recipient, issuer),
            ("2025-06-18", id, issuer, issuer),
        ] {
            assert!(request(version, id, &req, i, r).is_err())
        }
        for (id, i, r) in [
            ("wrong", recipient, issuer),
            (id, issuer, recipient),
            (id, recipient, recipient),
        ] {
            assert!(response("2025-06-18", id, &resp, &intent, i, r).is_err())
        }
        let changed = String::from_utf8(intent.clone())
            .unwrap()
            .replace("public.txt", "other.txt");
        assert!(response(
            "2025-06-18",
            id,
            &resp,
            changed.as_bytes(),
            recipient,
            issuer
        )
        .is_err());
        assert!(request("2025-06-18", id, &vec![0; 16349], issuer, recipient).is_err());
    }
}
