//! Bounded UUID JSON-RPC binding. Transport authentication remains a host duty.
use super::*;
use serde_json::{json, value::RawValue};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Closed structural tool descriptor; does not replace authentication or policy.
pub fn mcp_tool(version: &str) -> Result<Vec<u8>> {
    check_mcp_version(version)?;
    Ok(include_bytes!("mcp-tool.json").to_vec())
}
fn rpc_object(raw: &[u8], size: usize) -> Result<BTreeMap<String, Box<RawValue>>> {
    canonicalize_bounds(raw, 4110, size, 36)?;
    serde_json::from_slice(raw).map_err(|_| Invalid)
}
fn field<'a>(m: &'a BTreeMap<String, Box<RawValue>>, key: &str) -> Result<&'a [u8]> {
    Ok(m.get(key).ok_or(Invalid)?.get().as_bytes())
}
fn string(m: &BTreeMap<String, Box<RawValue>>, key: &str) -> Result<String> {
    serde_json::from_slice(field(m, key)?).map_err(|_| Invalid)
}
/// Encode the supported UUID string ID subset; only structure is checked here.
pub fn mcp_request(version: &str, id: &str, intent: &[u8]) -> Result<Vec<u8>> {
    check_mcp_version(version)?;
    ensure(uuid(id))?;
    let (_, canonical) = intent_envelope(intent)?;
    let envelope: Value = serde_json::from_slice(&canonical).map_err(|_| Invalid)?;
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"sage_secure_call","arguments":{"envelope":envelope}}})).map_err(|_|Invalid)
}
/// Return unauthenticated intent bytes. expected_id belongs to trusted transport,
/// never copied from the document. Notifications, batches and direct tools reject.
pub fn parse_mcp_request(version: &str, expected_id: &str, raw: &[u8]) -> Result<Vec<u8>> {
    check_mcp_version(version)?;
    ensure(uuid(expected_id))?;
    let m = rpc_object(raw, 2 * MAX_BYTES)?;
    ensure(
        m.len() == 4
            && string(&m, "jsonrpc")? == "2.0"
            && string(&m, "id")? == expected_id
            && string(&m, "method")? == "tools/call",
    )?;
    let p: BTreeMap<String, Box<RawValue>> =
        serde_json::from_slice(field(&m, "params")?).map_err(|_| Invalid)?;
    ensure(p.len() == 2 && string(&p, "name")? == "sage_secure_call")?;
    let a: BTreeMap<String, Box<RawValue>> =
        serde_json::from_slice(field(&p, "arguments")?).map_err(|_| Invalid)?;
    ensure(a.len() == 1)?;
    Ok(intent_envelope(field(&a, "envelope")?)?.1)
}
fn response(version: &str, id: &str, raw: &[u8]) -> Result<Vec<u8>> {
    check_mcp_version(version)?;
    ensure(uuid(id))?;
    let m = rpc_object(raw, 9 * MAX_BYTES)?;
    ensure(m.len() == 3 && string(&m, "jsonrpc")? == "2.0" && string(&m, "id")? == id)?;
    parse_mcp_result(version, field(&m, "result")?)
}
/// Trusted bounded protected transport; authenticates peer and complete RPC bytes,
/// binds the UUID, supplies fresh nonce/sequence and never queues duplicate sends.
pub trait MCPWireSender {
    /// One actual protected handoff; do not reenter the client.
    fn send(&mut self, id: &str, raw: &[u8]) -> Result<()>;
}
/// ClientSender binding that checks negotiated support before any transmission.
pub struct MCPClientSender {
    version: String,
    wire: Box<dyn MCPWireSender + Send>,
}
impl MCPClientSender {
    /// Host supplies authenticated negotiation and protected transport.
    pub fn new(version: &str, wire: Box<dyn MCPWireSender + Send>) -> Result<Self> {
        check_mcp_version(version)?;
        Ok(Self {
            version: version.into(),
            wire,
        })
    }
}
impl ClientSender for MCPClientSender {
    fn commit(&mut self, id: &str, intent: &[u8]) -> Result<()> {
        let raw = mcp_request(&self.version, id, intent)?;
        self.wire.send(id, &raw)
    }
}
impl Client {
    /// Consume wrong IDs, RPC errors and malformed replies as unverified failures.
    pub fn accept_mcp_response(
        &self,
        t: &ClientInvocation,
        version: &str,
        raw: &[u8],
    ) -> Result<ClientDelivery> {
        match response(version, t.id(), raw) {
            Ok(envelope) => self.accept(t, &envelope),
            Err(_) => {
                let _ = self.failed(t);
                Err(Invalid)
            }
        }
    }
}
struct Session {
    seen: BTreeSet<String>,
    closed: bool,
}
/// One authenticated transport session, exclusively routing protected tools to
/// the gate. Up to 1024 attempt IDs are consumed even on denial; exhaustion requires
/// closing this session. Cross-session replay prevention and complete interception
/// remain host responsibilities; never reset the endpoint within a live session.
pub struct MCPEndpoint {
    gate: Arc<DispatchGate>,
    version: String,
    owner: Arc<()>,
    session: Mutex<Session>,
}
/// Opaque endpoint-bound, one-response receipt; not a tool completion capability.
pub struct MCPReceipt {
    owner: Arc<()>,
    id: String,
    intent: Vec<u8>,
    receipt: DispatchReceipt,
}
impl MCPReceipt {
    /// Whether storage was created by this attempt.
    pub fn created(&self) -> bool {
        self.receipt.created()
    }
    /// Whether this attempt committed the bounded tool handoff.
    pub fn committed(&self) -> bool {
        self.receipt.committed()
    }
    /// Local ledger state, not an authenticated remote verdict.
    pub fn state(&self) -> &str {
        self.receipt.state()
    }
    /// Digest of the entire authenticated intent.
    pub fn intent_digest(&self) -> &str {
        self.receipt.intent_digest()
    }
}
struct Accepted(Vec<u8>);
impl Outstanding for Accepted {
    fn intent(&mut self, _: &str, _: &str) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
impl MCPEndpoint {
    /// Validate supported setup; host authenticates negotiation before construction.
    pub fn new(version: &str, gate: Arc<DispatchGate>) -> Result<Self> {
        check_mcp_version(version)?;
        Ok(Self {
            gate,
            version: version.into(),
            owner: Arc::new(()),
            session: Mutex::new(Session {
                seen: BTreeSet::new(),
                closed: false,
            }),
        })
    }
    /// Consume the trusted transport ID, then authenticate, reserve and dispatch.
    pub fn dispatch(&self, id: &str, raw: &[u8]) -> Result<MCPReceipt> {
        let mut s = self.session.lock().map_err(|_| Invalid)?;
        ensure(!s.closed && uuid(id) && s.seen.len() < 1024 && !s.seen.contains(id))?;
        s.seen.insert(id.into());
        let intent = parse_mcp_request(&self.version, id, raw)?;
        let receipt = self.gate.dispatch(&intent)?;
        Ok(MCPReceipt {
            owner: self.owner.clone(),
            id: id.into(),
            intent,
            receipt,
        })
    }
    /// Preserve the one-response permit and stored signed bytes. The host protects
    /// and sends the returned RPC only on this receipt's actual invocation.
    pub fn reply(&self, r: &mut MCPReceipt, signer: &mut dyn ResultSigner) -> Result<Vec<u8>> {
        let s = self.session.lock().map_err(|_| Invalid)?;
        ensure(!s.closed && Arc::ptr_eq(&self.owner, &r.owner))?;
        let raw = self.gate.reply(&mut r.receipt, signer)?;
        let v = verify_result(&raw, signer, &mut Accepted(r.intent.clone()))?;
        let body = v.mcp_result(&self.version)?;
        let result: Value = serde_json::from_slice(&body).map_err(|_| Invalid)?;
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":r.id,"result":result})).map_err(|_| Invalid)
    }
    /// Retire this endpoint without closing the shared execution gate.
    pub fn close(&self) -> Result<()> {
        self.session.lock().map_err(|_| Invalid)?.closed = true;
        Ok(())
    }
}
