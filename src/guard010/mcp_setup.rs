//! Private authenticated setup. No public readiness, dispatch or history import.
use super::*;
use crate::hpke::completion010::{CompletionEndpoint010, NonHTTPOwner010};
use serde_json::json;
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Phase {
    ClientStart,
    WaitInitialize,
    Initialized,
    WaitAck,
    Negotiated,
    WaitList,
    ServerStart,
    WaitInitialized,
    Discovery,
    Ready,
    Closed,
}
struct State {
    phase: Phase,
    pending: Option<Phase>,
    seen: BTreeSet<String>,
    operation: Option<Arc<()>>,
    protected_deadline: Option<i64>,
    output_pending: bool,
}
#[derive(Clone)]
pub(crate) struct SetupClose(Arc<Mutex<State>>, Arc<Mutex<()>>);
impl SetupClose {
    pub(crate) fn close(&self) {
        let _coordinator = self.1.lock().unwrap_or_else(|p| p.into_inner());
        let mut s = self.0.lock().unwrap_or_else(|p| p.into_inner());
        s.phase = Phase::Closed;
        s.pending = None;
        s.operation = None;
        s.output_pending = false;
    }
    pub(crate) fn close_operation(&self, operation: &Arc<()>) {
        let _coordinator = self.1.lock().unwrap_or_else(|p| p.into_inner());
        let mut s = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if s.operation
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, operation))
        {
            s.phase = Phase::Closed;
            s.pending = None;
            s.operation = None;
            s.output_pending = false;
        }
    }
    pub(crate) fn closed(&self) -> bool {
        self.1.is_poisoned() || self.0.lock().map_or(true, |s| s.phase == Phase::Closed)
    }
}
/// Trusted bounded provider: complete local handoff and one bounded frame only.
/// Honor the absolute original-clock deadline and closure; do not reenter this
/// owner. No receive pump, deferred input queue or callback-created worker exists.
pub(crate) trait SetupIO {
    fn send(&mut self, wire: &[u8], deadline_ms: i64, close: &SetupClose) -> Result<()>;
    fn receive(&mut self, deadline_ms: i64, close: &SetupClose) -> Result<Vec<u8>>;
}
pub(crate) struct MCPSetup {
    pub(crate) owner: NonHTTPOwner010,
    state: Arc<Mutex<State>>,
    coordinator: Arc<Mutex<()>>,
    deadline: i64,
    info: Value,
    started: bool,
    pub(crate) response: Option<super::mcp_admission::ProtectedReply>,
}
fn object(raw: &[u8]) -> Result<Value> {
    canonicalize_bounds(raw, 16348, 16348, 36)?;
    let v: Value = serde_json::from_slice(raw).map_err(|_| Invalid)?;
    ensure(v.is_object())?;
    Ok(v)
}
fn info(v: &Value) -> bool {
    v.is_object()
        && v["name"].is_string()
        && v["version"].is_string()
        && v.get("title").is_none_or(Value::is_string)
}
fn initialize(raw: &[u8], id: &str, response: bool) -> Result<()> {
    let m = object(raw)?;
    ensure(uuid(id) && text(&m, "id") == id && text(&m, "jsonrpc") == "2.0")?;
    let (key, who) = if response {
        ensure(closed(&m, "jsonrpc id result"))?;
        ("result", "serverInfo")
    } else {
        ensure(closed(&m, "jsonrpc id method params") && text(&m, "method") == "initialize")?;
        ("params", "clientInfo")
    };
    let b = &m[key];
    let caps = b["capabilities"].as_object().ok_or(Invalid)?;
    ensure(
        text(b, "protocolVersion") == MCP_VERSION
            && info(&b[who])
            && b.get("_meta").is_none_or(Value::is_object),
    )?;
    if response {
        ensure(
            caps.len() == 1
                && caps
                    .get("tools")
                    .and_then(Value::as_object)
                    .is_some_and(|x| x.is_empty())
                && b.get("instructions").is_none_or(Value::is_string),
        )?;
    } else {
        ensure(caps.is_empty())?;
        if let Some(token) = b.get("_meta").and_then(|m| m.get("progressToken")) {
            ensure(token.is_string() || token.is_number())?;
        }
    }
    Ok(())
}
fn initialized(raw: &[u8], ack: bool) -> Result<()> {
    if ack {
        return ensure(raw == b"{}");
    }
    let m = object(raw)?;
    ensure(
        closed(&m, "jsonrpc method")
            && text(&m, "jsonrpc") == "2.0"
            && text(&m, "method") == "notifications/initialized",
    )
}
fn discovery(raw: &[u8], id: &str, response: bool) -> Result<()> {
    let m = object(raw)?;
    ensure(uuid(id) && text(&m, "id") == id && text(&m, "jsonrpc") == "2.0")?;
    if !response {
        return ensure(closed(&m, "jsonrpc id method") && text(&m, "method") == "tools/list");
    }
    ensure(closed(&m, "jsonrpc id result") && closed(&m["result"], "tools"))?;
    let tools = m["result"]["tools"].as_array().ok_or(Invalid)?;
    ensure(tools.len() == 1)?;
    let actual = serde_json::to_vec(&tools[0]).map_err(|_| Invalid)?;
    ensure(
        canonicalize_bounds(&actual, 16348, 16348, 36)?
            == canonicalize_bounds(include_bytes!("mcp-tool.json"), 16348, 16348, 36)?,
    )
}
fn wire_id(raw: &[u8]) -> Result<String> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| Invalid)?;
    Ok(v["id"].as_str().ok_or(Invalid)?.into())
}
fn encode(v: Value) -> Result<Vec<u8>> {
    let b = serde_json::to_vec(&v).map_err(|_| Invalid)?;
    ensure(b.len() <= 16348)?;
    Ok(b)
}
impl MCPSetup {
    pub(crate) fn new(
        owner: NonHTTPOwner010,
        e: &mut CompletionEndpoint010,
        name: &str,
        version: &str,
    ) -> Result<Self> {
        Self::coordinated(owner, e, name, version, Arc::new(Mutex::new(())))
    }
    pub(crate) fn coordinated(
        mut owner: NonHTTPOwner010,
        e: &mut CompletionEndpoint010,
        name: &str,
        version: &str,
        coordinator: Arc<Mutex<()>>,
    ) -> Result<Self> {
        ensure(owner.unused())?;
        let info = json!({"name":name,"version":version});
        ensure(serde_json::to_vec(&info).map_err(|_| Invalid)?.len() <= 16000)?;
        let deadline = owner.created_mono_ms().checked_add(30000).ok_or(Invalid)?;
        ensure(owner.local_now(e).map_err(|_| Invalid)? < deadline)?;
        let phase = if owner.initiator() {
            Phase::ClientStart
        } else {
            Phase::ServerStart
        };
        Ok(Self {
            owner,
            state: Arc::new(Mutex::new(State {
                phase,
                pending: None,
                seen: BTreeSet::new(),
                operation: None,
                protected_deadline: None,
                output_pending: false,
            })),
            coordinator,
            deadline,
            info,
            started: false,
            response: None,
        })
    }
    pub(crate) fn closer(&self) -> SetupClose {
        SetupClose(self.state.clone(), self.coordinator.clone())
    }
    #[cfg(test)]
    pub(crate) fn history(&self) -> Vec<String> {
        self.state.lock().unwrap().seen.iter().cloned().collect()
    }
    pub(crate) fn phase(&self) -> Phase {
        if self.coordinator.is_poisoned() {
            return Phase::Closed;
        }
        self.state.lock().map_or(Phase::Closed, |s| s.phase)
    }
    pub(crate) fn fail(&mut self) {
        self.closer().close();
        self.owner.close();
    }
    pub(crate) fn guarded<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            ensure(!self.coordinator.is_poisoned())?;
            f(self)
        }))
        .unwrap_or(Err(Invalid));
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn valid(
        owner: &mut NonHTTPOwner010,
        e: &mut CompletionEndpoint010,
        s: &State,
        deadline: i64,
    ) -> Result<i64> {
        let now = owner.local_now(e).map_err(|_| Invalid)?;
        ensure(s.phase != Phase::Closed && (s.phase == Phase::Ready || now < deadline))?;
        Ok(now)
    }
    fn reserve(s: &mut State, id: &str) -> Result<()> {
        ensure(uuid(id) && s.seen.len() < 1024 && !s.seen.contains(id))?;
        s.seen.insert(id.into());
        Ok(())
    }
    fn begin(
        &mut self,
        e: &mut CompletionEndpoint010,
        expected: Phase,
        next: Phase,
        id: Option<&str>,
    ) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        Self::valid(&mut self.owner, e, &s, self.deadline)?;
        ensure(s.phase == expected && s.pending.is_none())?;
        if let Some(id) = id {
            Self::reserve(&mut s, id)?;
        }
        s.pending = Some(next);
        Ok(())
    }
    fn publish(&mut self, e: &mut CompletionEndpoint010, next: Phase, output: bool) -> Result<()> {
        ensure(!self.coordinator.is_poisoned())?;
        let observed = self.owner.observe(e).map_err(|_| Invalid)?;
        ensure(!self.coordinator.is_poisoned())?;
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        let now = Self::valid(&mut self.owner, e, &s, self.deadline)?;
        ensure(now >= observed && now - observed <= 5000)?;
        if output {
            ensure(s.pending == Some(next))?;
        } else {
            ensure(
                s.pending.is_none()
                    && matches!(
                        (s.phase, next),
                        (Phase::WaitInitialize, Phase::Initialized)
                            | (Phase::WaitAck, Phase::Negotiated)
                            | (Phase::WaitList, Phase::Ready)
                    ),
            )?;
        }
        s.phase = next;
        s.pending = None;
        Ok(())
    }
    fn send(
        &mut self,
        e: &mut CompletionEndpoint010,
        io: &mut dyn SetupIO,
        wire: &[u8],
        next: Phase,
    ) -> Result<()> {
        ensure(!wire.is_empty() && wire.len() <= 32768 && !self.closer().closed())?;
        {
            let state = self.state.lock().map_err(|_| Invalid)?;
            Self::valid(&mut self.owner, e, &state, self.deadline)?;
            ensure(state.pending == Some(next))?;
        }
        io.send(wire, self.deadline, &self.closer())?;
        self.publish(e, next, true)
    }
    fn receive(&mut self, io: &mut dyn SetupIO) -> Result<Vec<u8>> {
        ensure(!self.closer().closed())?;
        let b = io.receive(self.deadline, &self.closer())?;
        ensure(!b.is_empty() && b.len() <= 32768 && !self.closer().closed())?;
        Ok(b)
    }
    pub(crate) fn run(
        &mut self,
        e: &mut CompletionEndpoint010,
        io: &mut dyn SetupIO,
        prepare: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.guarded(|s| {
            ensure(!s.started)?;
            s.started = true;
            if s.owner.initiator() {
                s.initiate(e, io)
            } else {
                for _ in 0..3 {
                    let wire = s.receive(io)?;
                    s.accept_setup(e, &wire, io, prepare)?;
                }
                Ok(())
            }
        })
    }
    fn initiate(&mut self, e: &mut CompletionEndpoint010, io: &mut dyn SetupIO) -> Result<()> {
        let steps = [
            (
                Phase::ClientStart,
                Phase::WaitInitialize,
                Phase::Initialized,
            ),
            (Phase::Initialized, Phase::WaitAck, Phase::Negotiated),
            (Phase::Negotiated, Phase::WaitList, Phase::Ready),
        ];
        for (index, (before, pending, after)) in steps.into_iter().enumerate() {
            let id = if index == 1 {
                String::new()
            } else {
                ::uuid::Uuid::new_v4().to_string()
            };
            let raw = match index {
                0 => encode(
                    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":MCP_VERSION,"capabilities":{},"clientInfo":self.info}}),
                )?,
                1 => br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
                _ => encode(json!({"jsonrpc":"2.0","id":id,"method":"tools/list"}))?,
            };
            self.begin(
                e,
                before,
                pending,
                if index == 1 { None } else { Some(&id) },
            )?;
            let wire = self.owner.seal_request(e, &raw, 30).map_err(|_| Invalid)?;
            let outer = wire_id(&wire)?;
            ensure(id.is_empty() || id != outer)?;
            self.send(e, io, &wire, pending)?;
            let response = self.receive(io)?;
            let r = self
                .owner
                .open_response(e, &response)
                .map_err(|_| Invalid)?;
            ensure(
                r.message_id == outer
                    && r.success
                    && r.error.is_empty()
                    && (id.is_empty() || wire_id(&response)? != id),
            )?;
            match index {
                0 => initialize(&r.data, &id, true)?,
                1 => initialized(&r.data, true)?,
                _ => discovery(&r.data, &id, true)?,
            };
            self.publish(e, after, false)?;
        }
        Ok(())
    }
    /// Serialized receive entry; every call authenticates before inner routing.
    pub(crate) fn accept_setup(
        &mut self,
        e: &mut CompletionEndpoint010,
        wire: &[u8],
        io: &mut dyn SetupIO,
        prepare: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.guarded(|s| {
            ensure(!s.owner.initiator() && !wire.is_empty() && wire.len() <= 32768)?;
            {
                let state = s.state.lock().map_err(|_| Invalid)?;
                Self::valid(&mut s.owner, e, &state, s.deadline)?;
                ensure(matches!(state.phase, Phase::ServerStart | Phase::WaitInitialized | Phase::Discovery) && state.pending.is_none())?;
            }
            s.started = true;
            let raw = s.owner.open_request(e, wire).map_err(|_| Invalid)?;
            let m = object(&raw)?;
            let id = text(&m, "id");
            ensure(id.is_empty() || id != wire_id(wire)?)?;
            let phase = s.phase();
            let next = match phase {
                Phase::ServerStart => Phase::WaitInitialized,
                Phase::WaitInitialized => Phase::Discovery,
                Phase::Discovery => Phase::Ready,
                _ => return Err(Invalid),
            };
            // A forbidden but valid notification ID still consumes history.
            if phase == Phase::WaitInitialized && uuid(id) {
                let mut state = s.state.lock().map_err(|_| Invalid)?;
                Self::reserve(&mut state, id)?;
            }
            s.begin(e, phase, next, if phase == Phase::WaitInitialized { None } else { Some(id) })?;
            let response = match phase {
                Phase::ServerStart => {
                    initialize(&raw, id, false)?;
                    encode(json!({"jsonrpc":"2.0", "id":id, "result":{
                        "protocolVersion":MCP_VERSION, "capabilities":{"tools":{}}, "serverInfo":s.info
                    }}))?
                }
                Phase::WaitInitialized => {
                    initialized(&raw, false)?;
                    prepare()?;
                    b"{}".to_vec()
                }
                _ => {
                    discovery(&raw, id, false)?;
                    let tool: Value = serde_json::from_slice(include_bytes!("mcp-tool.json")).map_err(|_| Invalid)?;
                    encode(json!({"jsonrpc":"2.0", "id":id, "result":{"tools":[tool]}}))?
                }
            };
            ensure(!s.closer().closed())?;
            let reply = s.owner.seal_response(e, &wire_id(wire)?, &response, None, 30).map_err(|_| Invalid)?;
            ensure(id.is_empty() || wire_id(&reply)? != id)?;
            s.send(e, io, &reply, next)
        })
    }
    // The caller holds this same coordinator throughout start/final publication.
    // Only the bounded endpoint clock runs inside it; registry work stays outside.
    pub(crate) fn admission_time(
        &mut self,
        e: &mut CompletionEndpoint010,
        coordinator: &Arc<Mutex<()>>,
        operation: Option<&Arc<()>>,
    ) -> Result<crate::registry010::Stamp> {
        self.protected_time(e, coordinator, operation, false)
    }
    pub(crate) fn protected_time(
        &mut self,
        e: &mut CompletionEndpoint010,
        coordinator: &Arc<Mutex<()>>,
        operation: Option<&Arc<()>>,
        initiator: bool,
    ) -> Result<crate::registry010::Stamp> {
        ensure(Arc::ptr_eq(coordinator, &self.coordinator))?;
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        ensure(
            state.phase == Phase::Ready
                && state.pending.is_none()
                && self.owner.initiator() == initiator,
        )?;
        match operation {
            Some(id) => ensure(
                state
                    .operation
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, id)),
            )?,
            None => ensure(state.operation.is_none())?,
        }
        let now = Self::valid(&mut self.owner, e, &state, self.deadline)?;
        if operation.is_some() {
            ensure(now < state.protected_deadline.ok_or(Invalid)?)?;
        }
        if operation.is_none() {
            state.operation = Some(Arc::new(()));
        }
        Ok(self.owner.sampled_time())
    }
    pub(crate) fn reserve_client_id(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        ensure(self.owner.initiator() && state.phase == Phase::Ready)?;
        Self::reserve(&mut state, id)
    }
    pub(crate) fn begin_output(&self, operation: &Arc<()>) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(
            s.phase == Phase::Ready
                && !s.output_pending
                && s.operation
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, operation)),
        )?;
        s.output_pending = true;
        Ok(())
    }
    pub(crate) fn finish_output(&self, operation: &Arc<()>) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(
            s.phase == Phase::Ready
                && s.output_pending
                && s.operation
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, operation)),
        )?;
        s.output_pending = false;
        Ok(())
    }
    pub(crate) fn finish_operation(&self, operation: &Arc<()>) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(
            s.phase == Phase::Ready
                && !s.output_pending
                && s.operation
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, operation)),
        )?;
        s.operation = None;
        s.protected_deadline = None;
        Ok(())
    }
    pub(crate) fn bind_deadline(&self, deadline: i64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        ensure(state.operation.is_some() && state.protected_deadline.is_none())?;
        state.protected_deadline = Some(deadline);
        Ok(())
    }
    pub(crate) fn operation(&self) -> Result<Arc<()>> {
        self.state
            .lock()
            .map_err(|_| Invalid)?
            .operation
            .clone()
            .ok_or(Invalid)
    }
    pub(crate) fn observe_admission(&mut self, e: &mut CompletionEndpoint010) -> Result<i64> {
        self.owner.observe(e).map_err(|_| Invalid)
    }
    /// Private input staging only. Returned bytes still require owner-aware Guard
    /// admission; setup does not verify the intent signature or authorize effects.
    pub(crate) fn open_protected(
        &mut self,
        e: &mut CompletionEndpoint010,
        wire: &[u8],
    ) -> Result<Vec<u8>> {
        self.guarded(|s| {
            {
                let state = s.state.lock().map_err(|_| Invalid)?;
                Self::valid(&mut s.owner, e, &state, s.deadline)?;
                ensure(
                    state.phase == Phase::Ready && state.pending.is_none() && !s.owner.initiator(),
                )?;
            }
            ensure(!wire.is_empty() && wire.len() <= 32768)?;
            let raw = s.owner.open_request(e, wire).map_err(|_| Invalid)?;
            let m = object(&raw)?;
            let id = text(&m, "id");
            ensure(id != wire_id(wire)?)?;
            {
                let mut state = s.state.lock().map_err(|_| Invalid)?;
                Self::valid(&mut s.owner, e, &state, s.deadline)?;
                Self::reserve(&mut state, id)?;
            }
            let intent = parse_mcp_request(MCP_VERSION, id, &raw)?;
            let (v, _) = intent_envelope(&intent)?;
            let (local, peer) = s.owner.participants().map_err(|_| Invalid)?;
            ensure(
                text(&v["intent"], "issuer") == peer && text(&v["intent"], "recipient") == local,
            )?;
            ensure(!s.closer().closed())?;
            Ok(raw)
        })
    }
}
impl Drop for MCPSetup {
    fn drop(&mut self) {
        self.fail();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "00000000-0000-4000-8000-000000000001";
    fn request() -> Value {
        json!({"jsonrpc":"2.0","id":ID,"method":"initialize","params":{"protocolVersion":MCP_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}})
    }
    #[test]
    fn setup_codecs_are_bounded_and_closed() {
        let valid = serde_json::to_vec(&request()).unwrap();
        assert!(initialize(&valid, ID, false).is_ok());
        for raw in [
            br#"[]"#.to_vec(),
            br#"null"#.to_vec(),
            [valid.as_slice(), b" {}"].concat(),
            vec![b' '; 16349],
            String::from_utf8(valid.clone())
                .unwrap()
                .replace(
                    "\"jsonrpc\":\"2.0\"",
                    "\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\"",
                )
                .into_bytes(),
        ] {
            assert!(initialize(&raw, ID, false).is_err());
        }
        for (field, value) in [
            ("protocolVersion", json!("unsupported")),
            ("capabilities", json!({"sampling":{}})),
            ("clientInfo", json!({"name":"test","version":null})),
            ("_meta", json!({"progressToken":true})),
        ] {
            let mut m = request();
            m["params"][field] = value;
            assert!(initialize(&serde_json::to_vec(&m).unwrap(), ID, false).is_err());
        }
        assert!(initialized(b"{}", true).is_ok());
        for raw in [b" {}".as_slice(), b"{ }", b"{}\n", b"null"] {
            assert!(initialized(raw, true).is_err());
        }
        let tool: Value = serde_json::from_slice(include_bytes!("mcp-tool.json")).unwrap();
        let mut response = json!({"jsonrpc":"2.0","id":ID,"result":{"tools":[tool]}});
        assert!(discovery(&serde_json::to_vec(&response).unwrap(), ID, true).is_ok());
        let numeric_equivalent = serde_json::to_string(&response)
            .unwrap()
            .replace("\"minimum\":0", "\"minimum\":0.0");
        assert!(discovery(numeric_equivalent.as_bytes(), ID, true).is_ok());
        response["result"]["tools"][0]["description"] = json!("changed");
        assert!(discovery(&serde_json::to_vec(&response).unwrap(), ID, true).is_err());
    }
    #[test]
    fn poisoned_coordinator_still_closes_existing_handles() {
        let shared = Arc::new(Mutex::new(State {
            phase: Phase::Ready,
            pending: None,
            seen: BTreeSet::from([ID.into()]),
            operation: Some(Arc::new(())),
            protected_deadline: Some(100),
            output_pending: false,
        }));
        let coordinator = Arc::new(Mutex::new(()));
        let closer = SetupClose(shared.clone(), coordinator.clone());
        let poison = coordinator.clone();
        let _ = std::thread::spawn(move || {
            let _lock = poison.lock().unwrap();
            panic!("inert poison fixture");
        })
        .join();
        assert!(closer.closed());
        closer.close();
        let s = shared.lock().unwrap();
        assert_eq!(s.phase, Phase::Closed);
        assert!(s.operation.is_none());
        assert_eq!(s.seen.len(), 1);
    }
    #[test]
    fn history_capacity_is_not_reset_by_close() {
        let shared = Arc::new(Mutex::new(State {
            phase: Phase::Ready,
            pending: None,
            seen: BTreeSet::new(),
            operation: None,
            protected_deadline: None,
            output_pending: false,
        }));
        {
            let mut s = shared.lock().unwrap();
            for n in 0..1024 {
                MCPSetup::reserve(&mut s, &format!("00000000-0000-4000-8000-{n:012x}")).unwrap();
            }
            assert!(MCPSetup::reserve(&mut s, "00000000-0000-4000-8000-ffffffffffff").is_err());
        }
        SetupClose(shared.clone(), Arc::new(Mutex::new(()))).close();
        let s = shared.lock().unwrap();
        assert_eq!(s.phase, Phase::Closed);
        assert_eq!(s.seen.len(), 1024);
    }
}
