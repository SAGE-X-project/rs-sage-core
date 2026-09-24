//! Private owner-bound MCP publication and client exchange plumbing.
use super::mcp_setup::{MCPSetup, SetupIO};
use super::*;
use crate::hpke::completion010::{CompletionEndpoint010, NonHTTPOwner010};
use crate::registry010::Stamp;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub(crate) fn wire_id(raw: &[u8]) -> Result<String> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| Invalid)?;
    let id = text(&v, "id");
    ensure(uuid(id))?;
    Ok(id.into())
}
pub(crate) struct Accepted(pub(crate) Vec<u8>);
impl Outstanding for Accepted {
    fn intent(&mut self, _: &str, _: &str) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
pub(crate) struct Evidence {
    started: i64,
    session: i64,
    authority: super::registry::Observation,
    expires: i64,
}
impl Evidence {
    pub(crate) fn valid(&self, now: Stamp, start: Stamp, deadline: i64) -> Result<()> {
        ensure(
            now.mono_ms >= start.mono_ms
                && now.unix >= start.unix
                && now.mono_ms < deadline
                && now.unix >= self.authority.stamp.unix
                && now.unix < self.expires
                && self
                    .authority
                    .expires
                    .is_none_or(|expires| now.unix < expires),
        )?;
        for observed in [self.started, self.session, self.authority.started_ms] {
            ensure(
                observed >= start.mono_ms
                    && observed <= now.mono_ms
                    && now.mono_ms - observed <= 5000,
            )?;
        }
        Ok(())
    }
}
pub(crate) fn result_evidence(
    owner: &mut MCPSetup,
    endpoint: &mut CompletionEndpoint010,
    raw: &[u8],
    intent: &[u8],
    authority: &mut RegistryAuthority,
) -> Result<Evidence> {
    let started = owner.owner.local_now(endpoint).map_err(|_| Invalid)?;
    let result = verify_result(raw, authority, &mut Accepted(intent.to_vec()))?;
    let (env, _) = object(result.canonical())?;
    let expires = number(&env["result"], "expires")?;
    let authority = authority.observe()?;
    let session = owner.observe_admission(endpoint)?;
    Ok(Evidence {
        started,
        session,
        authority,
        expires,
    })
}
fn intent_evidence(
    owner: &mut MCPSetup,
    endpoint: &mut CompletionEndpoint010,
    raw: &[u8],
    authority: &mut RegistryAuthority,
    policy: &mut dyn IntentPolicy,
) -> Result<Evidence> {
    let started = owner.owner.local_now(endpoint).map_err(|_| Invalid)?;
    let (env, _) = intent_envelope(raw)?;
    verify_intent(raw, text(&env["intent"], "recipient"), authority, policy)?;
    let expires = number(&env["intent"], "expires")?;
    let authority = authority.observe()?;
    let session = owner.observe_admission(endpoint)?;
    Ok(Evidence {
        started,
        session,
        authority,
        expires,
    })
}
struct Binding(Arc<Mutex<RegistryAuthority>>);
impl Authority for Binding {
    fn now(&mut self) -> Result<i64> {
        self.0.lock().map_err(|_| Invalid)?.now()
    }
    fn active_key(&mut self, issuer: &str, key: &str) -> Result<[u8; 32]> {
        self.0.lock().map_err(|_| Invalid)?.active_key(issuer, key)
    }
}
struct Policy(Arc<Mutex<Box<dyn IntentPolicy + Send>>>);
impl IntentPolicy for Policy {
    fn bindings(&mut self, issuer: &str, request: &str) -> Result<Bindings> {
        self.0
            .lock()
            .map_err(|_| Invalid)?
            .bindings(issuer, request)
    }
    fn authorize(&mut self, issuer: &str, tool: &str, args: &[u8]) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Invalid)?
            .authorize(issuer, tool, args)
    }
}
// Convert clock unwind into an ordinary error while Client::open still owns its
// descriptor and can preserve its existing failed-journal recovery contract.
struct SafeClock(Box<dyn ClientClock + Send>);
impl ClientClock for SafeClock {
    fn sample(&mut self) -> Result<(i64, i64)> {
        catch_unwind(AssertUnwindSafe(|| self.0.sample())).unwrap_or(Err(Invalid))
    }
}
struct NoSender;
impl ClientSender for NoSender {
    fn commit(&mut self, _: &str, _: &[u8]) -> Result<()> {
        Err(Invalid)
    }
}
struct PoolState {
    active: usize,
    retired: bool,
    last: Option<Stamp>,
    setup_used: bool,
    owners: Option<Arc<super::mcp_lifecycle::OwnerRegistry>>,
}
/// Shared quota survives connection replacement. The host supplies finite provider
/// bounds. Optional pre-use owner registration supplies independent logical
/// cancellation; a production stream and automatic cleanup remain separate work.
pub(crate) struct ClientPool {
    coordinator: Arc<Mutex<()>>,
    state: Mutex<PoolState>,
    capacity: usize,
    timeout_ms: i64,
}
struct Lease<'a>(&'a ClientPool);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Ok(_c) = self.0.coordinator.lock() {
            if let Ok(mut state) = self.0.state.lock() {
                state.active -= 1;
            }
        }
    }
}
impl ClientPool {
    pub(crate) fn new(capacity: usize, timeout_ms: i64) -> Result<Self> {
        ensure((1..=128).contains(&capacity) && (1..=300_000).contains(&timeout_ms))?;
        Ok(Self {
            coordinator: Arc::new(Mutex::new(())),
            state: Mutex::new(PoolState {
                active: 0,
                retired: false,
                last: None,
                setup_used: false,
                owners: None,
            }),
            capacity,
            timeout_ms,
        })
    }
    pub(crate) fn attach_owners(
        &self,
        owners: Arc<super::mcp_lifecycle::OwnerRegistry>,
    ) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        ensure(
            !state.retired
                && !state.setup_used
                && state.last.is_none()
                && state.owners.is_none()
                && owners.live()
                && owners.interval() < std::time::Duration::from_millis(self.timeout_ms as u64),
        )?;
        state.owners = Some(owners);
        Ok(())
    }
    pub(crate) fn transport_ready(
        &self,
        owners: &Arc<super::mcp_lifecycle::OwnerRegistry>,
    ) -> bool {
        let Ok(_c) = self.coordinator.lock() else {
            return false;
        };
        self.state.lock().is_ok_and(|s| {
            !s.retired
                && !s.setup_used
                && s.owners
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, owners))
        })
    }
    pub(crate) fn setup(
        &self,
        owner: NonHTTPOwner010,
        endpoint: &mut CompletionEndpoint010,
        name: &str,
        version: &str,
    ) -> Result<MCPSetup> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let owners = {
            let mut state = self.state.lock().map_err(|_| Invalid)?;
            ensure(!state.retired && owner.initiator())?;
            state.setup_used = true;
            state.owners.clone()
        };
        let mut setup =
            MCPSetup::coordinated(owner, endpoint, name, version, self.coordinator.clone())?;
        if let Some(owners) = owners {
            if let Err(error) = owners.register(&mut setup) {
                drop(_c);
                return Err(error);
            }
        }
        Ok(setup)
    }
    pub(crate) fn retire(&self) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        self.state.lock().map_err(|_| Invalid)?.retired = true;
        Ok(())
    }
    fn sample(state: &mut PoolState, now: Stamp) -> Result<()> {
        if state
            .last
            .is_some_and(|old| now.mono_ms < old.mono_ms || now.unix < old.unix)
        {
            state.retired = true;
        }
        ensure(!state.retired)?;
        state.last = Some(now);
        Ok(())
    }
    fn start<'a>(
        &'a self,
        owner: &mut MCPSetup,
        endpoint: &mut CompletionEndpoint010,
    ) -> Result<(Lease<'a>, Stamp, i64, Arc<()>)> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        ensure(!state.retired && state.active < self.capacity)?;
        let start = owner.protected_time(endpoint, &self.coordinator, None, true)?;
        Self::sample(&mut state, start)?;
        let deadline = start.mono_ms.checked_add(self.timeout_ms).ok_or(Invalid)?;
        owner.bind_deadline(deadline)?;
        let operation = owner.operation()?;
        state.active += 1;
        Ok((Lease(self), start, deadline, operation))
    }
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        owner: &mut MCPSetup,
        endpoint: &mut CompletionEndpoint010,
        operation: &Arc<()>,
        start: Stamp,
        deadline: i64,
        evidence: &Evidence,
        output: bool,
        finish: bool,
    ) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        let now = owner.protected_time(endpoint, &self.coordinator, Some(operation), true)?;
        Self::sample(&mut state, now)?;
        evidence.valid(now, start, deadline)?;
        if output {
            owner.finish_output(operation)?;
        }
        if finish {
            owner.finish_operation(operation)?;
        }
        Ok(())
    }
}
pub(crate) struct OwnedServices {
    pub(crate) intent_authority: RegistryAuthority,
    pub(crate) result_authority: RegistryAuthority,
    pub(crate) policy: Box<dyn IntentPolicy + Send>,
    pub(crate) clock: Box<dyn ClientClock + Send>,
}
/// Consumes both the negotiated owner and durable client. No alternate sender,
/// session export, raw response or invocation token is exposed by this adapter.
pub(crate) struct OwnedClient {
    owner: MCPSetup,
    pool: Arc<ClientPool>,
    client: Client,
    intent: Vec<u8>,
    authority: Arc<Mutex<RegistryAuthority>>,
    result_authority: Arc<Mutex<RegistryAuthority>>,
    policy: Arc<Mutex<Box<dyn IntentPolicy + Send>>>,
    // Last field keeps shared owner capacity through journal/provider destruction.
    _registration: Option<Arc<()>>,
}
impl OwnedClient {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        pool: Arc<ClientPool>,
        mut owner: MCPSetup,
        endpoint: &mut CompletionEndpoint010,
        path: &Path,
        create: bool,
        intent: &[u8],
        services: OwnedServices,
    ) -> Result<Self> {
        let mut durable = None;
        let mut lease = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let intent = intent_envelope(intent)?.1;
            let raw = mcp_request(MCP_VERSION, "00000000-0000-4000-8000-000000000001", &intent)?;
            let (local, peer) = owner.owner.participants().map_err(|_| Invalid)?;
            super::mcp_session::request(
                MCP_VERSION,
                "00000000-0000-4000-8000-000000000001",
                &raw,
                &local,
                &peer,
            )?;
            let (slot, start, deadline, operation) = pool.start(&mut owner, endpoint)?;
            lease = Some(slot);
            let authority = Arc::new(Mutex::new(services.intent_authority));
            let result_authority = Arc::new(Mutex::new(services.result_authority));
            let policy = Arc::new(Mutex::new(services.policy));
            durable = Some(Client::open(
                path,
                create,
                &intent,
                ClientServices {
                    intent_authority: Box::new(Binding(authority.clone())),
                    result_authority: Box::new(Binding(result_authority.clone())),
                    policy: Box::new(Policy(policy.clone())),
                    clock: Box::new(SafeClock(services.clock)),
                    sender: Box::new(NoSender),
                    expected_issuer: local.clone(),
                    expected_recipient: peer.clone(),
                },
            )?);
            let evidence = intent_evidence(
                &mut owner,
                endpoint,
                &intent,
                &mut *authority.lock().map_err(|_| Invalid)?,
                policy.lock().map_err(|_| Invalid)?.as_mut(),
            )?;
            pool.publish(
                &mut owner, endpoint, &operation, start, deadline, &evidence, false, true,
            )?;
            Ok((intent, authority, result_authority, policy))
        }))
        .unwrap_or(Err(Invalid));
        if result.is_err() {
            owner.fail();
            if let Some(client) = durable.take() {
                let _ = client.close();
            }
        }
        drop(lease);
        match result {
            Ok((intent, authority, result_authority, policy)) => Ok(Self {
                _registration: owner.registration.clone(),
                owner,
                pool,
                client: durable.ok_or(Invalid)?,
                intent,
                authority,
                result_authority,
                policy,
            }),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn closer(&self) -> super::mcp_setup::SetupClose {
        self.owner.closer()
    }
    /// Exactly one correlated exchange. Durable terminal acceptance precedes final
    /// publication; a late failure suppresses output without restoring consumption.
    pub(crate) fn exchange(
        &mut self,
        endpoint: &mut CompletionEndpoint010,
        io: &mut dyn SetupIO,
    ) -> Result<ClientDelivery> {
        let mut ticket = None;
        let mut accepting = false;
        let pool = self.pool.clone();
        let mut lease = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (slot, start, deadline, operation) = pool.start(&mut self.owner, endpoint)?;
            lease = Some(slot);
            let id = ::uuid::Uuid::new_v4().to_string();
            let mut sender = Sender {
                owner: &mut self.owner,
                endpoint,
                io,
                pool: &pool,
                authority: &self.authority,
                policy: &self.policy,
                intent: &self.intent,
                operation: &operation,
                start,
                deadline,
                id: &id,
                outer: String::new(),
            };
            ticket = Some(self.client.begin_owned(&id, &mut sender)?);
            let outer = sender.outer;
            let wire = io.receive(deadline, &self.owner.closer())?;
            ensure(!wire.is_empty() && wire.len() <= 32768 && wire_id(&wire)? != id)?;
            let response = self
                .owner
                .owner
                .open_response(endpoint, &wire)
                .map_err(|_| Invalid)?;
            let (local, peer) = self.owner.owner.participants().map_err(|_| Invalid)?;
            let code = super::mcp_session::response(
                MCP_VERSION,
                &id,
                &response.data,
                &self.intent,
                &peer,
                &local,
            )?;
            ensure(
                response.message_id == outer
                    && response.success == code.is_none()
                    && response.error == code.unwrap_or(""),
            )?;
            let raw = super::mcp_rpc::response(MCP_VERSION, &id, &response.data)?;
            accepting = true;
            let delivery = self.client.accept_mcp_response(
                ticket.as_ref().ok_or(Invalid)?,
                MCP_VERSION,
                &response.data,
            )?;
            let evidence = result_evidence(
                &mut self.owner,
                endpoint,
                &raw,
                &self.intent,
                &mut *self.result_authority.lock().map_err(|_| Invalid)?,
            )?;
            pool.publish(
                &mut self.owner,
                endpoint,
                &operation,
                start,
                deadline,
                &evidence,
                false,
                true,
            )?;
            Ok(delivery)
        }))
        .unwrap_or(Err(Invalid));
        if result.is_err() {
            self.owner.fail();
            if !accepting {
                if let Some(ticket) = ticket {
                    let _ = self.client.failed(&ticket);
                }
            }
            let _ = self.client.close();
        }
        drop(lease); // callbacks and conservative journal cleanup have ended
        result
    }
    pub(crate) fn close(&mut self) -> Result<()> {
        self.owner.fail();
        self.client.close()
    }
}
impl Drop for OwnedClient {
    fn drop(&mut self) {
        self.owner.fail();
        let _ = self.client.close();
    }
}
struct Sender<'a> {
    owner: &'a mut MCPSetup,
    endpoint: &'a mut CompletionEndpoint010,
    io: &'a mut dyn SetupIO,
    pool: &'a ClientPool,
    authority: &'a Arc<Mutex<RegistryAuthority>>,
    policy: &'a Arc<Mutex<Box<dyn IntentPolicy + Send>>>,
    intent: &'a [u8],
    operation: &'a Arc<()>,
    start: Stamp,
    deadline: i64,
    id: &'a str,
    outer: String,
}
impl ClientSender for Sender<'_> {
    fn commit(&mut self, id: &str, intent: &[u8]) -> Result<()> {
        ensure(id == self.id && intent == self.intent)?;
        {
            let _c = self.pool.coordinator.lock().map_err(|_| Invalid)?;
            ensure(!self.pool.state.lock().map_err(|_| Invalid)?.retired)?;
            self.owner.protected_time(
                self.endpoint,
                &self.pool.coordinator,
                Some(self.operation),
                true,
            )?;
            self.owner.reserve_client_id(id)?;
            self.owner.begin_output(self.operation)?;
        }
        let raw = mcp_request(MCP_VERSION, id, intent)?;
        let (local, peer) = self.owner.owner.participants().map_err(|_| Invalid)?;
        super::mcp_session::request(MCP_VERSION, id, &raw, &local, &peer)?;
        let wire = self
            .owner
            .owner
            .seal_request(self.endpoint, &raw, 30)
            .map_err(|_| Invalid)?;
        ensure(wire.len() <= 32768 && wire_id(&wire)? != id)?;
        self.outer = wire_id(&wire)?;
        ensure(!self.owner.closer().closed())?;
        self.io.send(&wire, self.deadline, &self.owner.closer())?;
        let evidence = intent_evidence(
            self.owner,
            self.endpoint,
            intent,
            &mut *self.authority.lock().map_err(|_| Invalid)?,
            self.policy.lock().map_err(|_| Invalid)?.as_mut(),
        )?;
        self.pool.publish(
            self.owner,
            self.endpoint,
            self.operation,
            self.start,
            self.deadline,
            &evidence,
            true,
            false,
        )
    }
}
