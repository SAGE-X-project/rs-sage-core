//! Protected native host assembly over the private owner-aware MCP coordinator.
use super::{
    mcp_admission::{self, workers::Workers, MCPGate},
    mcp_lifecycle::OwnerMonitor,
    mcp_owned::{ClientPool, OwnedServices},
    mcp_transport::{self, connection},
    *,
};
use crate::hpke::completion010::CompletionEndpoint010;
use crate::registry010::{Clock, Stamp};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Read-only cooperative cancellation. It never releases charged capacity.
pub struct MCPCancellation {
    inner: mcp_admission::Cancellation,
}
impl MCPCancellation {
    /// Stop promptly and finish all effect/dependency cleanup before returning.
    pub fn cancelled(&self) -> bool {
        self.inner.cancelled()
    }
}
/// Trusted immutable loaded effect owner, with bounded, non-reentrant callbacks.
/// Never detach effects, resolve a different instance or mutate exact arguments.
pub trait MCPExecutor: Send + Sync {
    /// Check the approved immutable instance and exact tool before commitment.
    fn check(&self, manifest: &str, tool: &str) -> Result<()>;
    /// Return only after the actual effect and cleanup have ended.
    fn run(&self, invocation: &Invocation, cancellation: &MCPCancellation) -> Result<Vec<u8>>;
}
struct Executor(Arc<dyn MCPExecutor>);
impl mcp_admission::Executor for Executor {
    fn check(&self, manifest: &str, tool: &str) -> Result<()> {
        self.0.check(manifest, tool)
    }
    fn run(
        &self,
        invocation: &Invocation,
        cancellation: &mcp_admission::Cancellation,
    ) -> Result<Vec<u8>> {
        self.0.run(
            invocation,
            &MCPCancellation {
                inner: cancellation.clone(),
            },
        )
    }
}
struct SharedClock(Arc<Mutex<Box<dyn Clock + Send>>>);
impl Clock for SharedClock {
    fn now(&mut self) -> crate::error::Result<Stamp> {
        self.0
            .lock()
            .map_err(|_| crate::error::Error::Other("host clock unavailable".into()))?
            .now()
    }
}
/// Protected local capabilities; never provisioned from model/plugin input.
/// Registry, endpoint and Client clocks must share this monotonic time origin.
pub struct MCPHostServices {
    /// Fresh fixed caller key authority.
    pub intent_authority: RegistryAuthority,
    /// Fresh fixed executor result key authority.
    pub result_authority: RegistryAuthority,
    /// Local approved original, exact arguments and policy epoch.
    pub policy: Box<dyn IntentPolicy + Send>,
    /// Same immutable loaded instance for verification and actual execution.
    pub executor: Arc<dyn MCPExecutor>,
    /// One protected signer per fixed execution worker, without key fallback.
    pub signers: Vec<Box<dyn ResultSigner + Send>>,
    /// Trusted bounded local clock, shared by all three host coordinators.
    pub clock: Box<dyn Clock + Send>,
}
/// Explicit finite quotas and whole-millisecond logical deadlines.
pub struct MCPHostBounds {
    /// Maximum charged admitted effects and result publications (1..=128).
    pub capacity: usize,
    /// Maximum preparation work (capacity..=128).
    pub preparations: usize,
    /// Maximum shared outbound operations (1..=128).
    pub clients: usize,
    /// Maximum owned sessions and transport connections (1..=256).
    pub owners: usize,
    /// Exact execution worker count, matching the protected signer count.
    pub workers: usize,
    /// Request/publication lifetime, at most 300 seconds.
    pub request: Duration,
    /// Queue claim lifetime, at most 300 seconds.
    pub claim: Duration,
    /// Actual effect/cleanup lifetime, at most 300 seconds.
    pub worker: Duration,
    /// Outbound operation lifetime, at most 300 seconds.
    pub client: Duration,
    /// Independent supervision period, shorter than every deadline (1..=1000ms).
    pub tick: Duration,
}
fn millis(d: Duration, max: u64) -> Result<i64> {
    ensure(
        d >= Duration::from_millis(1)
            && d <= Duration::from_millis(max)
            && d.subsec_nanos() % 1_000_000 == 0,
    )?;
    i64::try_from(d.as_millis()).map_err(|_| Invalid)
}
impl MCPHostBounds {
    fn valid(&self) -> Result<()> {
        ensure(
            (1..=128).contains(&self.capacity)
                && (self.capacity..=128).contains(&self.preparations)
                && (1..=128).contains(&self.clients)
                && (1..=256).contains(&self.owners)
                && (1..=self.capacity).contains(&self.workers),
        )?;
        millis(self.tick, 1000)?;
        for d in [self.request, self.claim, self.worker, self.client] {
            millis(d, 300_000)?;
            ensure(self.tick < d)?;
        }
        Ok(())
    }
}
/// Owns the exclusive execution ledger, fixed effect workers, independent owner
/// monitoring and sole transport streams. No gate, READY setter, session, raw
/// transport, reservation or worker token is exposed. Keep this in the trusted host.
pub struct MCPHost {
    inner: mcp_transport::Host,
    gate: Option<Arc<MCPGate>>,
}
/// Finite quotas for an initiator-only host; whole-millisecond durations.
pub struct MCPClientHostBounds {
    /// Maximum shared outbound operations (1..=128).
    pub clients: usize,
    /// Maximum owned sessions and transport connections (1..=256).
    pub owners: usize,
    /// Outbound operation lifetime, at most 300 seconds.
    pub client: Duration,
    /// Independent supervision period, shorter than `client` (1..=1000ms).
    pub tick: Duration,
}
impl MCPHost {
    /// Assemble every coordinator before peer input. Explicit creation is only
    /// for a new isolated scope; reopening never resets missing durable history.
    pub fn open(
        path: &Path,
        create: bool,
        recipient: &str,
        s: MCPHostServices,
        b: MCPHostBounds,
    ) -> Result<Self> {
        ensure(cfg!(any(target_os = "linux", target_os = "macos")))?;
        b.valid()?;
        ensure(s.signers.len() == b.workers)?;
        let shared = Arc::new(Mutex::new(s.clock));
        let gate = Arc::new(MCPGate::open(
            path,
            create,
            recipient,
            s.intent_authority,
            s.result_authority,
            s.policy,
            Arc::new(Executor(s.executor)),
            Box::new(SharedClock(shared.clone())),
            b.capacity,
            b.preparations,
            millis(b.request, 300_000)?,
            millis(b.claim, 300_000)?,
        )?);
        let clients = Arc::new(ClientPool::new(b.clients, millis(b.client, 300_000)?)?);
        let owners = OwnerMonitor::start(b.owners, b.tick, Box::new(SharedClock(shared.clone())))?;
        gate.attach_owners(owners.registry())?;
        clients.attach_owners(owners.registry())?;
        let workers = Workers::start(gate.clone(), s.signers, b.tick, millis(b.worker, 300_000)?)?;
        let inner = mcp_transport::Host::start(
            Some(gate.clone()),
            clients,
            owners,
            Some(workers),
            b.owners,
            Box::new(SharedClock(shared)),
        )?;
        Ok(Self {
            inner,
            gate: Some(gate),
        })
    }
    /// Assemble a host that only initiates root Client calls. It opens no
    /// admission gate, execution ledger, executor, policy or result signer and
    /// refuses `serve` and responder connections. A participant that also
    /// receives calls, including every hop participant, uses `open`.
    pub fn open_client(clock: Box<dyn Clock + Send>, b: MCPClientHostBounds) -> Result<Self> {
        ensure(cfg!(any(target_os = "linux", target_os = "macos")))?;
        ensure(
            (1..=128).contains(&b.clients)
                && (1..=256).contains(&b.owners)
                && b.tick >= Duration::from_millis(1)
                && b.tick <= Duration::from_millis(1000)
                && b.tick.subsec_nanos() % 1_000_000 == 0
                && b.tick < b.client,
        )?;
        let shared = Arc::new(Mutex::new(clock));
        let clients = Arc::new(ClientPool::new(b.clients, millis(b.client, 300_000)?)?);
        let owners = OwnerMonitor::start(b.owners, b.tick, Box::new(SharedClock(shared.clone())))?;
        clients.attach_owners(owners.registry())?;
        let inner = mcp_transport::Host::start(
            None,
            clients,
            owners,
            None,
            b.owners,
            Box::new(SharedClock(shared)),
        )?;
        Ok(Self { inner, gate: None })
    }
    /// Permanently retire all rights first, then drain every charged lifetime.
    /// False retains the ledger lock and host cleanup responsibility. Retry close
    /// after bounded providers finish; only true releases protected storage.
    pub fn close(&self, timeout: Duration) -> Result<bool> {
        if !self.inner.stop(timeout)? {
            return Ok(false);
        }
        if let Some(gate) = &self.gate {
            gate.close()?;
        }
        Ok(true)
    }
    /// Transfer exclusive socket ownership even on rejection. Run synchronously
    /// on a bounded host worker; no per-connection thread is created here.
    pub fn connect(
        &self,
        tcp: TcpStream,
        config: &MCPConnectionConfig,
        handler: &mut dyn MCPConnectionHandler,
    ) -> Result<()> {
        let config = config.private()?;
        self.inner.connection(tcp, &config, &mut Handler(handler))
    }
    /// Own one listener and exactly one accept/connection worker per supplied
    /// handler. Endpoint construction occurs only after connection reservation.
    pub fn serve(
        &self,
        tcp: TcpListener,
        config: MCPConnectionConfig,
        handlers: Vec<Box<dyn MCPConnectionHandler + Send>>,
    ) -> Result<MCPListener> {
        ensure(self.gate.is_some())?;
        let config = config.private()?;
        let handlers = handlers
            .into_iter()
            .map(|h| Box::new(OwnedHandler(h)) as Box<dyn mcp_transport::Handler + Send>)
            .collect();
        Ok(MCPListener {
            inner: self.inner.serve(tcp, config, handlers)?,
        })
    }
}
/// Listener ownership; dropping it stops this host's carriage. Full worker and
/// ledger shutdown still requires MCPHost::close, and timeout never frees capacity.
pub struct MCPListener {
    inner: mcp_transport::Listener,
}
impl MCPListener {
    /// Stop transport acceptance/connections and wait for actual socket cleanup.
    pub fn close(&self, timeout: Duration) -> Result<bool> {
        self.inner.stop(timeout)
    }
}
/// Locally selected endpoint role, never peer-negotiated readiness.
pub enum MCPRole {
    /// Receive authentication and initialize the fixed local service.
    Responder,
    /// Initiate only toward this exact locally configured peer and signing key.
    Initiator {
        /// Canonical local policy recipient DID.
        recipient: String,
        /// Exact active role-bound Ed25519 key ID.
        key: String,
    },
}
/// Pinned native carriage configuration. A four-byte big-endian frame length
/// precedes each exact envelope; this is deployment carriage, not MCP stdio.
pub struct MCPConnectionConfig {
    /// Locally selected initiator or responder role.
    pub role: MCPRole,
    /// Protected MCP implementation name.
    pub name: String,
    /// Protected MCP implementation version.
    pub version: String,
    /// Authenticated session lifetime from one through 300 seconds.
    pub ttl_seconds: i64,
    /// Entire authentication/setup wall-time budget, at most 30 seconds.
    pub timeout: Duration,
}
impl MCPConnectionConfig {
    fn private(&self) -> Result<mcp_transport::Config> {
        millis(self.timeout, 30_000)?;
        ensure(
            (1..=300).contains(&self.ttl_seconds) && self.name.len() + self.version.len() <= 16000,
        )?;
        let role = match &self.role {
            MCPRole::Responder => mcp_transport::Role::Responder,
            MCPRole::Initiator { recipient, key } => {
                let (principal, name) = key.split_once('#').ok_or(Invalid)?;
                ensure(did(recipient) && principal == recipient && chars(name, 32, false))?;
                mcp_transport::Role::Initiator {
                    recipient: recipient.clone(),
                    key: key.clone(),
                }
            }
        };
        Ok(mcp_transport::Config {
            role,
            name: self.name.clone(),
            version: self.version.clone(),
            ttl: self.ttl_seconds,
            timeout: self.timeout,
        })
    }
}
/// Trusted, bounded, non-reentrant callbacks. No endpoint alias may be retained.
pub trait MCPConnectionHandler {
    /// Construct and exclusively transfer a fresh endpoint after quota reservation.
    fn endpoint(&mut self) -> Result<CompletionEndpoint010>;
    /// Establish actual local readiness before initialized acknowledgement.
    fn prepare(&mut self) -> Result<()>;
    /// Run only after authenticated MCP setup; finish all owned operations before
    /// returning. The borrowed connection cannot escape this callback's lifetime.
    fn handle(&mut self, connection: &mut MCPConnection<'_>) -> Result<()>;
}
struct Handler<'a>(&'a mut dyn MCPConnectionHandler);
impl mcp_transport::Handler for Handler<'_> {
    fn endpoint(&mut self) -> Result<CompletionEndpoint010> {
        self.0.endpoint()
    }
    fn prepare(&mut self) -> Result<()> {
        self.0.prepare()
    }
    fn handle(&mut self, c: &mut connection::Connection) -> Result<()> {
        self.0.handle(&mut MCPConnection { inner: c })
    }
}
struct OwnedHandler(Box<dyn MCPConnectionHandler + Send>);
impl mcp_transport::Handler for OwnedHandler {
    fn endpoint(&mut self) -> Result<CompletionEndpoint010> {
        self.0.endpoint()
    }
    fn prepare(&mut self) -> Result<()> {
        self.0.prepare()
    }
    fn handle(&mut self, c: &mut connection::Connection) -> Result<()> {
        self.0.handle(&mut MCPConnection { inner: c })
    }
}
/// Trusted outbound Guard services. The authenticated owner supplies the sender
/// and immutable local/peer tuple; callers cannot substitute a transport.
pub struct MCPClientServices {
    /// Current fixed caller signing key authority.
    pub intent_authority: RegistryAuthority,
    /// Current fixed result issuer signing key authority.
    pub result_authority: RegistryAuthority,
    /// Protected original, policy epoch and final tool argument authorizer.
    pub policy: Box<dyn IntentPolicy + Send>,
    /// Trusted bounded Client clock with the shared monotonic origin.
    pub clock: Box<dyn ClientClock + Send>,
}
impl MCPClientServices {
    fn private(self) -> OwnedServices {
        OwnedServices {
            intent_authority: self.intent_authority,
            result_authority: self.result_authority,
            policy: self.policy,
            clock: self.clock,
        }
    }
}
/// Current actually admitted upstream invocation and its protected verifier.
pub struct MCPHopServices<'a> {
    /// Parent minted by the running admitted MCP worker, never an ordinary token.
    pub parent: &'a Invocation,
    /// Fresh exact upstream identity authority.
    pub authority: Box<dyn Authority + Send>,
    /// Protected upstream policy bindings and evaluator.
    pub policy: Box<dyn IntentPolicy + Send>,
}
/// Opaque callback-scoped connection. No raw stream, key, owner, readiness flag or
/// sender can escape; each operation uses the sole authenticated private stream.
pub struct MCPConnection<'a> {
    inner: &'a mut connection::Connection,
}
impl MCPConnection<'_> {
    /// Receive one protected request, cross durable owner-aware admission, and
    /// publish a verified response using the protected executor signer. Pending
    /// status is possible; handoff is not peer acceptance or completed execution.
    pub fn serve_one(&mut self, signer: &mut dyn ResultSigner) -> Result<()> {
        self.inner.serve_one(signer)
    }
    /// Verify a signed root intent against independent original capture before
    /// journaling. One owner gets one Client; reopening preserves journal identity.
    pub fn open_root_client(
        &mut self,
        path: &Path,
        create: bool,
        intent: &[u8],
        s: MCPClientServices,
        capture: RootCapture,
    ) -> Result<()> {
        self.inner
            .open_client(path, create, intent, s.private(), capture)
    }
    /// Bind only a parent minted by an actually running admitted worker, with
    /// repeated upstream checks before protected downstream publication.
    pub fn open_hop_client(
        &mut self,
        path: &Path,
        create: bool,
        intent: &[u8],
        s: MCPClientServices,
        parent: MCPHopServices<'_>,
    ) -> Result<()> {
        self.inner.open_hop_client(
            path,
            create,
            intent,
            s.private(),
            parent.parent,
            parent.authority,
            parent.policy,
        )
    }
    /// Return journaled verified delivery through this owner's sole stream.
    pub fn exchange(&mut self) -> Result<ClientDelivery> {
        self.inner.exchange()
    }
}
