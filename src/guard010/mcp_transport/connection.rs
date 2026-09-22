use super::*;
use std::path::Path;
#[derive(Clone)]
pub(crate) enum Role {
    Responder,
    Initiator { recipient: String, key: String },
}
#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) role: Role,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) ttl: i64,
    pub(crate) timeout: Duration,
}
impl Config {
    pub(super) fn valid(&self) -> Result<()> {
        ensure(
            (1..=300).contains(&self.ttl)
                && !self.timeout.is_zero()
                && self.timeout <= Duration::from_secs(30)
                && self.name.len() + self.version.len() <= 16000,
        )
    }
}
/// Endpoint construction happens on the charged connection worker. No Send bound
/// is imposed on endpoint providers, and no endpoint alias is exported.
pub(crate) trait Handler {
    fn endpoint(&mut self) -> Result<CompletionEndpoint010>;
    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }
    fn handle(&mut self, connection: &mut Connection) -> Result<()>;
}
struct Endpoint(CompletionEndpoint010, Arc<Socket>);
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.1.close();
        self.0.close();
    }
}
struct Pending(PendingCompletion010);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.close();
    }
}
enum Protocol {
    Setup(Box<MCPSetup>),
    Client(Box<OwnedClient>),
    Closed,
}
/// All protocol operations use this connection's sole owned stream. Field order
/// keeps capacity charged through protocol, endpoint and socket destruction.
pub(crate) struct Connection {
    protocol: Protocol,
    endpoint: Endpoint,
    stream: Stream,
    pool: Arc<Pool>,
    _lease: Arc<()>,
}
impl Connection {
    fn establish(
        pool: Arc<Pool>,
        socket: Arc<Socket>,
        lease: Arc<()>,
        config: &Config,
        handler: &mut dyn Handler,
    ) -> Result<Self> {
        let mut stream = Stream::new(socket, pool.clone(), config.timeout);
        let mut endpoint = Endpoint(handler.endpoint()?, stream.socket.clone());
        ensure(stream.socket.live() && pool.live())?;
        let authenticated = match &config.role {
            Role::Initiator { recipient, key } => {
                let (pending, request) = endpoint
                    .0
                    .start(recipient, key, config.ttl)
                    .map_err(|_| Invalid)?;
                let mut pending = Pending(pending);
                stream.send_frame(&request, None)?;
                let response = stream.receive_frame(None)?;
                pending
                    .0
                    .complete(&mut endpoint.0, &response)
                    .map_err(|_| Invalid)?
            }
            Role::Responder => {
                let request = stream.receive_frame(None)?;
                let (mut authenticated, response) = endpoint
                    .0
                    .respond(&request, config.ttl)
                    .map_err(|_| Invalid)?;
                if stream.send_frame(&response, None).is_err() {
                    authenticated.close();
                    return Err(Invalid);
                }
                authenticated
            }
        };
        // Conversion consumes and erases the authenticated keys on failure.
        let owner = authenticated
            .into_non_http(&endpoint.0)
            .map_err(|_| Invalid)?;
        let mut setup = match config.role {
            Role::Initiator { .. } => {
                pool.clients
                    .setup(owner, &mut endpoint.0, &config.name, &config.version)?
            }
            Role::Responder => {
                pool.gate
                    .setup(owner, &mut endpoint.0, &config.name, &config.version)?
            }
        };
        stream.socket.bind(setup.closer())?;
        setup.run(&mut endpoint.0, &mut stream, &mut || handler.prepare())?;
        // Owner handle is already published. Never extend the original handshake
        // wall-time budget while transitioning into protected operation handling.
        stream.socket.ready()?;
        ensure(stream.socket.live() && pool.live())?;
        Ok(Self {
            protocol: Protocol::Setup(Box::new(setup)),
            endpoint,
            stream,
            pool,
            _lease: lease,
        })
    }
    pub(crate) fn closer(&self) -> Result<SetupClose> {
        match &self.protocol {
            Protocol::Setup(owner) => Ok(owner.closer()),
            Protocol::Client(client) => Ok(client.closer()),
            Protocol::Closed => Err(Invalid),
        }
    }
    /// Reads one bounded frame and returns after protected reply publication.
    /// Effects are executed only by the gate's separately fixed worker pool.
    pub(crate) fn serve_one(&mut self, signer: &mut dyn ResultSigner) -> Result<()> {
        let result = (|| {
            let Protocol::Setup(owner) = &mut self.protocol else {
                return Err(Invalid);
            };
            ensure(!owner.owner.initiator())?;
            let deadline = self
                .pool
                .sample()?
                .mono_ms
                .checked_add(self.stream.bound_ms())
                .ok_or(Invalid)?;
            let wire = self.stream.receive(deadline, &owner.closer())?;
            self.pool.gate.admit(owner, &mut self.endpoint.0, &wire)?;
            self.pool
                .gate
                .reply(owner, &mut self.endpoint.0, &mut self.stream, signer)
        })();
        if result.is_err() {
            self.stream.socket.close();
        }
        result
    }
    pub(crate) fn open_client(
        &mut self,
        path: &Path,
        create: bool,
        intent: &[u8],
        services: OwnedServices,
    ) -> Result<()> {
        let previous = std::mem::replace(&mut self.protocol, Protocol::Closed);
        let result = (|| {
            let Protocol::Setup(owner) = previous else {
                return Err(Invalid);
            };
            let client = OwnedClient::open(
                self.pool.clients.clone(),
                *owner,
                &mut self.endpoint.0,
                path,
                create,
                intent,
                services,
            )?;
            self.protocol = Protocol::Client(Box::new(client));
            Ok(())
        })();
        if result.is_err() {
            self.stream.socket.close();
        }
        result
    }
    pub(crate) fn exchange(&mut self) -> Result<ClientDelivery> {
        let result = match &mut self.protocol {
            Protocol::Client(client) => client.exchange(&mut self.endpoint.0, &mut self.stream),
            _ => Err(Invalid),
        };
        if result.is_err() {
            self.stream.socket.close();
        }
        result
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.stream.socket.close();
    }
}
pub(super) fn run(
    pool: &Arc<Pool>,
    tcp: TcpStream,
    config: &Config,
    handler: &mut dyn Handler,
) -> Result<()> {
    config.valid()?;
    let deadline = Instant::now().checked_add(config.timeout).ok_or(Invalid)?;
    let socket = Socket::new(tcp, deadline)?;
    let lease = pool.reserve(socket.clone())?;
    // The outer lease survives every construction/handler panic and all inner
    // field destructors, including provider cleanup during failed construction.
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut connection =
            Connection::establish(pool.clone(), socket, lease.clone(), config, handler)?;
        handler.handle(&mut connection)?;
        ensure(connection.stream.socket.live() && pool.live())
    }))
    .unwrap_or(Err(Invalid));
    drop(lease);
    pool.changed.notify_all();
    result
}
