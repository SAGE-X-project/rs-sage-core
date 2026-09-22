//! Benign loopback sessions and inert bounded cancellation/cleanup schedules.
use super::*;
use g::mcp_admission::workers::Workers;
use g::mcp_lifecycle::OwnerMonitor;
use g::mcp_transport::{connection::Connection, Config as TransportConfig, Handler, Host, Role};
use std::sync::mpsc;
use std::time::Instant;
fn host(path: &std::path::Path, sink: Arc<Sink>, capacity: usize) -> (Host, Arc<MCPGate>, Local) {
    let (gate, clock) = gate(path, sink, capacity);
    let clients = Arc::new(ClientPool::new(capacity, 30000).unwrap());
    let owners = OwnerMonitor::start(
        capacity * 2,
        Duration::from_millis(1),
        Box::new(clock.clone()),
    )
    .unwrap();
    gate.attach_owners(owners.registry()).unwrap();
    clients.attach_owners(owners.registry()).unwrap();
    let workers = Workers::start(
        gate.clone(),
        vec![Box::new(Signer)],
        Duration::from_millis(1),
        30000,
    )
    .unwrap();
    let host = Host::start(
        gate.clone(),
        clients,
        owners,
        workers,
        capacity,
        Box::new(clock.clone()),
    )
    .unwrap();
    (host, gate, clock)
}
fn config(initiator: bool, timeout: Duration) -> TransportConfig {
    TransportConfig {
        role: if initiator {
            Role::Initiator {
                recipient: BOB.into(),
                key: format!("{BOB}#signing-1"),
            }
        } else {
            Role::Responder
        },
        name: "local fixture".into(),
        version: "1".into(),
        ttl: 300,
        timeout,
    }
}
struct KeepReplay {
    inner: Box<dyn ReplayStore010>,
    _dir: tempfile::TempDir,
}
impl ReplayStore010 for KeepReplay {
    fn reserve(&mut self, entry: Replay010) -> Result<()> {
        self.inner.reserve(entry)
    }
    fn reserve_record(
        &mut self,
        entry: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.inner.reserve_record(entry, validate)
    }
}
fn endpoint(initiator: bool, clock: &Local) -> CompletionEndpoint010 {
    let (a, b, control, dir) = pair();
    let mut endpoint = if initiator { a } else { b };
    endpoint.clock = Box::new(AdvancingClock {
        control,
        time: clock.0.clone(),
    });
    endpoint.replay = Box::new(KeepReplay {
        inner: endpoint.replay,
        _dir: dir,
    });
    endpoint
}
struct Server {
    clock: Local,
}
impl Handler for Server {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Ok(endpoint(false, &self.clock))
    }
    fn handle(&mut self, connection: &mut Connection) -> g::Result<()> {
        // No detached effects: only the independently bounded gate worker executes.
        while connection.serve_one(&mut Signer).is_ok() {}
        Ok(())
    }
}
struct ClientHandler {
    clock: Local,
    path: std::path::PathBuf,
    status: String,
}
impl Handler for ClientHandler {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Ok(endpoint(true, &self.clock))
    }
    fn handle(&mut self, connection: &mut Connection) -> g::Result<()> {
        connection.open_client(&self.path, true, &envelope(), services(&self.clock))?;
        let delivery = connection.exchange()?;
        self.status = delivery.status().to_string();
        if delivery.status() == "completed" {
            assert!(delivery.first_terminal());
            assert!(!delivery.output().is_empty());
        }
        Ok(())
    }
}
#[test]
fn owned_tcp_listener_completes_real_handshake_setup_and_protected_exchange() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Arc::new(Sink::default());
    let (server, gate, server_clock) = host(&tmp.path().join("server"), sink.clone(), 2);
    let (client, client_gate, client_clock) = host(
        &tmp.path().join("client-gate"),
        Arc::new(Sink::default()),
        1,
    );
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = server
        .serve(
            tcp,
            config(false, Duration::from_secs(5)),
            vec![Box::new(Server {
                clock: server_clock,
            })],
        )
        .unwrap();
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    let mut handler = ClientHandler {
        clock: client_clock,
        path: tmp.path().join("client"),
        status: String::new(),
    };
    client
        .connection(tcp, &config(true, Duration::from_secs(5)), &mut handler)
        .unwrap();
    assert!(["pending", "completed"].contains(&handler.status.as_str()));
    let end = Instant::now() + Duration::from_secs(5);
    while sink.effects.load(Ordering::SeqCst) != 1 {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(client.stop(Duration::from_secs(5)).unwrap());
    assert!(listener.stop(Duration::from_secs(5)).unwrap());
    assert!(server.stop(Duration::from_secs(5)).unwrap());
    assert_eq!(row(&tmp.path().join("server"))["state"], "COMPLETED");
    gate.close().unwrap();
    client_gate.close().unwrap();
}
struct BlockedFactory {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
impl Handler for BlockedFactory {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
        Err(g::Invalid)
    }
    fn handle(&mut self, _: &mut Connection) -> g::Result<()> {
        panic!("factory must not publish a connection")
    }
}
struct CountFactory(Arc<AtomicUsize>);
impl Handler for CountFactory {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(g::Invalid)
    }
    fn handle(&mut self, _: &mut Connection) -> g::Result<()> {
        Err(g::Invalid)
    }
}
fn socket_pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        TcpStream::connect_timeout(&l.local_addr().unwrap(), Duration::from_secs(2)).unwrap();
    let server = l.accept().unwrap().0;
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    (client, server)
}
#[test]
fn handshake_timeout_shuts_socket_but_retains_factory_and_fixed_worker_capacity() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, gate, _) = host(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let listener = host
        .serve(
            tcp,
            config(false, Duration::from_millis(100)),
            vec![Box::new(BlockedFactory {
                entered,
                release: released,
            })],
        )
        .unwrap();
    let mut peer = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0); // native shutdown while factory still blocked
    let count = Arc::new(AtomicUsize::new(0));
    let (_peer2, tcp2) = socket_pair();
    assert!(host
        .connection(
            tcp2,
            &config(false, Duration::from_secs(1)),
            &mut CountFactory(count.clone())
        )
        .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 0); // rejected before another factory/provider
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err());
    release.send(()).unwrap();
    assert!(listener.stop(Duration::from_secs(5)).unwrap());
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn listener_and_connection_rejection_close_transferred_native_sockets() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, gate, _) = host(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    assert!(host
        .serve(tcp, config(false, Duration::from_secs(1)), vec![])
        .is_err());
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err());
    let (mut peer, tcp) = socket_pair();
    let count = Arc::new(AtomicUsize::new(0));
    let mut invalid = config(false, Duration::from_secs(1));
    invalid.ttl = 0;
    assert!(host
        .connection(tcp, &invalid, &mut CountFactory(count.clone()))
        .is_err());
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}

#[test]
fn bounded_frame_reader_handles_benign_fragmentation_and_incomplete_frame_timeout() {
    for complete in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let (host, gate, _) = host(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
        let (mut peer, socket) = socket_pair();
        let worker = std::thread::spawn(move || {
            let started = Instant::now();
            let result = host.frame_fixture(socket, Duration::from_millis(300), None);
            if complete {
                assert_eq!(result.unwrap(), b"hello");
            } else {
                assert!(result.is_err());
                assert!(started.elapsed() < Duration::from_secs(2));
            }
            assert!(host.stop(Duration::from_secs(5)).unwrap());
            gate.close().unwrap();
        });
        // Harmless framing fixture; malformed length cases stay in pure unit tests.
        peer.write_all(&[0, 0]).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        peer.write_all(&[0, 5]).unwrap();
        peer.write_all(b"he").unwrap();
        if complete {
            peer.write_all(b"llo").unwrap();
        }
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        worker.join().unwrap();
    }
}
#[test]
fn framed_io_checks_original_clock_deadline_even_when_wall_time_remains() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, gate, clock) = host(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let (mut peer, socket) = socket_pair();
    clock.0.store(1000, Ordering::SeqCst);
    assert!(host
        .frame_fixture(socket, Duration::from_secs(5), Some(1000))
        .is_err());
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
struct BlockedReady {
    clock: Local,
    entered: mpsc::SyncSender<SetupClose>,
    release: mpsc::Receiver<()>,
}
impl Handler for BlockedReady {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Ok(endpoint(false, &self.clock))
    }
    fn handle(&mut self, connection: &mut Connection) -> g::Result<()> {
        self.entered.send(connection.closer()?).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(())
    }
}
#[test]
fn owner_close_interrupts_native_client_receive_while_server_handler_remains_charged() {
    let tmp = tempfile::tempdir().unwrap();
    let (server, server_gate, server_clock) =
        host(&tmp.path().join("server"), Arc::new(Sink::default()), 1);
    let (client, client_gate, client_clock) = host(
        &tmp.path().join("client-gate"),
        Arc::new(Sink::default()),
        1,
    );
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let listener = server
        .serve(
            tcp,
            config(false, Duration::from_secs(5)),
            vec![Box::new(BlockedReady {
                clock: server_clock,
                entered,
                release: released,
            })],
        )
        .unwrap();
    let path = tmp.path().join("client");
    let thread = std::thread::spawn(move || {
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        let mut handler = ClientHandler {
            clock: client_clock,
            path,
            status: String::new(),
        };
        assert!(client
            .connection(tcp, &config(true, Duration::from_secs(5)), &mut handler)
            .is_err());
        assert!(handler.status.is_empty());
        assert!(client.stop(Duration::from_secs(5)).unwrap());
        client_gate.close().unwrap();
    });
    let close = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    close.close();
    thread.join().unwrap();
    assert!(!server.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    assert!(listener.stop(Duration::from_secs(5)).unwrap());
    assert!(server.stop(Duration::from_secs(5)).unwrap());
    server_gate.close().unwrap();
}
struct DropFactory {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
impl Handler for DropFactory {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Err(g::Invalid)
    }
    fn handle(&mut self, _: &mut Connection) -> g::Result<()> {
        Err(g::Invalid)
    }
}
impl Drop for DropFactory {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}
#[test]
fn listener_shutdown_keeps_worker_quota_until_handler_dependencies_are_destroyed() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, gate, _) = host(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let listener = host
        .serve(
            tcp,
            config(false, Duration::from_secs(1)),
            vec![Box::new(DropFactory {
                entered,
                release: released,
            })],
        )
        .unwrap();
    assert!(!listener.stop(Duration::from_millis(5)).unwrap());
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err());
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    assert!(listener.stop(Duration::from_secs(5)).unwrap());
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}

struct CleanupReplay {
    inner: Box<dyn ReplayStore010>,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
impl ReplayStore010 for CleanupReplay {
    fn reserve(&mut self, entry: Replay010) -> Result<()> {
        self.inner.reserve(entry)
    }
    fn reserve_record(
        &mut self,
        entry: Replay010,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.inner.reserve_record(entry, validate)
    }
}
impl Drop for CleanupReplay {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}
struct CleanupEndpoint {
    clock: Local,
    cleanup: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
}
impl Handler for CleanupEndpoint {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        let mut endpoint = endpoint(false, &self.clock);
        let (entered, release) = self.cleanup.take().unwrap();
        endpoint.replay = Box::new(CleanupReplay {
            inner: endpoint.replay,
            entered,
            release,
        });
        Ok(endpoint)
    }
    fn handle(&mut self, _: &mut Connection) -> g::Result<()> {
        Err(g::Invalid)
    }
}
#[test]
fn failed_handshake_keeps_connection_slot_until_endpoint_cleanup_finishes() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, gate, clock) = host(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let listener = host
        .serve(
            tcp,
            config(false, Duration::from_secs(5)),
            vec![Box::new(CleanupEndpoint {
                clock,
                cleanup: Some((entered, released)),
            })],
        )
        .unwrap();
    let mut peer = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap(); // benign peer disconnect
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    let count = Arc::new(AtomicUsize::new(0));
    let (_peer2, tcp2) = socket_pair();
    assert!(host
        .connection(
            tcp2,
            &config(false, Duration::from_secs(1)),
            &mut CountFactory(count.clone())
        )
        .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    assert!(listener.stop(Duration::from_secs(5)).unwrap());
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
