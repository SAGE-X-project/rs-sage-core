//! Public native host APIs with inert effects and bounded local TCP schedules.
use super::*;
use std::io::Read;
use std::sync::atomic::AtomicUsize;
use std::thread;

fn bounds() -> g::MCPHostBounds {
    g::MCPHostBounds {
        capacity: 2,
        preparations: 2,
        clients: 2,
        owners: 4,
        workers: 1,
        request: Duration::from_secs(20),
        claim: Duration::from_secs(10),
        worker: Duration::from_secs(1),
        client: Duration::from_secs(20),
        tick: Duration::from_millis(1),
    }
}
fn public_clock() -> Local {
    Local(Arc::new(AtomicI64::new(0)), Arc::new(AtomicI64::new(0)))
}
struct PublicPolicy;
impl g::IntentPolicy for PublicPolicy {
    fn bindings(&mut self, issuer: &str, _: &str) -> g::Result<g::Bindings> {
        if issuer != ALICE {
            return Err(g::Invalid);
        }
        let f = fixture();
        Ok(g::Bindings {
            original: g::original_commitment(&[b"trusted root input".to_vec()])?,
            policy: canonical(&f["approved_policy"]),
            manifest: canonical(&f["approved_manifest"]),
        })
    }
    fn authorize(&mut self, issuer: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        if issuer != ALICE || tool != "read" || args != br#"{"path":"public.txt"}"# {
            return Err(g::Invalid);
        };
        Ok(())
    }
}
/// Receiver administration for the fixture's one provisioned commitment. It
/// never holds the caller's original request.
struct PublicMapping;
impl g::ReceiverMapping for PublicMapping {
    fn approved(&mut self, issuer: &str, digest: &str) -> g::Result<(Vec<u8>, Vec<u8>)> {
        let f = fixture();
        let policy = canonical(&f["approved_policy"]);
        if issuer != ALICE || g::policy_commitment(&policy)? != digest {
            return Err(g::Invalid);
        }
        Ok((policy, canonical(&f["approved_manifest"])))
    }
    fn authorize(&mut self, issuer: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        g::IntentPolicy::authorize(&mut PublicPolicy, issuer, tool, args)
    }
}
#[derive(Default)]
struct PublicSink {
    effects: AtomicUsize,
}
impl g::MCPExecutor for PublicSink {
    fn check(&self, manifest: &str, tool: &str) -> g::Result<()> {
        if tool != "read"
            || manifest != g::manifest_commitment(&canonical(&fixture()["approved_manifest"]))?
        {
            return Err(g::Invalid);
        };
        Ok(())
    }
    fn run(&self, i: &g::Invocation, cancel: &g::MCPCancellation) -> g::Result<Vec<u8>> {
        if cancel.cancelled() || i.arguments() != br#"{"path":"public.txt"}"# {
            return Err(g::Invalid);
        }
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(br#"{"ok":true}"#.to_vec())
    }
}
fn public_services(clock: &Local, sink: Arc<PublicSink>) -> g::MCPHostServices {
    g::MCPHostServices {
        intent_authority: authority_for(clock.clone(), ALICE),
        result_authority: authority_for(clock.clone(), BOB),
        policy: Box::new(PublicPolicy),
        executor: sink,
        signers: vec![Box::new(Signer)],
        clock: Box::new(clock.clone()),
    }
}
fn public_host(path: &std::path::Path, sink: Arc<PublicSink>, clock: &Local) -> g::MCPHost {
    g::MCPHost::open(path, true, BOB, public_services(clock, sink), bounds()).unwrap()
}
fn public_config(initiator: bool) -> g::MCPConnectionConfig {
    g::MCPConnectionConfig {
        role: if initiator {
            g::MCPRole::Initiator {
                recipient: BOB.into(),
                key: format!("{BOB}#signing-1"),
            }
        } else {
            g::MCPRole::Responder
        },
        name: "public fixture".into(),
        version: "1".into(),
        ttl_seconds: 300,
        timeout: Duration::from_secs(3),
    }
}
fn public_envelope() -> Vec<u8> {
    let mut env: Value = serde_json::from_slice(&envelope()).unwrap();
    env["intent"]["original_digest"] =
        json!(g::original_commitment(&[b"trusted root input".to_vec()]).unwrap());
    signed_hop(env, 1)
}
fn public_capture(intent: &[u8]) -> g::RootCapture {
    let env: Value = serde_json::from_slice(intent).unwrap();
    g::RootCapture::new(
        &[b"trusted root input".to_vec()],
        env["intent"]["request_id"].as_str().unwrap(),
    )
    .unwrap()
}
fn client_services(clock: &Local) -> g::MCPClientServices {
    g::MCPClientServices {
        intent_authority: authority_for(clock.clone(), ALICE),
        result_authority: authority_for(clock.clone(), BOB),
        policy: Box::new(PublicPolicy),
        clock: Box::new(ClientTime(clock.clone())),
    }
}
struct PublicServer {
    clock: Local,
    prepared: Arc<AtomicBool>,
    deny: bool,
}
impl g::MCPConnectionHandler for PublicServer {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Ok(endpoint(false, &self.clock))
    }
    fn prepare(&mut self) -> g::Result<()> {
        if self.deny {
            return Err(g::Invalid);
        };
        self.prepared.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn handle(&mut self, c: &mut g::MCPConnection<'_>) -> g::Result<()> {
        assert!(self.prepared.load(Ordering::SeqCst));
        while c.serve_one(&mut Signer).is_ok() {}
        Ok(())
    }
}
struct PublicClient {
    clock: Local,
    path: std::path::PathBuf,
    called: bool,
    completed: bool,
    wrong_capture: bool,
}
impl g::MCPConnectionHandler for PublicClient {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Ok(endpoint(true, &self.clock))
    }
    fn prepare(&mut self) -> g::Result<()> {
        Ok(())
    }
    fn handle(&mut self, c: &mut g::MCPConnection<'_>) -> g::Result<()> {
        self.called = true;
        let raw = public_envelope();
        let capture = if self.wrong_capture {
            g::RootCapture::new(
                &[b"changed root".to_vec()],
                "00000000-0000-4000-8000-000000000002",
            )?
        } else {
            public_capture(&raw)
        };
        c.open_root_client(
            &self.path,
            true,
            &raw,
            client_services(&self.clock),
            capture,
        )?;
        for _ in 0..20 {
            let d = c.exchange()?;
            if d.status() == "completed" {
                assert!(d.first_terminal());
                assert_eq!(d.output(), br#"{"ok":true}"#);
                self.completed = true;
                return Ok(());
            };
            thread::sleep(Duration::from_millis(20));
            self.clock.0.fetch_add(1000, Ordering::SeqCst);
        }
        Err(g::Invalid)
    }
}
#[test]
fn public_host_rejects_configuration_before_storage() {
    let dir = tempfile::tempdir().unwrap();
    let clock = public_clock();
    let sink = Arc::new(PublicSink::default());
    for mode in [
        "capacity",
        "preparations",
        "owners",
        "workers",
        "deadline",
        "fractional",
        "tick",
        "signers",
    ] {
        let mut b = bounds();
        let mut s = public_services(&clock, sink.clone());
        match mode {
            "capacity" => b.capacity = 0,
            "preparations" => b.preparations = 1,
            "owners" => b.owners = 257,
            "workers" => b.workers = 3,
            "deadline" => b.worker = Duration::from_secs(360),
            "fractional" => b.client += Duration::from_nanos(1),
            "tick" => b.tick = b.worker,
            "signers" => s.signers.clear(),
            _ => unreachable!(),
        };
        let path = dir.path().join(mode);
        assert!(g::MCPHost::open(&path, true, BOB, s, b).is_err());
        assert!(!path.exists());
    }
}
#[test]
fn public_tcp_host_binds_capture_and_readiness_before_one_effect() {
    for mode in ["allowed", "changed capture", "prepare denied"] {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(PublicSink::default());
        let clock = public_clock();
        let server = public_host(&dir.path().join("server"), sink.clone(), &clock);
        let client = public_host(
            &dir.path().join("client-gate"),
            Arc::new(PublicSink::default()),
            &clock,
        );
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        let prepared = Arc::new(AtomicBool::new(false));
        let listener = server
            .serve(
                tcp,
                public_config(false),
                vec![Box::new(PublicServer {
                    clock: clock.clone(),
                    prepared: prepared.clone(),
                    deny: mode == "prepare denied",
                })],
            )
            .unwrap();
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
        let path = dir.path().join("client");
        let mut handler = PublicClient {
            clock: clock.clone(),
            path: path.clone(),
            called: false,
            completed: false,
            wrong_capture: mode == "changed capture",
        };
        let result = client.connect(tcp, &public_config(true), &mut handler);
        if mode == "allowed" {
            assert!(result.is_ok());
            assert!(handler.completed);
            assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
            assert_eq!(row(&dir.path().join("server"))["state"], "COMPLETED");
        } else {
            assert!(result.is_err());
            assert!(!handler.completed);
            assert!(!path.exists());
            assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
            if mode == "prepare denied" {
                assert!(!handler.called);
                assert!(!prepared.load(Ordering::SeqCst));
            }
        }
        assert!(client.close(Duration::from_secs(3)).unwrap());
        assert!(listener.close(Duration::from_secs(3)).unwrap());
        assert!(server.close(Duration::from_secs(3)).unwrap());
    }
}
struct PublicBlockedFactory {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    count: Arc<AtomicUsize>,
}
impl g::MCPConnectionHandler for PublicBlockedFactory {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(3)).unwrap();
        Err(g::Invalid)
    }
    fn prepare(&mut self) -> g::Result<()> {
        Err(g::Invalid)
    }
    fn handle(&mut self, _: &mut g::MCPConnection<'_>) -> g::Result<()> {
        panic!("blocked factory reached protected handler")
    }
}
struct RejectFactory(Arc<AtomicUsize>);
impl g::MCPConnectionHandler for RejectFactory {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(g::Invalid)
    }
    fn prepare(&mut self) -> g::Result<()> {
        Err(g::Invalid)
    }
    fn handle(&mut self, _: &mut g::MCPConnection<'_>) -> g::Result<()> {
        Err(g::Invalid)
    }
}
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let left = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (right, _) = listener.accept().unwrap();
    (left, right)
}
#[test]
fn public_factory_remains_charged_until_cleanup_and_close() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gate");
    let clock = public_clock();
    let sink = Arc::new(PublicSink::default());
    let mut b = bounds();
    b.owners = 1;
    let h = Arc::new(
        g::MCPHost::open(&path, true, BOB, public_services(&clock, sink.clone()), b).unwrap(),
    );
    let (entered, notice) = mpsc::sync_channel(1);
    let (release, blocked) = mpsc::sync_channel(1);
    let count = Arc::new(AtomicUsize::new(0));
    let (left, _right) = tcp_pair();
    let task = h.clone();
    let calls = count.clone();
    let worker = thread::spawn(move || {
        task.connect(
            left,
            &public_config(true),
            &mut PublicBlockedFactory {
                entered,
                release: blocked,
                count: calls,
            },
        )
    });
    notice.recv_timeout(Duration::from_secs(1)).unwrap();
    let (left, _right) = tcp_pair();
    assert!(h
        .connect(
            left,
            &public_config(true),
            &mut RejectFactory(count.clone())
        )
        .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(!h.close(Duration::from_millis(20)).unwrap());
    assert!(g::MCPHost::open(
        &path,
        false,
        BOB,
        public_services(&clock, sink.clone()),
        bounds()
    )
    .is_err());
    release.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(h.close(Duration::from_secs(3)).unwrap());
    let reopened =
        g::MCPHost::open(&path, false, BOB, public_services(&clock, sink), bounds()).unwrap();
    assert!(reopened.close(Duration::from_secs(3)).unwrap());
    let (left, _right) = tcp_pair();
    assert!(h
        .connect(
            left,
            &public_config(true),
            &mut RejectFactory(count.clone())
        )
        .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
#[test]
fn public_connection_rejects_wrong_config_before_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let clock = public_clock();
    let h = public_host(
        &dir.path().join("gate"),
        Arc::new(PublicSink::default()),
        &clock,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    for mode in ["ttl", "timeout", "fractional", "key"] {
        let mut c = public_config(true);
        match mode {
            "ttl" => c.ttl_seconds = 301,
            "timeout" => c.timeout = Duration::ZERO,
            "fractional" => c.timeout += Duration::from_nanos(1),
            "key" => {
                c.role = g::MCPRole::Initiator {
                    recipient: BOB.into(),
                    key: format!("{ALICE}#signing-1"),
                }
            }
            _ => unreachable!(),
        };
        let (left, mut right) = tcp_pair();
        assert!(h
            .connect(left, &c, &mut RejectFactory(calls.clone()))
            .is_err());
        right
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(right.read(&mut [0; 1]).unwrap(), 0);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(h.close(Duration::from_secs(3)).unwrap());
}

// Separate-process fixtures share an advancing UTC/monotonic origin. Registry
// and endpoint replay providers are local test fixtures, not deployed services.
#[derive(Clone)]
struct ProcessClock(Local);
impl r::Clock for ProcessClock {
    fn now(&mut self) -> Result<Stamp> {
        let mono = self.0 .0.load(Ordering::SeqCst);
        Ok(Stamp {
            mono_ms: mono,
            unix: 100 + mono / 1000,
        })
    }
}
struct ProcessEndpointClock {
    control: Controls,
    time: Local,
}
impl r::Clock for ProcessEndpointClock {
    fn now(&mut self) -> Result<Stamp> {
        let stamp = ProcessClock(self.time.clone()).now()?;
        {
            let mut c = self.control.0.borrow_mut();
            c.mono = stamp.mono_ms;
            c.utc = stamp.unix;
        }
        self.control.now()
    }
}
fn process_endpoint(initiator: bool, clock: &Local) -> CompletionEndpoint010 {
    let (a, b, control, dir) = pair();
    let mut e = if initiator { a } else { b };
    e.clock = Box::new(ProcessEndpointClock {
        control,
        time: clock.clone(),
    });
    e.replay = Box::new(KeepReplay {
        inner: e.replay,
        _dir: dir,
    });
    e
}
fn process_authority(clock: &Local, did: &str) -> g::RegistryAuthority {
    let registry = r::SendGate::new_send(
        r::Config {
            source: "admission-fixture".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            blockchain: false,
        },
        Box::new(Source(clock.clone())),
        Box::new(ProcessClock(clock.clone())),
        Box::new(Store),
    )
    .unwrap();
    g::RegistryAuthority::new(registry, did, &format!("{did}#signing-1")).unwrap()
}
struct ProcessSigner(Local);
impl g::Authority for ProcessSigner {
    fn now(&mut self) -> g::Result<i64> {
        Ok(100 + self.0 .0.load(Ordering::SeqCst) / 1000)
    }
    fn active_key(&mut self, issuer: &str, keyid: &str) -> g::Result<[u8; 32]> {
        Signer.active_key(issuer, keyid)
    }
}
impl g::ResultSigner for ProcessSigner {
    fn key_id(&mut self) -> g::Result<String> {
        Signer.key_id()
    }
    fn sign(&mut self, key: &str, msg: &[u8]) -> g::Result<Vec<u8>> {
        Signer.sign(key, msg)
    }
}
struct ProcessHandler {
    clock: Local,
    path: Option<std::path::PathBuf>,
    completed: bool,
}
impl g::MCPConnectionHandler for ProcessHandler {
    fn endpoint(&mut self) -> g::Result<CompletionEndpoint010> {
        Ok(process_endpoint(self.path.is_some(), &self.clock))
    }
    fn prepare(&mut self) -> g::Result<()> {
        Ok(())
    }
    fn handle(&mut self, c: &mut g::MCPConnection<'_>) -> g::Result<()> {
        let Some(path) = &self.path else {
            while c.serve_one(&mut ProcessSigner(self.clock.clone())).is_ok() {}
            return Ok(());
        };
        let mut env: Value = serde_json::from_slice(&public_envelope()).unwrap();
        env["intent"]["created"] = json!(460);
        env["intent"]["expires"] = json!(760);
        let raw = signed_hop(env, 1);
        c.open_root_client(
            path,
            true,
            &raw,
            g::MCPClientServices {
                intent_authority: process_authority(&self.clock, ALICE),
                result_authority: process_authority(&self.clock, BOB),
                policy: Box::new(PublicPolicy),
                clock: Box::new(ClientTime(self.clock.clone())),
            },
            public_capture(&raw),
        )?;
        for _ in 0..20 {
            let d = c.exchange()?;
            if d.status() == "completed" {
                assert!(d.first_terminal());
                assert_eq!(d.output(), br#"{"ok":true}"#);
                self.completed = true;
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
            self.clock.0.fetch_add(1000, Ordering::SeqCst);
        }
        Err(g::Invalid)
    }
}

// Fixed public fixture process: loopback only and an inert exact read effect.
#[test]
fn public_process_helper() {
    let Ok(root) = std::env::var("SAGE_MCP_PUBLIC_TEST_ROOT") else {
        return;
    };
    let mode = std::env::var("SAGE_MCP_PUBLIC_TEST_MODE").unwrap();
    assert!(["server", "client"].contains(&mode.as_str()));
    let root = std::path::PathBuf::from(root);
    let clock = public_clock();
    clock.0.store(360000, Ordering::SeqCst);
    let sink = Arc::new(PublicSink::default());
    let ledger = root.join(format!("{mode}-gate"));
    let host = g::MCPHost::open(
        &ledger,
        true,
        BOB,
        g::MCPHostServices {
            intent_authority: process_authority(&clock, ALICE),
            result_authority: process_authority(&clock, BOB),
            policy: if mode == "server"
                && std::env::var("SAGE_MCP_PUBLIC_RECEIVER_MAPPING").as_deref() == Ok("1")
            {
                Box::new(g::ReceiverPolicy::new(PublicMapping))
            } else {
                Box::new(PublicPolicy)
            },
            executor: sink.clone(),
            signers: vec![Box::new(ProcessSigner(clock.clone()))],
            clock: Box::new(ProcessClock(clock.clone())),
        },
        bounds(),
    )
    .unwrap();
    if mode == "server" {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        std::fs::write(root.join("address"), tcp.local_addr().unwrap().to_string()).unwrap();
        let listener = host
            .serve(
                tcp,
                public_config(false),
                vec![Box::new(ProcessHandler {
                    clock: clock.clone(),
                    path: None,
                    completed: false,
                })],
            )
            .unwrap();
        let end = Instant::now() + Duration::from_secs(15);
        while !root.join("finished").exists() {
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(listener.close(Duration::from_secs(3)).unwrap());
        assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    } else {
        let address: std::net::SocketAddr = std::fs::read_to_string(root.join("address"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            address.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_ne!(address.port(), 0);
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        let mut handler = ProcessHandler {
            clock: clock.clone(),
            path: Some(root.join("client-journal")),
            completed: false,
        };
        host.connect(tcp, &public_config(true), &mut handler)
            .unwrap();
        assert!(handler.completed);
        std::fs::write(root.join("finished"), b"done").unwrap();
    }
    assert!(host.close(Duration::from_secs(3)).unwrap());
    let mut record = json!({"mode":mode,"status":"completed","effects":sink.effects.load(Ordering::SeqCst),"ledger_hex":hex::encode(std::fs::read(&ledger).unwrap())});
    if mode == "client" {
        record["journal_hex"] = json!(hex::encode(
            std::fs::read(root.join("client-journal")).unwrap()
        ));
    }
    std::fs::write(
        root.join(format!("{mode}.json")),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
}
