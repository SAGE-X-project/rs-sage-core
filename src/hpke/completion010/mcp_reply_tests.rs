//! Inert end-to-end exchanges; no external agents, plugins or attack programs.
use super::*;
use crate::guard010::mcp_owned::{ClientPool, HopCapture, OwnedClient, OwnedServices};
use crate::guard010::mcp_setup::{SetupClose, SetupIO};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;

#[derive(Clone)]
struct HopPolicy {
    issuer: String,
    original: String,
    descriptor: Vec<u8>,
    manifest: Vec<u8>,
}
impl g::IntentPolicy for HopPolicy {
    fn bindings(&mut self, issuer: &str, _: &str) -> g::Result<g::Bindings> {
        if issuer != self.issuer {
            return Err(g::Invalid);
        }
        Ok(g::Bindings {
            original: self.original.clone(),
            policy: self.descriptor.clone(),
            manifest: self.manifest.clone(),
        })
    }
    fn authorize(&mut self, issuer: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        if issuer != self.issuer || tool != "read" || args != br#"{"path":"public.txt"}"# {
            return Err(g::Invalid);
        }
        Ok(())
    }
}
struct HopAuthority;
impl g::Authority for HopAuthority {
    fn now(&mut self) -> g::Result<i64> {
        Ok(100)
    }
    fn active_key(&mut self, issuer: &str, key: &str) -> g::Result<[u8; 32]> {
        const ORIGIN: &str = "did:sage:web:agent.example:origin";
        if issuer != ORIGIN || key != format!("{ORIGIN}#signing-1") {
            return Err(g::Invalid);
        }
        Ok(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes())
    }
}
struct HopAdmission {
    incoming: Vec<u8>,
    allowed: Arc<AtomicBool>,
}
impl g::HopParent for HopAdmission {
    fn authorized(&mut self, incoming: &[u8]) -> g::Result<()> {
        if !self.allowed.load(Ordering::SeqCst) || incoming != self.incoming {
            return Err(g::Invalid);
        }
        Ok(())
    }
}
fn signed_hop(mut envelope: Value, seed: u8) -> Vec<u8> {
    let message = [
        b"sage-execution-intent|0.10.0\0".as_slice(),
        &canonical(&envelope["intent"]),
    ]
    .concat();
    envelope["proof"] = json!(B64.encode(
        SigningKey::from_bytes(&[seed; 32])
            .sign(&message)
            .to_bytes()
    ));
    canonical(&envelope)
}
fn hop_inputs() -> (Vec<u8>, Vec<u8>, HopPolicy, HopPolicy) {
    const ORIGIN: &str = "did:sage:web:agent.example:origin";
    let fixture = fixture();
    let mut parent: Value = serde_json::from_slice(&envelope()).unwrap();
    parent["intent"]["issuer"] = json!(ORIGIN);
    parent["intent"]["recipient"] = json!(ALICE);
    parent["intent"]["keyid"] = json!(format!("{ORIGIN}#signing-1"));
    parent["intent"]["request_id"] = json!("00000000-0000-4000-8000-000000000031");
    parent["intent"]["call_id"] = json!("00000000-0000-4000-8000-000000000032");
    let mut parent_descriptor = fixture["approved_policy"].clone();
    parent_descriptor["issuer"] = json!(ORIGIN);
    parent["intent"]["policy_digest"] =
        json!(g::policy_commitment(&canonical(&parent_descriptor)).unwrap());
    let upstream = HopPolicy {
        issuer: ORIGIN.into(),
        original: fixture["original_digest"].as_str().unwrap().into(),
        descriptor: canonical(&parent_descriptor),
        manifest: canonical(&fixture["approved_manifest"]),
    };
    let incoming = signed_hop(parent, 3);
    let original = g::original_commitment(&[incoming.clone()]).unwrap();
    let mut child: Value = serde_json::from_slice(&envelope()).unwrap();
    child["intent"]["original_digest"] = json!(original);
    let outgoing = signed_hop(child, 1);
    let downstream = HopPolicy {
        issuer: ALICE.into(),
        original,
        descriptor: canonical(&fixture["approved_policy"]),
        manifest: canonical(&fixture["approved_manifest"]),
    };
    (incoming, outgoing, upstream, downstream)
}

#[test]
fn owned_hop_rechecks_parent_before_mcp_transport() {
    for mode in ["denied at open", "revoked before send", "allowed"] {
        let (left, right, mut a, mut b, _, tmp) = owner_pair();
        let (incoming, outgoing, upstream, downstream) = hop_inputs();
        let sink = Arc::new(Sink::default());
        let clock = Local(Arc::new(AtomicI64::new(0)), Arc::new(AtomicI64::new(0)));
        let gate = Arc::new(
            MCPGate::open(
                &tmp.path().join("execution"),
                true,
                BOB,
                authority_for(clock.clone(), ALICE),
                authority_for(clock.clone(), BOB),
                Box::new(downstream.clone()),
                sink.clone(),
                Box::new(clock.clone()),
                2,
                2,
                30000,
                1000,
            )
            .unwrap(),
        );
        let pool = Arc::new(ClientPool::new(2, 30000).unwrap());
        let mut client = pool.setup(left, &mut a, "client", "1").unwrap();
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        let mut link = Link::new(&mut server, &mut b, gate.clone(), mode == "allowed");
        client.run(&mut a, &mut link, &mut || Ok(())).unwrap();
        let parent = Arc::new(AtomicBool::new(mode != "denied at open"));
        let mut outbound = services(&clock);
        outbound.policy = Box::new(downstream);
        let path = tmp.path().join("client");
        let client = OwnedClient::open_hop(
            pool,
            client,
            &mut a,
            &path,
            true,
            &outgoing,
            outbound,
            HopCapture::fixture(
                incoming.clone(),
                g::HopServices {
                    authority: Box::new(HopAuthority),
                    policy: Box::new(upstream),
                    parent: Box::new(HopAdmission {
                        incoming,
                        allowed: parent.clone(),
                    }),
                },
            ),
        );
        if mode == "denied at open" {
            assert!(client.is_err());
            assert!(!path.exists());
            assert_eq!(link.protected_sends, 0);
            gate.close().unwrap();
            continue;
        }
        let mut client = client.unwrap();
        parent.store(mode == "allowed", Ordering::SeqCst);
        let result = client.exchange(&mut a, &mut link);
        if mode == "allowed" {
            let delivery = result.unwrap();
            assert_eq!(delivery.status(), "completed");
            assert_eq!(link.protected_sends, 1);
            assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
        } else {
            assert!(result.is_err());
            assert_eq!(link.protected_sends, 0);
            assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
        }
        client.close().unwrap();
        gate.close().unwrap();
    }
}

struct ClientTime(Local);
impl g::ClientClock for ClientTime {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        let m = self.0 .0.load(Ordering::SeqCst);
        Ok((100000 + m, m))
    }
}
fn services(clock: &Local) -> OwnedServices {
    OwnedServices {
        intent_authority: authority_for(clock.clone(), ALICE),
        result_authority: authority_for(clock.clone(), BOB),
        policy: Box::new(Policy),
        clock: Box::new(ClientTime(clock.clone())),
    }
}
struct Output {
    bytes: Vec<u8>,
    hook: Option<Box<dyn FnMut() -> g::Result<()>>>,
}
impl SetupIO for Output {
    fn send(&mut self, wire: &[u8], _: i64, _: &SetupClose) -> g::Result<()> {
        self.bytes = wire.to_vec();
        if let Some(hook) = self.hook.as_mut() {
            hook()?;
        }
        Ok(())
    }
    fn receive(&mut self, _: i64, _: &SetupClose) -> g::Result<Vec<u8>> {
        Err(g::Invalid)
    }
}
struct Link<'a> {
    server: &'a mut MCPSetup,
    endpoint: &'a mut CompletionEndpoint010,
    gate: Arc<MCPGate>,
    output: Output,
    run: bool,
    socket: Option<(TcpStream, TcpStream)>,
    protected_sends: usize,
    receive_hook: Option<Box<dyn FnMut() -> g::Result<()>>>,
}
fn transfer(from: &mut TcpStream, to: &mut TcpStream, raw: &[u8]) -> Vec<u8> {
    assert!((1..=32768).contains(&raw.len()));
    from.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
    from.write_all(raw).unwrap();
    let mut header = [0; 4];
    to.read_exact(&mut header).unwrap();
    let n = u32::from_be_bytes(header) as usize;
    assert!((1..=32768).contains(&n));
    let mut raw = vec![0; n];
    to.read_exact(&mut raw).unwrap();
    raw
}
impl SetupIO for Link<'_> {
    fn send(&mut self, wire: &[u8], _: i64, _: &SetupClose) -> g::Result<()> {
        let wire = if let Some((client, server)) = self.socket.as_mut() {
            transfer(client, server, wire)
        } else {
            wire.to_vec()
        };
        if self.server.phase() != Phase::Ready {
            self.server
                .accept_setup(self.endpoint, &wire, &mut self.output, &mut || Ok(()))?;
        } else {
            self.protected_sends += 1;
            self.gate.admit(self.server, self.endpoint, &wire)?;
            if self.run {
                self.gate.run_one(&mut Signer)?;
            }
            self.gate
                .reply(self.server, self.endpoint, &mut self.output, &mut Signer)?;
        }
        if let Some((client, server)) = self.socket.as_mut() {
            self.output.bytes = transfer(server, client, &self.output.bytes);
        }
        Ok(())
    }
    fn receive(&mut self, _: i64, _: &SetupClose) -> g::Result<Vec<u8>> {
        if let Some(hook) = self.receive_hook.as_mut() {
            hook()?;
        }
        Ok(std::mem::take(&mut self.output.bytes))
    }
}
impl<'a> Link<'a> {
    fn new(
        server: &'a mut MCPSetup,
        endpoint: &'a mut CompletionEndpoint010,
        gate: Arc<MCPGate>,
        tcp: bool,
    ) -> Self {
        let socket = if tcp {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let c =
                TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
                    .unwrap();
            let (s, _) = listener.accept().unwrap();
            for socket in [&c, &s] {
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
            }
            Some((c, s))
        } else {
            None
        };
        Self {
            server,
            endpoint,
            gate,
            output: Output {
                bytes: Vec::new(),
                hook: None,
            },
            run: true,
            socket,
            protected_sends: 0,
            receive_hook: None,
        }
    }
}
#[test]
fn owned_reply_and_client_consume_terminal_once_including_tcp_runtime() {
    for tcp in [false, true] {
        let (left, right, mut a, mut b, _, tmp) = owner_pair();
        let sink = Arc::new(Sink::default());
        let (gate, clock) = gate(&tmp.path().join("execution"), sink.clone(), 2);
        let pool = Arc::new(ClientPool::new(2, 30000).unwrap());
        let mut client = pool.setup(left, &mut a, "client", "1").unwrap();
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        let mut link = Link::new(&mut server, &mut b, gate.clone(), tcp);
        client.run(&mut a, &mut link, &mut || Ok(())).unwrap();
        let mut client = OwnedClient::open(
            pool,
            client,
            &mut a,
            &tmp.path().join("client"),
            true,
            &envelope(),
            services(&clock),
        )
        .unwrap();
        let result = client.exchange(&mut a, &mut link).unwrap();
        assert_eq!(result.status(), "completed");
        assert!(result.first_terminal());
        assert_eq!(result.output(), br#"{"text":"inert public fixture"}"#);
        assert!(client.exchange(&mut a, &mut link).is_err());
        assert_eq!(link.protected_sends, 1);
        assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
        client.close().unwrap();
        gate.close().unwrap();
    }
}
#[test]
fn pending_reply_ends_invocation_and_fresh_poll_does_not_repeat_effect() {
    let (left, right, mut a, mut b, control, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&tmp.path().join("execution"), sink.clone(), 2);
    let pool = Arc::new(ClientPool::new(2, 30000).unwrap());
    let mut client = pool.setup(left, &mut a, "client", "1").unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
    client.run(&mut a, &mut link, &mut || Ok(())).unwrap();
    let mut client = OwnedClient::open(
        pool,
        client,
        &mut a,
        &tmp.path().join("client"),
        true,
        &envelope(),
        services(&clock),
    )
    .unwrap();
    link.run = false;
    let result = client.exchange(&mut a, &mut link).unwrap();
    assert_eq!(result.status(), "pending");
    assert!(!result.first_terminal());
    assert!(result.output().is_empty());
    gate.run_one(&mut Signer).unwrap();
    clock.0.store(1000, Ordering::SeqCst);
    control.0.borrow_mut().mono = 1000;
    let result = client.exchange(&mut a, &mut link).unwrap();
    assert!(result.first_terminal());
    assert_eq!(result.status(), "completed");
    assert_eq!(link.server.history().len(), 4);
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    assert!(!gate.run_one(&mut Signer).unwrap());
    client.close().unwrap();
    gate.close().unwrap();
}
#[test]
fn failed_reply_does_not_erase_execution_or_allow_second_response() {
    for mode in ["send-error", "close", "panic", "deadline"] {
        let (mut left, right, mut a, mut b, control, tmp) = owner_pair();
        let sink = Arc::new(Sink::default());
        let path = tmp.path().join("execution");
        let (gate, _clock) = gate(&path, sink.clone(), 2);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut left, &mut server, &mut a, &mut b);
        gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
            .unwrap();
        gate.run_one(&mut Signer).unwrap();
        let before = std::fs::read(&path).unwrap();
        let close = server.closer();
        let c = control.clone();
        let mut io = Output {
            bytes: Vec::new(),
            hook: Some(Box::new(move || {
                match mode {
                    "send-error" => return Err(g::Invalid),
                    "close" => close.close(),
                    "panic" => panic!("inert send failure"),
                    "deadline" => c.0.borrow_mut().mono = 30000,
                    _ => (),
                }
                Ok(())
            })),
        };
        assert!(gate
            .reply(&mut server, &mut b, &mut io, &mut Signer)
            .is_err());
        assert!(gate
            .reply(&mut server, &mut b, &mut io, &mut Signer)
            .is_err());
        assert_eq!(server.phase(), Phase::Closed);
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert_eq!(row(&path)["state"], "COMPLETED");
        assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
        gate.close().unwrap();
    }
}

#[test]
fn protected_deadline_after_admission_fails_transport_without_rollback() {
    let (mut left, right, mut a, mut b, control, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let path = tmp.path().join("execution");
    let (gate, _clock) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap();
    assert!(gate.run_one(&mut Signer).unwrap());
    let before = std::fs::read(&path).unwrap();
    let sends = Arc::new(AtomicUsize::new(0));
    let observed = sends.clone();
    let mut io = Output {
        bytes: Vec::new(),
        hook: Some(Box::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            control.0.borrow_mut().mono = 30000;
            Ok(())
        })),
    };
    assert!(gate
        .reply(&mut server, &mut b, &mut io, &mut Signer)
        .is_err());
    assert!(gate
        .reply(&mut server, &mut b, &mut io, &mut Signer)
        .is_err());
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert_eq!(server.phase(), Phase::Closed);
    assert_eq!(before, std::fs::read(&path).unwrap());
    let entry = row(&path);
    assert_eq!(entry["state"], "COMPLETED");
    assert!(!entry["result_hex"].as_str().unwrap().is_empty());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    assert!(!gate.run_one(&mut Signer).unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    gate.close().unwrap();
}

struct CloseAfterTerminal {
    clock: Local,
    path: std::path::PathBuf,
    close: SetupClose,
}
impl g::ClientClock for CloseAfterTerminal {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        if std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .any(|line| line.contains("\"kind\":\"terminal\""))
        {
            self.close.close();
        }
        ClientTime(self.clock.clone()).sample()
    }
}
#[test]
fn close_after_durable_acceptance_suppresses_output_and_reopen_cannot_redeliver() {
    let (left, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("client");
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&tmp.path().join("execution"), sink.clone(), 2);
    let pool = Arc::new(ClientPool::new(2, 30000).unwrap());
    let mut setup = pool.setup(left, &mut a, "client", "1").unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
    setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
    let mut config = services(&clock);
    config.clock = Box::new(CloseAfterTerminal {
        clock: clock.clone(),
        path: path.clone(),
        close: setup.closer(),
    });
    let mut client = OwnedClient::open(
        pool.clone(),
        setup,
        &mut a,
        &path,
        true,
        &envelope(),
        config,
    )
    .unwrap();
    assert!(client.exchange(&mut a, &mut link).is_err());
    assert!(client.closer().closed());
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("\"kind\":\"terminal\""));
    let (left, right, mut a, mut b, _, _tmp2) = owner_pair();
    let mut setup = pool.setup(left, &mut a, "client", "1").unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
    setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
    let mut reopened = OwnedClient::open(
        pool,
        setup,
        &mut a,
        &path,
        false,
        &envelope(),
        services(&clock),
    )
    .unwrap();
    assert!(reopened.exchange(&mut a, &mut link).is_err());
    assert_eq!(link.protected_sends, 0);
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    gate.close().unwrap();
}
#[test]
fn old_worker_deadline_does_not_close_new_poll_after_pending_reply() {
    let (mut left, right, mut a, mut b, control, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&tmp.path().join("execution"), sink.clone(), 2);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap();
    let mut output = Output {
        bytes: Vec::new(),
        hook: None,
    };
    gate.reply(&mut server, &mut b, &mut output, &mut Signer)
        .unwrap();
    left.open_response(&mut a, &output.bytes).unwrap();
    let (entered, wait) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(3)).unwrap();
        Ok(())
    }));
    let worker = gate.clone();
    let thread = std::thread::spawn(move || worker.run_one(&mut Signer));
    wait.recv_timeout(Duration::from_secs(3)).unwrap();
    control.0.borrow_mut().mono = 1000;
    clock.0.store(1000, Ordering::SeqCst);
    let receipt = gate
        .admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap();
    assert!(!receipt.created());
    clock.0.store(30000, Ordering::SeqCst);
    control.0.borrow_mut().mono = 30000;
    release.send(()).unwrap();
    assert!(thread.join().unwrap().unwrap());
    assert_eq!(server.phase(), Phase::Ready);
    gate.reply(&mut server, &mut b, &mut output, &mut Signer)
        .unwrap();
    assert_eq!(server.phase(), Phase::Ready);
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    gate.close().unwrap();
}

#[test]
fn oversized_completed_result_is_preserved_without_transport_output() {
    let (mut left, right, mut a, mut b, _, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    sink.output_size.store(20000, Ordering::SeqCst);
    let path = tmp.path().join("execution");
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap();
    gate.run_one(&mut Signer).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut output = Output {
        bytes: Vec::new(),
        hook: None,
    };
    assert!(gate
        .reply(&mut server, &mut b, &mut output, &mut Signer)
        .is_err());
    assert!(output.bytes.is_empty());
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert_eq!(row(&path)["state"], "COMPLETED");
    gate.close().unwrap();
}
#[test]
fn reply_final_publication_rechecks_registry_observation_age() {
    for delay in [5000, 5001] {
        let (mut left, right, mut a, mut b, control, tmp) = owner_pair();
        let sink = Arc::new(Sink::default());
        let (gate, _) = gate(&tmp.path().join("execution"), sink, 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut left, &mut server, &mut a, &mut b);
        gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
            .unwrap();
        gate.run_one(&mut Signer).unwrap();
        let mut output = Output {
            bytes: Vec::new(),
            hook: Some(Box::new(move || {
                control.0.borrow_mut().mono = delay;
                Ok(())
            })),
        };
        assert_eq!(
            gate.reply(&mut server, &mut b, &mut output, &mut Signer)
                .is_ok(),
            delay == 5000
        );
        assert_eq!(
            server.phase(),
            if delay == 5000 {
                Phase::Ready
            } else {
                Phase::Closed
            }
        );
        gate.close().unwrap();
    }
}
#[test]
fn client_rejects_wrong_result_authority_and_unverified_receive_failure() {
    for mode in [
        "authority",
        "receive-error",
        "receive-panic",
        "closed",
        "retired",
    ] {
        let (left, right, mut a, mut b, _, tmp) = owner_pair();
        let sink = Arc::new(Sink::default());
        let path = tmp.path().join("execution");
        let journal = tmp.path().join("client");
        let (gate, clock) = gate(&path, sink.clone(), 2);
        let pool = Arc::new(ClientPool::new(1, 30000).unwrap());
        let mut setup = pool.setup(left, &mut a, "client", "1").unwrap();
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
        setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
        let mut config = services(&clock);
        if mode == "authority" {
            config.result_authority = authority_for(clock.clone(), ALICE);
        }
        let mut client = OwnedClient::open(
            pool.clone(),
            setup,
            &mut a,
            &journal,
            true,
            &envelope(),
            config,
        )
        .unwrap();
        let close = client.closer();
        link.receive_hook = Some(Box::new(move || {
            match mode {
                "receive-error" => return Err(g::Invalid),
                "receive-panic" => panic!("inert receive panic"),
                "closed" => close.close(),
                "retired" => pool.retire()?,
                _ => (),
            };
            Ok(())
        }));
        assert!(client.exchange(&mut a, &mut link).is_err());
        assert!(client.closer().closed());
        assert_eq!(row(&path)["state"], "COMPLETED");
        assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
        assert!(std::fs::read_to_string(journal)
            .unwrap()
            .contains("\"kind\":\"close\""));
        gate.close().unwrap();
    }
}
#[test]
fn client_quota_is_shared_and_not_released_by_close_during_receive() {
    let (left, right, mut a, mut b, _, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&tmp.path().join("execution"), sink.clone(), 2);
    let pool = Arc::new(ClientPool::new(1, 30000).unwrap());
    let mut setup = pool.setup(left, &mut a, "client", "1").unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
    setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
    let mut client = OwnedClient::open(
        pool.clone(),
        setup,
        &mut a,
        &tmp.path().join("client"),
        true,
        &envelope(),
        services(&clock),
    )
    .unwrap();
    let (left, right, mut a2, mut b2, _, tmp2) = owner_pair();
    let mut setup2 = pool.setup(left, &mut a2, "client", "2").unwrap();
    let mut server2 = gate.setup(right, &mut b2, "server", "2").unwrap();
    {
        let mut link2 = Link::new(&mut server2, &mut b2, gate.clone(), false);
        setup2.run(&mut a2, &mut link2, &mut || Ok(())).unwrap();
    }
    let mut client2 = OwnedClient::open(
        pool,
        setup2,
        &mut a2,
        &tmp2.path().join("client"),
        true,
        &envelope(),
        services(&clock),
    )
    .unwrap();
    let close = client.closer();
    let observed = Arc::new(AtomicUsize::new(0));
    let check = observed.clone();
    let second_gate = gate.clone();
    link.receive_hook = Some(Box::new(move || {
        close.close(); // closure must not free the still-running first receive slot
        let mut link2 = Link::new(&mut server2, &mut b2, second_gate.clone(), false);
        assert!(client2.exchange(&mut a2, &mut link2).is_err());
        assert_eq!(link2.protected_sends, 0);
        check.fetch_add(1, Ordering::SeqCst);
        let _ = &tmp2;
        Ok(())
    }));
    assert!(client.exchange(&mut a, &mut link).is_err());
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    gate.close().unwrap();
}
#[test]
fn server_reply_permit_cannot_cross_gates_or_repeat() {
    let (mut left, right, mut a, mut b, _, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&tmp.path().join("execution"), sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap();
    gate.run_one(&mut Signer).unwrap();
    let (other, _) = super::gate(&tmp.path().join("other"), sink, 1);
    let mut output = Output {
        bytes: Vec::new(),
        hook: None,
    };
    assert!(other
        .reply(&mut server, &mut b, &mut output, &mut Signer)
        .is_err());
    assert!(output.bytes.is_empty());
    assert!(gate
        .reply(&mut server, &mut b, &mut output, &mut Signer)
        .is_err());
    gate.close().unwrap();
    other.close().unwrap();
}

struct CleanupClock {
    close: SetupClose,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
impl g::ClientClock for CleanupClock {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        // Open creates the journal, then final owner publication must fail.
        self.close.close();
        Ok((100000, 0))
    }
}
impl Drop for CleanupClock {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}
#[test]
fn failed_constructor_keeps_quota_until_journal_and_dependency_cleanup_end() {
    let pool = Arc::new(ClientPool::new(1, 30000).unwrap());
    let first_pool = pool.clone();
    let (entered, wait) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let first = std::thread::spawn(move || {
        let (left, right, mut a, mut b, _, tmp) = owner_pair();
        let (gate, clock) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
        let mut setup = first_pool.setup(left, &mut a, "first", "1").unwrap();
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        {
            let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
            setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
        }
        let mut config = services(&clock);
        config.clock = Box::new(CleanupClock {
            close: setup.closer(),
            entered,
            release: released,
        });
        let path = tmp.path().join("client");
        assert!(
            OwnedClient::open(first_pool, setup, &mut a, &path, true, &envelope(), config).is_err()
        );
        assert!(path.exists());
        assert!(!path.with_extension("lock").exists());
        gate.close().unwrap();
    });
    wait.recv_timeout(Duration::from_secs(10)).unwrap();
    let (left, right, mut a, mut b, _, tmp) = owner_pair();
    let (gate, clock) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let mut setup = pool.setup(left, &mut a, "second", "1").unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    {
        let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
        setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
    }
    let path = tmp.path().join("client");
    assert!(OwnedClient::open(
        pool.clone(),
        setup,
        &mut a,
        &path,
        true,
        &envelope(),
        services(&clock)
    )
    .is_err());
    assert!(!path.exists()); // quota denied before retaining another journal
    release.send(()).unwrap();
    first.join().unwrap();
    let (left, right, mut a, mut b, _, _tmp2) = owner_pair();
    let mut setup = pool.setup(left, &mut a, "third", "1").unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    {
        let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
        setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
    }
    let mut third = OwnedClient::open(
        pool,
        setup,
        &mut a,
        &path,
        true,
        &envelope(),
        services(&clock),
    )
    .unwrap();
    third.close().unwrap();
    gate.close().unwrap();
}

#[test]
fn reply_storage_or_signer_failure_retires_unclaimed_execution() {
    for storage in [false, true] {
        let (mut left, right, mut a, mut b, _, tmp) = owner_pair();
        let sink = Arc::new(Sink::default());
        let path = tmp.path().join("execution");
        let (gate, _) = gate(&path, sink.clone(), 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut left, &mut server, &mut a, &mut b);
        gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
            .unwrap();
        let mut output = Output {
            bytes: Vec::new(),
            hook: None,
        };
        if storage {
            gate.unavailable_fixture();
            assert!(gate
                .reply(&mut server, &mut b, &mut output, &mut Signer)
                .is_err());
        } else {
            assert!(gate
                .reply(&mut server, &mut b, &mut output, &mut FailedSigner)
                .is_err());
        }
        assert!(output.bytes.is_empty());
        assert!(gate.run_one(&mut Signer).is_err());
        assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
        assert_eq!(
            row(&path)["state"],
            if storage { "EXECUTING" } else { "UNKNOWN" }
        );
        gate.close().unwrap();
    }
}

#[path = "mcp_lifecycle_tests.rs"]
mod mcp_lifecycle_tests;

#[path = "mcp_transport_tests.rs"]
mod mcp_transport_tests;
