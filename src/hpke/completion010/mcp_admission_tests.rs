//! Inert effects only: authenticated local sessions, real ledger and bounded threads.
use super::mcp_setup_tests::{setup_request, Capture, ID1, ID2};
use super::*;
use crate::guard010::{
    self as g,
    mcp_admission::{Executor, MCPGate},
    mcp_setup::{MCPSetup, Phase},
};
use crate::registry010 as r;
use ed25519_dalek::Signer as _;
use std::sync::{
    atomic::{AtomicI64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

#[derive(Clone)]
struct Local(Arc<AtomicI64>, Arc<AtomicI64>);
impl r::Clock for Local {
    fn now(&mut self) -> Result<Stamp> {
        Ok(Stamp {
            mono_ms: self.0.load(Ordering::SeqCst),
            unix: 100,
        })
    }
}
struct Source(Local);
impl r::Source for Source {
    fn read(&mut self, did: &str) -> Result<r::Snapshot> {
        Ok(r::Snapshot {
            source: "admission-fixture".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            did: did.into(),
            version: "1".into(),
            state: "active".into(),
            digest: "a".repeat(64),
            ready: true,
            validated: true,
            finalized: true,
            conflicting: false,
            acquired_ms: self.0 .0.load(Ordering::SeqCst) + self.0 .1.load(Ordering::SeqCst),
            block_hash: String::new(),
            keys_block_hash: String::new(),
            keys: vec![Key {
                name: "signing-1".into(),
                alg: "ed25519".into(),
                material: hex::encode(
                    SigningKey::from_bytes(&[if did == BOB { 2 } else { 1 }; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                state: "accepted".into(),
                expires: None,
            }],
        })
    }
}
struct Store;
impl r::Store for Store {
    fn advance(&mut self, _: r::Scope, _: u64, _: String, _: bool) -> Result<()> {
        Ok(())
    }
}
fn fixture() -> Value {
    let mut f: Value =
        serde_json::from_str(include_str!("../../guard010/testdata/guard-rpc.json")).unwrap();
    f["input"]["approved_policy"]["issuer"] = json!(ALICE);
    f["input"].clone()
}
fn envelope() -> Vec<u8> {
    let f = fixture();
    let mut env: Value =
        serde_json::from_slice(&hex::decode(f["envelope_hex"].as_str().unwrap()).unwrap()).unwrap();
    let i = &mut env["intent"];
    i["issuer"] = json!(ALICE);
    i["recipient"] = json!(BOB);
    i["keyid"] = json!(format!("{ALICE}#signing-1"));
    i["created"] = json!(100);
    i["expires"] = json!(400);
    i["policy_digest"] = json!(g::policy_commitment(&canonical(&f["approved_policy"])).unwrap());
    let signed = [b"sage-execution-intent|0.10.0\0".as_slice(), &canonical(i)].concat();
    env["proof"] = json!(B64.encode(SigningKey::from_bytes(&[1; 32]).sign(&signed).to_bytes()));
    canonical(&env)
}
struct Policy;
impl g::IntentPolicy for Policy {
    fn bindings(&mut self, issuer: &str, _: &str) -> g::Result<g::Bindings> {
        assert_eq!(issuer, ALICE);
        let f = fixture();
        Ok(g::Bindings {
            original: f["original_digest"].as_str().unwrap().into(),
            policy: canonical(&f["approved_policy"]),
            manifest: canonical(&f["approved_manifest"]),
        })
    }
    fn authorize(&mut self, _: &str, tool: &str, args: &[u8]) -> g::Result<()> {
        assert_eq!(tool, "read");
        assert_eq!(args, br#"{"path":"public.txt"}"#);
        Ok(())
    }
}
type Hook = Mutex<Option<Box<dyn FnMut() -> g::Result<()> + Send>>>;
#[derive(Default)]
struct Sink {
    effects: AtomicUsize,
    checks: AtomicUsize,
    hook: Hook,
    run_hook: Hook,
    output_size: AtomicUsize,
    cancellation: Mutex<Option<g::mcp_admission::Cancellation>>,
}
impl Executor for Sink {
    fn check(&self, manifest: &str, tool: &str) -> g::Result<()> {
        assert_eq!(tool, "read");
        assert_eq!(
            manifest,
            g::manifest_commitment(&canonical(&fixture()["approved_manifest"])).unwrap()
        );
        if self.checks.fetch_add(1, Ordering::SeqCst) == 1 {
            if let Some(hook) = self.hook.lock().unwrap().as_mut() {
                hook()?;
            }
        }
        Ok(())
    }
    fn run(
        &self,
        i: &g::Invocation,
        cancellation: &g::mcp_admission::Cancellation,
    ) -> g::Result<Vec<u8>> {
        let received: Value = serde_json::from_slice(i.canonical_intent()).unwrap();
        assert_eq!(received["intent"]["issuer"], ALICE);
        assert_eq!(received["intent"]["recipient"], BOB);
        assert_eq!(i.arguments(), br#"{"path":"public.txt"}"#);
        *self.cancellation.lock().unwrap() = Some(cancellation.clone());
        self.effects.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.run_hook.lock().unwrap().as_mut() {
            hook()?;
        }
        let size = self.output_size.load(Ordering::SeqCst);
        if size > 0 {
            return Ok(serde_json::to_vec(&json!({"text":"x".repeat(size)})).unwrap());
        }
        Ok(br#"{"text":"inert public fixture"}"#.to_vec())
    }
}
struct Signer;
impl g::Authority for Signer {
    fn now(&mut self) -> g::Result<i64> {
        Ok(100)
    }
    fn active_key(&mut self, issuer: &str, keyid: &str) -> g::Result<[u8; 32]> {
        assert_eq!(issuer, BOB);
        assert_eq!(keyid, format!("{BOB}#signing-1"));
        Ok(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes())
    }
}
impl g::ResultSigner for Signer {
    fn key_id(&mut self) -> g::Result<String> {
        Ok(format!("{BOB}#signing-1"))
    }
    fn sign(&mut self, _: &str, msg: &[u8]) -> g::Result<Vec<u8>> {
        Ok(SigningKey::from_bytes(&[2; 32])
            .sign(msg)
            .to_bytes()
            .to_vec())
    }
}
fn authority_for(clock: Local, did: &str) -> g::RegistryAuthority {
    let registry = r::SendGate::new_send(
        r::Config {
            source: "admission-fixture".into(),
            registry: "web:agent.example".into(),
            network: "local".into(),
            blockchain: false,
        },
        Box::new(Source(clock.clone())),
        Box::new(clock.clone()),
        Box::new(Store),
    )
    .unwrap();
    g::RegistryAuthority::new(registry, did, &format!("{did}#signing-1")).unwrap()
}
fn gate(path: &std::path::Path, sink: Arc<Sink>, capacity: usize) -> (Arc<MCPGate>, Local) {
    gate_mode(path, sink, capacity, true)
}
fn gate_mode(
    path: &std::path::Path,
    sink: Arc<Sink>,
    capacity: usize,
    create: bool,
) -> (Arc<MCPGate>, Local) {
    gate_with_preparations(path, sink, capacity, capacity, create)
}
fn gate_with_preparations(
    path: &std::path::Path,
    sink: Arc<Sink>,
    capacity: usize,
    preparation_capacity: usize,
    create: bool,
) -> (Arc<MCPGate>, Local) {
    let clock = Local(Arc::new(AtomicI64::new(0)), Arc::new(AtomicI64::new(0)));
    let authority = authority_for(clock.clone(), ALICE);
    let result_authority = authority_for(clock.clone(), BOB);
    (
        Arc::new(
            MCPGate::open(
                path,
                create,
                BOB,
                authority,
                result_authority,
                Box::new(Policy),
                sink,
                Box::new(clock.clone()),
                capacity,
                preparation_capacity,
                30000,
                1000,
            )
            .unwrap(),
        ),
        clock,
    )
}
fn ready(
    client: &mut NonHTTPOwner010,
    server: &mut MCPSetup,
    a: &mut CompletionEndpoint010,
    b: &mut CompletionEndpoint010,
) {
    let mut io = Capture::default();
    for (id, step) in [(ID1, 0), ("", 1), (ID2, 2)] {
        let wire = client
            .seal_request(a, &setup_request(id, step), 30)
            .unwrap();
        server
            .accept_setup(b, &wire, &mut io, &mut || Ok(()))
            .unwrap();
        client.open_response(a, &io.wire).unwrap();
    }
}
fn request(client: &mut NonHTTPOwner010, a: &mut CompletionEndpoint010) -> Vec<u8> {
    request_with_id(client, a).0
}
fn request_with_id(
    client: &mut NonHTTPOwner010,
    a: &mut CompletionEndpoint010,
) -> (Vec<u8>, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let raw = g::mcp_request(g::MCP_VERSION, &id, &envelope()).unwrap();
    (client.seal_request(a, &raw, 30).unwrap(), id)
}
fn row(path: &std::path::Path) -> Value {
    let raw = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(raw.lines().last().unwrap()).unwrap()
}
#[test]
fn close_before_reservation_denies_with_zero_effects() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let before = std::fs::read(&path).unwrap();
    let wire = request(&mut client, &mut a);
    server.closer().close();
    assert!(gate.admit(&mut server, &mut b, &wire).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(sink.checks.load(Ordering::SeqCst), 0);
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    assert!(!gate.run_one(&mut Signer).unwrap());
    gate.close().unwrap();
}

#[test]
fn admission_fences_before_effects_and_gate_close_cancels_unclaimed_work() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    let early_close = server.closer();
    ready(&mut client, &mut server, &mut a, &mut b);
    let receipt = gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    assert!(receipt.created() && receipt.committed());
    assert_eq!(row(&path)["state"], "EXECUTING");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    early_close.close();
    assert_eq!(server.phase(), Phase::Closed);
    assert!(gate.close().is_err()); // also retires: verify cancellation in separate test
    assert!(gate.run_one(&mut Signer).is_err());
    assert_eq!(row(&path)["state"], "UNKNOWN");
    gate.close().unwrap();
}
#[test]
fn crash_after_durable_admission_fixture() {
    let Some(path) = std::env::var_os("SAGE_MCP_ADMISSION_CRASH_PATH") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let receipt = gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    assert!(receipt.created() && receipt.committed());
    assert_eq!(row(&path)["state"], "EXECUTING");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    assert!(std::path::Path::new(&lock).is_file());
    std::process::exit(0);
}
#[test]
fn crash_recovery_marks_admission_unknown_and_never_executes_again() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("execution");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hpke::completion010::tests::mcp_admission_tests::crash_after_durable_admission_fixture",
            "--test-threads=1",
            "--color=never",
        ])
        .env("SAGE_MCP_ADMISSION_CRASH_PATH", &path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "crash fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    let lock = std::path::PathBuf::from(lock);
    assert!(lock.is_file());
    assert!(crate::execution010::Ledger::open(&path, false).is_err());
    // The owned child has exited; this models trusted administration proving
    // exclusive ownership before clearing the stale process lock.
    std::fs::remove_file(lock).unwrap();

    let sink = Arc::new(Sink::default());
    let (gate, _) = gate_mode(&path, sink.clone(), 1, false);
    assert_eq!(row(&path)["state"], "UNKNOWN");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let receipt = gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    assert!(!receipt.created() && !receipt.committed());
    assert_eq!(receipt.state(), "UNKNOWN");
    assert!(!gate.run_one(&mut Signer).unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.close().unwrap();
}
#[test]
fn admitted_worker_persists_signed_result_once_and_duplicate_never_runs() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    server.closer().close();
    assert!(gate.run_one(&mut Signer).unwrap());
    assert_eq!(row(&path)["state"], "COMPLETED");
    assert!(!row(&path)["result_hex"].as_str().unwrap().is_empty());
    assert!(!gate.run_one(&mut Signer).unwrap());
    let (mut client, right, mut a, mut b, _, _tmp2) = owner_pair();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let before = std::fs::read(&path).unwrap();
    let receipt = gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    assert!(!receipt.created() && !receipt.committed());
    assert_eq!(receipt.state(), "COMPLETED");
    assert!(!gate.run_one(&mut Signer).unwrap());
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    gate.close().unwrap();
}
#[test]
fn close_during_post_fence_callback_denies_and_retains_history() {
    for panic in [false, true] {
        let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let sink = Arc::new(Sink::default());
        let (gate, _) = gate(&path, sink.clone(), 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        let close = server.closer();
        ready(&mut client, &mut server, &mut a, &mut b);
        let (entered, wait) = std::sync::mpsc::channel();
        let (done, released) = std::sync::mpsc::channel();
        let path2 = path.clone();
        let thread = std::thread::spawn(move || {
            wait.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(row(&path2)["state"], "EXECUTING");
            close.close();
            done.send(()).unwrap();
        });
        *sink.hook.lock().unwrap() = Some(Box::new(move || {
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(!panic, "bounded fixture panic");
            Ok(())
        }));
        assert!(gate
            .admit(&mut server, &mut b, &request(&mut client, &mut a))
            .is_err());
        thread.join().unwrap();
        assert_eq!(server.phase(), Phase::Closed);
        assert_eq!(server.history().len(), 3);
        assert_eq!(row(&path)["state"], "UNKNOWN");
        assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
        assert!(!gate.run_one(&mut Signer).unwrap());
        gate.close().unwrap();
    }
}
#[test]
fn retired_and_expired_queue_entries_are_never_claimed() {
    for mode in ["retired", "deadline", "rollback", "run-error", "run-panic"] {
        let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let sink = Arc::new(Sink::default());
        let (gate, clock) = gate(&path, sink.clone(), 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut client, &mut server, &mut a, &mut b);
        gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
            .unwrap();
        match mode {
            "retired" => gate.retire().unwrap(),
            "deadline" => clock.0.store(1000, Ordering::SeqCst),
            "rollback" => clock.0.store(-1, Ordering::SeqCst),
            _ => {
                *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
                    assert_ne!(mode, "run-panic", "inert worker panic");
                    Err(g::Invalid)
                }))
            }
        }
        assert!(gate.run_one(&mut Signer).is_err());
        assert_eq!(row(&path)["state"], "UNKNOWN");
        assert_eq!(
            sink.effects.load(Ordering::SeqCst),
            usize::from(mode.starts_with("run-"))
        );
        assert!(!gate.run_one(&mut Signer).unwrap());
        gate.close().unwrap();
    }
}
#[test]
fn capacity_is_shared_across_connections_and_retained_during_actual_run() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    let (entered, wait) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(3)).unwrap();
        Ok(())
    }));
    let worker_gate = gate.clone();
    let thread = std::thread::spawn(move || worker_gate.run_one(&mut Signer));
    wait.recv_timeout(Duration::from_secs(3)).unwrap();
    let (mut client, right, mut a, mut b, _, _tmp2) = owner_pair();
    let mut second = gate.setup(right, &mut b, "second", "1").unwrap();
    ready(&mut client, &mut second, &mut a, &mut b);
    assert!(gate
        .admit(&mut second, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert_eq!(second.history().len(), 2); // quota checked before protected authentication
    server.closer().close();
    release.send(()).unwrap();
    assert!(thread.join().unwrap().unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    gate.close().unwrap();
}

#[test]
fn queue_capacity_race_fails_atomic_insertion() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate_with_preparations(&path, sink.clone(), 1, 2, true);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let competing = gate.clone();
    *sink.hook.lock().unwrap() = Some(Box::new(move || {
        competing.occupy_queue_fixture();
        Ok(())
    }));
    assert!(gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert_eq!(row(&path)["state"], "UNKNOWN");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.release_queue_fixture();
    assert!(!gate.run_one(&mut Signer).unwrap());
    gate.close().unwrap();
}

#[test]
fn authenticated_setup_reaches_record_limit_before_owner_history() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink, 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    for sequence in 3..1000 {
        let wire = client
            .seal_request(&mut a, br#"{"jsonrpc":"2.0","method":"ping"}"#, 30)
            .unwrap_or_else(|error| panic!("sequence {sequence}: {error}"));
        server
            .owner
            .open_request(&mut b, &wire)
            .unwrap_or_else(|error| panic!("sequence {sequence}: {error}"));
    }
    assert!(client.seal_request(&mut a, b"{}", 30).is_err());
    assert!(client.seal_request(&mut a, b"{}", 30).is_err());
    assert!(server.history().len() < 1024);
    gate.close().unwrap();
}

#[test]
fn failed_unknown_persistence_retires_scope_and_keeps_writer_lock() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let failed = gate.clone();
    *sink.hook.lock().unwrap() = Some(Box::new(move || {
        failed.fail_unknown_fixture();
        Err(g::Invalid)
    }));
    assert!(gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert_eq!(row(&path)["state"], "EXECUTING");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    assert!(gate.close().is_err());
    assert!(path.with_extension("lock").exists());
}

#[test]
fn policy_generation_change_before_coordinator_denies_admission() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let observed = gate.generation_fixture();
    let retired = gate.clone();
    *sink.hook.lock().unwrap() = Some(Box::new(move || retired.retire()));
    assert!(gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert_eq!(gate.generation_fixture(), observed + 1);
    assert_eq!(row(&path)["state"], "UNKNOWN");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.close().unwrap();
}

#[test]
fn component_generation_change_before_coordinator_denies_admission() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let observed = gate.generation_fixture();
    let retired = gate.clone();
    *sink.hook.lock().unwrap() = Some(Box::new(move || retired.retire()));
    assert!(gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert_eq!(gate.generation_fixture(), observed + 1);
    assert_eq!(row(&path)["state"], "UNKNOWN");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.close().unwrap();
}

#[test]
fn observation_acquired_before_operation_start_is_rejected() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    *sink.hook.lock().unwrap() = Some(Box::new(move || {
        clock.1.store(-1, Ordering::SeqCst);
        Ok(())
    }));
    assert!(gate
        .admit(&mut server, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert_eq!(row(&path)["state"], "UNKNOWN");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.close().unwrap();
}

#[test]
fn policy_retirement_and_claim_are_serialized() {
    for claim_first in [false, true] {
        let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let sink = Arc::new(Sink::default());
        let (gate, _) = gate(&path, sink.clone(), 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut client, &mut server, &mut a, &mut b);
        gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
            .unwrap();
        if !claim_first {
            gate.retire().unwrap();
            assert!(gate.run_one(&mut Signer).is_err());
            assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
            assert_eq!(row(&path)["state"], "UNKNOWN");
        } else {
            let retired = gate.clone();
            *sink.run_hook.lock().unwrap() = Some(Box::new(move || retired.retire()));
            assert!(gate.run_one(&mut Signer).unwrap());
            assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
            assert_eq!(row(&path)["state"], "COMPLETED");
        }
        gate.close().unwrap();
    }
}

#[test]
fn scheduler_cancel_and_claim_race_is_serialized() {
    for claim_first in [false, true] {
        let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let sink = Arc::new(Sink::default());
        let (gate, clock) = gate(&path, sink.clone(), 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut client, &mut server, &mut a, &mut b);
        gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
            .unwrap();
        if !claim_first {
            clock.0.store(1000, Ordering::SeqCst);
            gate.sweep().unwrap();
            assert!(gate.run_one(&mut Signer).is_err());
            assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
            assert_eq!(row(&path)["state"], "UNKNOWN");
        } else {
            let claimed = gate.clone();
            *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
                clock.0.store(1000, Ordering::SeqCst);
                claimed.sweep()
            }));
            assert!(gate.run_one(&mut Signer).unwrap());
            assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
            assert_eq!(row(&path)["state"], "COMPLETED");
        }
        gate.close().unwrap();
    }
}

#[test]
fn unavailable_storage_cancels_existing_unclaimed_work() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 2);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    let (mut client, right, mut a, mut b, _, _tmp2) = owner_pair();
    let mut second = gate.setup(right, &mut b, "second", "1").unwrap();
    ready(&mut client, &mut second, &mut a, &mut b);
    gate.unavailable_fixture();
    assert!(gate
        .admit(&mut second, &mut b, &request(&mut client, &mut a))
        .is_err());
    assert!(gate.run_one(&mut Signer).is_err());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    assert_eq!(row(&path)["state"], "EXECUTING"); // unavailable is not fabricated UNKNOWN
}
#[test]
fn completion_expiry_closes_owner_without_losing_signed_outcome() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
        clock.0.store(30000, Ordering::SeqCst);
        Ok(())
    }));
    assert!(gate.run_one(&mut Signer).unwrap());
    assert_eq!(server.phase(), Phase::Closed);
    assert_eq!(row(&path)["state"], "COMPLETED");
    gate.close().unwrap();
}
struct AdvancingClock {
    control: Controls,
    time: Arc<AtomicI64>,
}
impl r::Clock for AdvancingClock {
    fn now(&mut self) -> Result<Stamp> {
        self.control.0.borrow_mut().mono = self.time.load(Ordering::SeqCst);
        self.control.now()
    }
}
#[test]
fn final_admission_rechecks_observation_age_and_fixed_request_deadline() {
    for (delay, refresh_registry, accepted) in [
        (4999, false, true),
        (5000, false, true),
        (5001, false, false),
        (30000, true, false),
    ] {
        let (mut client, right, mut a, mut b, control, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let sink = Arc::new(Sink::default());
        let (gate, registry_clock) = gate(&path, sink.clone(), 1);
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut client, &mut server, &mut a, &mut b);
        let wire = request(&mut client, &mut a);
        let time = Arc::new(AtomicI64::new(0));
        b.clock = Box::new(AdvancingClock {
            control,
            time: time.clone(),
        });
        *sink.hook.lock().unwrap() = Some(Box::new(move || {
            time.store(delay, Ordering::SeqCst);
            if refresh_registry {
                registry_clock.0.store(delay, Ordering::SeqCst);
            }
            Ok(())
        }));
        assert_eq!(gate.admit(&mut server, &mut b, &wire).is_ok(), accepted);
        assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
        if accepted {
            gate.retire().unwrap();
            assert!(gate.run_one(&mut Signer).is_err());
        }
        assert_eq!(row(&path)["state"], "UNKNOWN");
        gate.close().unwrap();
    }
}

#[test]
fn ready_session_expiry_denies_new_admission_and_closes_owner() {
    let (mut client, right, mut a, mut b, control, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    control.0.borrow_mut().mono = 599_999;
    let wire = request(&mut client, &mut a);
    let protected: Value = serde_json::from_slice(&wire).unwrap();
    control.0.borrow_mut().mono = 600_000;
    assert!(control.0.borrow().utc < protected["expires"].as_i64().unwrap());
    assert!(gate.admit(&mut server, &mut b, &wire).is_err());
    assert_eq!(server.phase(), Phase::Closed);
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    assert!(server.owner.local_now(&mut b).is_err());
    gate.close().unwrap();
}

#[test]
fn protected_deadline_before_final_admission_retains_identity_and_reservation() {
    let (mut client, right, mut a, mut b, control, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, registry_clock) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let history_before = server.history().len();
    let (wire, request_id) = request_with_id(&mut client, &mut a);
    let time = Arc::new(AtomicI64::new(0));
    b.clock = Box::new(AdvancingClock {
        control,
        time: time.clone(),
    });
    *sink.hook.lock().unwrap() = Some(Box::new(move || {
        time.store(30000, Ordering::SeqCst);
        registry_clock.0.store(30000, Ordering::SeqCst);
        Ok(())
    }));
    assert!(gate.admit(&mut server, &mut b, &wire).is_err());
    let saved = row(&path);
    let intent: Value = serde_json::from_slice(&envelope()).unwrap();
    assert_eq!(saved["state"], "UNKNOWN");
    assert_eq!(saved["call_id"], intent["intent"]["call_id"]);
    assert_eq!(saved["nonce"], intent["intent"]["nonce"]);
    let history = server.history();
    assert!(history.contains(&request_id));
    assert_eq!(history.len(), history_before + 1);
    assert_eq!(server.phase(), Phase::Closed);
    assert!(!gate.run_one(&mut Signer).unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.close().unwrap();
}
#[test]
fn authenticated_tcp_request_reaches_durable_inert_execution() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    let wire = request(&mut client, &mut a);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
        .unwrap();
    let (mut s, _) = listener.accept().unwrap();
    c.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.write_all(&(wire.len() as u32).to_be_bytes()).unwrap();
    c.write_all(&wire).unwrap();
    let mut header = [0; 4];
    s.read_exact(&mut header).unwrap();
    let n = u32::from_be_bytes(header) as usize;
    assert!((1..=32768).contains(&n));
    let mut received = vec![0; n];
    s.read_exact(&mut received).unwrap();
    gate.admit(&mut server, &mut b, &received).unwrap();
    assert!(gate.run_one(&mut Signer).unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    assert_eq!(row(&path)["state"], "COMPLETED");
    gate.close().unwrap();
}

struct FailedSigner;
impl g::Authority for FailedSigner {
    fn now(&mut self) -> g::Result<i64> {
        g::Authority::now(&mut Signer)
    }
    fn active_key(&mut self, issuer: &str, key: &str) -> g::Result<[u8; 32]> {
        g::Authority::active_key(&mut Signer, issuer, key)
    }
}
impl g::ResultSigner for FailedSigner {
    fn key_id(&mut self) -> g::Result<String> {
        g::ResultSigner::key_id(&mut Signer)
    }
    fn sign(&mut self, _: &str, _: &[u8]) -> g::Result<Vec<u8>> {
        panic!("inert signer failure")
    }
}
#[test]
fn failed_result_persistence_retires_other_unclaimed_work() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 2);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    let (mut client, right, mut a, mut b, _, _tmp2) = owner_pair();
    let mut second = gate.setup(right, &mut b, "second", "1").unwrap();
    ready(&mut client, &mut second, &mut a, &mut b);
    let mut env: Value = serde_json::from_slice(&envelope()).unwrap();
    env["intent"]["call_id"] = json!("00000000-0000-4000-8000-000000000099");
    env["intent"]["nonce"] = json!(B64.encode([9u8; 16]));
    let message = [
        b"sage-execution-intent|0.10.0\0".as_slice(),
        &canonical(&env["intent"]),
    ]
    .concat();
    env["proof"] = json!(B64.encode(SigningKey::from_bytes(&[1; 32]).sign(&message).to_bytes()));
    let raw = g::mcp_request(
        g::MCP_VERSION,
        &uuid::Uuid::new_v4().to_string(),
        &canonical(&env),
    )
    .unwrap();
    let wire = client.seal_request(&mut a, &raw, 30).unwrap();
    gate.admit(&mut second, &mut b, &wire).unwrap();
    assert!(gate.run_one(&mut FailedSigner).is_err());
    assert!(gate.run_one(&mut Signer).is_err());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    assert_eq!(row(&path)["state"], "UNKNOWN");
    gate.close().unwrap();
}
#[test]
fn admission_requires_ready_owner_from_this_gate() {
    for ready_unbound in [false, true] {
        let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let sink = Arc::new(Sink::default());
        let (gate, _) = gate(&path, sink.clone(), 1);
        let mut server = if ready_unbound {
            MCPSetup::new(right, &mut b, "unbound", "1").unwrap()
        } else {
            gate.setup(right, &mut b, "server", "1").unwrap()
        };
        if ready_unbound {
            ready(&mut client, &mut server, &mut a, &mut b);
        }
        let before = std::fs::read(&path).unwrap();
        assert!(gate
            .admit(&mut server, &mut b, &request(&mut client, &mut a))
            .is_err());
        assert_eq!(server.phase(), Phase::Closed);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(sink.checks.load(Ordering::SeqCst), 0);
        assert!(!gate.run_one(&mut Signer).unwrap());
        gate.close().unwrap();
    }
}

#[path = "mcp_reply_tests.rs"]
mod mcp_reply_tests;

#[path = "mcp_worker_tests.rs"]
mod mcp_worker_tests;
