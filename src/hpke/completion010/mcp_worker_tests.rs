//! Bounded inert scheduling fixtures; no external effects or attack programs.
use super::*;
use g::mcp_admission::workers::Workers;
use std::sync::mpsc;
use std::time::Instant;

fn eventually(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < end,
            "bounded scheduling condition not reached"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn start(gate: Arc<MCPGate>, worker_ms: i64) -> Workers {
    Workers::start(
        gate,
        vec![Box::new(Signer)],
        Duration::from_millis(1),
        worker_ms,
    )
    .unwrap()
}
#[test]
fn independent_monitor_cancels_running_work_but_retains_quota_until_actual_return() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&path, sink.clone(), 1);
    let host = start(gate.clone(), 1000);
    assert!(Workers::start(
        gate.clone(),
        vec![Box::new(Signer)],
        Duration::from_millis(1),
        1000
    )
    .is_err());
    assert!(gate.run_one(&mut Signer).is_err());
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(())
    }));
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.0.store(999, Ordering::SeqCst);
    gate.sweep().unwrap();
    assert!(!sink
        .cancellation
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .cancelled());
    clock.0.store(1000, Ordering::SeqCst);
    eventually(|| {
        sink.cancellation
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .cancelled()
    });
    assert!(!server.closer().closed()); // worker bound does not rewrite request bound
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    assert_eq!(row(&path)["state"], "EXECUTING");
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    release_tx.send(()).unwrap();
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    assert_eq!(row(&path)["state"], "COMPLETED");
    gate.close().unwrap();
}
#[test]
fn independent_monitor_closes_admission_while_component_provider_is_blocked() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&path, sink.clone(), 1);
    let host = start(gate.clone(), 1000);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
        let mut server = worker_gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut client, &mut server, &mut a, &mut b);
        let close = server.closer();
        *sink.hook.lock().unwrap() = Some(Box::new(move || {
            entered_tx.send(close.clone()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(())
        }));
        assert!(worker_gate
            .admit(&mut server, &mut b, &request(&mut client, &mut a))
            .is_err());
        assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    });
    let close = entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| close.closed());
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    assert_eq!(row(&path)["state"], "UNKNOWN");
    gate.close().unwrap();
}
#[test]
fn monitor_cancels_expired_queue_before_claim_without_releasing_durable_slot() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&path, sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    clock.0.store(1000, Ordering::SeqCst);
    gate.sweep().unwrap();
    assert_eq!(row(&path)["state"], "EXECUTING");
    assert!(gate.run_one(&mut Signer).is_err());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    assert_eq!(row(&path)["state"], "UNKNOWN");
    gate.close().unwrap();
}
#[test]
fn monitor_clock_rollback_retires_gate_and_closes_current_operation() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let sink = Arc::new(Sink::default());
    let (gate, clock) = gate(&tmp.path().join("execution"), sink.clone(), 1);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    clock.0.store(1, Ordering::SeqCst);
    gate.sweep().unwrap();
    clock.0.store(0, Ordering::SeqCst);
    assert!(gate.sweep().is_err());
    assert!(server.closer().closed());
    assert!(gate.run_one(&mut Signer).is_err());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 0);
    gate.close().unwrap();
}
#[test]
fn empty_worker_pool_stops_and_cannot_restart_retired_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    assert!(Workers::start(gate.clone(), vec![], Duration::from_millis(1), 1000).is_err());
    let host = start(gate.clone(), 1000);
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    assert!(host.stop(Duration::ZERO).unwrap());
    assert!(Workers::start(
        gate.clone(),
        vec![Box::new(Signer)],
        Duration::from_millis(1),
        1000
    )
    .is_err());
    gate.close().unwrap();
}

#[test]
fn independent_monitor_closes_blocked_reply_and_stop_keeps_output_charged() {
    use g::mcp_setup::{SetupClose, SetupIO};
    struct Blocked {
        entered: mpsc::SyncSender<SetupClose>,
        release: mpsc::Receiver<()>,
    }
    impl SetupIO for Blocked {
        fn send(&mut self, _: &[u8], _: i64, close: &SetupClose) -> g::Result<()> {
            self.entered.send(close.clone()).unwrap();
            self.release.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(())
        }
        fn receive(&mut self, _: i64, _: &SetupClose) -> g::Result<Vec<u8>> {
            Err(g::Invalid)
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("execution");
    let (gate, clock) = gate(&path, Arc::new(Sink::default()), 1);
    let host = start(gate.clone(), 1000);
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        let (mut client, right, mut a, mut b, _, _tmp) = owner_pair();
        let mut server = worker_gate.setup(right, &mut b, "server", "1").unwrap();
        ready(&mut client, &mut server, &mut a, &mut b);
        worker_gate
            .admit(&mut server, &mut b, &request(&mut client, &mut a))
            .unwrap();
        assert!(worker_gate
            .reply(
                &mut server,
                &mut b,
                &mut Blocked {
                    entered,
                    release: released
                },
                &mut Signer
            )
            .is_err());
    });
    let close = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| close.closed());
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    worker.join().unwrap();
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}

#[test]
fn expired_older_work_does_not_close_a_new_pending_poll() {
    use g::mcp_setup::{SetupClose, SetupIO};
    struct Output;
    impl SetupIO for Output {
        fn send(&mut self, _: &[u8], _: i64, _: &SetupClose) -> g::Result<()> {
            Ok(())
        }
        fn receive(&mut self, _: i64, _: &SetupClose) -> g::Result<Vec<u8>> {
            Err(g::Invalid)
        }
    }
    let (mut client, right, mut a, mut b, control, tmp) = owner_pair();
    let (gate, clock) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 2);
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    gate.reply(&mut server, &mut b, &mut Output, &mut Signer)
        .unwrap();
    clock.0.store(1000, Ordering::SeqCst);
    control.0.borrow_mut().mono = 1000;
    gate.admit(&mut server, &mut b, &request(&mut client, &mut a))
        .unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    gate.sweep().unwrap();
    assert!(!server.closer().closed());
    gate.retire().unwrap();
    assert!(gate.run_one(&mut Signer).is_err());
    gate.close().unwrap();
}

#[test]
fn one_fixed_worker_keeps_second_admitted_effect_queued_while_first_is_blocked() {
    let (mut client, right, mut a, mut b, _, tmp) = owner_pair();
    let path = tmp.path().join("execution");
    let sink = Arc::new(Sink::default());
    let (gate, _) = gate(&path, sink.clone(), 2);
    let host = start(gate.clone(), 1000);
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    *sink.run_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(())
    }));
    let mut first = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut client, &mut first, &mut a, &mut b);
    gate.admit(&mut first, &mut b, &request(&mut client, &mut a))
        .unwrap();
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    let (mut second_client, right, mut a2, mut b2, _, _tmp2) = owner_pair();
    let mut second = gate.setup(right, &mut b2, "server", "1").unwrap();
    ready(&mut second_client, &mut second, &mut a2, &mut b2);
    let mut env: Value = serde_json::from_slice(&envelope()).unwrap();
    for field in ["request_id", "call_id"] {
        env["intent"][field] = json!(uuid::Uuid::new_v4().to_string());
    }
    env["intent"]["nonce"] = json!(B64.encode([42; 16]));
    let signed = [
        b"sage-execution-intent|0.10.0\0".as_slice(),
        &canonical(&env["intent"]),
    ]
    .concat();
    env["proof"] = json!(B64.encode(SigningKey::from_bytes(&[1; 32]).sign(&signed).to_bytes()));
    let rpc = g::mcp_request(
        g::MCP_VERSION,
        &uuid::Uuid::new_v4().to_string(),
        &canonical(&env),
    )
    .unwrap();
    let wire = second_client.seal_request(&mut a2, &rpc, 30).unwrap();
    assert!(gate.admit(&mut second, &mut b2, &wire).unwrap().created());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    assert!(!host.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    assert!(host.stop(Duration::from_secs(5)).unwrap());
    assert_eq!(sink.effects.load(Ordering::SeqCst), 1);
    assert_eq!(row(&path)["state"], "UNKNOWN");
    gate.close().unwrap();
}
