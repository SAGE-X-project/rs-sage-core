//! Safe local session and inert blocked-provider lifecycle schedules.
use super::*;
use g::mcp_lifecycle::OwnerMonitor;
use std::sync::mpsc;
use std::time::Instant;

fn eventually(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < end, "lifecycle condition timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn monitor(capacity: usize) -> (OwnerMonitor, Local) {
    let clock = Local(Arc::new(AtomicI64::new(0)));
    (
        OwnerMonitor::start(capacity, Duration::from_millis(1), Box::new(clock.clone())).unwrap(),
        clock,
    )
}
#[test]
fn setup_expiry_is_independent_and_registration_survives_logical_close() {
    let (left, right, mut a, mut b, _, tmp) = owner_pair();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let (monitor, clock) = monitor(1);
    gate.attach_owners(monitor.registry()).unwrap();
    assert!(gate.attach_owners(monitor.registry()).is_err());
    let server = gate.setup(right, &mut b, "server", "1").unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    assert!(!monitor.stop(Duration::from_millis(5)).unwrap());
    drop(server);
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    assert!(gate.setup(left, &mut a, "wrong-role", "1").is_err());
    gate.close().unwrap();
}
#[test]
fn local_observation_does_not_refresh_ready_session_idle_deadline() {
    let (mut left, right, mut a, mut b, controls, tmp) = owner_pair();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let (monitor, clock) = monitor(1);
    gate.attach_owners(monitor.registry()).unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    clock.0.store(599999, Ordering::SeqCst);
    controls.0.borrow_mut().mono = 599999;
    server.owner.observe(&mut b).unwrap();
    assert!(!server.closer().closed());
    clock.0.store(600000, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    drop(server);
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn record_activity_refreshes_idle_but_never_absolute_session_lifetime() {
    let (mut left, right, mut a, mut b, controls, tmp) = owner_pair();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let (monitor, clock) = monitor(1);
    gate.attach_owners(monitor.registry()).unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    for time in (590000..3600000).step_by(590000) {
        clock.0.store(time, Ordering::SeqCst);
        controls.0.borrow_mut().mono = time;
        server
            .owner
            .seal_request(&mut b, b"inert keepalive", 30)
            .unwrap();
    }
    clock.0.store(3599999, Ordering::SeqCst);
    controls.0.borrow_mut().mono = 3599999;
    server.owner.observe(&mut b).unwrap();
    assert!(!server.closer().closed());
    clock.0.store(3600000, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    drop(server);
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn response_permit_deadline_remains_watched_after_worker_completion() {
    let (mut left, right, mut a, mut b, _, tmp) = owner_pair();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let (monitor, clock) = monitor(1);
    gate.attach_owners(monitor.registry()).unwrap();
    let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
    ready(&mut left, &mut server, &mut a, &mut b);
    gate.admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap();
    gate.run_one(&mut Signer).unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    let mut output = Output {
        bytes: Vec::new(),
        hook: None,
    };
    assert!(gate
        .reply(&mut server, &mut b, &mut output, &mut Signer)
        .is_err());
    assert!(output.bytes.is_empty());
    assert_eq!(row(&tmp.path().join("execution"))["state"], "COMPLETED");
    drop(server);
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn client_receive_expiry_is_independent_of_blocked_io_and_retains_registration() {
    let pool = Arc::new(ClientPool::new(1, 30000).unwrap());
    let (monitor, clock) = monitor(1);
    pool.attach_owners(monitor.registry()).unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let (left, right, mut a, mut b, _, tmp) = owner_pair();
        let path = tmp.path().join("execution");
        let (gate, local) = gate(&path, Arc::new(Sink::default()), 1);
        let mut setup = pool.setup(left, &mut a, "client", "1").unwrap();
        let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
        let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
        setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
        let mut client = OwnedClient::open(
            pool,
            setup,
            &mut a,
            &tmp.path().join("client"),
            true,
            &envelope(),
            services(&local),
        )
        .unwrap();
        let close = client.closer();
        link.receive_hook = Some(Box::new(move || {
            entered.send(close.clone()).unwrap();
            released.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(())
        }));
        assert!(client.exchange(&mut a, &mut link).is_err());
        assert_eq!(row(&path)["state"], "COMPLETED");
        drop(client);
        gate.close().unwrap();
    });
    let close = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| close.closed());
    assert!(!monitor.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    worker.join().unwrap();
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
}
struct DropClock {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
impl g::ClientClock for DropClock {
    fn sample(&mut self) -> g::Result<(i64, i64)> {
        Ok((100000, 0))
    }
}
impl Drop for DropClock {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}
#[test]
fn closed_client_registration_outlives_dependency_destructors() {
    for failed_constructor in [false, true] {
        let pool = Arc::new(ClientPool::new(1, 30000).unwrap());
        let (monitor, _) = monitor(1);
        pool.attach_owners(monitor.registry()).unwrap();
        let worker_pool = pool.clone();
        let (entered, receiver) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let (left, right, mut a, mut b, _, tmp) = owner_pair();
            let (gate, local) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
            let mut setup = worker_pool.setup(left, &mut a, "client", "1").unwrap();
            let mut server = gate.setup(right, &mut b, "server", "1").unwrap();
            {
                let mut link = Link::new(&mut server, &mut b, gate.clone(), false);
                setup.run(&mut a, &mut link, &mut || Ok(())).unwrap();
            }
            let mut config = services(&local);
            config.clock = Box::new(DropClock {
                entered,
                release: released,
            });
            if failed_constructor {
                setup.fail();
            }
            let client = OwnedClient::open(
                worker_pool,
                setup,
                &mut a,
                &tmp.path().join("client"),
                true,
                &envelope(),
                config,
            );
            assert_eq!(client.is_err(), failed_constructor);
            drop(client);
            gate.close().unwrap();
        });
        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        let (left, _, mut a, _, _, _tmp) = owner_pair();
        assert!(pool.setup(left, &mut a, "replacement", "1").is_err());
        assert!(!monitor.stop(Duration::from_millis(5)).unwrap());
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    }
}

#[test]
fn fresh_poll_retires_previous_transport_deadline_without_refreshing_execution() {
    let (mut left, right, mut a, mut b, controls, tmp) = owner_pair();
    let (gate, gate_clock) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 2);
    let (monitor, clock) = monitor(1);
    gate.attach_owners(monitor.registry()).unwrap();
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
    clock.0.store(1000, Ordering::SeqCst);
    gate_clock.0.store(1000, Ordering::SeqCst);
    controls.0.borrow_mut().mono = 1000;
    assert!(!gate
        .admit(&mut server, &mut b, &request(&mut left, &mut a))
        .unwrap()
        .created());
    clock.0.store(30000, Ordering::SeqCst);
    // A trusted synchronous sample exercises the same atomic owner check.
    server.closer().supervise(&mut || {
        Some(Stamp {
            mono_ms: 30000,
            unix: 100,
        })
    });
    assert!(!server.closer().closed());
    clock.0.store(31000, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    gate.retire().unwrap();
    assert!(gate.run_one(&mut Signer).is_err());
    drop(server);
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn closed_owner_cannot_free_capacity_or_close_another_owner() {
    let (monitor, _) = monitor(2);
    let tmp = tempfile::tempdir().unwrap();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    gate.attach_owners(monitor.registry()).unwrap();
    let (_, right, _, mut b, _, _tmp1) = owner_pair();
    let first = gate.setup(right, &mut b, "first", "1").unwrap();
    let (_, right, _, mut b, _, _tmp2) = owner_pair();
    let second = gate.setup(right, &mut b, "second", "1").unwrap();
    first.closer().close();
    let (_, right, _, mut b, _, _tmp3) = owner_pair();
    assert!(gate.setup(right, &mut b, "third", "1").is_err());
    assert!(!second.closer().closed());
    drop(first);
    let (_, right, _, mut b, _, _tmp4) = owner_pair();
    let third = gate.setup(right, &mut b, "replacement", "1").unwrap();
    assert!(!second.closer().closed());
    drop(second);
    drop(third);
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn monitor_clock_failure_closes_owners_and_prevents_replacement_registration() {
    let (monitor, clock) = monitor(1);
    let (_, right, _, mut b, _, tmp) = owner_pair();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    gate.attach_owners(monitor.registry()).unwrap();
    let server = gate.setup(right, &mut b, "server", "1").unwrap();
    clock.0.store(-1, Ordering::SeqCst);
    eventually(|| server.closer().closed());
    drop(server);
    let (_, right, _, mut b, _, _tmp2) = owner_pair();
    assert!(gate.setup(right, &mut b, "replacement", "1").is_err());
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}

#[test]
fn setup_receive_can_be_closed_without_waiting_for_its_provider() {
    struct Waiting {
        entered: mpsc::SyncSender<SetupClose>,
        release: mpsc::Receiver<()>,
    }
    impl SetupIO for Waiting {
        fn send(&mut self, _: &[u8], _: i64, _: &SetupClose) -> g::Result<()> {
            Err(g::Invalid)
        }
        fn receive(&mut self, _: i64, close: &SetupClose) -> g::Result<Vec<u8>> {
            self.entered.send(close.clone()).unwrap();
            self.release.recv_timeout(Duration::from_secs(10)).unwrap();
            Err(g::Invalid)
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let (monitor, clock) = monitor(1);
    gate.attach_owners(monitor.registry()).unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        let (_, right, _, mut b, _, _tmp) = owner_pair();
        let mut server = worker_gate.setup(right, &mut b, "server", "1").unwrap();
        assert!(server
            .run(
                &mut b,
                &mut Waiting {
                    entered,
                    release: released
                },
                &mut || Ok(())
            )
            .is_err());
    });
    let close = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.0.store(30000, Ordering::SeqCst);
    eventually(|| close.closed());
    assert!(!monitor.stop(Duration::from_millis(5)).unwrap());
    release.send(()).unwrap();
    worker.join().unwrap();
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
#[test]
fn monitor_attachment_is_rejected_after_any_setup_owner_was_created() {
    let (left, right, mut a, mut b, _, tmp) = owner_pair();
    let (gate, _) = gate(&tmp.path().join("execution"), Arc::new(Sink::default()), 1);
    let pool = ClientPool::new(1, 30000).unwrap();
    let server = gate.setup(right, &mut b, "server", "1").unwrap();
    let client = pool.setup(left, &mut a, "client", "1").unwrap();
    drop(server);
    drop(client);
    let (monitor, _) = monitor(2);
    assert!(gate.attach_owners(monitor.registry()).is_err());
    assert!(pool.attach_owners(monitor.registry()).is_err());
    assert!(monitor.stop(Duration::from_secs(5)).unwrap());
    gate.close().unwrap();
}
