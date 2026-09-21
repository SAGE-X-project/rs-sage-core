//! Gate-only scheduling. Owner setup, idle sessions and client pools require a
//! separate host registration layer; this is not a production transport binding.
use super::*;
use std::sync::Condvar;
use std::thread;
use std::time::{Duration, Instant};

struct Control {
    stopping: AtomicBool,
    live: Mutex<usize>,
    changed: Condvar,
    interval: Duration,
}
struct ThreadLease(Arc<Control>, Arc<MCPGate>);
impl Drop for ThreadLease {
    fn drop(&mut self) {
        // Even unexpected unwinding must invalidate subsequent claims.
        if thread::panicking() {
            let _ = self.1.retire();
            self.0.stopping.store(true, Ordering::Release);
        }
        let mut live = self.0.live.lock().unwrap_or_else(|p| p.into_inner());
        *live -= 1;
        self.0.changed.notify_all();
    }
}
/// Exactly N effect/cleanup workers and one independent monitor. Dropping or
/// timing out requests retirement, but never pretends a blocked callback ended.
pub(crate) struct Workers {
    gate: Arc<MCPGate>,
    control: Arc<Control>,
}
impl Workers {
    pub(crate) fn start(
        gate: Arc<MCPGate>,
        signers: Vec<Box<dyn ResultSigner + Send>>,
        interval: Duration,
        worker_ms: i64,
    ) -> Result<Self> {
        ensure(
            !signers.is_empty()
                && signers.len() <= gate.capacity
                && !interval.is_zero()
                && interval <= Duration::from_secs(1)
                && interval < Duration::from_millis(gate.claim_ms as u64)
                && interval < Duration::from_millis(gate.request_ms as u64)
                && (1..=300_000).contains(&worker_ms)
                && interval < Duration::from_millis(worker_ms as u64),
        )?;
        {
            let _c = gate.coordinator.lock().map_err(|_| Invalid)?;
            let mut q = gate.queue.lock().map_err(|_| Invalid)?;
            ensure(
                !q.hosted && !q.retired && q.last.is_none() && q.occupied == 0 && q.outputs == 0,
            )?;
            q.hosted = true;
            q.worker_ms = worker_ms;
        }
        let host = Self {
            gate,
            control: Arc::new(Control {
                stopping: AtomicBool::new(false),
                live: Mutex::new(0),
                changed: Condvar::new(),
                interval,
            }),
        };
        for mut signer in signers {
            host.spawn(move |gate, control| {
                loop {
                    match gate.run_worker(signer.as_mut(), true) {
                        Ok(false) => {
                            if control.stopping.load(Ordering::Acquire) {
                                break;
                            }
                            pause(control);
                        }
                        Ok(true) | Err(_) => {
                            // Failures retire the gate; still drain cancelled queue
                            // entries using these same bounded cleanup workers.
                            if gate.queue.lock().map_or(true, |q| q.items.is_empty()) {
                                if control.stopping.load(Ordering::Acquire) {
                                    break;
                                }
                                pause(control);
                            }
                        }
                    }
                }
            })?;
        }
        host.spawn(|gate, control| loop {
            if gate.sweep().is_err() {
                let _ = gate.retire();
            }
            if control.stopping.load(Ordering::Acquire) && gate.quiescent().unwrap_or(false) {
                break;
            }
            pause(control);
        })?;
        Ok(host)
    }
    fn spawn(&self, f: impl FnOnce(&MCPGate, &Control) + Send + 'static) -> Result<()> {
        *self.control.live.lock().map_err(|_| Invalid)? += 1;
        let lease = ThreadLease(self.control.clone(), self.gate.clone());
        // If spawn fails, the moved closure is dropped and its lease returns the
        // count. Existing workers retain their gate and signer until termination.
        thread::Builder::new()
            .spawn(move || {
                let _lease = lease;
                f(&_lease.1, &_lease.0);
            })
            .map_err(|_| Invalid)?;
        Ok(())
    }
    fn retire(&self) {
        let _ = self.gate.retire();
        self.control.stopping.store(true, Ordering::Release);
        self.control.changed.notify_all();
    }
    /// True means all owned threads and charged operations have ended. Ledger
    /// close is separate; on timeout the gate stays retired and retains its lock.
    pub(crate) fn stop(&self, timeout: Duration) -> Result<bool> {
        self.retire();
        let end = Instant::now().checked_add(timeout).ok_or(Invalid)?;
        let mut live = self.control.live.lock().map_err(|_| Invalid)?;
        while *live != 0 {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            live = self
                .control
                .changed
                .wait_timeout(live, left)
                .map_err(|_| Invalid)?
                .0;
        }
        self.gate.quiescent()
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        self.retire();
    }
}
fn pause(control: &Control) {
    let live = control.live.lock().unwrap_or_else(|p| p.into_inner());
    drop(control.changed.wait_timeout(live, control.interval));
}
impl MCPGate {
    fn quiescent(&self) -> Result<bool> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let q = self.queue.lock().map_err(|_| Invalid)?;
        Ok(q.occupied == 0 && q.outputs == 0)
    }
    /// No endpoint, registry, storage, signer or executor lock on this path.
    /// The trusted gate clock must be bounded and share the endpoint clock domain.
    pub(crate) fn sweep(&self) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let mut q = self.queue.lock().map_err(|_| Invalid)?;
        let now = catch_unwind(AssertUnwindSafe(|| self.sample(&mut q))).unwrap_or(Err(Invalid));
        if now.is_err() {
            q.retired = true;
        }
        for job in q.jobs.iter().chain(q.output_jobs.iter()) {
            let job = job.lock().map_err(|_| Invalid)?;
            if q.retired
                || now.as_ref().is_ok_and(|t| {
                    job.claim_before.is_some_and(|end| t.mono_ms >= end)
                        || job.worker_before.is_some_and(|end| t.mono_ms >= end)
                })
            {
                job.cancellation.cancel();
            }
            if q.retired || now.as_ref().is_ok_and(|t| t.mono_ms >= job.deadline) {
                job.close.close_operation_locked(&job.operation);
            }
        }
        now.map(|_| ())
    }
}
