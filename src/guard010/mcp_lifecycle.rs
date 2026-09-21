//! Bounded registration and independent logical closure of non-HTTP owners.
//! Socket shutdown and destruction of exclusively held keys/providers remain the
//! owning host's responsibility. A closed owner still consumes registration.
use super::mcp_setup::{MCPSetup, SetupClose};
use super::*;
use crate::registry010::{Clock, Stamp};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

struct Entry {
    lease: Weak<()>,
    close: SetupClose,
}
struct State {
    owners: Vec<Entry>,
    last: Option<Stamp>,
    retired: bool,
    stopping: bool,
    done: bool,
}
pub(crate) struct OwnerRegistry {
    state: Mutex<State>,
    changed: Condvar,
    capacity: usize,
    interval: Duration,
    clock: Mutex<Box<dyn Clock + Send>>,
}
impl OwnerRegistry {
    /// Called only by the gate/pool constructor path under its coordinator,
    /// before setup I/O. Registry never holds its mutex while closing an owner.
    pub(crate) fn register(&self, owner: &mut MCPSetup) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        state.owners.retain(|entry| entry.lease.strong_count() != 0);
        ensure(
            !state.retired && owner.registration.is_none() && state.owners.len() < self.capacity,
        )?;
        let lease = Arc::new(());
        state.owners.push(Entry {
            lease: Arc::downgrade(&lease),
            close: owner.closer(),
        });
        owner.registration = Some(lease);
        drop(state);
        // Re-sample after reservation in mirror -> registry order, so registration
        // cannot confuse an earlier constructor sample with clock rollback.
        ensure(
            owner
                .owner
                .lifecycle()
                .inspect(&mut || self.sample())
                .is_some(),
        )
    }
    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }
    pub(crate) fn live(&self) -> bool {
        self.state.lock().is_ok_and(|s| !s.retired)
    }
    fn snapshot(state: &mut State) -> Vec<SetupClose> {
        state.owners.retain(|entry| entry.lease.strong_count() != 0);
        state
            .owners
            .iter()
            .map(|entry| entry.close.clone())
            .collect()
    }
    fn sample(&self) -> Option<Stamp> {
        // Same lock order as registration. The only callback here is the trusted
        // bounded local clock; no registry, journal, endpoint or transport access.
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.retired {
            return None;
        }
        let sampled = catch_unwind(AssertUnwindSafe(|| {
            self.clock
                .lock()
                .map_err(|_| Invalid)?
                .now()
                .map_err(|_| Invalid)
        }))
        .unwrap_or(Err(Invalid));
        let now = sampled.ok().filter(|t| {
            (0..=i64::MAX / 1_000_000).contains(&t.mono_ms)
                && (0..=9007199254740691).contains(&t.unix)
                && state
                    .last
                    .is_none_or(|old| t.mono_ms >= old.mono_ms && t.unix >= old.unix)
        });
        if now.is_none() {
            state.retired = true;
        }
        if let Some(now) = now {
            state.last = Some(now);
        }
        now
    }
    fn sweep(&self) {
        self.sample();
        let owners = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            Self::snapshot(&mut state)
        };
        for owner in owners {
            owner.supervise(&mut || self.sample());
        }
    }
    fn retire(&self) {
        let owners = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.retired = true;
            state.stopping = true;
            Self::snapshot(&mut state)
        };
        for owner in owners {
            owner.supervise(&mut || None);
        }
        self.changed.notify_all();
    }
}
pub(crate) struct OwnerMonitor {
    registry: Arc<OwnerRegistry>,
}
impl OwnerMonitor {
    pub(crate) fn start(
        capacity: usize,
        interval: Duration,
        clock: Box<dyn Clock + Send>,
    ) -> Result<Self> {
        ensure(
            (1..=256).contains(&capacity)
                && !interval.is_zero()
                && interval <= Duration::from_secs(1),
        )?;
        let registry = Arc::new(OwnerRegistry {
            state: Mutex::new(State {
                owners: Vec::with_capacity(capacity),
                last: None,
                retired: false,
                stopping: false,
                done: false,
            }),
            changed: Condvar::new(),
            capacity,
            interval,
            clock: Mutex::new(clock),
        });
        let task = registry.clone();
        thread::Builder::new()
            .spawn(move || loop {
                task.sweep();
                let mut state = task.state.lock().unwrap_or_else(|p| p.into_inner());
                Self::prune(&mut state);
                if state.stopping && state.owners.is_empty() {
                    state.done = true;
                    task.changed.notify_all();
                    break;
                }
                drop(task.changed.wait_timeout(state, task.interval));
            })
            .map_err(|_| Invalid)?;
        Ok(Self { registry })
    }
    fn prune(state: &mut State) {
        state.owners.retain(|entry| entry.lease.strong_count() != 0);
    }
    pub(crate) fn registry(&self) -> Arc<OwnerRegistry> {
        self.registry.clone()
    }
    /// Logical close precedes the wait. Timeout retains all registrations and the
    /// monitor thread. Callers must actually drop owners/clients before success.
    pub(crate) fn stop(&self, timeout: Duration) -> Result<bool> {
        self.registry.retire();
        let end = Instant::now().checked_add(timeout).ok_or(Invalid)?;
        let mut state = self.registry.state.lock().map_err(|_| Invalid)?;
        while !state.done {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            state = self
                .registry
                .changed
                .wait_timeout(state, left)
                .map_err(|_| Invalid)?
                .0;
        }
        Ok(true)
    }
}
impl Drop for OwnerMonitor {
    fn drop(&mut self) {
        self.registry.retire();
    }
}
