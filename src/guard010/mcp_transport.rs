//! Private deployment-selected TCP carriage; not MCP stdio or a wire negotiation.
//! Native sockets are exclusively transferred. Providers/handlers are trusted,
//! bounded and non-reentrant; handlers must finish their work before returning.
use super::mcp_admission::{workers::Workers, MCPGate};
use super::mcp_lifecycle::OwnerMonitor;
use super::mcp_owned::{ClientPool, HopCapture, OwnedClient, OwnedServices, RootCapture};
use super::mcp_setup::{MCPSetup, SetupClose, SetupIO};
use super::*;
use crate::hpke::completion010::{CompletionEndpoint010, PendingCompletion010};
use crate::registry010::{Clock, Stamp};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::thread;
use std::time::{Duration, Instant};
pub(crate) mod connection;
mod listener;
mod stream;
pub(crate) use connection::{Config, Handler, Role};
pub(crate) use listener::Listener;
use stream::{Socket, Stream};
const TICK: Duration = Duration::from_millis(5);
struct Entry {
    lease: Weak<()>,
    socket: Weak<Socket>,
}
struct State {
    retired: bool,
    entries: Vec<Entry>,
    listener_started: bool,
    listener: Option<Arc<listener::Control>>,
    listener_workers: usize,
    reaper_done: bool,
}
struct Time {
    clock: Box<dyn Clock + Send>,
    last: Option<Stamp>,
}
struct Pool {
    state: Mutex<State>,
    changed: Condvar,
    capacity: usize,
    time: Mutex<Time>,
    gate: Arc<MCPGate>,
    clients: Arc<ClientPool>,
}
impl Pool {
    fn sample(&self) -> Result<Stamp> {
        let sampled = catch_unwind(AssertUnwindSafe(|| {
            let mut clock = self.time.lock().map_err(|_| Invalid)?;
            let now = clock.clock.now().map_err(|_| Invalid)?;
            ensure(
                (0..=i64::MAX / 1_000_000).contains(&now.mono_ms)
                    && (0..=9007199254740691).contains(&now.unix)
                    && clock
                        .last
                        .is_none_or(|old| now.mono_ms >= old.mono_ms && now.unix >= old.unix),
            )?;
            clock.last = Some(now);
            Ok(now)
        }))
        .unwrap_or(Err(Invalid));
        if sampled.is_err() {
            self.retire();
        }
        sampled
    }
    fn prune(state: &mut State) {
        state
            .entries
            .retain(|entry| entry.lease.strong_count() != 0);
    }
    fn sockets(state: &mut State) -> Vec<Arc<Socket>> {
        state
            .entries
            .retain(|entry| entry.lease.strong_count() != 0);
        state
            .entries
            .iter()
            .filter_map(|entry| entry.socket.upgrade())
            .collect()
    }
    fn retire(&self) {
        let sockets = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.retired = true;
            (state.listener.clone(), Self::sockets(&mut state))
        };
        if let Some(listener) = sockets.0 {
            listener.stop();
        }
        for socket in sockets.1 {
            socket.close();
        }
        self.changed.notify_all();
    }
    fn live(&self) -> bool {
        self.state.lock().is_ok_and(|state| !state.retired)
    }
    fn pause(&self) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        drop(self.changed.wait_timeout(state, TICK));
    }
    fn reserve(&self, socket: Arc<Socket>) -> Result<Arc<()>> {
        let mut state = self.state.lock().map_err(|_| Invalid)?;
        Self::prune(&mut state);
        ensure(!state.retired && state.entries.len() < self.capacity)?;
        let lease = Arc::new(());
        *socket.lease.lock().map_err(|_| Invalid)? = Some(lease.clone());
        state.entries.push(Entry {
            lease: Arc::downgrade(&lease),
            socket: Arc::downgrade(&socket),
        });
        Ok(lease)
    }
}
/// Owns fixed execution/accept workers, lifetime monitoring and socket shutdown.
/// Gate ledger close remains separate, and is safe only after successful stop.
pub(crate) struct Host {
    pool: Arc<Pool>,
    owners: OwnerMonitor,
    workers: Workers,
}
impl Host {
    #[cfg(test)]
    pub(crate) fn frame_fixture(
        &self,
        tcp: TcpStream,
        bound: Duration,
        mono: Option<i64>,
    ) -> Result<Vec<u8>> {
        let socket = Socket::new(tcp, Instant::now() + Duration::from_secs(30))?;
        let lease = self.pool.reserve(socket.clone())?;
        let result = {
            let mut stream = Stream::new(socket, self.pool.clone(), bound);
            stream.receive_frame(mono)
        };
        drop(lease);
        result
    }

    pub(crate) fn start(
        gate: Arc<MCPGate>,
        clients: Arc<ClientPool>,
        owners: OwnerMonitor,
        workers: Workers,
        capacity: usize,
        clock: Box<dyn Clock + Send>,
    ) -> Result<Self> {
        ensure(
            (1..=256).contains(&capacity)
                && owners.registry().live()
                && workers.bound_to(&gate)
                && gate.transport_ready(&owners.registry())
                && clients.transport_ready(&owners.registry()),
        )?;
        let pool = Arc::new(Pool {
            state: Mutex::new(State {
                retired: false,
                entries: Vec::with_capacity(capacity),
                listener_started: false,
                listener: None,
                listener_workers: 0,
                reaper_done: false,
            }),
            changed: Condvar::new(),
            capacity,
            time: Mutex::new(Time { clock, last: None }),
            gate,
            clients,
        });
        let task = pool.clone();
        thread::Builder::new()
            .spawn(move || loop {
                let sockets = {
                    let mut state = task.state.lock().unwrap_or_else(|p| p.into_inner());
                    Pool::sockets(&mut state)
                };
                for socket in sockets {
                    if !socket.live() {
                        socket.close();
                    }
                }
                let mut state = task.state.lock().unwrap_or_else(|p| p.into_inner());
                Pool::prune(&mut state);
                if state.retired && state.entries.is_empty() && state.listener_workers == 0 {
                    state.reaper_done = true;
                    task.changed.notify_all();
                    break;
                }
                drop(task.changed.wait_timeout(state, TICK));
            })
            .map_err(|_| Invalid)?;
        Ok(Self {
            pool,
            owners,
            workers,
        })
    }
    /// Takes exclusive socket ownership even on rejection. No new thread is made.
    pub(crate) fn connection(
        &self,
        socket: TcpStream,
        config: &Config,
        handler: &mut dyn Handler,
    ) -> Result<()> {
        connection::run(&self.pool, socket, config, handler)
    }
    pub(crate) fn serve(
        &self,
        listener: TcpListener,
        config: Config,
        handlers: Vec<Box<dyn Handler + Send>>,
    ) -> Result<Listener> {
        listener::start(&self.pool, listener, config, handlers)
    }
    pub(crate) fn stop(&self, timeout: Duration) -> Result<bool> {
        let end = Instant::now().checked_add(timeout).ok_or(Invalid)?;
        self.pool.retire();
        // Signal every subsystem before waiting for any provider or worker.
        let _ = self.workers.stop(Duration::ZERO)?;
        let _ = self.owners.stop(Duration::ZERO)?;
        let mut state = self.pool.state.lock().map_err(|_| Invalid)?;
        while !state.reaper_done {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            state = self
                .pool
                .changed
                .wait_timeout(state, left)
                .map_err(|_| Invalid)?
                .0;
        }
        drop(state);
        if !self
            .workers
            .stop(end.saturating_duration_since(Instant::now()))?
        {
            return Ok(false);
        }
        self.owners
            .stop(end.saturating_duration_since(Instant::now()))
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        self.pool.retire();
    }
}
