use super::*;
use std::io::ErrorKind;
pub(super) struct Control {
    tcp: Mutex<Option<TcpListener>>,
    stopping: AtomicBool,
}
impl Control {
    pub(super) fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        let listener = self.tcp.lock().unwrap_or_else(|p| p.into_inner()).take();
        drop(listener); // no worker keeps a listener alias during handler/provider work
    }
}
pub(crate) struct Listener {
    control: Arc<Control>,
    pool: Arc<Pool>,
}
impl Listener {
    /// Stops this host's transport acceptance/connections. Full execution and
    /// owner-monitor shutdown remains Host::stop's responsibility.
    pub(crate) fn stop(&self, timeout: Duration) -> Result<bool> {
        self.control.stop();
        self.pool.retire();
        let end = Instant::now().checked_add(timeout).ok_or(Invalid)?;
        let mut state = self.pool.state.lock().map_err(|_| Invalid)?;
        while state.listener_workers != 0 {
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
        Ok(true)
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.control.stop();
        self.pool.retire();
    }
}
struct WorkerLease(Arc<Pool>);
impl Drop for WorkerLease {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        state.listener_workers -= 1;
        self.0.changed.notify_all();
    }
}
struct Task {
    handler: Box<dyn Handler + Send>,
    control: Arc<Control>,
    config: Config,
    pool: Arc<Pool>,
    _lease: WorkerLease,
}
impl Task {
    fn run(&mut self) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            while self.pool.live() && !self.control.stopping.load(Ordering::Acquire) {
                let accepted = {
                    let listener = self.control.tcp.lock().map_err(|_| Invalid)?;
                    let Some(listener) = listener.as_ref() else {
                        break;
                    };
                    listener.accept()
                };
                match accepted {
                    Ok((tcp, _)) => {
                        let _ =
                            connection::run(&self.pool, tcp, &self.config, self.handler.as_mut());
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => self.pool.pause(),
                    Err(e) if e.kind() == ErrorKind::Interrupted => (),
                    Err(_) => return Err(Invalid),
                }
            }
            Ok(())
        }))
        .unwrap_or(Err(Invalid));
        if result.is_err() {
            self.pool.retire();
        }
    }
}
pub(super) fn start(
    pool: &Arc<Pool>,
    tcp: TcpListener,
    config: Config,
    handlers: Vec<Box<dyn Handler + Send>>,
) -> Result<Listener> {
    config.valid()?;
    ensure(
        matches!(config.role, Role::Responder)
            && !handlers.is_empty()
            && handlers.len() <= pool.capacity,
    )?;
    tcp.set_nonblocking(true).map_err(|_| Invalid)?;
    let control = Arc::new(Control {
        tcp: Mutex::new(Some(tcp)),
        stopping: AtomicBool::new(false),
    });
    {
        let mut state = pool.state.lock().map_err(|_| Invalid)?;
        ensure(!state.retired && !state.listener_started)?;
        state.listener_started = true;
        state.listener = Some(control.clone());
        // Reserve all worker lifetimes before stop/reaper can observe this listener.
        state.listener_workers = handlers.len();
    }
    let listener = Listener {
        control,
        pool: pool.clone(),
    };
    let tasks: Vec<_> = handlers
        .into_iter()
        .map(|handler| Task {
            handler,
            control: listener.control.clone(),
            config: config.clone(),
            pool: pool.clone(),
            _lease: WorkerLease(pool.clone()),
        })
        .collect();
    for mut task in tasks {
        thread::Builder::new()
            .spawn(move || task.run())
            .map_err(|_| Invalid)?;
    }
    Ok(listener)
}
