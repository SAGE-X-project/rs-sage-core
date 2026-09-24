//! Private non-HTTP admission. No caller-supplied READY flags or work capabilities.
//! All clocks share the original endpoint monotonic domain. Providers are trusted,
//! bounded and non-reentrant. Full owner supervision and production transport remain external.
use super::*;
use crate::guard010::mcp_setup::{MCPSetup, SetupClose};
use crate::hpke::completion010::{CompletionEndpoint010, NonHTTPOwner010};
use crate::registry010::{Clock, Stamp};
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub(crate) struct ParentAdmission(Arc<ParentState>);

struct ParentState {
    canonical: Vec<u8>,
    active: AtomicBool,
    cancellation: Cancellation,
}

impl ParentAdmission {
    fn new(canonical: Vec<u8>, cancellation: Cancellation) -> Self {
        Self(Arc::new(ParentState {
            canonical,
            active: AtomicBool::new(false),
            cancellation,
        }))
    }
    fn activate(&self) -> ActiveParent {
        self.0.active.store(true, Ordering::Release);
        ActiveParent(self.clone())
    }
}

struct ActiveParent(ParentAdmission);
impl Drop for ActiveParent {
    fn drop(&mut self) {
        self.0 .0.active.store(false, Ordering::Release);
    }
}

impl crate::guard010::client::HopParent for ParentAdmission {
    fn authorized(&mut self, incoming: &[u8]) -> Result<()> {
        ensure(
            self.0.active.load(Ordering::Acquire)
                && !self.0.cancellation.cancelled()
                && incoming == self.0.canonical,
        )
    }
}

/// One pinned immutable instance. Run returns only after the actual effect ends;
/// detached execution, name resolution and unbounded callbacks are forbidden.
/// Poll cancellation during work and perform bounded cleanup before returning.
pub(crate) trait Executor: Send + Sync {
    fn check(&self, manifest: &str, tool: &str) -> Result<()>;
    fn run(&self, invocation: &Invocation, cancellation: &Cancellation) -> Result<Vec<u8>>;
}
mod reply;
pub(crate) mod workers;

/// Cooperative cancellation never releases the charged resource. Executors must
/// return only after their actual work and all dependent cleanup have ended.
#[derive(Clone, Default)]
pub(crate) struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub(crate) fn cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}
struct Job {
    cancellation: Cancellation,
    close: SetupClose,
    operation: Arc<()>,
    deadline: i64,
    claim_before: Option<i64>,
    worker_before: Option<i64>,
    admitted: bool,
}

pub(crate) use reply::ProtectedReply;

pub(crate) struct Admission {
    created: bool,
    state: String,
    digest: String,
}
impl Admission {
    pub(crate) fn created(&self) -> bool {
        self.created
    }
    pub(crate) fn committed(&self) -> bool {
        self.created
    }
    pub(crate) fn state(&self) -> &str {
        &self.state
    }
    pub(crate) fn intent_digest(&self) -> &str {
        &self.digest
    }
}

struct Pinned(Arc<dyn Executor>);
impl Component for Pinned {
    fn check(&mut self, manifest: &str, tool: &str) -> Result<()> {
        self.0.check(manifest, tool)
    }
    fn commit(&mut self, _: &Invocation) -> Result<()> {
        Err(Invalid)
    }
}
struct AuthorityBinding(Arc<Mutex<RegistryAuthority>>);
impl Authority for AuthorityBinding {
    fn now(&mut self) -> Result<i64> {
        self.0.lock().map_err(|_| Invalid)?.now()
    }
    fn active_key(&mut self, issuer: &str, key: &str) -> Result<[u8; 32]> {
        self.0.lock().map_err(|_| Invalid)?.active_key(issuer, key)
    }
}
struct Work {
    invocation: Invocation,
    entry: Entry,
    claim_before: i64,
    deadline: i64,
    close: SetupClose,
    operation: Arc<()>,
    job: Arc<Mutex<Job>>,
}
struct Queue {
    retired: bool,
    generation: u64,
    occupied: usize,
    admitted: usize,
    outputs: usize,
    items: VecDeque<Work>,
    last: Option<Stamp>,
    jobs: Vec<Arc<Mutex<Job>>>,
    output_jobs: Vec<Arc<Mutex<Job>>>,
    hosted: bool,
    worker_ms: i64,
    setup_used: bool,
    owners: Option<Arc<crate::guard010::mcp_lifecycle::OwnerRegistry>>,
}
/// Construction pins configuration for the gate lifetime. Retirement is permanent;
/// replacement requires stopping/cleaning this gate and reopening the same ledger.
/// No queue recovery and no public DispatchGate alias are provided.
pub(crate) struct MCPGate {
    execution: DispatchGate,
    coordinator: Arc<Mutex<()>>,
    queue: Mutex<Queue>,
    authority: Arc<Mutex<RegistryAuthority>>,
    result_authority: Mutex<RegistryAuthority>,
    executor: Arc<dyn Executor>,
    clock: Mutex<Box<dyn Clock + Send>>,
    capacity: usize,
    preparation_capacity: usize,
    request_ms: i64,
    claim_ms: i64,
    retain_writer: AtomicBool,
    #[cfg(test)]
    fail_unknown: AtomicBool,
    #[cfg(test)]
    fail_insert: AtomicBool,
    #[cfg(test)]
    fence_mode: AtomicUsize,
    #[cfg(test)]
    fence_hook: Mutex<Option<Box<dyn FnMut() + Send>>>,
}
impl MCPGate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        path: &Path,
        create: bool,
        recipient: &str,
        authority: RegistryAuthority,
        result_authority: RegistryAuthority,
        policy: Box<dyn IntentPolicy + Send>,
        executor: Arc<dyn Executor>,
        clock: Box<dyn Clock + Send>,
        capacity: usize,
        preparation_capacity: usize,
        request_ms: i64,
        claim_ms: i64,
    ) -> Result<Self> {
        ensure(
            (1..=128).contains(&capacity)
                && (capacity..=128).contains(&preparation_capacity)
                && (1..=300_000).contains(&request_ms)
                && (1..=300_000).contains(&claim_ms),
        )?;
        let authority = Arc::new(Mutex::new(authority));
        let execution = DispatchGate::open(
            path,
            create,
            recipient,
            Box::new(AuthorityBinding(authority.clone())),
            policy,
            Box::new(Pinned(executor.clone())),
        )?;
        Ok(Self {
            execution,
            coordinator: Arc::new(Mutex::new(())),
            queue: Mutex::new(Queue {
                retired: false,
                generation: 1,
                occupied: 0,
                admitted: 0,
                outputs: 0,
                items: VecDeque::with_capacity(capacity),
                last: None,
                jobs: Vec::with_capacity(capacity),
                output_jobs: Vec::with_capacity(capacity),
                hosted: false,
                worker_ms: 300_000,
                setup_used: false,
                owners: None,
            }),
            authority,
            result_authority: Mutex::new(result_authority),
            executor,
            clock: Mutex::new(clock),
            capacity,
            preparation_capacity,
            request_ms,
            claim_ms,
            retain_writer: AtomicBool::new(false),
            #[cfg(test)]
            fail_unknown: AtomicBool::new(false),
            #[cfg(test)]
            fail_insert: AtomicBool::new(false),
            #[cfg(test)]
            fence_mode: AtomicUsize::new(0),
            #[cfg(test)]
            fence_hook: Mutex::new(None),
        })
    }
    pub(crate) fn attach_owners(
        &self,
        owners: Arc<crate::guard010::mcp_lifecycle::OwnerRegistry>,
    ) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let mut q = self.queue.lock().map_err(|_| Invalid)?;
        ensure(
            !q.retired
                && !q.hosted
                && !q.setup_used
                && q.last.is_none()
                && q.owners.is_none()
                && owners.live()
                && owners.interval() < std::time::Duration::from_millis(self.request_ms as u64),
        )?;
        q.owners = Some(owners);
        Ok(())
    }
    pub(crate) fn transport_ready(
        &self,
        owners: &Arc<crate::guard010::mcp_lifecycle::OwnerRegistry>,
    ) -> bool {
        let Ok(_c) = self.coordinator.lock() else {
            return false;
        };
        self.queue.lock().is_ok_and(|q| {
            !q.retired
                && q.hosted
                && !q.setup_used
                && q.owners
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, owners))
        })
    }
    /// Bind before setup, so even the earliest close handle uses this coordinator.
    pub(crate) fn setup(
        &self,
        owner: NonHTTPOwner010,
        endpoint: &mut CompletionEndpoint010,
        name: &str,
        version: &str,
    ) -> Result<MCPSetup> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let owners = {
            let mut q = self.queue.lock().map_err(|_| Invalid)?;
            ensure(!q.retired && !owner.initiator())?;
            q.setup_used = true;
            q.owners.clone()
        };
        let mut setup =
            MCPSetup::coordinated(owner, endpoint, name, version, self.coordinator.clone())?;
        if let Some(owners) = owners {
            if let Err(error) = owners.register(&mut setup) {
                // Drop outside the coordinator: MCPSetup::drop closes through it.
                drop(_c);
                return Err(error);
            }
        }
        Ok(setup)
    }
    /// No execution/storage lock: an in-flight provider cannot delay retirement.
    /// Queued work retains capacity until a worker performs conservative cleanup.
    pub(crate) fn retire(&self) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        let mut q = self.queue.lock().map_err(|_| Invalid)?;
        if !q.retired {
            q.generation = q.generation.checked_add(1).ok_or(Invalid)?;
            q.retired = true;
        }
        for job in &q.jobs {
            job.lock().map_err(|_| Invalid)?.cancellation.cancel();
        }
        Ok(())
    }
    fn release(&self, job: &Arc<Mutex<Job>>) {
        if let Ok(_c) = self.coordinator.lock() {
            if let Ok(mut q) = self.queue.lock() {
                q.jobs.retain(|old| !Arc::ptr_eq(old, job));
                q.occupied = q.occupied.saturating_sub(1);
                if job.lock().is_ok_and(|job| job.admitted) {
                    q.admitted = q.admitted.saturating_sub(1);
                }
            }
        }
    }
    fn watermark(q: &mut Queue, now: Stamp) -> Result<()> {
        ensure(
            q.last
                .is_none_or(|old| now.mono_ms >= old.mono_ms && now.unix >= old.unix),
        )?;
        q.last = Some(now);
        Ok(())
    }
    fn sample(&self, q: &mut Queue) -> Result<Stamp> {
        let t = self
            .clock
            .lock()
            .map_err(|_| Invalid)?
            .now()
            .map_err(|_| Invalid)?;
        ensure(
            (0..=i64::MAX / 1_000_000).contains(&t.mono_ms)
                && (0..=9007199254740691).contains(&t.unix)
                && q.last
                    .is_none_or(|old| t.mono_ms >= old.mono_ms && t.unix >= old.unix),
        )?;
        q.last = Some(t);
        Ok(t)
    }
    /// Authenticate using the owner's sole lifetime ID set, fence durably, then
    /// revalidate and insert under the same coordinator used by close/retirement.
    /// The returned receipt is diagnostic; only the private queue grants execution.
    pub(crate) fn admit(
        &self,
        owner: &mut MCPSetup,
        endpoint: &mut CompletionEndpoint010,
        wire: &[u8],
    ) -> Result<Admission> {
        let mut held = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (started, operation, deadline, generation) = {
                let _c = self.coordinator.lock().map_err(|_| Invalid)?;
                let mut q = self.queue.lock().map_err(|_| Invalid)?;
                ensure(!q.retired && q.occupied < self.preparation_capacity)?;
                let start = owner.admission_time(endpoint, &self.coordinator, None)?;
                Self::watermark(&mut q, start)?;
                let deadline = start.mono_ms.checked_add(self.request_ms).ok_or(Invalid)?;
                owner.bind_deadline(deadline)?;
                q.occupied += 1;
                let operation = owner.operation()?;
                let job = Arc::new(Mutex::new(Job {
                    cancellation: Cancellation::default(),
                    close: owner.closer(),
                    operation: operation.clone(),
                    deadline,
                    claim_before: None,
                    worker_before: None,
                    admitted: false,
                }));
                q.jobs.push(job.clone());
                held = Some(job);
                (start, operation, deadline, q.generation)
            };
            let raw = owner.open_protected(endpoint, wire)?;
            let root: Value = serde_json::from_slice(&raw).map_err(|_| Invalid)?;
            let outer = super::super::mcp_owned::wire_id(wire)?;
            let intent = parse_mcp_request(MCP_VERSION, text(&root, "id"), &raw)?;
            let mut s = self.execution.state.lock().map_err(|_| Invalid)?;
            let s = &mut *s;
            ensure(!s.retired && s.store.is_some())?;
            let mut pending = None;
            let result = catch_unwind(AssertUnwindSafe(|| {
                let v = verify_intent(
                    &intent,
                    &s.recipient,
                    s.authority.as_mut(),
                    s.policy.as_mut(),
                )?;
                let (env, _) = intent_envelope(&v.canonical)?;
                let body = &env["intent"];
                let invocation = Invocation {
                    canonical: v.canonical.clone(),
                    arguments: encode(&body["arguments"])?,
                    tool: text(body, "tool").into(),
                    manifest: text(body, "manifest_digest").into(),
                    digest: v.digest(),
                    completion: Completion {
                        owner: s.owner.clone(),
                        canonical: v.canonical.clone(),
                    },
                    parent: None,
                };
                s.component.check(&invocation.manifest, &invocation.tool)?;
                let mut entry = super::super::ledger::reservation_entry(&v)?;
                let (stored, created) =
                    match s.store.as_mut().ok_or(Invalid)?.reserve(entry.clone()) {
                        Ok(result) => result,
                        Err(crate::execution010::Error::Unavailable) => {
                            s.retired = true;
                            return Err(Invalid);
                        }
                        Err(_) => return Err(Invalid),
                    };
                if created {
                    pending = Some(entry.clone());
                    entry.state = "EXECUTING".into();
                    #[cfg(test)]
                    let fence_mode = self.fence_mode.swap(0, Ordering::SeqCst);
                    #[cfg(not(test))]
                    let fence_mode = 0;
                    if fence_mode == 1 {
                        #[cfg(test)]
                        if let Some(hook) = self.fence_hook.lock().unwrap().as_mut() {
                            hook();
                        }
                        pending = None;
                        self.retain_writer.store(true, Ordering::SeqCst);
                        s.retired = true;
                        return Err(Invalid);
                    }
                    if !matches!(
                        s.store.as_mut().ok_or(Invalid)?.commit(entry.clone()),
                        Ok(true)
                    ) {
                        pending = None;
                        self.retain_writer.store(true, Ordering::SeqCst);
                        s.retired = true;
                        return Err(Invalid);
                    }
                    #[cfg(test)]
                    if let Some(hook) = self.fence_hook.lock().unwrap().as_mut() {
                        hook();
                    }
                    if fence_mode == 2 {
                        pending = None;
                        self.retain_writer.store(true, Ordering::SeqCst);
                        s.retired = true;
                        return Err(Invalid);
                    }
                }
                verify_intent(
                    &v.canonical,
                    &s.recipient,
                    s.authority.as_mut(),
                    s.policy.as_mut(),
                )?;
                s.component.check(&invocation.manifest, &invocation.tool)?;
                let observation = self.authority.lock().map_err(|_| Invalid)?.observe()?;
                let session_observed = owner.observe_admission(endpoint)?;
                // execution -> coordinator -> leaf state. No registry/storage/tool
                // callback occurs here; close never acquires the execution mutex.
                let _c = self.coordinator.lock().map_err(|_| Invalid)?;
                let mut q = self.queue.lock().map_err(|_| Invalid)?;
                let now = owner.admission_time(endpoint, &self.coordinator, Some(&operation))?;
                ensure(
                    !q.retired
                        && q.generation == generation
                        && now.mono_ms >= started.mono_ms
                        && now.unix >= started.unix
                        && now.mono_ms < deadline
                        && now.unix >= observation.stamp.unix
                        && observation.expires.is_none_or(|expiry| now.unix < expiry),
                )?;
                for observed in [observation.started_ms, session_observed] {
                    ensure(
                        observed >= started.mono_ms
                            && observed <= now.mono_ms
                            && now.mono_ms - observed <= 5000,
                    )?;
                }
                Self::watermark(&mut q, now)?;
                times(body, now.unix)?;
                if created {
                    ensure(q.admitted < self.capacity)?;
                    #[cfg(test)]
                    ensure(!self.fail_insert.swap(false, Ordering::SeqCst))?;
                    let claim_before = now.mono_ms.checked_add(self.claim_ms).ok_or(Invalid)?;
                    let job = held.as_ref().ok_or(Invalid)?.clone();
                    {
                        let mut job = job.lock().map_err(|_| Invalid)?;
                        job.claim_before = Some(claim_before);
                        job.admitted = true;
                    }
                    q.admitted += 1;
                    q.items.push_back(Work {
                        job,
                        invocation,
                        entry,
                        claim_before,
                        deadline,
                        close: owner.closer(),
                        operation: operation.clone(),
                    });
                    held = None; // queue now owns capacity, including actual execution/cleanup
                    pending = None;
                }
                let receipt = DispatchReceipt {
                    created,
                    committed: created,
                    state: if created {
                        "EXECUTING".into()
                    } else {
                        stored.state
                    },
                    digest: v.digest(),
                    reply: ReplyPermit {
                        owner: s.owner.clone(),
                        canonical: v.canonical,
                        used: false,
                    },
                };
                let admission = Admission {
                    created,
                    state: receipt.state.clone(),
                    digest: receipt.digest.clone(),
                };
                owner.response = Some(ProtectedReply {
                    operation,
                    started,
                    deadline,
                    inner: text(&root, "id").into(),
                    outer,
                    receipt,
                });
                Ok(admission)
            }));
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    s.retired = true;
                    Err(Invalid)
                }
            };
            if result.is_err() {
                // Known retirement must precede potentially blocking cleanup.
                if s.retired {
                    self.retire()?;
                }
                if let Some(entry) = pending {
                    #[cfg(test)]
                    if self.fail_unknown.swap(false, Ordering::SeqCst) {
                        s.store.as_mut().unwrap().fail_writes_fixture();
                    }
                    unknown(s, entry);
                }
                if s.retired {
                    self.retire()?;
                }
            }
            result
        }));
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                let _ = self.retire();
                Err(Invalid)
            }
        };
        if result.is_err() {
            owner.fail();
        }
        if let Some(job) = held {
            self.release(&job);
        }
        result
    }
    /// Called by a fixed trusted host worker, never spawned per request. Claim and
    /// retirement are serialized. Transport closure after admission is not rollback.
    /// Capacity is retained through actual termination and result/UNKNOWN persistence.
    pub(crate) fn run_one(&self, signer: &mut dyn ResultSigner) -> Result<bool> {
        self.run_worker(signer, false)
    }
    fn run_worker(&self, signer: &mut dyn ResultSigner, hosted: bool) -> Result<bool> {
        let (mut work, allowed, expired) = {
            let _c = self.coordinator.lock().map_err(|_| Invalid)?;
            let mut q = self.queue.lock().map_err(|_| Invalid)?;
            ensure(q.hosted == hosted)?;
            let Some(work) = q.items.pop_front() else {
                return Ok(false);
            };
            let sample =
                catch_unwind(AssertUnwindSafe(|| self.sample(&mut q))).unwrap_or(Err(Invalid));
            let mut job = work.job.lock().map_err(|_| Invalid)?;
            let allowed = sample.is_ok_and(|now| now.mono_ms < work.claim_before)
                && !q.retired
                && !job.cancellation.cancelled();
            job.claim_before = None;
            if allowed {
                job.worker_before = Some(
                    sample
                        .as_ref()
                        .map_err(|_| Invalid)?
                        .mono_ms
                        .checked_add(q.worker_ms)
                        .ok_or(Invalid)?,
                );
            }
            drop(job);
            if sample.is_err() {
                q.retired = true;
            }
            let expired = sample.is_err() || sample.is_ok_and(|now| now.mono_ms >= work.deadline);
            (work, allowed, expired)
        };
        if expired {
            work.close.close_operation(&work.operation);
        }
        let cancellation = work.job.lock().map_err(|_| Invalid)?.cancellation.clone();
        let output = if allowed {
            let parent =
                ParentAdmission::new(work.invocation.canonical.clone(), cancellation.clone());
            work.invocation.parent = Some(parent.clone());
            let _active = parent.activate();
            catch_unwind(AssertUnwindSafe(|| {
                self.executor.run(&work.invocation, &cancellation)
            }))
            .unwrap_or(Err(Invalid))
        } else {
            Err(Invalid)
        };
        if output.is_err() {
            self.retire()?;
        }
        let result = {
            let mut s = self.execution.state.lock().map_err(|_| Invalid)?;
            let result = output.and_then(|output| {
                catch_unwind(AssertUnwindSafe(|| {
                    publication::finish(&mut s, &work.invocation.completion, &output, signer)
                }))
                .unwrap_or(Err(Invalid))
            });
            if result.is_err() {
                // Publish retirement before releasing execution serialization.
                // A later worker cannot claim against failed durable storage.
                self.retire()?;
                unknown(&mut s, work.entry);
            }
            result
        };
        // A worker may finish after its request deadline. Close transport on the
        // observed expiry without discarding the durable first outcome.
        let expired = {
            let _c = self.coordinator.lock().map_err(|_| Invalid)?;
            let mut q = self.queue.lock().map_err(|_| Invalid)?;
            match catch_unwind(AssertUnwindSafe(|| self.sample(&mut q))).unwrap_or(Err(Invalid)) {
                Ok(now) => now.mono_ms >= work.deadline,
                Err(_) => {
                    q.retired = true;
                    true
                }
            }
        };
        if expired {
            work.close.close_operation(&work.operation);
        }
        self.release(&work.job);
        result.map(|_| true)
    }
    #[cfg(test)]
    pub(crate) fn unavailable_fixture(&self) {
        self.execution
            .state
            .lock()
            .unwrap()
            .store
            .as_mut()
            .unwrap()
            .close()
            .unwrap();
    }
    #[cfg(test)]
    pub(crate) fn occupy_queue_fixture(&self) {
        let _c = self.coordinator.lock().unwrap();
        let mut q = self.queue.lock().unwrap();
        assert!(q.admitted < self.capacity && q.occupied < self.preparation_capacity);
        q.admitted += 1;
        q.occupied += 1;
    }
    #[cfg(test)]
    pub(crate) fn release_queue_fixture(&self) {
        let _c = self.coordinator.lock().unwrap();
        let mut q = self.queue.lock().unwrap();
        assert!(q.admitted > 0 && q.occupied > 0);
        q.admitted -= 1;
        q.occupied -= 1;
    }
    #[cfg(test)]
    pub(crate) fn fail_unknown_fixture(&self) {
        self.fail_unknown.store(true, Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn fail_insert_fixture(&self) {
        self.fail_insert.store(true, Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn fence_outcome_fixture(&self, mode: usize, hook: Box<dyn FnMut() + Send>) {
        assert!((0..=2).contains(&mode));
        self.fence_mode.store(mode, Ordering::SeqCst);
        *self.fence_hook.lock().unwrap() = Some(hook);
    }
    #[cfg(test)]
    pub(crate) fn generation_fixture(&self) -> u64 {
        self.queue.lock().unwrap().generation
    }
    /// Refuse to unlock durable storage while any provider, work or cleanup lives.
    pub(crate) fn close(&self) -> Result<()> {
        self.retire()?;
        let mut s = self.execution.state.lock().map_err(|_| Invalid)?;
        ensure(!self.retain_writer.load(Ordering::SeqCst))?;
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        {
            let q = self.queue.lock().map_err(|_| Invalid)?;
            ensure(q.occupied == 0 && q.outputs == 0)?;
        }
        s.retired = true;
        drop(_c);
        if let Some(mut store) = s.store.take() {
            store.close().map_err(|_| Invalid)?;
        }
        Ok(())
    }
}
