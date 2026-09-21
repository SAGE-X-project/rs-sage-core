//! Private non-HTTP admission. No caller-supplied READY flags or work capabilities.
//! All clocks share the original endpoint monotonic domain. Providers are trusted,
//! bounded and non-reentrant. This is not a scheduler or a response transport.
use super::*;
use crate::guard010::mcp_setup::{MCPSetup, SetupClose};
use crate::hpke::completion010::{CompletionEndpoint010, NonHTTPOwner010};
use crate::registry010::{Clock, Stamp};
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// One pinned immutable instance. Run returns only after the actual effect ends;
/// detached execution, name resolution and unbounded callbacks are forbidden.
pub(crate) trait Executor: Send + Sync {
    fn check(&self, manifest: &str, tool: &str) -> Result<()>;
    fn run(&self, invocation: &Invocation) -> Result<Vec<u8>>;
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
}
struct Queue {
    retired: bool,
    occupied: usize,
    items: VecDeque<Work>,
    last: Option<Stamp>,
}
/// Construction pins configuration for the gate lifetime. Retirement is permanent;
/// replacement requires stopping/cleaning this gate and reopening the same ledger.
/// No queue recovery and no public DispatchGate alias are provided.
pub(crate) struct MCPGate {
    execution: DispatchGate,
    coordinator: Arc<Mutex<()>>,
    queue: Mutex<Queue>,
    authority: Arc<Mutex<RegistryAuthority>>,
    executor: Arc<dyn Executor>,
    clock: Mutex<Box<dyn Clock + Send>>,
    capacity: usize,
    request_ms: i64,
    claim_ms: i64,
}
impl MCPGate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        path: &Path,
        create: bool,
        recipient: &str,
        authority: RegistryAuthority,
        policy: Box<dyn IntentPolicy + Send>,
        executor: Arc<dyn Executor>,
        clock: Box<dyn Clock + Send>,
        capacity: usize,
        request_ms: i64,
        claim_ms: i64,
    ) -> Result<Self> {
        ensure(
            (1..=128).contains(&capacity)
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
                occupied: 0,
                items: VecDeque::with_capacity(capacity),
                last: None,
            }),
            authority,
            executor,
            clock: Mutex::new(clock),
            capacity,
            request_ms,
            claim_ms,
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
        ensure(!self.queue.lock().map_err(|_| Invalid)?.retired && !owner.initiator())?;
        MCPSetup::coordinated(owner, endpoint, name, version, self.coordinator.clone())
    }
    /// No execution/storage lock: an in-flight provider cannot delay retirement.
    /// Queued work retains capacity until a worker performs conservative cleanup.
    pub(crate) fn retire(&self) -> Result<()> {
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        self.queue.lock().map_err(|_| Invalid)?.retired = true;
        Ok(())
    }
    fn release(&self) {
        if let Ok(_c) = self.coordinator.lock() {
            if let Ok(mut q) = self.queue.lock() {
                q.occupied = q.occupied.saturating_sub(1);
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
            t.mono_ms >= 0
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
    ) -> Result<DispatchReceipt> {
        let mut held = false;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (started, operation, deadline) = {
                let _c = self.coordinator.lock().map_err(|_| Invalid)?;
                let mut q = self.queue.lock().map_err(|_| Invalid)?;
                ensure(!q.retired && q.occupied < self.capacity)?;
                let start = owner.admission_time(endpoint, &self.coordinator, None)?;
                Self::watermark(&mut q, start)?;
                let deadline = start.mono_ms.checked_add(self.request_ms).ok_or(Invalid)?;
                owner.bind_deadline(deadline)?;
                q.occupied += 1;
                held = true;
                (start, owner.operation()?, deadline)
            };
            let raw = owner.open_protected(endpoint, wire)?;
            let root: Value = serde_json::from_slice(&raw).map_err(|_| Invalid)?;
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
                    if !matches!(
                        s.store.as_mut().ok_or(Invalid)?.commit(entry.clone()),
                        Ok(true)
                    ) {
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
                    let claim_before = now.mono_ms.checked_add(self.claim_ms).ok_or(Invalid)?;
                    q.items.push_back(Work {
                        invocation,
                        entry,
                        claim_before,
                        deadline,
                        close: owner.closer(),
                    });
                    held = false; // queue now owns capacity, including actual execution/cleanup
                    pending = None;
                }
                Ok(DispatchReceipt {
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
                })
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
        if held {
            self.release();
        }
        result
    }
    /// Called by a fixed trusted host worker, never spawned per request. Claim and
    /// retirement are serialized. Transport closure after admission is not rollback.
    /// Capacity is retained through actual termination and result/UNKNOWN persistence.
    pub(crate) fn run_one(&self, signer: &mut dyn ResultSigner) -> Result<bool> {
        let (work, allowed, expired) = {
            let _c = self.coordinator.lock().map_err(|_| Invalid)?;
            let mut q = self.queue.lock().map_err(|_| Invalid)?;
            let Some(work) = q.items.pop_front() else {
                return Ok(false);
            };
            let sample =
                catch_unwind(AssertUnwindSafe(|| self.sample(&mut q))).unwrap_or(Err(Invalid));
            let allowed = sample.is_ok_and(|now| now.mono_ms < work.claim_before) && !q.retired;
            if sample.is_err() {
                q.retired = true;
            }
            let expired = sample.is_err() || sample.is_ok_and(|now| now.mono_ms >= work.deadline);
            (work, allowed, expired)
        };
        if expired {
            work.close.close();
        }
        let output = if allowed {
            catch_unwind(AssertUnwindSafe(|| self.executor.run(&work.invocation)))
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
            work.close.close();
        }
        self.release();
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
    /// Refuse to unlock durable storage while any provider, work or cleanup lives.
    pub(crate) fn close(&self) -> Result<()> {
        self.retire()?;
        let mut s = self.execution.state.lock().map_err(|_| Invalid)?;
        let _c = self.coordinator.lock().map_err(|_| Invalid)?;
        ensure(self.queue.lock().map_err(|_| Invalid)?.occupied == 0)?;
        s.retired = true;
        drop(_c);
        if let Some(mut store) = s.store.take() {
            store.close().map_err(|_| Invalid)?;
        }
        Ok(())
    }
}
