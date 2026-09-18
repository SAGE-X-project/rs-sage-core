//! Serialized authenticated dispatch to a trusted bounded component commitment.
use super::*;
use crate::execution010::{Entry, Ledger};
use std::path::Path;
use std::sync::{Arc, Mutex};
mod publication;
pub use publication::ResultSigner;

/// Trusted pinned immutable loaded instance, never a peer-supplied identifier.
/// Check validates its protected baseline, measured instance and tool binding.
/// Commit atomically accepts the exact invocation into this same instance's
/// protected execution boundary. It must not resolve names/paths again, add
/// defaults, reenter the gate or run an unbounded tool under the lock. Callbacks
/// must bound their deadlines. Long-running work runs after bounded commitment.
/// Host isolation and durable administrative baseline updates are external duties.
pub trait Component: Send {
    /// Validate the locally approved measured instance against the verified claim.
    fn check(&mut self, manifest: &str, tool: &str) -> Result<()>;
    /// Bounded effect commitment, not tool completion or a signed result.
    fn commit(&mut self, invocation: &Invocation) -> Result<()>;
}
/// Private authenticated invocation. Borrows are immutable; no unsigned defaults.
/// Only delivered to the trusted component, never returned as a capability.
pub struct Invocation {
    canonical: Vec<u8>,
    arguments: Vec<u8>,
    tool: String,
    manifest: String,
    digest: String,
    completion: Completion,
}
/// Opaque accepted-execution token, bound to one gate and exact canonical intent.
/// A recovered UNKNOWN cannot be completed, even with a retained token.
#[derive(Clone)]
pub struct Completion {
    owner: Arc<()>,
    canonical: Vec<u8>,
}
struct ReplyPermit {
    owner: Arc<()>,
    canonical: Vec<u8>,
    used: bool,
}
impl Invocation {
    /// Retain only in the trusted worker; permits recording, never re-execution.
    pub fn completion(&self) -> Completion {
        self.completion.clone()
    }

    /// Complete canonical authenticated envelope including proof.
    pub fn canonical_intent(&self) -> &[u8] {
        &self.canonical
    }
    /// Exact canonical final arguments.
    pub fn arguments(&self) -> &[u8] {
        &self.arguments
    }
    /// Authenticated tool name.
    pub fn tool(&self) -> &str {
        &self.tool
    }
    /// Authenticated commitment to the approved component manifest.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest
    }
    /// SHA-256 of the whole canonical intent envelope.
    pub fn intent_digest(&self) -> &str {
        &self.digest
    }
}
/// Local storage and bounded handoff metadata, never completion or signed output.
pub struct DispatchReceipt {
    created: bool,
    committed: bool,
    state: String,
    digest: String,
    reply: ReplyPermit,
}
impl DispatchReceipt {
    /// Whether this invocation durably created the reservation.
    pub fn created(&self) -> bool {
        self.created
    }
    /// Whether this invocation performed bounded commitment.
    pub fn committed(&self) -> bool {
        self.committed
    }
    /// Stored execution state, never signed output.
    pub fn state(&self) -> &str {
        &self.state
    }
    /// SHA-256 of the whole canonical intent envelope.
    pub fn intent_digest(&self) -> &str {
        &self.digest
    }
}
struct State {
    owner: Arc<()>,
    store: Option<Ledger>,
    recipient: String,
    authority: Box<dyn Authority + Send>,
    policy: Box<dyn IntentPolicy + Send>,
    component: Box<dyn Component>,
    retired: bool,
}
/// Owns storage and serializes fresh verification, configuration, retirement and
/// bounded handoff. Policy/instance changes must use replace/retire, not mutation
/// behind the gate. Registry providers must return fresh observations. Retirement
/// is permanent locally; the host enforces it across receivers and restarts.
pub struct DispatchGate {
    state: Mutex<State>,
}
impl DispatchGate {
    /// Explicit creation is only for a new isolated scope. Recovery requires
    /// current trusted configuration and stopped prior workers; never reset loss.
    pub fn open(
        path: &Path,
        create: bool,
        recipient: &str,
        authority: Box<dyn Authority + Send>,
        policy: Box<dyn IntentPolicy + Send>,
        component: Box<dyn Component>,
    ) -> Result<Self> {
        ensure(did(recipient))?;
        let store = Ledger::open(path, create).map_err(|_| Invalid)?;
        Ok(Self {
            state: Mutex::new(State {
                owner: Arc::new(()),
                store: Some(store),
                recipient: recipient.into(),
                authority,
                policy,
                component,
                retired: false,
            }),
        })
    }
    /// Trusted administrative replacement. The host persists approved old/new
    /// baseline and policy mappings. Already committed work retains its old pinned
    /// instance. A retired gate cannot be reactivated by replacement.
    pub fn replace(
        &self,
        authority: Box<dyn Authority + Send>,
        policy: Box<dyn IntentPolicy + Send>,
        component: Box<dyn Component>,
    ) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(s.store.is_some() && !s.retired)?;
        s.authority = authority;
        s.policy = policy;
        s.component = component;
        Ok(())
    }
    /// Permanently cancel not-yet-committed local work, serialized with commitment.
    /// Does not roll back effects or wait for long-running tool completion.
    pub fn retire(&self) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(s.store.is_some())?;
        s.retired = true;
        Ok(())
    }
    /// Close healthy storage; failed storage retains its administrative lock.
    pub fn close(&self) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        if let Some(mut store) = s.store.take() {
            store.close().map_err(|_| Invalid)?;
        }
        Ok(())
    }
    /// Reserve once, persist EXECUTING and freshly verify authority, policy,
    /// instance and time before committing. Duplicates never reach commitment.
    /// Failed or panicking post-reservation callbacks leave UNKNOWN or unavailable
    /// storage. No terminal bytes are released. Panics also retire this gate.
    pub fn dispatch(&self, raw: &[u8]) -> Result<DispatchReceipt> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(!s.retired && s.store.is_some())?;
        let mut pending = None;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch(&mut s, raw, &mut pending)
        })) {
            Ok(r) => r,
            Err(_) => {
                s.retired = true;
                if let Some(e) = pending {
                    unknown(&mut s, e);
                };
                Err(Invalid)
            }
        }
    }
}
fn unknown(s: &mut State, mut e: Entry) {
    e.state = "UNKNOWN".into();
    // Failure poisons storage and retains its lock. No success or effect retry.
    if let Some(store) = s.store.as_mut() {
        if store.commit(e).is_err() {
            s.retired = true;
        }
    }
}
fn dispatch(s: &mut State, raw: &[u8], pending: &mut Option<Entry>) -> Result<DispatchReceipt> {
    let v = verify_intent(raw, &s.recipient, s.authority.as_mut(), s.policy.as_mut())?;
    let (env, _) = intent_envelope(&v.canonical)?;
    let intent = &env["intent"];
    let i = Invocation {
        canonical: v.canonical.clone(),
        arguments: encode(&intent["arguments"])?,
        tool: text(intent, "tool").into(),
        manifest: text(intent, "manifest_digest").into(),
        digest: v.digest(),
        completion: Completion {
            owner: s.owner.clone(),
            canonical: v.canonical.clone(),
        },
    };
    s.component.check(&i.manifest, &i.tool)?;
    let mut e = super::ledger::reservation_entry(&v)?;
    let (stored, created) = s
        .store
        .as_mut()
        .ok_or(Invalid)?
        .reserve(e.clone())
        .map_err(|_| Invalid)?;
    if !created {
        times(intent, s.authority.now()?)?;
        return Ok(DispatchReceipt {
            created: false,
            committed: false,
            state: stored.state,
            digest: v.digest(),
            reply: ReplyPermit {
                owner: s.owner.clone(),
                canonical: v.canonical.clone(),
                used: false,
            },
        });
    }
    *pending = Some(e.clone());
    e.state = "EXECUTING".into();
    if !matches!(s.store.as_mut().ok_or(Invalid)?.commit(e.clone()), Ok(true)) {
        s.retired = true;
        return Err(Invalid);
    }
    let result = (|| {
        verify_intent(
            &v.canonical,
            &s.recipient,
            s.authority.as_mut(),
            s.policy.as_mut(),
        )?;
        s.component.check(&i.manifest, &i.tool)?;
        times(intent, s.authority.now()?)?;
        s.component.commit(&i)
    })();
    if result.is_err() {
        unknown(s, e);
        return Err(Invalid);
    }
    Ok(DispatchReceipt {
        created: true,
        committed: true,
        state: "EXECUTING".into(),
        digest: v.digest(),
        reply: ReplyPermit {
            owner: s.owner.clone(),
            canonical: v.canonical.clone(),
            used: false,
        },
    })
}
