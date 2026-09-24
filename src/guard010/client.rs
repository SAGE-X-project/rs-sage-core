//! Protected one-operation client journal and single terminal consumption.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Trusted UTC and monotonic milliseconds, never peer time. Both must be
/// nonnegative safe integers and must not move backwards. Callbacks are bounded.
pub trait ClientClock {
    /// Read trusted UTC and monotonic milliseconds together.
    fn sample(&mut self) -> Result<(i64, i64)>;
}
/// Bounded protected transport handoff under the client lock. Bind this UUID and
/// exact intent to one request with fresh outer security fields; honor expiry,
/// never enqueue delayed duplicates, and never reenter the client. Errors are
/// unverified and may mean transmission already occurred.
pub trait ClientSender {
    /// Commit one actual bounded handoff, not a reusable permission to send later.
    fn commit(&mut self, id: &str, intent: &[u8]) -> Result<()>;
}
/// Trusted non-reentrant client services, outside plugin/model write capabilities.
pub struct ClientServices {
    /// Current issuer key authority for every transmission.
    pub intent_authority: Box<dyn Authority + Send>,
    /// Current original, manifest and argument authorization.
    pub policy: Box<dyn IntentPolicy + Send>,
    /// Current executor key authority for every response.
    pub result_authority: Box<dyn Authority + Send>,
    /// Trusted UTC and monotonic time source.
    pub clock: Box<dyn ClientClock + Send>,
    /// Protected transport used for each allowed invocation.
    pub sender: Box<dyn ClientSender + Send>,
    /// Trusted local signer identity; never selected by the signed intent.
    pub expected_issuer: String,
    /// Trusted target identity; never selected by the signed intent.
    pub expected_recipient: String,
}
/// Durable authorized parent admission for the exact authenticated envelope.
/// Missing, rejected and unknown states must fail.
pub trait HopParent {
    /// Recheck the parent before each protected downstream handoff.
    fn authorized(&mut self, incoming: &[u8]) -> Result<()>;
}
/// Trusted A-to-B providers, independent of B's B-to-C authority and policy.
pub struct HopServices {
    /// Current upstream signing authority.
    pub authority: Box<dyn Authority + Send>,
    /// Upstream authorization policy.
    pub policy: Box<dyn IntentPolicy + Send>,
    /// Protected parent outcome store.
    pub parent: Box<dyn HopParent + Send>,
}
struct HopBinding {
    incoming: Vec<u8>,
    services: HopServices,
}
fn check_hop(
    incoming: &[u8],
    outgoing: &[u8],
    s: &ClientServices,
    h: &mut HopServices,
) -> Result<()> {
    let (parent_envelope, parent_canonical) = intent_envelope(incoming)?;
    let parent = &parent_envelope["intent"];
    ensure(incoming == parent_canonical && text(parent, "recipient") == s.expected_issuer)?;
    verify_intent(
        incoming,
        &s.expected_issuer,
        h.authority.as_mut(),
        h.policy.as_mut(),
    )?;
    h.parent.authorized(incoming)?;
    let (child_envelope, _) = intent_envelope(outgoing)?;
    let child = &child_envelope["intent"];
    ensure(
        text(child, "issuer") == s.expected_issuer
            && text(child, "recipient") == s.expected_recipient
            && text(child, "request_id") != text(parent, "request_id")
            && text(child, "call_id") != text(parent, "call_id")
            && original_commitment(&[incoming.to_vec()])? == text(child, "original_digest"),
    )
}
/// Private outstanding invocation bound to one client and outer request identity.
/// Clones share the same one-use identity; transport must bind it to the real request.
#[derive(Clone)]
pub struct ClientInvocation {
    owner: Arc<()>,
    id: String,
    canonical: Vec<u8>,
}
impl ClientInvocation {
    /// Fresh outer request UUID assigned by the trusted transport.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Exact original intent, unchanged across retrievals.
    pub fn intent(&self) -> &[u8] {
        &self.canonical
    }
}
/// Output exists only for the first durably accepted completed terminal.
pub struct ClientDelivery {
    status: String,
    first: bool,
    ignored: bool,
    output: Vec<u8>,
}
impl ClientDelivery {
    /// Verified status, empty for ignored responses.
    pub fn status(&self) -> &str {
        &self.status
    }
    /// Whether this is the operation's first accepted terminal.
    pub fn first_terminal(&self) -> bool {
        self.first
    }
    /// Delayed pending or byte-identical terminal from an outstanding invocation.
    pub fn ignored(&self) -> bool {
        self.ignored
    }
    /// Consumable output only for first completed delivery.
    pub fn output(&self) -> &[u8] {
        &self.output
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    kind: String,
    id: String,
    at: i64,
    intent_hex: String,
    result_hex: String,
}
impl Event {
    fn new(kind: &str, id: &str) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            at: 0,
            intent_hex: String::new(),
            result_hex: String::new(),
        }
    }
}
const HEADER: &[u8] = b"sage-guard-client|0.10.0\n";
const MAX_SIZE: u64 = 8 << 20;
/// One durable protected operation. Host code must keep one stable journal per
/// issuer/call and never initialize a second journal for the same operation.
/// Reopen cannot recreate missing state. Failed writes retain the exclusive lock;
/// disk rollback and exactly-once downstream effects remain external concerns.
pub struct Client {
    state: Mutex<State>,
}
struct State {
    owner: Arc<()>,
    file: Option<File>,
    lock: PathBuf,
    services: ClientServices,
    hop: Option<HopBinding>,
    intent: Vec<u8>,
    terminal: Vec<u8>,
    seen: BTreeMap<String, bool>,
    last: i64,
    last_mono: i64,
    last_wall: i64,
    observed_utc: i64,
    observed_mono: i64,
    opened_mono: i64,
    rows: usize,
    size: u64,
    failed: bool,
}
fn terminal(raw: &[u8], intent: &[u8]) -> Result<()> {
    let (e, b) = object(raw)?;
    ensure(b == raw && closed(&e, "result proof"))?;
    let r = &e["result"];
    ensure(closed(r,"version request_id call_id issuer recipient created expires keyid alg intent_digest status output"))?;
    common(r)?;
    b64(text(&e, "proof"), 64)?;
    let (i, _) = intent_envelope(intent)?;
    let i = &i["intent"];
    let status = text(r, "status");
    let out = r["output"].as_object().ok_or(Invalid)?;
    ensure(
        matches!(status, "completed" | "rejected" | "unknown")
            && (status == "completed" || out.is_empty()),
    )?;
    ensure(
        text(r, "intent_digest") == hash(intent)
            && r["request_id"] == i["request_id"]
            && r["call_id"] == i["call_id"]
            && r["issuer"] == i["recipient"]
            && r["recipient"] == i["issuer"],
    )
}
impl State {
    fn apply(&mut self, e: &Event) -> Result<()> {
        match e.kind.as_str() {
            "open" => ensure(
                self.rows == 0
                    && e.id.is_empty()
                    && e.at == 0
                    && e.result_hex.is_empty()
                    && e.intent_hex == hex::encode(&self.intent),
            )?,
            "send" => {
                ensure(
                    self.rows > 0
                        && self.terminal.is_empty()
                        && uuid(&e.id)
                        && (0..=9007199254740991).contains(&e.at)
                        && e.intent_hex.is_empty()
                        && e.result_hex.is_empty()
                        && !self.seen.contains_key(&e.id)
                        && (self.last < 0 || e.at - self.last >= 1000),
                )?;
                self.seen.insert(e.id.clone(), true);
                self.last = e.at;
            }
            "close" => {
                ensure(
                    self.seen.get(&e.id) == Some(&true)
                        && e.at == 0
                        && e.intent_hex.is_empty()
                        && e.result_hex.is_empty(),
                )?;
                self.seen.insert(e.id.clone(), false);
            }
            "terminal" => {
                ensure(
                    self.seen.get(&e.id) == Some(&false)
                        && self.terminal.is_empty()
                        && e.at == 0
                        && e.intent_hex.is_empty(),
                )?;
                let raw = hex::decode(&e.result_hex).map_err(|_| Invalid)?;
                ensure(hex::encode(&raw) == e.result_hex)?;
                terminal(&raw, &self.intent)?;
                self.terminal = raw;
            }
            _ => return Err(Invalid),
        };
        self.rows += 1;
        Ok(())
    }
    fn append(&mut self, e: Event) -> Result<()> {
        let mut b = serde_json::to_vec(&e).map_err(|_| Invalid)?;
        b.push(b'\n');
        if self.rows >= 1024 || self.size + b.len() as u64 > MAX_SIZE {
            self.failed = true;
            return Err(Invalid);
        }
        let f = self.file.as_mut().ok_or(Invalid)?;
        if f.write_all(&b).and_then(|_| f.sync_all()).is_err() {
            self.failed = true;
            return Err(Invalid);
        }
        if self.apply(&e).is_err() {
            self.failed = true;
            return Err(Invalid);
        };
        self.size += b.len() as u64;
        Ok(())
    }
    fn sample(&mut self) -> Result<(i64, i64)> {
        let (u, m) = match self.services.clock.sample() {
            Ok(v) => v,
            Err(_) => {
                self.failed = true;
                return Err(Invalid);
            }
        };
        if !(0..=9007199254740991).contains(&u)
            || !(0..=9007199254740991).contains(&m)
            || u < self.observed_utc
            || m < self.observed_mono
            || u < self.last
        {
            self.failed = true;
            return Err(Invalid);
        }
        self.observed_utc = u;
        self.observed_mono = m;
        Ok((u, m))
    }
    fn close(&mut self) -> Result<()> {
        if self.file.take().is_some() {
            ensure(!self.failed)?;
            fs::remove_file(&self.lock).map_err(|_| Invalid)?
        };
        Ok(())
    }
    fn close_invocation(&mut self, t: &ClientInvocation) -> Result<()> {
        ensure(Arc::ptr_eq(&self.owner, &t.owner) && self.seen.get(&t.id) == Some(&true))?;
        self.append(Event::new("close", &t.id))
    }
    fn begin(
        &mut self,
        id: &str,
        sender: Option<&mut dyn ClientSender>,
    ) -> Result<ClientInvocation> {
        ensure(
            !self.failed
                && self.file.is_some()
                && self.terminal.is_empty()
                && uuid(id)
                && !self.seen.contains_key(id),
        )?;
        let (u, m) = self.sample()?;
        ensure(
            self.last < 0
                || (u - self.last >= 1000
                    && (self.last_wall < 0 || u - self.last_wall >= 1000)
                    && if self.last_mono >= 0 {
                        m - self.last_mono >= 1000
                    } else {
                        m - self.opened_mono >= 1000
                    }),
        )?;
        let (env, _) = intent_envelope(&self.intent)?;
        let i = &env["intent"];
        let recipient = text(i, "recipient");
        verify_intent(
            &self.intent,
            recipient,
            self.services.intent_authority.as_mut(),
            self.services.policy.as_mut(),
        )?;
        if let Some(hop) = &mut self.hop {
            check_hop(
                &hop.incoming,
                &self.intent,
                &self.services,
                &mut hop.services,
            )?;
        }
        let expires = number(i, "expires")?;
        ensure(u < expires * 1000)?;
        let mut e = Event::new("send", id);
        e.at = u;
        self.append(e)?;
        self.last_mono = m;
        verify_intent(
            &self.intent,
            recipient,
            self.services.intent_authority.as_mut(),
            self.services.policy.as_mut(),
        )?;
        if let Some(hop) = &mut self.hop {
            check_hop(
                &hop.incoming,
                &self.intent,
                &self.services,
                &mut hop.services,
            )?;
        }
        let (u, _) = self.sample()?;
        ensure(u < expires * 1000)?;
        let sent = match sender {
            Some(sender) => sender.commit(id, &self.intent),
            None => self.services.sender.commit(id, &self.intent),
        };
        let (u, m) = self.sample()?;
        self.last_mono = m;
        self.last_wall = u;
        if sent.is_err() {
            self.append(Event::new("close", id))?;
            return Err(Invalid);
        }
        Ok(ClientInvocation {
            owner: self.owner.clone(),
            id: id.into(),
            canonical: self.intent.clone(),
        })
    }
    fn accept(&mut self, t: &ClientInvocation, raw: &[u8]) -> Result<ClientDelivery> {
        ensure(!self.failed && self.file.is_some())?;
        self.close_invocation(t)?;
        self.sample()?;
        let v = verify_result(
            raw,
            self.services.result_authority.as_mut(),
            &mut Accepted(self.intent.clone()),
        )?;
        if !self.terminal.is_empty() {
            ensure(v.status() == "pending" || v.canonical() == self.terminal)?;
            return Ok(ClientDelivery {
                status: String::new(),
                first: false,
                ignored: true,
                output: Vec::new(),
            });
        }
        if v.status() == "pending" {
            return Ok(ClientDelivery {
                status: "pending".into(),
                first: false,
                ignored: false,
                output: Vec::new(),
            });
        }
        let mut e = Event::new("terminal", &t.id);
        e.result_hex = hex::encode(v.canonical());
        self.append(e)?;
        self.sample()?;
        let v = verify_result(
            v.canonical(),
            self.services.result_authority.as_mut(),
            &mut Accepted(self.intent.clone()),
        )?;
        Ok(ClientDelivery {
            status: v.status().into(),
            first: true,
            ignored: false,
            output: if v.status() == "completed" {
                v.output().to_vec()
            } else {
                Vec::new()
            },
        })
    }
}
struct Accepted(Vec<u8>);
impl Outstanding for Accepted {
    fn intent(&mut self, _: &str, _: &str) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
impl Client {
    /// Bind an authenticated A-to-B call to B's fresh capture and independently
    /// authorized B-to-C operation. The host must use this path for every
    /// multi-hop protected effect and reopen with the protected parent admission.
    pub fn open_hop(
        path: &Path,
        create: bool,
        incoming: &[u8],
        outgoing: &[u8],
        services: ClientServices,
        mut hop: HopServices,
    ) -> Result<Self> {
        check_hop(incoming, outgoing, &services, &mut hop)?;
        let client = Self::open(path, create, outgoing, services)?;
        client.state.lock().map_err(|_| Invalid)?.hop = Some(HopBinding {
            incoming: incoming.to_vec(),
            services: hop,
        });
        Ok(client)
    }
    /// Initialize a new authorized operation, or reopen its exact protected original.
    /// Reopening never redelivers a terminal and abandons pre-restart transport handles.
    /// Only trusted Linux/macOS paths are supported. No automatic unlock on Drop.
    pub fn open(
        path: &Path,
        create: bool,
        raw: &[u8],
        mut services: ClientServices,
    ) -> Result<Self> {
        ensure(cfg!(any(target_os = "linux", target_os = "macos")))?;
        let (env, intent) = intent_envelope(raw)?;
        ensure(
            did(&services.expected_issuer)
                && did(&services.expected_recipient)
                && text(&env["intent"], "issuer") == services.expected_issuer
                && text(&env["intent"], "recipient") == services.expected_recipient,
        )?;
        if create {
            verify_intent(
                &intent,
                text(&env["intent"], "recipient"),
                services.intent_authority.as_mut(),
                services.policy.as_mut(),
            )?;
        }
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let mut opt = OpenOptions::new();
        opt.write(true).create_new(true);
        #[cfg(unix)]
        opt.mode(0o600);
        drop(opt.open(&lock).map_err(|_| Invalid)?);
        let mut opt = OpenOptions::new();
        opt.read(true).append(true).create_new(create);
        #[cfg(unix)]
        opt.mode(0o600);
        let file = match opt.open(path) {
            Ok(f) => f,
            Err(_) => {
                let _ = fs::remove_file(&lock);
                return Err(Invalid);
            }
        };
        let mut s = State {
            owner: Arc::new(()),
            file: Some(file),
            lock,
            services,
            hop: None,
            intent,
            terminal: Vec::new(),
            seen: BTreeMap::new(),
            last: -1,
            last_mono: -1,
            last_wall: -1,
            observed_utc: -1,
            observed_mono: -1,
            opened_mono: 0,
            rows: 0,
            size: 0,
            failed: false,
        };
        let loaded = (|| -> Result<()> {
            let f = s.file.as_mut().ok_or(Invalid)?;
            if create {
                f.write_all(HEADER)
                    .and_then(|_| f.sync_all())
                    .map_err(|_| Invalid)?;
                File::open(
                    path.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                )
                .and_then(|d| d.sync_all())
                .map_err(|_| Invalid)?;
                s.size = HEADER.len() as u64;
                let mut e = Event::new("open", "");
                e.intent_hex = hex::encode(&s.intent);
                s.append(e)?;
            } else {
                f.seek(SeekFrom::Start(0)).map_err(|_| Invalid)?;
                let mut b = Vec::new();
                f.take(MAX_SIZE + 1)
                    .read_to_end(&mut b)
                    .map_err(|_| Invalid)?;
                ensure(b.len() as u64 <= MAX_SIZE && b.starts_with(HEADER) && b.ends_with(b"\n"))?;
                let body = &b[HEADER.len()..];
                ensure(!body.is_empty())?;
                for line in body[..body.len() - 1].split(|b| *b == b'\n') {
                    let e: Event = serde_json::from_slice(line).map_err(|_| Invalid)?;
                    ensure(serde_json::to_vec(&e).map_err(|_| Invalid)? == line && s.rows < 1024)?;
                    s.apply(&e)?;
                }
                s.size = b.len() as u64;
            };
            s.opened_mono = s.sample()?.1;
            Ok(())
        })();
        if loaded.is_err() {
            s.failed = true;
            let _ = s.close();
            return Err(Invalid);
        }
        Ok(Self {
            state: Mutex::new(s),
        })
    }
    /// Persist a fresh outer UUID, then perform one protected bounded handoff.
    /// Polls require UTC and monotonic elapsed time >=1s since the previous handoff
    /// finished; reopen adds a 1s wait. Terminal acceptance prevents new handoffs.
    /// Transport must additionally provide its fresh nonce/session sequence and bind
    /// the receipt to exactly this actual invocation. This is not a read-only query.
    pub fn begin(&self, id: &str) -> Result<ClientInvocation> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.begin(id, None))) {
            Ok(r) => r,
            Err(_) => {
                s.failed = true;
                Err(Invalid)
            }
        }
    }
    /// Private synchronous owner adapter; no sender replacement or public permit.
    pub(crate) fn begin_owned(
        &self,
        id: &str,
        sender: &mut dyn ClientSender,
    ) -> Result<ClientInvocation> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.begin(id, Some(sender)))) {
            Ok(result) => result,
            Err(_) => {
                s.failed = true;
                Err(Invalid)
            }
        }
    }
    /// Consume an unverified transport failure without creating a remote verdict.
    pub fn failed(&self, t: &ClientInvocation) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(!s.failed && s.file.is_some())?;
        s.close_invocation(t)
    }
    /// Consume one invocation even on invalid proof; persist the first terminal before
    /// output release. Crash after persistence can lose delivery, never redeliver it.
    pub fn accept(&self, t: &ClientInvocation, raw: &[u8]) -> Result<ClientDelivery> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.accept(t, raw))) {
            Ok(r) => r,
            Err(_) => {
                s.failed = true;
                Err(Invalid)
            }
        }
    }
    /// Release a healthy exclusive lock; failed state needs protected administration.
    pub fn close(&self) -> Result<()> {
        self.state.lock().map_err(|_| Invalid)?.close()
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod storage_tests;
