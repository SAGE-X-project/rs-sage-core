//! Protected intent approval and one-use journaled issuance. Host capabilities,
//! policy administration, loaded-instance identity and durable paths stay trusted.
use super::*;
use rand::TryRng;
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

/// Protected host key custody, never a model-facing arbitrary signing tool.
pub trait IntentSigner {
    /// Sign only the locally selected key's domain-separated exact intent bytes.
    /// Honor bounded host deadlines; no fallback key or algorithm is permitted.
    fn sign(&mut self, key_id: &str, message: &[u8]) -> Result<Vec<u8>>;
}
/// Locally approved policy, including exact recipient and complete unsigned intent.
pub trait IssuancePolicy: IntentPolicy {
    /// Evaluate canonical intent before private-key use. No peer self-provisioning.
    fn approve_intent(&mut self, canonical_intent: &[u8]) -> Result<()>;
}
/// Same immutable loaded instance and dependencies, not merely a manifest hash.
pub trait IntentMeasurement {
    /// Validate the protected manifest and exact tool against the pinned instance.
    fn check(&mut self, manifest_digest: &str, tool: &str) -> Result<()>;
}
/// Trusted immutable configuration with bounded, non-reentrant callbacks. Keep
/// keys, policy and storage outside model/plugin capabilities; serialize changes
/// through retirement. Client services transfer once on issue/reopen attempt.
pub struct IssuerServices {
    /// Protected Client collaborators and locally selected peer tuple.
    pub client: ClientServices,
    /// Full local issuance evaluator, independent of wire-supplied descriptors.
    pub policy: Box<dyn IssuancePolicy + Send>,
    /// Private-key custody for the locally selected signing key.
    pub signer: Box<dyn IntentSigner + Send>,
    /// Trusted pinned loaded-component measurement.
    pub measurement: Box<dyn IntentMeasurement + Send>,
    /// Exact issuer-owned active Ed25519 key ID; never proposed by the model.
    pub key_id: String,
}
/// Untrusted proposal: identity, capture, time, commitments and randomness are owned.
pub struct IntentProposal {
    /// Exact registered tool name.
    pub tool: String,
    /// Fully resolved closed-schema JSON object bytes.
    pub arguments: Vec<u8>,
    /// Requested exclusive lifetime, from one through 300 seconds.
    pub lifetime_seconds: i64,
}
/// Opaque owner-bound one-use decision. No constructor, clone or serialization.
pub struct AuthorizedIntent {
    owner: Arc<()>,
    body: Vec<u8>,
    used: bool,
}
/// One protected operation issuer. Exclusive mutable access serializes approval,
/// issuance and retirement. A permanent .issuance fence reserves each stable
/// operation path before key use. Failed or interrupted issuance requires protected
/// reconciliation, never automatic signing under a new path. Protect fence and
/// Client journal against deletion/rollback. Resume using a fresh configured issuer.
pub struct IntentIssuer {
    owner: Arc<()>,
    capture: RootCapture,
    services: Option<IssuerServices>,
    incoming: Vec<u8>,
    hop: Option<HopServices>,
    retired: bool,
}
const HEADER: &str = "sage-intent-issuance|0.10.0\n";

fn unsigned(body: &[u8]) -> Vec<u8> {
    [
        b"{\"intent\":".as_slice(),
        body,
        b",\"proof\":\"",
        B64.encode([0; 64]).as_bytes(),
        b"\"}",
    ]
    .concat()
}
fn policy_check(policy: &mut dyn IntentPolicy, i: &Value) -> Result<()> {
    let bindings = policy.bindings(text(i, "issuer"), text(i, "request_id"))?;
    let (descriptor, _) = object(&bindings.policy)?;
    ensure(
        bindings.original == text(i, "original_digest")
            && policy_commitment(&bindings.policy)? == text(i, "policy_digest")
            && manifest_commitment(&bindings.manifest)? == text(i, "manifest_digest")
            && text(&descriptor, "issuer") == text(i, "issuer"),
    )?;
    policy.authorize(
        text(i, "issuer"),
        text(i, "tool"),
        &encode(&i["arguments"])?,
    )
}
fn fence_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".issuance");
    name.into()
}
fn reserve(path: &Path, body: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(fence_path(path)).map_err(|_| Invalid)?;
    file.write_all(format!("{HEADER}{}\n", hash(body)).as_bytes())
        .map_err(|_| Invalid)?;
    file.sync_all().map_err(|_| Invalid)?;
    drop(file);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|_| Invalid)
}
impl IntentIssuer {
    /// Construct one root issuer without private-key use. Resume with a fresh
    /// issuer after Client services have transferred to a journaled operation.
    pub fn new(capture: RootCapture, services: IssuerServices) -> Result<Self> {
        ensure(cfg!(any(target_os = "linux", target_os = "macos")))?;
        ensure(uuid(&capture.request_id) && digest(&capture.digest))?;
        common(
            &json!({"version":"0.10.0","request_id":capture.request_id,"call_id":capture.request_id,
            "issuer":services.client.expected_issuer,"recipient":services.client.expected_recipient,
            "keyid":services.key_id,"alg":"ed25519","created":0,"expires":1}),
        )?;
        Ok(Self {
            owner: Arc::new(()),
            capture,
            services: Some(services),
            incoming: Vec::new(),
            hop: None,
            retired: false,
        })
    }
    /// Bind downstream issuance to a fresh capture of an authenticated admitted
    /// inbound envelope. Parent authority is rechecked before approval and signing.
    pub fn new_hop(
        capture: RootCapture,
        services: IssuerServices,
        incoming: &[u8],
        hop: HopServices,
    ) -> Result<Self> {
        let mut issuer = Self::new(capture, services)?;
        let (env, canonical) = intent_envelope(incoming)?;
        ensure(
            incoming == canonical
                && text(&env["intent"], "recipient")
                    == issuer
                        .services
                        .as_ref()
                        .ok_or(Invalid)?
                        .client
                        .expected_issuer
                && issuer.capture.request_id != text(&env["intent"], "request_id")
                && issuer.capture.digest == original_commitment(&[incoming.to_vec()])?,
        )?;
        issuer.incoming = incoming.to_vec();
        issuer.hop = Some(hop);
        Ok(issuer)
    }
    fn guarded<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(self))) {
            Ok(result) => result,
            Err(_) => {
                self.retired = true;
                Err(Invalid)
            }
        }
    }
    fn check(&mut self, body: &[u8]) -> Result<[u8; 32]> {
        ensure(!self.retired)?;
        let (env, _) = intent_envelope(&unsigned(body))?;
        let i = &env["intent"];
        let s = self.services.as_mut().ok_or(Invalid)?;
        ensure(
            text(i, "issuer") == s.client.expected_issuer
                && text(i, "recipient") == s.client.expected_recipient
                && text(i, "request_id") == self.capture.request_id
                && text(i, "original_digest") == self.capture.digest
                && text(i, "keyid") == s.key_id,
        )?;
        if let Some(hop) = self.hop.as_mut() {
            super::client::check_hop(&self.incoming, &unsigned(body), &s.client, hop)?;
        } else {
            ensure(i["parent_call_id"].is_null())?;
        }
        policy_check(s.policy.as_mut(), i)?;
        policy_check(s.client.policy.as_mut(), i)?;
        s.policy.approve_intent(body)?;
        s.measurement
            .check(text(i, "manifest_digest"), text(i, "tool"))?;
        let key = s
            .client
            .intent_authority
            .active_key(&s.client.expected_issuer, &s.key_id)?;
        ensure(
            canonical_edwards_y(key)
                && !VerifyingKey::from_bytes(&key)
                    .map_err(|_| Invalid)?
                    .is_weak(),
        )?;
        times(i, s.client.intent_authority.now()?)?;
        Ok(key)
    }
    /// Approve immutable canonical bytes without signing, creating storage or sending.
    pub fn authorize(&mut self, proposal: IntentProposal) -> Result<AuthorizedIntent> {
        self.guarded(|s| s.authorize_inner(proposal))
    }
    fn authorize_inner(&mut self, p: IntentProposal) -> Result<AuthorizedIntent> {
        ensure(!self.retired && (1..=300).contains(&p.lifetime_seconds))?;
        let (arguments, _) = object(&p.arguments)?;
        let s = self.services.as_mut().ok_or(Invalid)?;
        let now = s.client.intent_authority.now()?;
        ensure((0..=9007199254740691).contains(&now))?;
        let bindings = s
            .policy
            .bindings(&s.client.expected_issuer, &self.capture.request_id)?;
        ensure(bindings.original == self.capture.digest)?;
        let mut random = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut random)
            .map_err(|_| Invalid)?;
        random[6] = (random[6] & 15) | 64;
        random[8] = (random[8] & 63) | 128;
        let call_id =
            uuid::Uuid::from_bytes(random[..16].try_into().map_err(|_| Invalid)?).to_string();
        let parent = if self.hop.is_some() {
            intent_envelope(&self.incoming)?.0["intent"]["call_id"].clone()
        } else {
            Value::Null
        };
        let body = encode(&json!({"version":"0.10.0","profile":"sage-execution-guard",
            "request_id":self.capture.request_id,"call_id":call_id,"parent_call_id":parent,
            "original_digest":bindings.original,"issuer":s.client.expected_issuer,"recipient":s.client.expected_recipient,
            "tool":p.tool,"arguments":arguments,"policy_digest":policy_commitment(&bindings.policy)?,
            "manifest_digest":manifest_commitment(&bindings.manifest)?,"created":now,"expires":now+p.lifetime_seconds,
            "nonce":B64.encode(&random[16..]),"keyid":s.key_id,"alg":"ed25519"}))?;
        self.check(&body)?;
        Ok(AuthorizedIntent {
            owner: self.owner.clone(),
            body,
            used: false,
        })
    }
    /// Consume approval, durably fence the path, recheck authority and sign once.
    /// Return only a journaled Client; any failure preserves consumed authority
    /// and the durable fence. No transport or effect is invoked here.
    pub fn issue(&mut self, path: &Path, token: &mut AuthorizedIntent) -> Result<Client> {
        self.guarded(|s| s.issue_inner(path, token))
    }
    fn issue_inner(&mut self, path: &Path, token: &mut AuthorizedIntent) -> Result<Client> {
        ensure(
            !self.retired
                && self.services.is_some()
                && Arc::ptr_eq(&self.owner, &token.owner)
                && !token.used,
        )?;
        token.used = true;
        self.check(&token.body)?;
        ensure(
            matches!(fs::symlink_metadata(path),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        )?;
        reserve(path, &token.body)?;
        let key = self.check(&token.body)?;
        let s = self.services.as_mut().ok_or(Invalid)?;
        let message = [b"sage-execution-intent|0.10.0\0".as_slice(), &token.body].concat();
        let proof = s.signer.sign(&s.key_id, &message)?;
        ensure(proof.len() == 64)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| Invalid)?
            .verify_strict(
                &message,
                &Signature::from_slice(&proof).map_err(|_| Invalid)?,
            )
            .map_err(|_| Invalid)?;
        let raw = encode(
            &json!({"intent":serde_json::from_slice::<Value>(&token.body).map_err(|_|Invalid)?,"proof":B64.encode(proof)}),
        )?;
        self.check(&token.body)?;
        let s = self.services.take().ok_or(Invalid)?;
        if let Some(hop) = self.hop.take() {
            Client::open_hop(path, true, &self.incoming, &raw, s.client, hop)
        } else {
            Client::open_captured(path, true, &raw, s.client, &self.capture)
        }
    }
    /// Permanently invalidate all pending approvals before administrative changes.
    pub fn retire(&mut self) -> Result<()> {
        self.retired = true;
        Ok(())
    }
    /// Resume exact journaled bytes with fresh host services and no signing.
    /// Missing/partial fences or journals fail closed and require reconciliation.
    pub fn reopen(&mut self, path: &Path) -> Result<Client> {
        self.guarded(|s| s.reopen_inner(path))
    }
    fn reopen_inner(&mut self, path: &Path) -> Result<Client> {
        ensure(!self.retired && self.services.is_some())?;
        let mut raw = Vec::new();
        File::open(path)
            .map_err(|_| Invalid)?
            .take(super::client::MAX_SIZE + 1)
            .read_to_end(&mut raw)
            .map_err(|_| Invalid)?;
        ensure(
            raw.len() as u64 <= super::client::MAX_SIZE && raw.starts_with(super::client::HEADER),
        )?;
        let first = raw[super::client::HEADER.len()..]
            .split(|b| *b == b'\n')
            .next()
            .ok_or(Invalid)?;
        let row: Value = serde_json::from_slice(first).map_err(|_| Invalid)?;
        ensure(text(&row, "kind") == "open")?;
        let envelope = hex::decode(text(&row, "intent_hex")).map_err(|_| Invalid)?;
        let (env, _) = intent_envelope(&envelope)?;
        let i = &env["intent"];
        let body = encode(i)?;
        let mut marker = Vec::new();
        File::open(fence_path(path))
            .map_err(|_| Invalid)?
            .take(128)
            .read_to_end(&mut marker)
            .map_err(|_| Invalid)?;
        ensure(
            marker == format!("{HEADER}{}\n", hash(&body)).as_bytes()
                && text(i, "keyid") == self.services.as_ref().ok_or(Invalid)?.key_id
                && text(i, "request_id") == self.capture.request_id
                && text(i, "original_digest") == self.capture.digest,
        )?;
        let s = self.services.take().ok_or(Invalid)?;
        if let Some(hop) = self.hop.take() {
            Client::open_hop(path, false, &self.incoming, &envelope, s.client, hop)
        } else {
            Client::open_captured(path, false, &envelope, s.client, &self.capture)
        }
    }
}
