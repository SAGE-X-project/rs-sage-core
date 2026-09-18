use super::*;
use serde_json::json;

/// Trusted executor signer with current result-key authority and clock. All
/// callbacks require bounded deadlines. Returned proofs are verified before storage.
pub trait ResultSigner: Authority {
    /// Exact active executor key identifier, never selected by the peer.
    fn key_id(&mut self) -> Result<String>;
    /// Sign only these domain-separated bytes for the supplied exact key ID.
    fn sign(&mut self, key_id: &str, message: &[u8]) -> Result<Vec<u8>>;
}
struct Accepted(Vec<u8>);
impl Outstanding for Accepted {
    fn intent(&mut self, _: &str, _: &str) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
fn matches(e: &Entry, raw: &[u8]) -> Result<bool> {
    let v = VerifiedIntent {
        canonical: raw.to_vec(),
    };
    let mut expected = super::super::ledger::reservation_entry(&v)?;
    let mut actual = e.clone();
    expected.state.clear();
    actual.state.clear();
    actual.result_hex.clear();
    Ok(actual == expected)
}
fn entry(s: &State, raw: &[u8]) -> Result<Entry> {
    let (env, _) = intent_envelope(raw)?;
    let i = &env["intent"];
    let e = s
        .store
        .as_ref()
        .ok_or(Invalid)?
        .lookup(text(i, "issuer"), text(i, "call_id"))
        .map_err(|_| Invalid)?
        .ok_or(Invalid)?;
    ensure(matches(&e, raw)?)?;
    Ok(e)
}
fn check(
    raw: &[u8],
    intent: &[u8],
    state: &str,
    signer: &mut dyn ResultSigner,
) -> Result<VerifiedResult> {
    let v = verify_result(raw, signer, &mut Accepted(intent.to_vec()))?;
    let status = match state {
        "RESERVED" | "EXECUTING" => "pending",
        "COMPLETED" => "completed",
        "REJECTED" => "rejected",
        "UNKNOWN" => "unknown",
        _ => return Err(Invalid),
    };
    ensure(v.canonical() == raw && v.status() == status)?;
    Ok(v)
}
fn sign(
    intent: &[u8],
    status: &str,
    output: &[u8],
    signer: &mut dyn ResultSigner,
) -> Result<Vec<u8>> {
    let (env, _) = intent_envelope(intent)?;
    let i = &env["intent"];
    let (output, _) = object(output)?;
    let now = signer.now()?;
    ensure((0..=9007199254740691).contains(&now))?;
    let kid = signer.key_id()?;
    let result = json!({"version":"0.10.0","request_id":i["request_id"],"call_id":i["call_id"],"issuer":i["recipient"],"recipient":i["issuer"],"created":now,"expires":now+300,"keyid":kid,"alg":"ed25519","intent_digest":hash(intent),"status":status,"output":output});
    common(&result)?;
    let body = encode(&result)?;
    let proof = signer.sign(
        &kid,
        &[b"sage-tool-result|0.10.0\0".as_slice(), &body].concat(),
    )?;
    ensure(proof.len() == 64)?;
    let raw = encode(&json!({"result":result,"proof":B64.encode(proof)}))?;
    let state = match status {
        "pending" => "EXECUTING",
        "completed" => "COMPLETED",
        "rejected" => "REJECTED",
        "unknown" => "UNKNOWN",
        _ => return Err(Invalid),
    };
    check(&raw, intent, state, signer)?;
    Ok(raw)
}
impl DispatchGate {
    /// Persist the first completed outcome and exact signed bytes; never push a
    /// response. Accepted execution may finish after intent expiry or retirement.
    /// Current result-key/time validity still applies. Identical output retries
    /// reuse stored bytes; conflicting or recovered UNKNOWN outcomes are denied.
    pub fn finish(
        &self,
        token: &Completion,
        output: &[u8],
        signer: &mut dyn ResultSigner,
    ) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(Arc::ptr_eq(&s.owner, &token.owner) && s.store.is_some())?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            finish(&mut s, token, output, signer)
        })) {
            Ok(r) => r,
            Err(_) => {
                s.retired = true;
                Err(Invalid)
            }
        }
    }
    /// Consume this accepted invocation's single response permit, including on
    /// local failure. The host must bind the receipt to one fresh outer invocation
    /// and must not dispatch twice for that invocation. Client polling and terminal
    /// consumption are separate. Accepted replies may outlive intent expiry only.
    pub fn reply(
        &self,
        receipt: &mut DispatchReceipt,
        signer: &mut dyn ResultSigner,
    ) -> Result<Vec<u8>> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(Arc::ptr_eq(&s.owner, &receipt.reply.owner) && !receipt.reply.used)?;
        receipt.reply.used = true;
        ensure(s.store.is_some())?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reply(&mut s, &receipt.reply.canonical, signer)
        })) {
            Ok(r) => r,
            Err(_) => {
                s.retired = true;
                Err(Invalid)
            }
        }
    }
    /// Explicit trusted non-execution decision for an authenticated, currently
    /// policy-authorized intent. Verification failures remain unverified failures.
    /// Atomically create absent REJECTED state and nonce with its first signature;
    /// never overwrite an existing reservation or execution with rejection.
    pub fn reject(&self, raw: &[u8], signer: &mut dyn ResultSigner) -> Result<DispatchReceipt> {
        let mut s = self.state.lock().map_err(|_| Invalid)?;
        ensure(!s.retired && s.store.is_some())?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reject(&mut s, raw, signer)))
        {
            Ok(r) => r,
            Err(_) => {
                s.retired = true;
                Err(Invalid)
            }
        }
    }
}
fn finish(
    s: &mut State,
    token: &Completion,
    output: &[u8],
    signer: &mut dyn ResultSigner,
) -> Result<()> {
    let (_, out) = object(output)?;
    let mut e = entry(s, &token.canonical)?;
    if e.state == "COMPLETED" {
        let raw = hex::decode(&e.result_hex).map_err(|_| Invalid)?;
        let v = check(&raw, &token.canonical, &e.state, signer)?;
        return ensure(v.output() == out);
    }
    ensure(e.state == "EXECUTING" && e.result_hex.is_empty())?;
    let raw = sign(&token.canonical, "completed", &out, signer)?;
    e.state = "COMPLETED".into();
    e.result_hex = hex::encode(&raw);
    if !matches!(s.store.as_mut().ok_or(Invalid)?.commit(e), Ok(true)) {
        s.retired = true;
        return Err(Invalid);
    }
    check(&raw, &token.canonical, "COMPLETED", signer)?;
    Ok(())
}
fn reply(s: &mut State, intent: &[u8], signer: &mut dyn ResultSigner) -> Result<Vec<u8>> {
    let mut e = entry(s, intent)?;
    let raw = if !e.result_hex.is_empty() {
        hex::decode(&e.result_hex).map_err(|_| Invalid)?
    } else {
        let status = match e.state.as_str() {
            "RESERVED" | "EXECUTING" => "pending",
            "UNKNOWN" => "unknown",
            _ => return Err(Invalid),
        };
        let raw = sign(intent, status, b"{}", signer)?;
        if e.state == "UNKNOWN" {
            e.result_hex = hex::encode(&raw);
            if !matches!(s.store.as_mut().ok_or(Invalid)?.commit(e.clone()), Ok(true)) {
                s.retired = true;
                return Err(Invalid);
            }
        }
        raw
    };
    check(&raw, intent, &e.state, signer)?;
    Ok(raw)
}
fn reject(s: &mut State, raw: &[u8], signer: &mut dyn ResultSigner) -> Result<DispatchReceipt> {
    let v = verify_intent(raw, &s.recipient, s.authority.as_mut(), s.policy.as_mut())?;
    let mut e = super::super::ledger::reservation_entry(&v)?;
    let old = s
        .store
        .as_ref()
        .ok_or(Invalid)?
        .lookup(&e.issuer, &e.call_id)
        .map_err(|_| Invalid)?;
    let created = old.is_none();
    if let Some(old) = old {
        ensure(old.state == "REJECTED" && matches(&old, &v.canonical)?)?
    } else {
        let raw = sign(&v.canonical, "rejected", b"{}", signer)?;
        e.state = "REJECTED".into();
        e.result_hex = hex::encode(raw);
        ensure(
            s.store
                .as_mut()
                .ok_or(Invalid)?
                .commit(e)
                .map_err(|_| Invalid)?,
        )?;
    }
    Ok(DispatchReceipt {
        created,
        committed: false,
        state: "REJECTED".into(),
        digest: v.digest(),
        reply: ReplyPermit {
            owner: s.owner.clone(),
            canonical: v.canonical,
            used: false,
        },
    })
}
