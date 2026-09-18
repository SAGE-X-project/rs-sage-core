//! Bounded Execution Guard commitments and Ed25519 envelope verification.
//! Trusted host integrations supply clock, active keys, policy and outstanding
//! invocations. Verification is a snapshot, not dispatch or isolation authority.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Maximum bytes in a Guard JSON input.
const MAX_BYTES: usize = 1 << 20;
/// Uniform authentication or input validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("guard authentication failed")]
pub struct Invalid;
/// Guard operation result.
pub type Result<T> = std::result::Result<T, Invalid>;
fn ensure(b: bool) -> Result<()> {
    if b {
        Ok(())
    } else {
        Err(Invalid)
    }
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn closed(v: &Value, fields: &str) -> bool {
    v.as_object().is_some_and(|m| {
        m.len() == fields.split_whitespace().count()
            && fields.split_whitespace().all(|k| m.contains_key(k))
    })
}
fn ascii(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.is_ascii()
}
fn chars(s: &str, max: usize, dot: bool) -> bool {
    ascii(s, max)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (dot && b == b'.'))
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || matches!(b, b'a'..=b'f'),
        })
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn did(s: &str) -> bool {
    let p: Vec<_> = s.split(':').collect();
    if s.len() > 256
        || p.len() < 5
        || p[0] != "did"
        || p[1] != "sage"
        || !chars(p[p.len() - 1], 64, true)
        || matches!(p[p.len() - 1], "." | "..")
    {
        return false;
    }
    match p[2] {
        "eip155" => {
            p.len() == 6
                && ascii(p[3], 32)
                && !p[3].starts_with('0')
                && p[3].bytes().all(|b| b.is_ascii_digit())
                && p[4].len() == 42
                && p[4].starts_with("0x")
                && p[4][2..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        }
        "web" => {
            p.len() == 5
                && ascii(p[3], 64)
                && p[3].split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
        }
        _ => false,
    }
}
/// Validate bounds before entering the recursive JCS parser, then reject
/// duplicate keys, invalid Unicode, nonfinite values and signed numeric zero.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>> {
    canonicalize_limit(raw, 4096)
}
fn canonicalize_limit(raw: &[u8], limit: usize) -> Result<Vec<u8>> {
    ensure(raw.len() <= MAX_BYTES)?;
    let s = std::str::from_utf8(raw).map_err(|_| Invalid)?;
    let (mut string, mut escape, mut depth) = (false, false, 0usize);
    for b in raw {
        if string {
            if escape {
                escape = false;
            } else if *b == b'\\' {
                escape = true;
            } else if *b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'[' | b'{' => {
                    depth += 1;
                    ensure(depth <= 32)?
                }
                b']' | b'}' => depth = depth.checked_sub(1).ok_or(Invalid)?,
                _ => {}
            }
        }
    }
    let v = crate::jcs::parse(s).map_err(|_| Invalid)?;
    fn walk(v: &crate::jcs::Value, m: &mut usize, limit: usize) -> Result<()> {
        use crate::jcs::Value as J;
        match v {
            J::Object(a) => {
                *m += a.len();
                ensure(*m <= limit)?;
                for (_, v) in a {
                    walk(v, m, limit)?
                }
            }
            J::Array(a) => {
                for v in a {
                    walk(v, m, limit)?
                }
            }
            J::Number(s) => {
                let n = s.parse::<f64>().map_err(|_| Invalid)?;
                ensure(n.is_finite() && !(n == 0.0 && n.is_sign_negative()))?
            }
            _ => {}
        };
        Ok(())
    }
    walk(&v, &mut 0, limit)?;
    let b = crate::jcs::to_string(&v).map_err(|_| Invalid)?.into_bytes();
    ensure(b.len() <= MAX_BYTES)?;
    Ok(b)
}

fn exact_integer(s: &str) -> Result<i64> {
    ensure(!s.starts_with('-'))?;
    let parts: Vec<_> = s.split(['e', 'E']).collect();
    let mantissa = parts[0];
    let frac = mantissa.find('.').map_or(0, |i| mantissa.len() - i - 1);
    let digits = mantissa.replace('.', "");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    let exp = if parts.len() == 2 {
        parts[1].parse::<i64>().map_err(|_| Invalid)?
    } else {
        0
    };
    ensure((-1048576..=1048576).contains(&exp))?;
    let trimmed = digits.trim_end_matches('0');
    let scale = exp - frac as i64 + (digits.len() - trimmed.len()) as i64;
    ensure((0..=16).contains(&scale) && trimmed.len() as i64 + scale <= 16)?;
    let n = format!("{}{}", trimmed, "0".repeat(scale as usize))
        .parse::<i64>()
        .map_err(|_| Invalid)?;
    ensure(n <= 9007199254740991)?;
    Ok(n)
}
// Check protocol integers before binary64 canonicalization can round fractions.
fn validate_wire_times(raw: &[u8]) -> Result<()> {
    use crate::jcs::Value as J;
    let v =
        crate::jcs::parse(std::str::from_utf8(raw).map_err(|_| Invalid)?).map_err(|_| Invalid)?;
    if let J::Object(root) = v {
        for (kind, value) in root {
            if kind != "intent" && kind != "result" {
                continue;
            }
            if let J::Object(fields) = value {
                for (key, value) in fields {
                    if key == "created" || key == "expires" {
                        if let J::Number(n) = value {
                            exact_integer(&n)?;
                        } else {
                            return Err(Invalid);
                        }
                    }
                }
            }
        }
    };
    Ok(())
}

fn object(raw: &[u8]) -> Result<(Value, Vec<u8>)> {
    object_limit(raw, 4096)
}
fn object_limit(raw: &[u8], limit: usize) -> Result<(Value, Vec<u8>)> {
    let b = canonicalize_limit(raw, limit)?;
    validate_wire_times(raw)?;
    let v: Value = serde_json::from_slice(&b).map_err(|_| Invalid)?;
    ensure(v.is_object())?;
    Ok((v, b))
}
fn encode(v: &Value) -> Result<Vec<u8>> {
    canonicalize(&serde_json::to_vec(v).map_err(|_| Invalid)?)
}
/// Commit exact ordered UTF-8 bytes without normalization.
pub fn original_commitment(items: &[Vec<u8>]) -> Result<String> {
    ensure(items.len() <= 1024)?;
    let mut total = 0usize;
    for b in items {
        total = total.checked_add(b.len()).ok_or(Invalid)?;
        ensure(total <= MAX_BYTES && std::str::from_utf8(b).is_ok())?
    }
    let mut h = Sha256::new();
    h.update(b"sage-original|0.10.0\0");
    h.update((items.len() as u32).to_be_bytes());
    for b in items {
        h.update((b.len() as u64).to_be_bytes());
        h.update(b)
    }
    Ok(hex::encode(h.finalize()))
}
fn manifest(v: &Value, nonempty: bool) -> Result<()> {
    ensure(closed(v, "version files") && text(v, "version") == "0.10.0")?;
    let a = v["files"].as_array().ok_or(Invalid)?;
    ensure(a.len() <= 4096 && (!nonempty || !a.is_empty()))?;
    let mut last = "";
    for f in a {
        ensure(closed(f, "path sha256"))?;
        let p = text(f, "path");
        ensure(
            !p.is_empty()
                && p.len() <= 1024
                && p > last
                && !p.contains(['\\', '\0'])
                && digest(text(f, "sha256"))
                && p.split('/').all(|s| !s.is_empty() && s != "." && s != ".."),
        )?;
        last = p
    }
    Ok(())
}
/// Descriptor validation does not prove physical file or loaded instance identity.
pub fn manifest_commitment(raw: &[u8]) -> Result<String> {
    let (v, b) = object_limit(raw, 8194)?;
    manifest(&v, false)?;
    Ok(hash(&b))
}
/// Verify the exact artifact set; hosts enforce regular files, no symlinks and
/// immutable loading separately.
/// Exact path and bytes from the host artifact loader.
pub struct Artifact {
    /// Relative manifest path.
    pub path: String,
    /// Exact unnormalized bytes.
    pub bytes: Vec<u8>,
}
/// Validate the exact artifact set and return the manifest commitment.
pub fn verify_manifest(raw: &[u8], items: &[Artifact]) -> Result<String> {
    let mut artifacts = BTreeMap::new();
    for item in items {
        ensure(
            artifacts
                .insert(item.path.clone(), item.bytes.as_slice())
                .is_none(),
        )?;
    }
    let (v, b) = object_limit(raw, 8194)?;
    manifest(&v, false)?;
    let a = v["files"].as_array().ok_or(Invalid)?;
    ensure(a.len() == artifacts.len())?;
    for f in a {
        ensure(hash(artifacts.get(text(f, "path")).ok_or(Invalid)?) == text(f, "sha256"))?
    }
    Ok(hash(&b))
}
/// A policy commitment is not an authorization grant.
pub fn policy_commitment(raw: &[u8]) -> Result<String> {
    let (v, b) = object(raw)?;
    ensure(
        closed(&v, "version issuer epoch engine artifacts")
            && text(&v, "version") == "0.10.0"
            && did(text(&v, "issuer"))
            && uuid(text(&v, "epoch"))
            && ascii(text(&v, "engine"), 128),
    )?;
    manifest(&v["artifacts"], true)?;
    Ok(hash(&[b"sage-policy|0.10.0\0".as_slice(), &b].concat()))
}

/// Trusted host dependency, never populated from a peer envelope. Implementors
/// fail on untrusted time and must freshly resolve the exact accepted, unrevoked,
/// unexpired Ed25519 key with bounded resolution deadlines.
pub trait Authority {
    /// Read trusted protocol seconds.
    fn now(&mut self) -> Result<i64>;
    /// Resolve the named active Ed25519 signing key.
    fn active_key(&mut self, issuer: &str, keyid: &str) -> Result<[u8; 32]>;
}
/// Protected, locally provisioned commitment inputs.
pub struct Bindings {
    /// Protected captured original commitment.
    pub original: String,
    /// Locally approved policy descriptor bytes.
    pub policy: Vec<u8>,
    /// Locally approved component descriptor bytes.
    pub manifest: Vec<u8>,
}
/// Trusted policy evaluator. Authorize must validate a closed tool schema and
/// all final arguments; missing decisions, timeouts and evaluator errors fail.
pub trait IntentPolicy {
    /// Return protected bindings for the authenticated issuer.
    fn bindings(&mut self, issuer: &str, _request_id: &str) -> Result<Bindings>;
    /// Authorize the exact tool and canonical final arguments.
    fn authorize(&mut self, issuer: &str, tool: &str, arguments: &[u8]) -> Result<()>;
}
/// Return exact previously authorized intent bytes only for an outstanding
/// transport invocation. Durable single terminal consumption is a host duty.
pub trait Outstanding {
    /// Read a previously accepted invocation from the protected store.
    fn intent(&mut self, request_id: &str, call_id: &str) -> Result<Vec<u8>>;
}
/// Owned authenticated envelope, including proof. No public constructor.
pub struct VerifiedIntent {
    canonical: Vec<u8>,
}
impl VerifiedIntent {
    /// Borrow the entire authenticated canonical envelope.
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    /// Hash the entire envelope, including proof.
    pub fn digest(&self) -> String {
        hash(&self.canonical)
    }
}
/// Authenticated result snapshot; does not consume a client call.
pub struct VerifiedResult {
    canonical: Vec<u8>,
    status: String,
    output: Vec<u8>,
}
impl VerifiedResult {
    /// Borrow the entire authenticated canonical envelope.
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    /// Read authenticated result status.
    pub fn status(&self) -> &str {
        &self.status
    }
    /// Borrow canonical authenticated output.
    pub fn output(&self) -> &[u8] {
        &self.output
    }
}
fn number(v: &Value, k: &str) -> Result<i64> {
    let n = v[k].as_f64().ok_or(Invalid)?;
    ensure((0.0..=9007199254740991.0).contains(&n) && n.trunc() == n)?;
    Ok(n as i64)
}
fn times(v: &Value, now: i64) -> Result<()> {
    let c = number(v, "created")?;
    let x = number(v, "expires")?;
    ensure(
        (0..=9007199254740991).contains(&now) && c <= now + 30 && now < x && x > c && x - c <= 300,
    )
}
fn b64(s: &str, n: usize) -> Result<Vec<u8>> {
    ensure(s.len() <= (n * 4).div_ceil(3))?;
    let b = B64.decode(s).map_err(|_| Invalid)?;
    ensure(b.len() == n && B64.encode(&b) == s)?;
    Ok(b)
}
fn common(v: &Value) -> Result<()> {
    let kid = text(v, "keyid");
    let (owner, name) = kid.split_once('#').ok_or(Invalid)?;
    ensure(
        text(v, "version") == "0.10.0"
            && uuid(text(v, "request_id"))
            && uuid(text(v, "call_id"))
            && did(text(v, "issuer"))
            && did(text(v, "recipient"))
            && kid.len() <= 289
            && owner == text(v, "issuer")
            && chars(name, 32, false)
            && text(v, "alg") == "ed25519",
    )?;
    number(v, "created")?;
    number(v, "expires")?;
    Ok(())
}
fn intent_envelope(raw: &[u8]) -> Result<(Value, Vec<u8>)> {
    let (e, b) = object(raw)?;
    ensure(closed(&e, "intent proof"))?;
    let v = &e["intent"];
    ensure(closed(v,"version profile request_id call_id parent_call_id original_digest issuer recipient tool arguments policy_digest manifest_digest created expires nonce keyid alg"))?;
    common(v)?;
    ensure(
        text(v, "profile") == "sage-execution-guard"
            && chars(text(v, "tool"), 128, true)
            && text(v, "tool") != "sage_secure_call"
            && (v["parent_call_id"].is_null() || uuid(text(v, "parent_call_id")))
            && v["arguments"].is_object(),
    )?;
    for k in ["original_digest", "policy_digest", "manifest_digest"] {
        ensure(digest(text(v, k)))?
    }
    b64(text(v, "nonce"), 16)?;
    b64(text(&e, "proof"), 64)?;
    let c = number(v, "created")?;
    let x = number(v, "expires")?;
    ensure(x > c && x - c <= 300)?;
    Ok((e, b))
}
// Dalek accepts ZIP-215 public encodings on construction; Guard requires
// canonical RFC 8032 y coordinates. Strict verification rejects low-order points.
fn canonical_edwards_y(mut bytes: [u8; 32]) -> bool {
    bytes[31] &= 0x7f;
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    bytes.iter().rev().cmp(modulus.iter().rev()).is_lt()
}
fn authenticate(a: &mut dyn Authority, e: &Value, kind: &str, domain: &str) -> Result<()> {
    let v = &e[kind];
    times(v, a.now()?)?;
    let bytes = a.active_key(text(v, "issuer"), text(v, "keyid"))?;
    ensure(canonical_edwards_y(bytes))?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Invalid)?;
    let sig = Signature::from_slice(&b64(text(e, "proof"), 64)?).map_err(|_| Invalid)?;
    let msg = [format!("{domain}|0.10.0\0").as_bytes(), &encode(v)?].concat();
    key.verify_strict(&msg, &sig).map_err(|_| Invalid)?;
    times(v, a.now()?)
}
/// Verify mandatory Ed25519, bindings and policy. Optional algorithms reject.
/// Revalidate current authority at a serialized dispatch boundary before effects.
pub fn verify_intent(
    raw: &[u8],
    recipient: &str,
    a: &mut dyn Authority,
    p: &mut dyn IntentPolicy,
) -> Result<VerifiedIntent> {
    let (e, b) = intent_envelope(raw)?;
    let v = &e["intent"];
    ensure(text(v, "recipient") == recipient)?;
    authenticate(a, &e, "intent", "sage-execution-intent")?;
    let bindings = p.bindings(text(v, "issuer"), text(v, "request_id"))?;
    ensure(
        bindings.original == text(v, "original_digest")
            && policy_commitment(&bindings.policy)? == text(v, "policy_digest")
            && manifest_commitment(&bindings.manifest)? == text(v, "manifest_digest"),
    )?;
    let (policy, _) = object(&bindings.policy)?;
    ensure(text(&policy, "issuer") == text(v, "issuer"))?;
    p.authorize(
        text(v, "issuer"),
        text(v, "tool"),
        &encode(&v["arguments"])?,
    )?;
    times(v, a.now()?)?;
    Ok(VerifiedIntent { canonical: b })
}
/// Fresh result verification for an already accepted invocation. Stored intent
/// expiry is deliberately not rechecked when receiving that invocation's reply.
pub fn verify_result(
    raw: &[u8],
    a: &mut dyn Authority,
    o: &mut dyn Outstanding,
) -> Result<VerifiedResult> {
    let (e, b) = object(raw)?;
    ensure(closed(&e, "result proof"))?;
    let v = &e["result"];
    ensure(closed(v,"version request_id call_id issuer recipient created expires keyid alg intent_digest status output"))?;
    common(v)?;
    ensure(digest(text(v, "intent_digest")))?;
    let status = text(v, "status");
    let out: &Map<String, Value> = v["output"].as_object().ok_or(Invalid)?;
    ensure(match status {
        "completed" => true,
        "pending" | "rejected" | "unknown" => out.is_empty(),
        _ => false,
    })?;
    authenticate(a, &e, "result", "sage-tool-result")?;
    let stored = o.intent(text(v, "request_id"), text(v, "call_id"))?;
    let (intent, canonical) = intent_envelope(&stored)?;
    let i = &intent["intent"];
    ensure(
        hash(&canonical) == text(v, "intent_digest")
            && text(i, "request_id") == text(v, "request_id")
            && text(i, "call_id") == text(v, "call_id")
            && text(i, "issuer") == text(v, "recipient")
            && text(i, "recipient") == text(v, "issuer"),
    )?;
    times(v, a.now()?)?;
    Ok(VerifiedResult {
        canonical: b,
        status: status.into(),
        output: encode(&v["output"])?,
    })
}

#[cfg(test)]
mod fixtures_test;
#[cfg(test)]
mod tests;

mod ledger;
pub use ledger::{GuardLedger, Reservation};

mod dispatch;
pub use dispatch::{Component, DispatchGate, DispatchReceipt, Invocation};
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod dispatch_tests;
