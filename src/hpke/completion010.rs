//! Authenticated metadata-free plain handshake carriage. HTTP binding, durable
//! transport replay storage and application dispatch are separate integrations.
use super::derivation010::{self as d, Derivation010, Initiator010};
use super::{respond_fresh_010, start_initiator_010, verify_ack_tag_010};
use crate::session::RecordSession010;
use crate::{
    error::{Error, Result},
    registry010::{Clock, Gate, Key, Pinned, Stamp},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{
    de::{MapAccess, Visitor},
    Deserializer, Serialize,
};
use serde_json::{json, value::RawValue, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;
mod record010;
fn bad() -> Error {
    Error::ValidationError("authentication failed".into())
}
type Raw = BTreeMap<String, Box<RawValue>>;
type Fields = BTreeMap<String, String>;
fn canonical(v: &impl Serialize) -> Vec<u8> {
    crate::jcs::canonicalize(&serde_json::to_vec(v).expect("serializable closed object"))
        .expect("closed ASCII object")
}
fn raw(raw: &[u8], names: &[&str]) -> Result<Raw> {
    if raw.len() > 32768 {
        return Err(bad());
    }
    struct Object;
    impl<'de> Visitor<'de> for Object {
        type Value = Raw;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("closed object")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> std::result::Result<Raw, M::Error> {
            let mut m = Raw::new();
            while let Some((k, v)) = access.next_entry::<String, Box<RawValue>>()? {
                if v.get() == "null" || m.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom("invalid member"));
                }
            }
            Ok(m)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let m = decoder.deserialize_map(Object).map_err(|_| bad())?;
    decoder.end().map_err(|_| bad())?;
    if m.len() != names.len() || !names.iter().all(|n| m.contains_key(*n)) {
        return Err(bad());
    }
    Ok(m)
}
fn string(m: &Raw, k: &str) -> String {
    m.get(k)
        .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
        .filter(|s| s.is_ascii())
        .unwrap_or_default()
}
fn number(m: &Raw, k: &str) -> Result<i64> {
    m.get(k).ok_or_else(bad)?.get().parse().map_err(|_| bad())
}
const WIRE: [&str; 12] = [
    "version",
    "id",
    "did",
    "recipient",
    "kid",
    "created",
    "expires",
    "nonce",
    "encoding",
    "context_id",
    "role",
    "signature",
];
fn wire(raw_bytes: &[u8], response: bool, now: i64) -> Result<(Raw, Vec<u8>)> {
    let mut names = WIRE.to_vec();
    let (field, role) = if response {
        names.extend(["message_id", "request_hash", "success"]);
        ("data", "responder")
    } else {
        ("payload", "initiator")
    };
    names.push(field);
    let m = raw(raw_bytes, &names)?;
    if string(&m, "version") != "0.10.0"
        || string(&m, "encoding") != "plain"
        || string(&m, "role") != role
        || !d::uuid(&string(&m, "id"))
        || !d::uuid(&string(&m, "context_id"))
        || !d::did(&string(&m, "did"))
        || !d::did(&string(&m, "recipient"))
        || !d::key(&string(&m, "kid"), &string(&m, "did"))
    {
        return Err(bad());
    }
    let created = number(&m, "created")?;
    let expires = number(&m, "expires")?;
    if created < 0
        || expires > 9007199254740991
        || expires <= created
        || expires - created > 300
        || created > now + 30
        || now >= expires
    {
        return Err(bad());
    }
    d::binary(&string(&m, "nonce"), 16)?;
    d::binary(&string(&m, "signature"), 64)?;
    if response {
        if m["success"].get() != "true" || !d::uuid(&string(&m, "message_id")) {
            return Err(bad());
        }
        d::binary(&string(&m, "request_hash"), 32)?;
    }
    let encoded = string(&m, field);
    let body = B64.decode(&encoded).map_err(|_| bad())?;
    if body.len() > 16384 || B64.encode(&body) != encoded {
        return Err(bad());
    }
    Ok((m, body))
}
fn verify(data: &[u8], signature: &[u8], key: &Key) -> Result<()> {
    if key.alg != "ed25519" {
        return Err(bad());
    }
    let bytes: [u8; 32] = hex::decode(&key.material)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| bad())?
        .verify_strict(data, &Signature::from_slice(signature).map_err(|_| bad())?)
        .map_err(|_| bad())
}
fn verify_wire(m: &Raw, response: bool, key: &Key) -> Result<()> {
    let sig = d::binary(&string(m, "signature"), 64)?;
    let unsigned: BTreeMap<_, _> = m
        .iter()
        .filter(|(k, _)| k.as_str() != "signature")
        .collect();
    let mut data = if response {
        b"sage-wire-response|0.10.0\n".to_vec()
    } else {
        b"sage-wire-request|0.10.0\n".to_vec()
    };
    data.extend(canonical(&unsigned));
    verify(&data, &sig, key)
}
fn signed(mut m: Value, domain: &[u8], key: &SigningKey) -> Vec<u8> {
    let mut data = domain.to_vec();
    data.extend(canonical(&m));
    m["signature"] = json!(B64.encode(key.sign(&data).to_bytes()));
    canonical(&m)
}
fn envelope(
    did: &str,
    recipient: &str,
    kid: &str,
    ctx: &str,
    response: bool,
    payload: &[u8],
    times: (i64, i64),
) -> Result<Value> {
    let mut nonce = [0; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| bad())?;
    let mut v = json!({"version":"0.10.0","id":uuid::Uuid::new_v4().to_string(),"did":did,"recipient":recipient,"kid":kid,"context_id":ctx,"role":if response{"responder"}else{"initiator"},"created":times.0,"expires":times.1,"nonce":B64.encode(nonce),"encoding":"plain"});
    v[if response { "data" } else { "payload" }] = json!(B64.encode(payload));
    Ok(v)
}
/// Fully authenticated plain-envelope replay reservation, scoped by both DIDs.
pub struct Replay010 {
    /// Sender DID.
    pub sender: String,
    /// Recipient DID.
    pub recipient: String,
    /// Message identifier.
    pub id: String,
    /// Canonical nonce.
    pub nonce: String,
    /// Absolute expiry; retention extends through expires+30.
    pub expires: i64,
    /// Nonempty initiation context must never be reused by this sender.
    pub context: String,
}
/// Required trusted deployment storage: atomically reject reused IDs/nonces,
/// reject reused nonempty contexts per sender, persist before success, fail closed on capacity/clock/storage faults, and
/// recover durable state or quarantine for 360 seconds after restart/lost state.
pub trait ReplayStore010 {
    /// Commit authenticated replay denial state. Never a peer-provided boolean.
    fn reserve(&mut self, entry: Replay010) -> Result<()>;
    /// Atomically reserve ID and nonce for a verified session request. Stage all
    /// fallible/blocking durable work before calling validate exactly once at
    /// final publication. A failed validate or storage operation publishes neither
    /// entry. Success must durably publish both, with no fallible work after the
    /// gate. Never reenter the endpoint. Exclusive session access spans this call
    /// and sequence/confirmation publication; restart discards session state.
    /// Implementations without this transaction contract reject record receive.
    fn reserve_record(
        &mut self,
        _entry: Replay010,
        _validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        Err(bad())
    }
}
fn reservation(m: &Raw) -> Result<Replay010> {
    Ok(Replay010 {
        sender: string(m, "did"),
        recipient: string(m, "recipient"),
        id: string(m, "id"),
        nonce: string(m, "nonce"),
        expires: number(m, "expires")?,
        context: if string(m, "role") == "initiator" {
            string(m, "context_id")
        } else {
            String::new()
        },
    })
}
/// Owns local credentials and serializes operations through exclusive borrowing.
/// Use the same durable replay store across transports and process restarts.
pub struct CompletionEndpoint010 {
    registry: Gate,
    clock: Box<dyn Clock>,
    replay: Box<dyn ReplayStore010>,
    did: String,
    kid: String,
    signing: Option<SigningKey>,
    kem: Zeroizing<Vec<u8>>,
    last: Option<Stamp>,
    identity: uuid::Uuid,
}
impl CompletionEndpoint010 {
    /// Copies the local Ed25519 seed and optional X25519 key. Current registered
    /// public-key equality is checked before use; no verified flags are accepted.
    pub fn new(
        did: &str,
        kid: &str,
        seed: &[u8],
        kem: &[u8],
        registry: Gate,
        clock: Box<dyn Clock>,
        replay: Box<dyn ReplayStore010>,
    ) -> Result<Self> {
        if !d::did(did) || !d::key(kid, did) || (!kem.is_empty() && kem.len() != 32) {
            return Err(bad());
        }
        let seed: &[u8; 32] = seed.try_into().map_err(|_| bad())?;
        Ok(Self {
            registry,
            clock,
            replay,
            did: did.into(),
            kid: kid.into(),
            signing: Some(SigningKey::from_bytes(seed)),
            kem: Zeroizing::new(kem.to_vec()),
            last: None,
            identity: uuid::Uuid::new_v4(),
        })
    }
    fn sample(&mut self) -> Result<Stamp> {
        if self.signing.is_none() {
            return Err(bad());
        }
        let t = self.clock.now().map_err(|_| bad())?;
        if t.mono_ms < 0
            || t.unix < 0
            || t.unix > 9007199254740691
            || self
                .last
                .is_some_and(|p| t.mono_ms < p.mono_ms || t.unix < p.unix)
        {
            return Err(bad());
        }
        self.last = Some(t);
        Ok(t)
    }
    fn current(&mut self, a: &Pinned, b: &Pinned) -> Result<()> {
        self.registry.check_pinned(a).map_err(|_| bad())?;
        self.registry.check_pinned(b).map_err(|_| bad())
    }
    fn selected(&mut self, m: &Fields) -> Result<(Pinned, Pinned)> {
        let a = self
            .registry
            .select(&m["initDid"], &m["initKid"], false)
            .map_err(|_| bad())?;
        let b = self
            .registry
            .select(&m["respDid"], &m["respKid"], true)
            .map_err(|_| bad())?;
        if b.kem()
            .is_none_or(|k| format!("{}#{}", b.did(), k.name) != m["kemKid"])
        {
            return Err(bad());
        }
        let local = if self.did == m["respDid"] { &b } else { &a };
        if local.did() != self.did
            || format!("{}#{}", local.did(), local.signing().name) != self.kid
            || hex::decode(&local.signing().material).map_err(|_| bad())?
                != self
                    .signing
                    .as_ref()
                    .ok_or_else(bad)?
                    .verifying_key()
                    .to_bytes()
        {
            return Err(bad());
        }
        Ok((a, b))
    }
    /// Fresh context, nonce and independent ephemeral keys; returns the exact signed
    /// request retained for completion binding. Return is the local emission boundary.
    pub fn start(
        &mut self,
        recipient: &str,
        resp_kid: &str,
        ttl: i64,
    ) -> Result<(PendingCompletion010, Vec<u8>)> {
        let start = self.sample()?;
        if !(1..=300).contains(&ttl) {
            return Err(bad());
        }
        let a = self
            .registry
            .select(&self.did, &self.kid, false)
            .map_err(|_| bad())?;
        let b = self
            .registry
            .select(recipient, resp_kid, true)
            .map_err(|_| bad())?;
        let kem = b.kem().ok_or_else(bad)?;
        if hex::decode(&a.signing().material).map_err(|_| bad())?
            != self
                .signing
                .as_ref()
                .ok_or_else(bad)?
                .verifying_key()
                .to_bytes()
        {
            return Err(bad());
        }
        let ctx = uuid::Uuid::new_v4().to_string();
        let mut nonce = [0; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| bad())?;
        let binding = json!({"v":"0.10.0","ctx":ctx,"initDid":self.did,"respDid":recipient,"initKid":self.kid,"respKid":resp_kid,"kemKid":format!("{}#{}",recipient,kem.name),"suite":"hpke-base+x25519+hkdf-sha256","combiner":"e2e-x25519-hkdf-v1","nonce":B64.encode(nonce)});
        let (state, initiation) = start_initiator_010(
            &canonical(&binding),
            &hex::decode(&kem.material).map_err(|_| bad())?,
        )?;
        let mut w = envelope(
            &self.did,
            recipient,
            &self.kid,
            &ctx,
            false,
            &initiation,
            (start.unix, start.unix + ttl),
        )?;
        w["nonce"] = binding["nonce"].clone();
        let request = signed(
            w,
            b"sage-wire-request|0.10.0\n",
            self.signing.as_ref().ok_or_else(bad)?,
        );
        let end = self.sample()?;
        if end.mono_ms - start.mono_ms > 5000
            || !pinned_live(end.unix, &a, &b)
            || end.unix >= start.unix + ttl
        {
            return Err(bad());
        }
        let init = d::initiation(&initiation)?.0;
        let pending = PendingCompletion010 {
            endpoint: self.identity,
            state: Some(state),
            request: request.clone(),
            init,
            a,
            b,
            emitted: end,
            expires: start.unix + ttl,
        };
        Ok((pending, request))
    }
    /// Verify the signed request and exact current keys; emit independently signed
    /// completion and response. The result cannot send until its first record confirms it.
    pub fn respond(
        &mut self,
        request: &[u8],
        ttl: i64,
    ) -> Result<(AuthenticatedCompletion010, Vec<u8>)> {
        let start = self.sample()?;
        if !(1..=300).contains(&ttl) || self.kem.len() != 32 {
            return Err(bad());
        }
        let (w, body) = wire(request, false, start.unix)?;
        let (m, _) = d::initiation(&body)?;
        if body != canonical(&m)
            || m["respDid"] != self.did
            || m["respKid"] != self.kid
            || string(&w, "did") != m["initDid"]
            || string(&w, "kid") != m["initKid"]
            || string(&w, "recipient") != m["respDid"]
            || string(&w, "context_id") != m["ctx"]
            || string(&w, "nonce") != m["nonce"]
        {
            return Err(bad());
        }
        let (a, b) = self.selected(&m)?;
        verify_wire(&w, false, a.signing())?;
        let kem: [u8; 32] = self.kem.as_slice().try_into().map_err(|_| bad())?;
        if x25519(kem, X25519_BASEPOINT_BYTES).as_slice()
            != hex::decode(&b.kem().ok_or_else(bad)?.material).map_err(|_| bad())?
        {
            return Err(bad());
        }
        let result = respond_fresh_010(&body, &self.kem)?;
        let t: Value = serde_json::from_slice(&result.transcript).map_err(|_| bad())?;
        let mut c = json!({"v":"0.10.0","task":"hpke/complete@0.10.0","transcript":t,"ackTagB64":B64.encode(result.ack_tag)});
        let mut data = b"sage-hpke-complete|0.10.0\n".to_vec();
        data.extend(canonical(&c));
        c["sigB64"] = json!(B64.encode(
            self.signing
                .as_ref()
                .ok_or_else(bad)?
                .sign(&data)
                .to_bytes()
        ));
        let expires = number(&w, "expires")?.min(start.unix + ttl);
        let mut response = envelope(
            &self.did,
            &m["initDid"],
            &self.kid,
            &m["ctx"],
            true,
            &canonical(&c),
            (start.unix, expires),
        )?;
        if response["id"] == string(&w, "id") || response["nonce"] == string(&w, "nonce") {
            return Err(bad());
        }
        response["message_id"] = json!(string(&w, "id"));
        response["request_hash"] = json!(B64.encode(Sha256::digest(canonical(&w))));
        response["success"] = json!(true);
        let bytes = signed(
            response,
            b"sage-wire-response|0.10.0\n",
            self.signing.as_ref().ok_or_else(bad)?,
        );
        let end = self.sample()?;
        if end.mono_ms - start.mono_ms > 5000
            || !pinned_live(end.unix, &a, &b)
            || end.unix >= expires
        {
            return Err(bad());
        }
        self.replay.reserve(reservation(&w)?)?;
        let end = self.sample()?;
        if end.mono_ms - start.mono_ms > 5000
            || !pinned_live(end.unix, &a, &b)
            || end.unix >= expires
        {
            return Err(bad());
        }
        Ok((
            owned(self.identity, result, a, b, end, expires, false)?,
            bytes,
        ))
    }
    /// Retire local private copies; owners must also close returned pending/results.
    pub fn close(&mut self) {
        self.signing = None;
        self.kem = Zeroizing::new(Vec::new());
    }
}
fn pinned_live(now: i64, a: &Pinned, b: &Pinned) -> bool {
    std::iter::once(a.signing())
        .chain(std::iter::once(b.signing()))
        .chain(b.kem())
        .all(|k| k.expires.is_none_or(|x| now < x))
}
fn live(now: Stamp, start: Stamp, expires: i64) -> bool {
    now.mono_ms >= start.mono_ms
        && now.unix >= start.unix
        && now.mono_ms - start.mono_ms < 300000
        && now.unix < expires
}
/// Owns one emitted initiation and private derivation state; no Clone/restore API.
pub struct PendingCompletion010 {
    endpoint: uuid::Uuid,
    state: Option<Initiator010>,
    request: Vec<u8>,
    init: Fields,
    a: Pinned,
    b: Pinned,
    emitted: Stamp,
    expires: i64,
}
impl PendingCompletion010 {
    /// Whether one-shot pending material remains available.
    pub fn state(&self) -> &'static str {
        if self.state.is_some() {
            "INIT_SENT"
        } else {
            "CLOSED"
        }
    }
    /// Destroy pending material on abandonment. Invalid completion also consumes it.
    pub fn close(&mut self) {
        self.state = None;
    }
    /// Actual outer and inner signatures, exact request/echo binding, current keys,
    /// constant-time ACK and both trusted clocks must succeed before result creation.
    pub fn complete(
        &mut self,
        e: &mut CompletionEndpoint010,
        response: &[u8],
    ) -> Result<AuthenticatedCompletion010> {
        let state = self.state.take().ok_or_else(bad)?;
        if e.identity != self.endpoint {
            return Err(bad());
        }
        let start = e.sample()?;
        if !live(start, self.emitted, self.expires) {
            return Err(bad());
        }
        let (w, body) = wire(response, true, start.unix)?;
        let (request, _) = wire(&self.request, false, self.emitted.unix)?;
        if string(&w, "message_id") != string(&request, "id")
            || string(&w, "request_hash") != B64.encode(Sha256::digest(canonical(&request)))
            || string(&w, "did") != self.init["respDid"]
            || string(&w, "recipient") != self.init["initDid"]
            || string(&w, "kid") != self.init["respKid"]
            || string(&w, "context_id") != self.init["ctx"]
            || string(&w, "id") == string(&request, "id")
            || string(&w, "nonce") == string(&request, "nonce")
        {
            return Err(bad());
        }
        let mut c = raw(&body, &["v", "task", "transcript", "ackTagB64", "sigB64"])?;
        if string(&c, "v") != "0.10.0" || string(&c, "task") != "hpke/complete@0.10.0" {
            return Err(bad());
        }
        let transcript = d::fields(
            c["transcript"].get().as_bytes(),
            &["task", "enc", "ephC", "ephS", "kid"],
        )?;
        if self.init.iter().any(|(k, v)| transcript.get(k) != Some(v)) {
            return Err(bad());
        }
        if body != canonical(&c) {
            return Err(bad());
        }
        let sig = d::binary(&string(&c, "sigB64"), 64)?;
        let ack = d::binary(&string(&c, "ackTagB64"), 32)?;
        c.remove("sigB64");
        e.current(&self.a, &self.b)?;
        verify_wire(&w, true, self.b.signing())?;
        let mut data = b"sage-hpke-complete|0.10.0\n".to_vec();
        data.extend(canonical(&c));
        verify(&data, &sig, self.b.signing())?;
        let result = state.derive(c["transcript"].get().as_bytes())?;
        if !verify_ack_tag_010(&result.seed, &result.th, &ack) {
            return Err(bad());
        }
        let expires = number(&w, "expires")?;
        let end = e.sample()?;
        if end.mono_ms - start.mono_ms > 5000
            || !pinned_live(end.unix, &self.a, &self.b)
            || !live(end, self.emitted, self.expires)
            || end.unix >= expires
        {
            return Err(bad());
        }
        e.replay.reserve(reservation(&w)?)?;
        let end = e.sample()?;
        if end.mono_ms - start.mono_ms > 5000
            || !pinned_live(end.unix, &self.a, &self.b)
            || !live(end, self.emitted, self.expires)
            || end.unix >= expires
        {
            return Err(bad());
        }
        owned(
            e.identity,
            result,
            self.a.clone(),
            self.b.clone(),
            end,
            0,
            true,
        )
    }
}
/// Private seed plus immutable public authenticated tuple. Not a dispatch API.
/// Responder state stays provisional until open_request atomically confirms it.
pub struct AuthenticatedCompletion010 {
    endpoint: uuid::Uuid,
    a: Pinned,
    b: Pinned,
    tuple: Fields,
    created: Stamp,
    expires: i64,
    initiator: bool,
    closed: bool,
    confirmed: bool,
    active: Stamp,
    records: Option<RecordSession010>,
}
fn owned(
    endpoint: uuid::Uuid,
    result: Derivation010,
    a: Pinned,
    b: Pinned,
    created: Stamp,
    expires: i64,
    initiator: bool,
) -> Result<AuthenticatedCompletion010> {
    let t: Fields = serde_json::from_slice(&result.transcript).map_err(|_| bad())?;
    let mut tuple = Fields::new();
    for k in [
        "v", "ctx", "initDid", "respDid", "initKid", "respKid", "kemKid", "suite", "combiner",
        "kid",
    ] {
        tuple.insert(k.into(), t[k].clone());
    }
    tuple.insert("th".into(), B64.encode(result.th));
    tuple.insert("sid".into(), result.sid);
    let records = RecordSession010::new(&result.seed, &result.th, initiator)?;
    Ok(AuthenticatedCompletion010 {
        endpoint,
        a,
        b,
        tuple,
        created,
        expires,
        initiator,
        closed: false,
        confirmed: false,
        active: created,
        records: Some(records),
    })
}
impl AuthenticatedCompletion010 {
    /// Public binding copy, never a reusable grant or a secret export.
    pub fn tuple(&self) -> Fields {
        self.tuple.clone()
    }
    /// Local state only; Check must be called for a current operation.
    pub fn state(&self) -> &'static str {
        if self.closed {
            "CLOSED"
        } else if self.initiator || self.confirmed {
            "ESTABLISHED"
        } else {
            "RESPONSE_SENT"
        }
    }
    /// Erase the owned seed and retire the result.
    pub fn close(&mut self) {
        if let Some(r) = self.records.as_mut() {
            r.close();
        }
        self.closed = true;
    }
    /// Revalidate both signing keys and KEM, closing on failure. Does not confirm
    /// responder state or authorize record dispatch. No traffic extends idle time here.
    pub fn check(&mut self, e: &mut CompletionEndpoint010) -> Result<()> {
        let result = (|| {
            if self.closed || self.endpoint != e.identity {
                return Err(bad());
            }
            let start = e.sample()?;
            self.record_live(start)?;
            e.current(&self.a, &self.b)?;
            let end = e.sample()?;
            if end.mono_ms - start.mono_ms > 5000
                || !pinned_live(end.unix, &self.a, &self.b)
                || self.record_live(end).is_err()
            {
                return Err(bad());
            }
            Ok(())
        })();
        if result.is_err() {
            self.close()
        }
        result
    }
}

#[cfg(test)]
mod tests;
