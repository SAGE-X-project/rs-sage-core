//! SAGE 0.10.0 record keys and counters. This is not an authenticated-envelope
//! or registry verifier. Create only from a fresh authenticated handshake and
//! close on external identity, confirmation, registry or policy failure.
use crate::error::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: u64 = 1000;
const MAX_AAD: usize = 4033;
const MAX_WIRE: usize = 8 * 1024 * 1024;

#[cfg(test)]
type TestClock = std::sync::Arc<dyn Fn() -> Instant + Send + Sync>;

/// Owns directional counters and replay state; not Clone or serializable.
/// Reconstructing with an old seed would reuse nonces and is forbidden.
pub struct RecordSession010 {
    seed: Zeroizing<[u8; 32]>,
    th: [u8; 32],
    initiator: bool,
    sid: String,
    next: u64,
    seen: [u64; 16],
    created: Instant,
    active: Instant,
    closed: bool,
    #[cfg(test)]
    clock: Option<TestClock>,
}
fn invalid(message: &str) -> Error {
    Error::InvalidInput(message.into())
}
impl RecordSession010 {
    /// Accepts the 32-byte seed and transcript hash from a fresh authenticated handshake.
    pub fn new(seed: &[u8], th: &[u8], initiator: bool) -> Result<Self> {
        Self::new_sampled(seed, th, initiator, Instant::now)
    }
    fn new_sampled(
        seed: &[u8],
        th: &[u8],
        initiator: bool,
        sample: impl FnOnce() -> Instant,
    ) -> Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| invalid("seed must be 32 bytes"))?;
        let th: [u8; 32] = th
            .try_into()
            .map_err(|_| invalid("transcript must be 32 bytes"))?;
        let mut hash = Sha256::new();
        hash.update(b"sage-session|0.10.0");
        hash.update(th);
        let sid = URL_SAFE_NO_PAD.encode(&hash.finalize()[..16]);
        let now = sample();
        Ok(Self {
            seed: Zeroizing::new(seed),
            th,
            initiator,
            sid,
            next: 0,
            seen: [0; 16],
            created: now,
            active: now,
            closed: false,
            #[cfg(test)]
            clock: None,
        })
    }
    // Test-only construction: a clock is selected before created/active exist.
    // There is deliberately no setter that can reset an already-owned session.
    #[cfg(test)]
    pub(crate) fn new_with_test_clock(
        seed: &[u8],
        th: &[u8],
        initiator: bool,
        clock: TestClock,
    ) -> Result<Self> {
        let mut session = Self::new_sampled(seed, th, initiator, || clock())?;
        session.clock = Some(clock);
        Ok(session)
    }
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return clock();
        }
        Instant::now()
    }
    /// Public identifier derived from the transcript.
    pub fn id(&self) -> &str {
        &self.sid
    }
    /// Permanently retire the session and clear its retained seed.
    pub fn close(&mut self) {
        self.seed.zeroize();
        self.closed = true;
    }
    fn live(&mut self, _stage: &str) -> Result<()> {
        let now = self.now();
        #[cfg(test)]
        let was_closed = self.closed;
        let result = self.live_at(now);
        #[cfg(test)]
        if result.is_err() {
            eprintln!(
                "record-lifetime-refusal stage={} closed_before={} absolute_ns={} idle_ns={} explicit_test_clock={}",
                _stage,
                was_closed,
                now.duration_since(self.created).as_nanos(),
                now.duration_since(self.active).as_nanos(),
                self.clock.is_some(),
            );
        }
        result
    }
    fn live_at(&mut self, now: Instant) -> Result<()> {
        if self.closed
            || now.duration_since(self.created) >= Duration::from_secs(3600)
            || now.duration_since(self.active) >= Duration::from_secs(600)
        {
            self.close();
            return Err(invalid("record session is closed or expired"));
        }
        Ok(())
    }
    fn direction(&self, sending: bool) -> u8 {
        if self.initiator == sending {
            0
        } else {
            1
        }
    }
    fn key(&self, direction: u8, seq: u64) -> Result<Zeroizing<[u8; 32]>> {
        let label = if direction == 0 { "c2s" } else { "s2c" };
        let mut info = format!("sage-{label}-key|0.10.0").into_bytes();
        info.extend(self.th);
        info.extend((seq / 256).to_be_bytes());
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::from_prk(self.seed.as_ref())
            .map_err(|_| invalid("invalid PRK"))?
            .expand(&info, key.as_mut())
            .map_err(|_| invalid("invalid key length"))?;
        Ok(key)
    }
    fn aad(&self, direction: u8, seq: u64, caller: &[u8]) -> Vec<u8> {
        let mut a = b"sage-record|0.10.0".to_vec();
        a.extend(self.th);
        a.push(direction);
        a.extend(seq.to_be_bytes());
        a.extend((caller.len() as u32).to_be_bytes());
        a.extend(caller);
        a
    }
    fn nonce(seq: u64) -> [u8; 12] {
        let mut n = [0; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    }
    /// Allocate a sequence and return wire bytes. Transport retries reuse these
    /// bytes; they must not recreate a record by encrypting again.
    pub fn seal(&mut self, plaintext: &[u8], caller_aad: &[u8]) -> Result<Vec<u8>> {
        self.live("pre-seal")?;
        if caller_aad.len() > MAX_AAD || plaintext.len() > MAX_WIRE - 36 {
            return Err(invalid("record size limit"));
        }
        if self.next >= LIMIT {
            self.close();
            return Err(invalid("record sequence limit"));
        }
        let seq = self.next;
        self.next += 1;
        let direction = self.direction(true);
        let key = self.key(direction, seq)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| invalid("invalid key"))?;
        let nonce = Self::nonce(seq);
        let aad = self.aad(direction, seq, caller_aad);
        let encrypted = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::CryptoError("record encryption failed".into()))?;
        self.live("post-seal")?;
        let mut wire = seq.to_be_bytes().to_vec();
        wire.extend(nonce);
        wire.extend(encrypted);
        self.active = self.now();
        Ok(wire)
    }
    /// Authenticate and accept once. Exclusive mutable access serializes replay
    /// acceptance; applications remain responsible for ordered business effects.
    pub fn open(&mut self, wire: &[u8], caller_aad: &[u8]) -> Result<Vec<u8>> {
        self.open_checked(wire, caller_aad, || Ok(()))
    }
    /// Authenticate before the trusted acceptance gate; failed gates consume no sequence.
    /// The exclusive borrow spans authentication, the gate and replay publication.
    pub(crate) fn open_checked(
        &mut self,
        wire: &[u8],
        caller_aad: &[u8],
        accept: impl FnOnce() -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.live("pre-open")?;
        if wire.len() < 36 || wire.len() > MAX_WIRE || caller_aad.len() > MAX_AAD {
            return Err(invalid("record size limit"));
        }
        let seq = u64::from_be_bytes(
            wire[..8]
                .try_into()
                .map_err(|_| invalid("missing sequence"))?,
        );
        if seq >= LIMIT {
            return Err(invalid("record sequence limit"));
        }
        let nonce = Self::nonce(seq);
        if wire[8..20] != nonce {
            return Err(invalid("invalid record nonce"));
        }
        let index = (seq / 64) as usize;
        let bit = 1u64 << (seq % 64);
        if self.seen[index] & bit != 0 {
            return Err(invalid("duplicate record"));
        }
        let direction = self.direction(false);
        let key = self.key(direction, seq)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| invalid("invalid key"))?;
        let aad = self.aad(direction, seq, caller_aad);
        let mut plaintext = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &wire[20..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Verification("record authentication failed".into()))?;
        if let Err(error) = self.live("post-open") {
            plaintext.zeroize();
            return Err(error);
        }
        if let Err(error) = accept() {
            plaintext.zeroize();
            return Err(error);
        }
        self.seen[index] |= bit;
        self.active = self.now();
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst},
        Arc,
    };

    fn controlled_session(initiator: bool) -> (RecordSession010, Arc<AtomicU64>) {
        let epoch = Instant::now();
        let ticks = Arc::new(AtomicU64::new(0));
        let current = ticks.clone();
        let clock: TestClock =
            Arc::new(move || epoch + Duration::from_millis(current.load(SeqCst)));
        let session =
            RecordSession010::new_with_test_clock(&[1; 32], &[2; 32], initiator, clock).unwrap();
        (session, ticks)
    }

    #[test]
    fn explicit_clock_preserves_lifetime_and_failed_acceptance() {
        let (mut idle, ticks) = controlled_session(true);
        let origin = idle.created;
        ticks.store(599_000, SeqCst);
        assert!(idle.seal(b"inert", b"").is_ok());
        assert_eq!(idle.created, origin);
        assert_eq!(idle.active, origin + Duration::from_secs(599));
        ticks.store(1_199_000, SeqCst);
        assert!(idle.seal(b"inert", b"").is_err());
        assert!(idle.closed);
        assert_eq!(*idle.seed, [0; 32]);

        let (mut absolute, ticks) = controlled_session(true);
        let origin = absolute.created;
        for step in 1..=6 {
            ticks.store(step * 599_000, SeqCst);
            assert!(absolute.seal(b"inert", b"").is_ok());
            assert_eq!(absolute.created, origin);
        }
        ticks.store(3_600_000, SeqCst);
        assert!(absolute.seal(b"inert", b"").is_err());
        assert!(absolute.closed);
        assert_eq!(*absolute.seed, [0; 32]);

        let (mut sender, _) = controlled_session(true);
        let (mut receiver, ticks) = controlled_session(false);
        let first = sender.seal(b"first", b"").unwrap();
        ticks.store(1_000, SeqCst);
        assert_eq!(receiver.open(&first, b"").unwrap(), b"first");
        let active = receiver.active;
        let origin = receiver.created;
        ticks.store(2_000, SeqCst);
        assert!(receiver.open(&first, b"").is_err());
        let mut corrupt = sender.seal(b"second", b"").unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(receiver.open(&corrupt, b"").is_err());
        assert_eq!(receiver.active, active);
        assert_eq!(receiver.created, origin);
        assert!(!receiver.closed);
    }

    #[test]
    fn explicit_clock_checks_expiry_after_crypto() {
        for opening in [false, true] {
            let epoch = Instant::now();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let clock: TestClock = Arc::new(move || {
                let sample = observed.fetch_add(1, SeqCst);
                epoch + Duration::from_secs(if sample < 2 { 0 } else { 600 })
            });
            let mut session =
                RecordSession010::new_with_test_clock(&[1; 32], &[2; 32], !opening, clock).unwrap();
            let result = if opening {
                let mut peer = RecordSession010::new(&[1; 32], &[2; 32], true).unwrap();
                let wire = peer.seal(b"inert", b"").unwrap();
                session.open(&wire, b"")
            } else {
                session.seal(b"inert", b"")
            };
            assert!(result.is_err());
            assert_eq!(calls.load(SeqCst), 3);
            assert!(session.closed);
            assert_eq!(*session.seed, [0; 32]);
            assert_eq!(session.created, epoch);
            assert_eq!(session.active, epoch);
            assert_eq!(session.next, u64::from(!opening));
            assert_eq!(session.seen, [0; 16]);
        }
    }

    fn vector_suite() -> &'static Value {
        static SUITE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
        SUITE.get_or_init(|| {
            serde_json::from_str(include_str!(
                "../../tests/fixtures/session-records-010.json"
            ))
            .unwrap()
        })
    }

    macro_rules! record_vectors {
        ($($name:ident => ($index:expr, $id:literal)),+ $(,)?) => {
            const VECTOR_CASES: &[(&str, usize, &str)] = &[
                $((stringify!($name), $index, $id)),+
            ];
            $(
                #[test]
                fn $name() {
                    independent_vector($index, $id);
                }
            )+
        };
    }

    record_vectors! {
        record_vector_c2s_key_0 => (0, "c2s-key-0"),
        record_vector_c2s_open_0 => (1, "c2s-open-0"),
        record_vector_c2s_key_1 => (2, "c2s-key-1"),
        record_vector_c2s_open_1 => (3, "c2s-open-1"),
        record_vector_c2s_key_255 => (4, "c2s-key-255"),
        record_vector_c2s_open_255 => (5, "c2s-open-255"),
        record_vector_c2s_key_256 => (6, "c2s-key-256"),
        record_vector_c2s_open_256 => (7, "c2s-open-256"),
        record_vector_c2s_key_511 => (8, "c2s-key-511"),
        record_vector_c2s_open_511 => (9, "c2s-open-511"),
        record_vector_c2s_key_512 => (10, "c2s-key-512"),
        record_vector_c2s_open_512 => (11, "c2s-open-512"),
        record_vector_c2s_key_767 => (12, "c2s-key-767"),
        record_vector_c2s_open_767 => (13, "c2s-open-767"),
        record_vector_c2s_key_768 => (14, "c2s-key-768"),
        record_vector_c2s_open_768 => (15, "c2s-open-768"),
        record_vector_c2s_key_999 => (16, "c2s-key-999"),
        record_vector_c2s_open_999 => (17, "c2s-open-999"),
        record_vector_s2c_key_0 => (18, "s2c-key-0"),
        record_vector_s2c_open_0 => (19, "s2c-open-0"),
        record_vector_s2c_key_1 => (20, "s2c-key-1"),
        record_vector_s2c_open_1 => (21, "s2c-open-1"),
        record_vector_s2c_key_255 => (22, "s2c-key-255"),
        record_vector_s2c_open_255 => (23, "s2c-open-255"),
        record_vector_s2c_key_256 => (24, "s2c-key-256"),
        record_vector_s2c_open_256 => (25, "s2c-open-256"),
        record_vector_s2c_key_511 => (26, "s2c-key-511"),
        record_vector_s2c_open_511 => (27, "s2c-open-511"),
        record_vector_s2c_key_512 => (28, "s2c-key-512"),
        record_vector_s2c_open_512 => (29, "s2c-open-512"),
        record_vector_s2c_key_767 => (30, "s2c-key-767"),
        record_vector_s2c_open_767 => (31, "s2c-open-767"),
        record_vector_s2c_key_768 => (32, "s2c-key-768"),
        record_vector_s2c_open_768 => (33, "s2c-open-768"),
        record_vector_s2c_key_999 => (34, "s2c-key-999"),
        record_vector_s2c_open_999 => (35, "s2c-open-999"),
        record_vector_aad_open_0 => (36, "aad-open-0"),
        record_vector_aad_open_4033 => (37, "aad-open-4033"),
        record_vector_aad_open_4034 => (38, "aad-open-4034"),
        record_vector_aad_seal_4033 => (39, "aad-seal-4033"),
        record_vector_aad_seal_4034 => (40, "aad-seal-4034"),
        record_vector_plaintext_size_0 => (41, "plaintext-size-0"),
        record_vector_plaintext_size_1 => (42, "plaintext-size-1"),
        record_vector_plaintext_size_8388572 => (43, "plaintext-size-8388572"),
        record_vector_plaintext_size_8388573 => (44, "plaintext-size-8388573"),
        record_vector_short => (45, "short"),
        record_vector_tag => (46, "tag"),
        record_vector_seq => (47, "seq"),
        record_vector_nonce => (48, "nonce"),
        record_vector_nonce_valid_tag => (49, "nonce-valid-tag"),
        record_vector_seq_1000 => (50, "seq-1000"),
        record_vector_seq_max => (51, "seq-max"),
        record_vector_reflection => (52, "reflection"),
        record_vector_transcript => (53, "transcript"),
        record_vector_aad_changed => (54, "aad-changed"),
    }

    #[test]
    fn independent_vectors() {
        let cases = vector_suite()["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 55);
        assert_eq!(VECTOR_CASES.len(), cases.len());
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for (index, (name, case_index, id)) in VECTOR_CASES.iter().enumerate() {
            assert_eq!(*case_index, index);
            assert_eq!(cases[index]["id"].as_str().unwrap(), *id);
            assert!(ids.insert(*id));
            assert!(names.insert(*name));
        }
    }

    fn vector_progress(
        id: &str,
        operation: &str,
        plaintext_bytes: usize,
        record_bytes: usize,
        aad_bytes: usize,
        phase: &str,
    ) {
        use std::io::Write;
        let Some(directory) = std::env::var_os("SAGE_RECORD_VECTOR_PROGRESS_DIR") else {
            return;
        };
        // Keep public fixture metadata out of libtest's JSON result stream.
        // Each named case owns a separate file; no session material is logged.
        let mut output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::path::Path::new(&directory).join(format!("{id}.log")))
            .unwrap();
        writeln!(
            output,
            "record-vector id={id} operation={operation} plaintext_bytes={plaintext_bytes} record_bytes={record_bytes} aad_bytes={aad_bytes} phase={phase}"
        )
        .unwrap();
    }

    fn independent_vector(index: usize, id: &str) {
        let c = &vector_suite()["cases"][index];
        assert_eq!(c["id"].as_str().unwrap(), id);
        let i = &c["input"];
        let decode = |name: &str| hex::decode(i[name].as_str().unwrap()).unwrap();
        let op = c["operation"].as_str().unwrap();
        let progress = |phase| {
            vector_progress(
                id,
                op,
                i["plaintext"]["length"].as_u64().unwrap_or(0) as usize,
                i["record_hex"].as_str().map_or(0, |value| value.len() / 2),
                i["caller_aad_hex"]
                    .as_str()
                    .map_or(0, |value| value.len() / 2),
                phase,
            );
        };
        progress("construct-begin");
        let sending = op != "sage.session.record.open";
        // Vectors contain no time fields. Select their clock before creating a
        // fresh session; never reset a session, sequence or lifetime afterward.
        let epoch = Instant::now();
        let clock: TestClock = Arc::new(move || epoch);
        let mut s = RecordSession010::new_with_test_clock(
            &decode("seed_hex"),
            &decode("th_hex"),
            (i["direction"] == "c2s") == sending,
            clock,
        )
        .unwrap();
        progress("construct-end");
        let out = &c["expected"]["output"];
        let result: Result<Vec<u8>> = match op {
            "sage.session.key" => {
                let d = if i["direction"] == "c2s" { 0 } else { 1 };
                progress("key-begin");
                let key = s.key(d, i["seq"].as_u64().unwrap()).unwrap();
                progress("key-end");
                assert_eq!(
                    hex::encode(key.as_ref()),
                    out["key_hex"].as_str().unwrap(),
                    "{}",
                    c["id"]
                );
                Ok(key.to_vec())
            }
            "sage.session.record.open" => {
                let record = decode("record_hex");
                let aad = decode("caller_aad_hex");
                progress("open-begin");
                let r = s.open(&record, &aad);
                progress("open-end");
                if let Ok(ref p) = r {
                    assert_eq!(
                        hex::encode(p),
                        out["plaintext_hex"].as_str().unwrap(),
                        "{}",
                        c["id"]
                    );
                }
                r
            }
            "sage.session.record.seal" => {
                progress("plaintext-allocation-begin");
                let p = vec![
                    i["plaintext"]["byte"].as_u64().unwrap() as u8;
                    i["plaintext"]["length"].as_u64().unwrap() as usize
                ];
                let aad = decode("caller_aad_hex");
                progress("seal-begin");
                let r = s.seal(&p, &aad);
                progress("seal-end");
                if let Ok(ref w) = r {
                    progress("record-hash-begin");
                    assert_eq!(
                        hex::encode(Sha256::digest(w)),
                        out["record_sha256"].as_str().unwrap()
                    );
                    assert_eq!(w.len() as u64, out["record_bytes"].as_u64().unwrap());
                    progress("record-hash-end");
                }
                r
            }
            _ => panic!("unknown operation"),
        };
        assert_eq!(
            result.is_ok(),
            c["expected"]["verdict"] == "ACCEPT",
            "{}",
            c["id"]
        );
        progress("verified");
    }
    #[test]
    fn state_and_lifetime() {
        let mut sender = RecordSession010::new(&[1; 32], &[2; 32], true).unwrap();
        let mut receiver = RecordSession010::new(&[1; 32], &[2; 32], false).unwrap();
        assert_eq!(sender.id(), receiver.id());
        assert_eq!(sender.id().len(), 22);
        let first = sender.seal(b"first", b"").unwrap();
        let second = sender.seal(b"second", b"").unwrap();
        let mut bad = first.clone();
        *bad.last_mut().unwrap() ^= 1;
        let before = receiver.active;
        assert!(receiver.open(&bad, b"").is_err());
        assert_eq!(receiver.active, before);
        assert_eq!(receiver.open(&second, b"").unwrap(), b"second");
        assert_eq!(receiver.open(&first, b"").unwrap(), b"first");
        assert!(receiver.open(&first, b"").is_err());
        receiver.close();
        assert!(receiver.open(&second, b"").is_err());
        assert_eq!(*receiver.seed, [0; 32]);
        for absolute in [false, true] {
            let mut s = RecordSession010::new(&[1; 32], &[2; 32], true).unwrap();
            let deadline = if absolute {
                s.active = s.created + Duration::from_secs(3500);
                s.created + Duration::from_secs(3600)
            } else {
                s.active + Duration::from_secs(600)
            };
            assert!(s.live_at(deadline - Duration::from_nanos(1)).is_ok());
            assert!(s.live_at(deadline).is_err());
            assert!(s.seal(b"", b"").is_err());
            assert!(s.closed);
        }
        let mut capped = RecordSession010::new(&[1; 32], &[2; 32], true).unwrap();
        capped.next = 999;
        assert!(capped.seal(b"", b"").is_ok());
        assert!(capped.seal(b"", b"").is_err());
        assert!(capped.closed);
        assert!(RecordSession010::new(&[1; 31], &[2; 32], true).is_err());
        assert!(RecordSession010::new(&[1; 32], &[2; 31], true).is_err());
    }
    #[test]
    fn roundtrip_all_generations() {
        for initiator in [false, true] {
            let mut a = RecordSession010::new(&[0; 32], &[9; 32], initiator).unwrap();
            let mut b = RecordSession010::new(&[0; 32], &[9; 32], !initiator).unwrap();
            for _ in 0..1000 {
                let wire = a.seal(b"message", b"aad").unwrap();
                assert_eq!(b.open(&wire, b"aad").unwrap(), b"message");
            }
            assert!(a.seal(b"", b"").is_err());
            a.close();
            b.close();
        }
    }
}

#[cfg(test)]
mod dependency_tests {
    #[test]
    fn cipher_retains_zeroize_on_drop() {
        fn requires_key_erasure<T: zeroize::ZeroizeOnDrop>() {}
        requires_key_erasure::<chacha20poly1305::ChaCha20Poly1305>();
    }
}
