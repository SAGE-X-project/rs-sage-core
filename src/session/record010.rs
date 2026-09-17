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
}
fn invalid(message: &str) -> Error {
    Error::InvalidInput(message.into())
}
impl RecordSession010 {
    /// Accepts the 32-byte seed and transcript hash from a fresh authenticated handshake.
    pub fn new(seed: &[u8], th: &[u8], initiator: bool) -> Result<Self> {
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
        let now = Instant::now();
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
        })
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
    fn live(&mut self) -> Result<()> {
        self.live_at(Instant::now())
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
        self.live()?;
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
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::CryptoError("record encryption failed".into()))?;
        self.live()?;
        let mut wire = seq.to_be_bytes().to_vec();
        wire.extend(nonce);
        wire.extend(encrypted);
        self.active = Instant::now();
        Ok(wire)
    }
    /// Authenticate and accept once. Exclusive mutable access serializes replay
    /// acceptance; applications remain responsible for ordered business effects.
    pub fn open(&mut self, wire: &[u8], caller_aad: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
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
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &wire[20..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Verification("record authentication failed".into()))?;
        if let Err(error) = self.live() {
            plaintext.zeroize();
            return Err(error);
        }
        self.seen[index] |= bit;
        self.active = Instant::now();
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    #[test]
    fn independent_vectors() {
        let suite: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/session-records-010.json"
        ))
        .unwrap();
        let cases = suite["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 55);
        for c in cases {
            let i = &c["input"];
            let decode = |name: &str| hex::decode(i[name].as_str().unwrap()).unwrap();
            let op = c["operation"].as_str().unwrap();
            let sending = op != "sage.session.record.open";
            let mut s = RecordSession010::new(
                &decode("seed_hex"),
                &decode("th_hex"),
                (i["direction"] == "c2s") == sending,
            )
            .unwrap();
            let out = &c["expected"]["output"];
            let result: Result<Vec<u8>> = match op {
                "sage.session.key" => {
                    let d = if i["direction"] == "c2s" { 0 } else { 1 };
                    let key = s.key(d, i["seq"].as_u64().unwrap()).unwrap();
                    assert_eq!(
                        hex::encode(key.as_ref()),
                        out["key_hex"].as_str().unwrap(),
                        "{}",
                        c["id"]
                    );
                    Ok(key.to_vec())
                }
                "sage.session.record.open" => {
                    let r = s.open(&decode("record_hex"), &decode("caller_aad_hex"));
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
                    let p = vec![
                        i["plaintext"]["byte"].as_u64().unwrap() as u8;
                        i["plaintext"]["length"].as_u64().unwrap() as usize
                    ];
                    let r = s.seal(&p, &decode("caller_aad_hex"));
                    if let Ok(ref w) = r {
                        assert_eq!(
                            hex::encode(Sha256::digest(w)),
                            out["record_sha256"].as_str().unwrap()
                        );
                        assert_eq!(w.len() as u64, out["record_bytes"].as_u64().unwrap());
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
        }
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
