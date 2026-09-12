//! Secure session records (sage-spec `05-session.md`).
//!
//! ```text
//! record = be64(seq) || nonce[12] || ChaCha20-Poly1305(key, nonce, plaintext, aad = be64(seq) || callerAAD)
//! ```
//!
//! Keys come from the session seed with RFC 5869 HKDF-SHA256, salt = the
//! session id bytes: `sage-session-keys-v1` (shared encrypt and signing
//! keys), `sage-directional-keys-v1` (c2s and s2c encrypt and signing keys)
//! and `sage-session-rekey-v1 || direction || be64(generation)` for the
//! rotated AEAD key of generation `seq / rekey_interval`. Receivers keep a
//! 1024-slot replay window over the sequence numbers they accepted.

use crate::error::{Error, Result};
use crate::session::types::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
/// Rotated AEAD keys by (direction, generation).
type GenerationKeys = HashMap<(String, u64), Zeroizing<[u8; 32]>>;

/// Size of the sequence header.
pub const SEQ_SIZE: usize = 8;
/// Size of the nonce.
pub const NONCE_SIZE: usize = 12;
/// Size of the record header (`seq || nonce`).
pub const HEADER_SIZE: usize = SEQ_SIZE + NONCE_SIZE;
/// Replay window size in records.
pub const REPLAY_WINDOW_SIZE: u64 = 1024;
/// Poly1305 tag size.
const TAG_SIZE: usize = 16;

const INFO_KEYS: &[u8] = b"sage-session-keys-v1";
const INFO_DIRECTIONAL: &[u8] = b"sage-directional-keys-v1";
const INFO_REKEY: &[u8] = b"sage-session-rekey-v1";

/// Sliding replay window over accepted sequence numbers.
#[derive(Debug, Default)]
struct ReplayWindow {
    highest: u64,
    any: bool,
    bitmap: [u64; (REPLAY_WINDOW_SIZE / 64) as usize],
}

impl ReplayWindow {
    fn check(&self, seq: u64) -> Result<()> {
        if !self.any {
            return Ok(());
        }
        if seq > self.highest {
            return Ok(());
        }
        let diff = self.highest - seq;
        if diff >= REPLAY_WINDOW_SIZE {
            return Err(Error::Verification("stale message".into()));
        }
        if self.bit(seq) {
            return Err(Error::Verification("replayed message".into()));
        }
        Ok(())
    }

    fn mark(&mut self, seq: u64) {
        if !self.any {
            self.any = true;
            self.highest = seq;
            self.bitmap = [0; (REPLAY_WINDOW_SIZE / 64) as usize];
            self.set(seq);
            return;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= REPLAY_WINDOW_SIZE {
                self.bitmap = [0; (REPLAY_WINDOW_SIZE / 64) as usize];
            } else {
                for _ in 0..shift {
                    self.highest += 1;
                    self.clear(self.highest);
                }
            }
            self.highest = seq;
        }
        self.set(seq);
    }

    fn idx(seq: u64) -> (usize, u64) {
        let slot = seq % REPLAY_WINDOW_SIZE;
        ((slot / 64) as usize, slot % 64)
    }
    fn bit(&self, seq: u64) -> bool {
        let (w, b) = Self::idx(seq);
        self.bitmap[w] & (1u64 << b) != 0
    }
    fn set(&mut self, seq: u64) {
        let (w, b) = Self::idx(seq);
        self.bitmap[w] |= 1u64 << b;
    }
    fn clear(&mut self, seq: u64) {
        let (w, b) = Self::idx(seq);
        self.bitmap[w] &= !(1u64 << b);
    }
}

struct Keys {
    seed: Zeroizing<Vec<u8>>,
    encrypt: Zeroizing<[u8; 32]>,
    sign: Zeroizing<[u8; 32]>,
    // directional keys (present for role-aware sessions)
    out_key: Option<Zeroizing<[u8; 32]>>,
    out_sign: Option<Zeroizing<[u8; 32]>>,
    in_key: Option<Zeroizing<[u8; 32]>>,
    in_sign: Option<Zeroizing<[u8; 32]>>,
}

/// A secure session bound to a seed and a session id.
pub struct SecureSession {
    id: String,
    keys: Keys,
    initiator: Option<bool>,
    config: SessionConfig,
    created_at: DateTime<Utc>,
    last_used_at: RwLock<DateTime<Utc>>,
    status: RwLock<SessionStatus>,
    message_count: Mutex<usize>,
    send_seq: Mutex<u64>,
    recv: Mutex<ReplayWindow>,
    gen_keys: Mutex<GenerationKeys>,
}

fn hkdf_expand(seed: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(Some(salt), seed)
        .expand(info, out)
        .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))
}

fn key32(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = [0u8; 32];
    k.copy_from_slice(bytes);
    Zeroizing::new(k)
}

impl SecureSession {
    /// A session with the shared (non-directional) keys derived from `seed`.
    pub fn new(session_id: String, seed: &[u8], config: SessionConfig) -> Result<Self> {
        Self::build(session_id, seed, None, config)
    }

    /// A role-aware session: the initiator sends on `c2s` and receives on
    /// `s2c`; the responder the reverse. The shared keys are derived as well.
    pub fn with_role(
        session_id: String,
        seed: &[u8],
        is_initiator: bool,
        config: SessionConfig,
    ) -> Result<Self> {
        Self::build(session_id, seed, Some(is_initiator), config)
    }

    /// Alias of [`SecureSession::with_role`] taking the HPKE exporter secret as the seed.
    pub fn from_exporter_with_role(
        session_id: String,
        exporter: &[u8],
        is_initiator: bool,
        config: SessionConfig,
    ) -> Result<Self> {
        Self::with_role(session_id, exporter, is_initiator, config)
    }

    fn build(
        session_id: String,
        seed: &[u8],
        initiator: Option<bool>,
        config: SessionConfig,
    ) -> Result<Self> {
        if session_id.is_empty() || seed.is_empty() {
            return Err(Error::InvalidInput(
                "session id and seed are required".into(),
            ));
        }
        let salt = session_id.as_bytes();
        let mut shared = [0u8; 64];
        hkdf_expand(seed, salt, INFO_KEYS, &mut shared)?;
        let mut keys = Keys {
            seed: Zeroizing::new(seed.to_vec()),
            encrypt: key32(&shared[..32]),
            sign: key32(&shared[32..]),
            out_key: None,
            out_sign: None,
            in_key: None,
            in_sign: None,
        };
        if let Some(is_initiator) = initiator {
            let mut d = [0u8; 128];
            hkdf_expand(seed, salt, INFO_DIRECTIONAL, &mut d)?;
            let (c2s_enc, c2s_sign, s2c_enc, s2c_sign) =
                (&d[0..32], &d[32..64], &d[64..96], &d[96..128]);
            if is_initiator {
                keys.out_key = Some(key32(c2s_enc));
                keys.out_sign = Some(key32(c2s_sign));
                keys.in_key = Some(key32(s2c_enc));
                keys.in_sign = Some(key32(s2c_sign));
            } else {
                keys.out_key = Some(key32(s2c_enc));
                keys.out_sign = Some(key32(s2c_sign));
                keys.in_key = Some(key32(c2s_enc));
                keys.in_sign = Some(key32(c2s_sign));
            }
        }
        let now = Utc::now();
        Ok(Self {
            id: session_id,
            keys,
            initiator,
            config,
            created_at: now,
            last_used_at: RwLock::new(now),
            status: RwLock::new(SessionStatus::Active),
            message_count: Mutex::new(0),
            send_seq: Mutex::new(0),
            recv: Mutex::new(ReplayWindow::default()),
            gen_keys: Mutex::new(HashMap::new()),
        })
    }

    /// Whether this session was created with a role.
    pub fn is_initiator(&self) -> Option<bool> {
        self.initiator
    }

    fn direction_label(&self, outbound: bool) -> &'static str {
        match self.initiator {
            Some(true) => {
                if outbound {
                    "c2s"
                } else {
                    "s2c"
                }
            }
            Some(false) => {
                if outbound {
                    "s2c"
                } else {
                    "c2s"
                }
            }
            None => "single",
        }
    }

    fn generation(&self, seq: u64) -> u64 {
        if self.config.rekey_interval == 0 {
            0
        } else {
            seq / self.config.rekey_interval
        }
    }

    fn key_for(&self, base: &[u8; 32], direction: &str, seq: u64) -> Result<Zeroizing<[u8; 32]>> {
        let generation = self.generation(seq);
        if generation == 0 {
            return Ok(Zeroizing::new(*base));
        }
        let mut cache = self.gen_keys.lock().unwrap();
        if let Some(k) = cache.get(&(direction.to_string(), generation)) {
            return Ok(k.clone());
        }
        let mut info = Vec::with_capacity(INFO_REKEY.len() + direction.len() + 8);
        info.extend_from_slice(INFO_REKEY);
        info.extend_from_slice(direction.as_bytes());
        info.extend_from_slice(&generation.to_be_bytes());
        let mut k = [0u8; 32];
        hkdf_expand(&self.keys.seed, self.id.as_bytes(), &info, &mut k)?;
        let k = Zeroizing::new(k);
        cache.insert((direction.to_string(), generation), k.clone());
        Ok(k)
    }

    fn check_usable(&self) -> Result<()> {
        if self.is_expired() {
            return Err(Error::Other("Session expired".into()));
        }
        Ok(())
    }

    fn count_message(&self) -> Result<()> {
        let mut count = self.message_count.lock().unwrap();
        *count += 1;
        if self.config.max_messages > 0 && *count > self.config.max_messages {
            *self.status.write().unwrap() = SessionStatus::Expired;
            return Err(Error::Other("Message limit exceeded".into()));
        }
        Ok(())
    }

    fn touch(&self) {
        *self.last_used_at.write().unwrap() = Utc::now();
    }

    fn seal(
        &self,
        base: &[u8; 32],
        direction: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_usable()?;
        self.count_message()?;
        let seq = {
            let mut s = self.send_seq.lock().unwrap();
            let v = *s;
            *s += 1;
            v
        };
        let key = self.key_for(base, direction, seq)?;
        let mut out = vec![0u8; HEADER_SIZE];
        out[..SEQ_SIZE].copy_from_slice(&seq.to_be_bytes());
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        out[SEQ_SIZE..HEADER_SIZE].copy_from_slice(&nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let mut bound = Vec::with_capacity(SEQ_SIZE + aad.len());
        bound.extend_from_slice(&out[..SEQ_SIZE]);
        bound.extend_from_slice(aad);
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &bound,
                },
            )
            .map_err(|_| Error::CryptoError("encryption failed".into()))?;
        out.extend_from_slice(&ct);
        self.touch();
        Ok(out)
    }

    fn open(&self, base: &[u8; 32], direction: &str, record: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.check_usable()?;
        if record.len() < HEADER_SIZE + TAG_SIZE {
            return Err(Error::InvalidInput("record too short".into()));
        }
        let seq = u64::from_be_bytes(record[..SEQ_SIZE].try_into().unwrap());
        let mut recv = self.recv.lock().unwrap();
        recv.check(seq)?;
        let key = self.key_for(base, direction, seq)?;
        let nonce_bytes: [u8; NONCE_SIZE] = record[SEQ_SIZE..HEADER_SIZE].try_into().unwrap();
        let nonce = Nonce::from(nonce_bytes);
        let mut bound = Vec::with_capacity(SEQ_SIZE + aad.len());
        bound.extend_from_slice(&record[..SEQ_SIZE]);
        bound.extend_from_slice(aad);
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let pt = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &record[HEADER_SIZE..],
                    aad: &bound,
                },
            )
            .map_err(|_| Error::CryptoError("decryption failed".into()))?;
        recv.mark(seq);
        drop(recv);
        self.count_message()?;
        self.touch();
        Ok(pt)
    }

    fn out_key(&self) -> Result<&[u8; 32]> {
        self.keys
            .out_key
            .as_deref()
            .ok_or_else(|| Error::Other("session has no role; use encrypt".into()))
    }

    fn in_key(&self) -> Result<&[u8; 32]> {
        self.keys
            .in_key
            .as_deref()
            .ok_or_else(|| Error::Other("session has no role; use decrypt".into()))
    }

    /// Encrypt with caller AAD. Role-aware sessions use the outbound
    /// directional key; others the shared key.
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.keys.out_key.as_deref() {
            Some(k) => self.seal(k, self.direction_label(true), plaintext, aad),
            None => self.seal(&self.keys.encrypt, "single", plaintext, aad),
        }
    }

    /// Decrypt with caller AAD (inbound directional key when the session has a role).
    pub fn decrypt_with_aad(&self, record: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.keys.in_key.as_deref() {
            Some(k) => self.open(k, self.direction_label(false), record, aad),
            None => self.open(&self.keys.encrypt, "single", record, aad),
        }
    }

    /// Encrypt on the outbound direction (role-aware sessions only).
    pub fn encrypt_outbound(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let k = self.out_key()?;
        self.seal(k, self.direction_label(true), plaintext, &[])
    }

    /// Decrypt a record received on the inbound direction.
    pub fn decrypt_inbound(&self, record: &[u8]) -> Result<Vec<u8>> {
        let k = self.in_key()?;
        self.open(k, self.direction_label(false), record, &[])
    }

    /// Encrypt on the outbound direction with caller AAD.
    pub fn encrypt_with_aad_outbound(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let k = self.out_key()?;
        self.seal(k, self.direction_label(true), plaintext, aad)
    }

    /// Decrypt an inbound record with caller AAD.
    pub fn decrypt_with_aad_inbound(&self, record: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let k = self.in_key()?;
        self.open(k, self.direction_label(false), record, aad)
    }

    fn sign_with(key: &[u8; 32], covered: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size");
        mac.update(covered);
        mac.finalize().into_bytes().to_vec()
    }

    fn verify_with(key: &[u8; 32], covered: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size");
        mac.update(covered);
        mac.verify_slice(tag)
            .map_err(|_| Error::Verification("MAC verification failed".into()))
    }
}

impl Session for SecureSession {
    fn get_id(&self) -> &str {
        &self.id
    }
    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn get_last_used_at(&self) -> DateTime<Utc> {
        *self.last_used_at.read().unwrap()
    }
    fn get_status(&self) -> SessionStatus {
        *self.status.read().unwrap()
    }
    fn is_expired(&self) -> bool {
        let status = self.get_status();
        if status != SessionStatus::Active {
            return true;
        }
        let now = Utc::now();
        let expired = now - self.created_at > self.config.max_age
            || now - self.get_last_used_at() > self.config.idle_timeout;
        if expired {
            *self.status.write().unwrap() = SessionStatus::Expired;
        }
        expired
    }
    fn update_last_used(&mut self) {
        self.touch();
    }
    fn close(&mut self) -> Result<()> {
        *self.status.write().unwrap() = SessionStatus::Closed;
        Ok(())
    }
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal(&self.keys.encrypt, "single", plaintext, &[])
    }
    fn decrypt(&self, record: &[u8]) -> Result<Vec<u8>> {
        self.open(&self.keys.encrypt, "single", record, &[])
    }
    fn encrypt_and_sign(&self, plaintext: &[u8], covered: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let record = self.encrypt_with_aad(plaintext, covered)?;
        Ok((record, self.sign_covered(covered)))
    }
    fn decrypt_and_verify(&self, record: &[u8], covered: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        self.verify_covered(covered, mac)?;
        self.decrypt_with_aad(record, covered)
    }
    fn sign_covered(&self, covered: &[u8]) -> Vec<u8> {
        let key = self.keys.out_sign.as_deref().unwrap_or(&self.keys.sign);
        Self::sign_with(key, covered)
    }
    fn verify_covered(&self, covered: &[u8], mac: &[u8]) -> Result<()> {
        let key = self.keys.in_sign.as_deref().unwrap_or(&self.keys.sign);
        Self::verify_with(key, covered, mac)
    }
    fn get_message_count(&self) -> usize {
        *self.message_count.lock().unwrap()
    }
    fn get_config(&self) -> &SessionConfig {
        &self.config
    }
}

impl std::fmt::Debug for SecureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSession")
            .field("id", &self.id)
            .field("initiator", &self.initiator)
            .field("status", &self.get_status())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Vec<u8> {
        vec![0x42; 32]
    }

    #[test]
    fn record_format_and_roundtrip() {
        let s = SecureSession::new("sid".into(), &seed(), SessionConfig::default()).unwrap();
        let r = s.encrypt(b"hello").unwrap();
        assert_eq!(r.len(), HEADER_SIZE + 5 + TAG_SIZE);
        assert_eq!(&r[..SEQ_SIZE], &0u64.to_be_bytes());
        let peer = SecureSession::new("sid".into(), &seed(), SessionConfig::default()).unwrap();
        assert_eq!(peer.decrypt(&r).unwrap(), b"hello");
        assert!(
            matches!(peer.decrypt(&r), Err(Error::Verification(_))),
            "replay"
        );
        let r2 = s.encrypt(b"x").unwrap();
        assert_eq!(&r2[..SEQ_SIZE], &1u64.to_be_bytes());
        assert_ne!(
            &r[SEQ_SIZE..HEADER_SIZE],
            &r2[SEQ_SIZE..HEADER_SIZE],
            "random nonce"
        );
    }

    #[test]
    fn different_sessions_do_not_interoperate() {
        let a = SecureSession::new("sid-a".into(), &seed(), SessionConfig::default()).unwrap();
        let b = SecureSession::new("sid-b".into(), &seed(), SessionConfig::default()).unwrap();
        let r = a.encrypt(b"hello").unwrap();
        assert!(b.decrypt(&r).is_err());
        let mut tampered = a.encrypt(b"hello").unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let c = SecureSession::new("sid-a".into(), &seed(), SessionConfig::default()).unwrap();
        assert!(c.decrypt(&tampered).is_err());
    }

    #[test]
    fn rekey_by_generation() {
        let cfg = SessionConfig {
            rekey_interval: 4,
            max_messages: 0,
            ..Default::default()
        };
        let s = SecureSession::new("sid".into(), &seed(), cfg.clone()).unwrap();
        let peer = SecureSession::new("sid".into(), &seed(), cfg).unwrap();
        let records: Vec<Vec<u8>> = (0..10)
            .map(|i| s.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();
        for (i, r) in records.iter().enumerate() {
            assert_eq!(peer.decrypt(r).unwrap(), format!("m{i}").as_bytes());
        }
        // a peer without rotation cannot open generation 1
        let no_rekey = SecureSession::new(
            "sid".into(),
            &seed(),
            SessionConfig {
                rekey_interval: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(no_rekey.decrypt(&records[0]).is_ok());
        assert!(no_rekey.decrypt(&records[5]).is_err());
    }

    #[test]
    fn directional_and_aad() {
        let a = SecureSession::with_role("sid".into(), &seed(), true, SessionConfig::default())
            .unwrap();
        let b = SecureSession::with_role("sid".into(), &seed(), false, SessionConfig::default())
            .unwrap();
        let r = a.encrypt_outbound(b"to b").unwrap();
        assert_eq!(b.decrypt_inbound(&r).unwrap(), b"to b");
        assert!(a.decrypt_inbound(&r).is_err(), "own direction");
        let r2 = b.encrypt_with_aad(b"to a", b"ctx").unwrap();
        assert_eq!(a.decrypt_with_aad(&r2, b"ctx").unwrap(), b"to a");
        let a2 = SecureSession::with_role("sid".into(), &seed(), true, SessionConfig::default())
            .unwrap();
        assert!(a2.decrypt_with_aad(&r2, b"other").is_err());
        let (rec, mac) = a.encrypt_and_sign(b"signed", b"covered").unwrap();
        assert_eq!(
            b.decrypt_and_verify(&rec, b"covered", &mac).unwrap(),
            b"signed"
        );
        assert!(b.decrypt_and_verify(&rec, b"covered", &[0u8; 32]).is_err());
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.check(5).is_ok());
        w.mark(5);
        assert!(w.check(5).is_err());
        assert!(w.check(4).is_ok());
        w.mark(4);
        assert!(w.check(4).is_err());
        w.mark(5 + REPLAY_WINDOW_SIZE);
        assert!(w.check(5).is_err(), "stale");
        assert!(w.check(6 + REPLAY_WINDOW_SIZE).is_ok());
    }

    #[test]
    fn limits() {
        let cfg = SessionConfig {
            max_messages: 2,
            ..Default::default()
        };
        let s = SecureSession::new("sid".into(), &seed(), cfg).unwrap();
        s.encrypt(b"1").unwrap();
        s.encrypt(b"2").unwrap();
        assert!(s.encrypt(b"3").is_err());
        assert!(s.is_expired());
    }
}
