//! Fresh registry observations for a single locally configured Guard principal.
use super::*;
use crate::registry010::{Key, SendGate, Stamp};

pub(crate) struct Observation {
    pub(crate) stamp: Stamp,
    pub(crate) started_ms: i64,
    pub(crate) expires: Option<i64>,
}

/// Trusted registry binding; every callback makes a new authoritative read.
/// The first selected key is immutable for this binding's lifetime. A replacement
/// requires trusted setup. Source validation, durable storage, bounded callbacks
/// and host isolation remain deployment responsibilities; this is not a resolver.
pub struct RegistryAuthority {
    gate: SendGate,
    issuer: String,
    keyid: String,
    key: Option<Key>,
}
impl RegistryAuthority {
    /// Take ownership of a gate without performing an observation.
    pub fn new(gate: SendGate, issuer: &str, keyid: &str) -> Result<Self> {
        let (principal, name) = keyid.split_once('#').ok_or(Invalid)?;
        ensure(did(issuer) && principal == issuer && chars(name, 32, false))?;
        Ok(Self {
            gate,
            issuer: issuer.into(),
            keyid: keyid.into(),
            key: None,
        })
    }
    pub(crate) fn observe(&mut self) -> Result<Observation> {
        self.read().map(|(_, observation)| observation)
    }
    fn read(&mut self) -> Result<([u8; 32], Observation)> {
        let start = self.gate.sample().map_err(|_| Invalid)?;
        let (p, stamp) = self
            .gate
            .select_with_time(&self.issuer, &self.keyid, false)
            .map_err(|_| Invalid)?;
        let key = p.signing();
        if let Some(old) = &self.key {
            ensure(old == key)?;
        }
        let raw: [u8; 32] = hex::decode(&key.material)
            .map_err(|_| Invalid)?
            .try_into()
            .map_err(|_| Invalid)?;
        ensure(canonical_edwards_y(raw))?;
        ensure(
            !VerifyingKey::from_bytes(&raw)
                .map_err(|_| Invalid)?
                .is_weak(),
        )?;
        self.key = Some(key.clone());
        Ok((
            raw,
            Observation {
                stamp,
                started_ms: start.mono_ms,
                expires: key.expires,
            },
        ))
    }
}
impl Authority for RegistryAuthority {
    /// Revalidate the pinned principal/key and return this observation's gate time.
    fn now(&mut self) -> Result<i64> {
        self.read().map(|(_, observation)| observation.stamp.unix)
    }
    /// Resolve only the exact locally configured issuer/keyid without fallback.
    fn active_key(&mut self, issuer: &str, keyid: &str) -> Result<[u8; 32]> {
        ensure(issuer == self.issuer && keyid == self.keyid)?;
        self.read().map(|(key, _)| key)
    }
}
