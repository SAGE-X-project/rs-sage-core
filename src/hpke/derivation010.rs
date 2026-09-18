//! Cryptographic 0.10.0 derivation only: no envelope authentication or registry gate.
use super::{combine_secrets_010, kem_open, kem_seal, make_ack_tag_010};
use crate::error::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::TryRng;
use serde::de::{MapAccess, Visitor};
use serde::Deserializer;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

const B: [&str; 10] = [
    "v", "ctx", "initDid", "respDid", "initKid", "respKid", "kemKid", "suite", "combiner", "nonce",
];
type Fields = BTreeMap<String, String>;
fn invalid() -> Error {
    Error::CryptoError("invalid 0.10.0 HPKE derivation".into())
}
pub(super) fn fields(raw: &[u8], extra: &[&str]) -> Result<Fields> {
    if raw.len() > 16384 {
        return Err(invalid());
    }
    struct Flat;
    impl<'de> Visitor<'de> for Flat {
        type Value = Fields;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("closed string object")
        }
        fn visit_map<M: MapAccess<'de>>(
            self,
            mut access: M,
        ) -> std::result::Result<Fields, M::Error> {
            let mut map = Fields::new();
            while let Some((k, v)) = access.next_entry::<String, String>()? {
                if !v.is_ascii() || map.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom("invalid member"));
                }
            }
            Ok(map)
        }
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    let m = d.deserialize_map(Flat).map_err(|_| invalid())?;
    d.end().map_err(|_| invalid())?;
    if m.len() != B.len() + extra.len() || !B.iter().chain(extra.iter()).all(|n| m.contains_key(*n))
    {
        return Err(invalid());
    }
    Ok(m)
}
pub(super) fn uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s)
        .map(|v| {
            v.get_version_num() == 4
                && v.get_variant() == uuid::Variant::RFC4122
                && v.to_string() == s
        })
        .unwrap_or(false)
}
fn agent(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
pub(super) fn did(s: &str) -> bool {
    let p: Vec<_> = s.split(':').collect();
    if s.len() > 256 || p.len() < 5 || p[0] != "did" || p[1] != "sage" || !agent(p[p.len() - 1]) {
        return false;
    }
    match p[2] {
        "eip155" => {
            p.len() == 6
                && !p[3].is_empty()
                && p[3].len() <= 32
                && !p[3].starts_with('0')
                && p[3].bytes().all(|c| c.is_ascii_digit())
                && p[4].len() == 42
                && p[4].starts_with("0x")
                && p[4][2..]
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }
        "web" => {
            p.len() == 5
                && p[3].len() <= 64
                && p[3].parse::<std::net::IpAddr>().is_err()
                && p[3].split('.').all(|s| {
                    !s.is_empty()
                        && s.len() <= 63
                        && !s.starts_with('-')
                        && !s.ends_with('-')
                        && s.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                })
        }
        _ => false,
    }
}
pub(super) fn key(s: &str, owner: &str) -> bool {
    s.len() <= 289
        && s.strip_prefix(&format!("{owner}#"))
            .map(|n| {
                !n.is_empty()
                    && n.len() <= 32
                    && n.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            })
            .unwrap_or(false)
}
pub(super) fn binary(s: &str, len: usize) -> Result<Vec<u8>> {
    let b = URL_SAFE_NO_PAD.decode(s).map_err(|_| invalid())?;
    if b.len() != len || URL_SAFE_NO_PAD.encode(&b) != s {
        return Err(invalid());
    }
    Ok(b)
}
pub(super) fn binding(m: &Fields) -> Result<Fields> {
    if m["v"] != "0.10.0"
        || m["suite"] != "hpke-base+x25519+hkdf-sha256"
        || m["combiner"] != "e2e-x25519-hkdf-v1"
        || !uuid(&m["ctx"])
        || !did(&m["initDid"])
        || !did(&m["respDid"])
        || !key(&m["initKid"], &m["initDid"])
        || !key(&m["respKid"], &m["respDid"])
        || !key(&m["kemKid"], &m["respDid"])
    {
        return Err(invalid());
    }
    binary(&m["nonce"], 16)?;
    Ok(B.iter()
        .map(|n| ((*n).to_string(), m[*n].clone()))
        .collect())
}
pub(super) fn canonical(m: &Fields) -> Result<Vec<u8>> {
    crate::jcs::canonicalize(&serde_json::to_vec(m).map_err(|_| invalid())?).map_err(|_| invalid())
}
/// Public context bytes recomputed locally from the validated closed B object.
pub struct Domains010 {
    /// JCS(B).
    pub binding: Vec<u8>,
    /// Domain-prefixed JCS(B).
    pub info: Vec<u8>,
    /// Domain-prefixed SHA256(info).
    pub export_context: Vec<u8>,
}
fn domains(b: &Fields) -> Result<Domains010> {
    let binding = canonical(b)?;
    let mut info = b"sage-hpke-info|0.10.0\n".to_vec();
    info.extend_from_slice(&binding);
    let mut export_context = b"sage-hpke-export|0.10.0\n".to_vec();
    export_context.extend_from_slice(&Sha256::digest(&info));
    Ok(Domains010 {
        binding,
        info,
        export_context,
    })
}
/// Validates syntax and computes domains. Registration, selected key material,
/// and policy allowing the optional web profile must be checked by the caller.
pub fn build_domains_010(raw: &[u8]) -> Result<Domains010> {
    domains(&binding(&fields(raw, &[])?)?)
}
pub(super) fn initiation(raw: &[u8]) -> Result<(Fields, Domains010)> {
    let m = fields(raw, &["task", "enc", "ephC"])?;
    let b = binding(&m)?;
    if m["task"] != "hpke/init@0.10.0" {
        return Err(invalid());
    }
    binary(&m["enc"], 32)?;
    binary(&m["ephC"], 32)?;
    Ok((m, domains(&b)?))
}
/// Cryptographic result only; does not authenticate a peer or establish a session.
pub struct Derivation010 {
    /// JCS(T).
    pub transcript: Vec<u8>,
    /// SHA256(JCS(T)).
    pub th: [u8; 32],
    /// Secret session seed, cleared on drop.
    pub seed: Zeroizing<Vec<u8>>,
    /// Transcript-bound ACK.
    pub ack_tag: [u8; 32],
    /// Public transcript-derived session identifier.
    pub sid: String,
}
fn finish(
    m: &Fields,
    exporter: &[u8],
    private: &[u8; 32],
    peer_field: &str,
) -> Result<Derivation010> {
    let peer: [u8; 32] = binary(&m[peer_field], 32)?
        .try_into()
        .map_err(|_| invalid())?;
    let shared = Zeroizing::new(x25519(*private, peer));
    if bool::from(shared.ct_eq(&[0; 32])) {
        return Err(invalid());
    }
    let transcript = canonical(m)?;
    let th: [u8; 32] = Sha256::digest(&transcript).into();
    let seed = combine_secrets_010(exporter, &*shared, &th)?;
    let ack_tag = make_ack_tag_010(&seed, &th)?;
    let mut sid_input = b"sage-session|0.10.0".to_vec();
    sid_input.extend_from_slice(&th);
    let sid = URL_SAFE_NO_PAD.encode(&Sha256::digest(&sid_input)[..16]);
    Ok(Derivation010 {
        transcript,
        th,
        seed,
        ack_tag,
        sid,
    })
}
/// Derives the responder result from explicit keys. Caller must supply a fresh
/// independent E2E private key and UUIDv4 handle. No signatures or registry checks.
pub fn derive_responder_010(
    raw: &[u8],
    kem_private: &[u8],
    e2e_private: &[u8],
    kid: &str,
) -> Result<Derivation010> {
    let (mut m, dom) = initiation(raw)?;
    if !uuid(kid) {
        return Err(invalid());
    }
    let kem: &[u8; 32] = kem_private.try_into().map_err(|_| invalid())?;
    let e2e: &[u8; 32] = e2e_private.try_into().map_err(|_| invalid())?;
    let enc = binary(&m["enc"], 32)?;
    let exporter = kem_open(kem, &enc, &dom.info, &dom.export_context).map_err(|_| invalid())?;
    m.insert(
        "ephS".into(),
        URL_SAFE_NO_PAD.encode(x25519(*e2e, X25519_BASEPOINT_BYTES)),
    );
    m.insert("kid".into(), kid.into());
    finish(&m, &exporter, e2e, "ephC")
}
/// Generates the responder E2E key and UUIDv4 handle with the system CSPRNG.
pub fn respond_fresh_010(raw: &[u8], kem_private: &[u8]) -> Result<Derivation010> {
    initiation(raw)?;
    let mut private = Zeroizing::new([0; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut *private)
        .map_err(|_| invalid())?;
    derive_responder_010(
        raw,
        kem_private,
        &*private,
        &uuid::Uuid::new_v4().to_string(),
    )
}
/// One-shot cryptographic material; not the authenticated HPKE pending machine.
/// Drop on abandonment. Derive consumes it on success or failure.
pub struct Initiator010 {
    init: Fields,
    exporter: Zeroizing<Vec<u8>>,
    private: Zeroizing<[u8; 32]>,
}
/// Generates independent HPKE and E2E ephemeral keys. Caller supplies fresh
/// authenticated context/nonce and the exact current selected KEM public key.
pub fn start_initiator_010(raw: &[u8], kem_public: &[u8]) -> Result<(Initiator010, Vec<u8>)> {
    let mut m = fields(raw, &[])?;
    let dom = domains(&binding(&m)?)?;
    let pk: &[u8; 32] = kem_public.try_into().map_err(|_| invalid())?;
    let (enc, exporter) = kem_seal(pk, &dom.info, &dom.export_context).map_err(|_| invalid())?;
    let mut private = Zeroizing::new([0; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut *private)
        .map_err(|_| invalid())?;
    m.insert("task".into(), "hpke/init@0.10.0".into());
    m.insert("enc".into(), URL_SAFE_NO_PAD.encode(enc));
    m.insert(
        "ephC".into(),
        URL_SAFE_NO_PAD.encode(x25519(*private, X25519_BASEPOINT_BYTES)),
    );
    let init = canonical(&m)?;
    Ok((
        Initiator010 {
            init: m,
            exporter,
            private,
        },
        init,
    ))
}
impl Initiator010 {
    /// Checks all echoed fields and derives the result. Completion signatures,
    /// current keys, ACK verification and lifetime remain external obligations.
    pub fn derive(self, raw: &[u8]) -> Result<Derivation010> {
        let m = fields(raw, &["task", "enc", "ephC", "ephS", "kid"])?;
        if self.init.iter().any(|(k, v)| m.get(k) != Some(v)) || !uuid(&m["kid"]) {
            return Err(invalid());
        }
        finish(&m, &self.exporter, &self.private, "ephS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/fixtures/hpke-derivation010.json")).unwrap()
    }
    #[test]
    fn independent_vectors() {
        let f = fixture();
        let cases = f["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 60);
        for c in cases {
            let input = &c["input"];
            let d = |k: &str| hex::decode(input[k].as_str().unwrap()).unwrap();
            let result = if c["operation"] == "domains" {
                build_domains_010(&d("binding_hex")).map(|v|serde_json::json!({"binding_hex":hex::encode(v.binding),"info_hex":hex::encode(v.info),"export_context_hex":hex::encode(v.export_context)}))
            } else {
                derive_responder_010(&d("initiation_hex"),&d("kem_private_hex"),&d("e2e_private_hex"),input["kid"].as_str().unwrap()).map(|v|serde_json::json!({"transcript_hex":hex::encode(v.transcript),"th_hex":hex::encode(v.th),"seed_hex":hex::encode(&*v.seed),"ack_tag_hex":hex::encode(v.ack_tag),"sid":v.sid}))
            };
            if c["expected"].is_null() {
                assert!(result.is_err(), "{}", c["id"]);
            } else {
                assert_eq!(result.unwrap(), c["expected"], "{}", c["id"]);
            }
        }
    }
    fn controls() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let f = fixture();
        let b = hex::decode(f["cases"][0]["input"]["binding_hex"].as_str().unwrap()).unwrap();
        let mut private = [0; 32];
        rand::rngs::SysRng.try_fill_bytes(&mut private).unwrap();
        let public = x25519(private, X25519_BASEPOINT_BYTES);
        (b, private, public)
    }
    #[test]
    fn fresh_exchange() {
        let (b, private, public) = controls();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            let (s, init) = start_initiator_010(&b, &public).unwrap();
            let m = fields(&init, &["task", "enc", "ephC"]).unwrap();
            assert!(seen.insert(m["enc"].clone()));
            assert!(seen.insert(m["ephC"].clone()));
            let r = respond_fresh_010(&init, &private).unwrap();
            let l = s.derive(&r.transcript).unwrap();
            assert_eq!(*l.seed, *r.seed);
            assert_eq!(l.th, r.th);
            assert_eq!(l.sid, r.sid);
            assert!(super::super::verify_ack_tag_010(&l.seed, &l.th, &r.ack_tag));
        }
    }
    #[test]
    fn rejects_changed_transcript_and_kem_keys() {
        let (b, private, public) = controls();
        for field in B
            .iter()
            .chain(["task", "enc", "ephC", "ephS", "kid", "extra"].iter())
        {
            let (s, init) = start_initiator_010(&b, &public).unwrap();
            let r = respond_fresh_010(&init, &private).unwrap();
            let mut m: Fields = serde_json::from_slice(&r.transcript).unwrap();
            m.insert((*field).into(), "invalid".into());
            assert!(
                s.derive(&serde_json::to_vec(&m).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut one = [0; 32];
        one[0] = 1;
        for bad in [&[0u8; 32][..], &one[..], &[0u8; 31][..]] {
            assert!(start_initiator_010(&b, bad).is_err());
        }
    }
}
