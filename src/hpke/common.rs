//! HPKE derivations (sage-spec `04-hpke.md` §3-§5): the RFC 9180 export
//! step, the E2E secret combiner, the HMAC counter expansion of the traffic
//! keys and the ACK tag.

use crate::error::{Error, Result};
use crate::hpke::types::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
type Kem = X25519HkdfSha256;

/// HPKE base-mode encapsulation to `peer_kem_key` with `Export(export_ctx, 32)`.
/// Returns `(enc, exporter)`.
pub fn kem_seal(
    peer_kem_key: &[u8; 32],
    info: &[u8],
    export_ctx: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(peer_kem_key)
        .map_err(|_| Error::CryptoError("invalid KEM public key".into()))?;
    let (enc, ctx) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeS::Base, &pk, info)
            .map_err(|e| Error::CryptoError(format!("HPKE setup failed: {e}")))?;
    let mut exporter = Zeroizing::new(vec![0u8; 32]);
    ctx.export(export_ctx, &mut exporter)
        .map_err(|e| Error::CryptoError(format!("HPKE export failed: {e}")))?;
    Ok((enc.to_bytes().to_vec(), exporter))
}

/// HPKE base-mode decapsulation with the responder's static X25519 secret,
/// returning `Export(export_ctx, 32)`.
pub fn kem_open(
    kem_secret: &[u8; 32],
    enc: &[u8],
    info: &[u8],
    export_ctx: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(kem_secret)
        .map_err(|_| Error::CryptoError("invalid KEM private key".into()))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|_| Error::CryptoError("invalid encapsulated key".into()))?;
    let ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
    )
    .map_err(|e| Error::CryptoError(format!("HPKE setup failed: {e}")))?;
    let mut exporter = Zeroizing::new(vec![0u8; 32]);
    ctx.export(export_ctx, &mut exporter)
        .map_err(|e| Error::CryptoError(format!("HPKE export failed: {e}")))?;
    Ok(exporter)
}

/// `seed = HKDF-Expand(HKDF-Extract(SHA-256, exporter || ssE2E, salt = exportCtx), "SAGE-HPKE+E2E-Combiner", 32)`
pub fn combine_secrets(
    exporter_hpke: &[u8],
    ss_e2e: &[u8],
    export_ctx: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(exporter_hpke.len() + ss_e2e.len()));
    ikm.extend_from_slice(exporter_hpke);
    ikm.extend_from_slice(ss_e2e);
    let hkdf = Hkdf::<Sha256>::new(Some(export_ctx), &ikm);
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(COMBINER_LABEL, &mut okm)
        .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

/// Counter-mode expansion used for the traffic keys and the ACK key
/// (`04-hpke.md` §4): `HMAC-SHA256(key, label || be32(i))` for i = 1, 2, …
pub fn hmac_expand(key: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + 32);
    let mut counter: u32 = 1;
    while out.len() < out_len {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(label);
        mac.update(&counter.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Traffic keys from the seed (`04-hpke.md` §4).
pub fn derive_traffic_keys(seed: &[u8]) -> Result<TrafficKeys> {
    if seed.len() < 32 {
        return Err(Error::CryptoError("seed must be at least 32 bytes".into()));
    }
    let take = |label: &[u8], n: usize| hmac_expand(seed, label, n);
    let mut tk = TrafficKeys {
        c2s_key: [0; 32],
        c2s_iv: [0; 12],
        s2c_key: [0; 32],
        s2c_iv: [0; 12],
        channel_binding: [0; 32],
    };
    tk.c2s_key.copy_from_slice(&take(C2S_KEY_LABEL, 32));
    tk.c2s_iv.copy_from_slice(&take(C2S_IV_LABEL, 12));
    tk.s2c_key.copy_from_slice(&take(S2C_KEY_LABEL, 32));
    tk.s2c_iv.copy_from_slice(&take(S2C_IV_LABEL, 12));
    tk.channel_binding.copy_from_slice(&take(CB_LABEL, 32));
    Ok(tk)
}

/// ACK tag (`04-hpke.md` §5). `binds` is the transcript in the order
/// `info, exportCtx, enc, ephC, ephS, initDID, respDID`.
pub fn make_ack_tag(
    seed: &[u8],
    ctx_id: &str,
    nonce: &str,
    kid: &str,
    binds: &[&[u8]],
) -> Result<Vec<u8>> {
    let ack_key = Zeroizing::new(hmac_expand(seed, ACK_KEY_LABEL, 32));
    let mut th = Sha256::new();
    for b in binds {
        th.update([0u8]);
        th.update(b);
    }
    let transcript = th.finalize();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&ack_key)
        .map_err(|e| Error::CryptoError(format!("HMAC init failed: {e}")))?;
    mac.update(ACK_MSG_LABEL);
    for s in [ctx_id, nonce, kid] {
        let len = s.len() as u16;
        mac.update(&len.to_be_bytes());
        mac.update(s.as_bytes());
    }
    mac.update(&transcript);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Constant-time ACK tag comparison.
pub fn verify_ack_tag(expected: &[u8], actual: &[u8]) -> Result<()> {
    if expected.len() == actual.len() && bool::from(expected.ct_eq(actual)) {
        Ok(())
    } else {
        Err(Error::Verification("ACK tag verification failed".into()))
    }
}

/// Whether a 32-byte shared secret is all zero (invalid point).
pub fn is_all_zero_32(data: &[u8]) -> bool {
    data.len() == 32 && bool::from(data.ct_eq(&[0u8; 32]))
}

/// Zeroise a buffer.
pub fn zero_bytes(data: &mut [u8]) {
    zeroize::Zeroize::zeroize(data);
}

/// SHA-256.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Hex SHA-256.
pub fn sha256_hash_hex(data: &[u8]) -> String {
    hex::encode(sha256_hash(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let kp = crate::crypto::X25519KeyPair::generate();
        let info = DefaultInfoBuilder.build_info("ctx", "did:a", "did:b");
        let ectx = DefaultInfoBuilder.build_export_context("ctx");
        let (enc, exp1) = kem_seal(kp.public_key_bytes(), &info, &ectx).unwrap();
        assert_eq!(enc.len(), 32);
        let exp2 = kem_open(&kp.private_key_bytes(), &enc, &info, &ectx).unwrap();
        assert_eq!(exp1, exp2);
        assert!(
            kem_open(&kp.private_key_bytes(), &enc, b"other info", &ectx)
                .map(|e| *e != *exp1)
                .unwrap_or(true)
        );
    }

    #[test]
    fn hmac_expand_is_counter_mode() {
        let a = hmac_expand(b"k", b"l", 32);
        let b = hmac_expand(b"k", b"l", 40);
        assert_eq!(&b[..32], &a[..]);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(b"k").unwrap();
        mac.update(b"l");
        mac.update(&1u32.to_be_bytes());
        assert_eq!(a, mac.finalize().into_bytes().to_vec());
    }

    #[test]
    fn ack_tag_binds_transcript() {
        let seed = [7u8; 32];
        let t1 = make_ack_tag(&seed, "ctx", "n", "kid", &[b"a", b"b"]).unwrap();
        let t2 = make_ack_tag(&seed, "ctx", "n", "kid", &[b"a", b"c"]).unwrap();
        assert_ne!(t1, t2);
        assert!(verify_ack_tag(&t1, &t1).is_ok());
        assert!(verify_ack_tag(&t1, &t2).is_err());
    }
}
