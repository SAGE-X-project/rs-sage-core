//! Common HPKE Utilities
//!
//! This module provides utility functions for HPKE operations including
//! secret combination, ACK tag generation, and traffic key derivation.

use crate::error::{Error, Result};
use crate::hpke::types::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Combine HPKE exporter secret with E2E ECDH secret
///
/// This function implements the SAGE secret combination algorithm:
/// 1. Concatenate exporterHPKE || ssE2E
/// 2. HKDF-Extract with exportCtx as salt
/// 3. HKDF-Expand with label "SAGE-HPKE+E2E-Combiner"
///
/// # Arguments
/// * `exporter_hpke` - HPKE exporter secret (32 bytes)
/// * `ss_e2e` - E2E ECDH shared secret (32 bytes)
/// * `export_ctx` - HPKE export context string
///
/// # Returns
/// Combined secret (32 bytes)
///
/// # Security
/// - Uses HKDF-SHA256 for cryptographic strength
/// - Output is automatically zeroized on drop
pub fn combine_secrets(
    exporter_hpke: &[u8],
    ss_e2e: &[u8],
    export_ctx: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // 1. Concatenate secrets
    let mut ikm = Vec::with_capacity(exporter_hpke.len() + ss_e2e.len());
    ikm.extend_from_slice(exporter_hpke);
    ikm.extend_from_slice(ss_e2e);
    let ikm = Zeroizing::new(ikm);

    // 2. HKDF-Extract with exportCtx as salt
    let hkdf = Hkdf::<Sha256>::new(Some(export_ctx), &ikm);

    // 3. HKDF-Expand with combiner label
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(COMBINER_LABEL, &mut okm)
        .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))?;

    Ok(okm)
}

/// Make ACK tag for key confirmation
///
/// This function generates an HMAC-based acknowledgment tag that binds
/// all handshake parameters together. Both client and server compute this
/// independently to verify they derived the same session key.
///
/// # Arguments
/// * `seed` - Combined secret (32 bytes)
/// * `ctx_id` - Context identifier
/// * `nonce` - Nonce for replay protection
/// * `kid` - Key identifier
/// * `binds` - Additional data to bind (e.g., info, exportCtx, enc, ephC, ephS)
///
/// # Returns
/// HMAC tag (32 bytes)
///
/// # Algorithm
/// 1. Derive ackKey = HKDF-Expand(seed, "SAGE-ack-key-v1", 32)
/// 2. Compute transcript hash = SHA256(0x00 || bind[0] || 0x00 || bind[1] || ...)
/// 3. Compute HMAC = HMAC-SHA256(ackKey, "SAGE-ack-msg|v1|" || len(ctxID) || ctxID || len(nonce) || nonce || len(kid) || kid || transcriptHash)
pub fn make_ack_tag(
    seed: &[u8],
    ctx_id: &str,
    nonce: &str,
    kid: &str,
    binds: &[&[u8]],
) -> Result<Vec<u8>> {
    // 1. Derive ack key using HKDF-Expand
    let ack_key = hkdf_expand(seed, ACK_KEY_LABEL, 32)?;

    // 2. Compute transcript hash
    let mut hasher = Sha256::new();
    for b in binds {
        hasher.update([0u8]); // delimiter
        hasher.update(b);
    }
    let transcript_hash = hasher.finalize();

    // 3. Compute HMAC
    let mut mac = HmacSha256::new_from_slice(&ack_key)
        .map_err(|e| Error::CryptoError(format!("HMAC init failed: {e}")))?;

    mac.update(ACK_MSG_LABEL);

    // Length-prefixed strings
    write_length_prefixed(&mut mac, ctx_id.as_bytes());
    write_length_prefixed(&mut mac, nonce.as_bytes());
    write_length_prefixed(&mut mac, kid.as_bytes());
    mac.update(&transcript_hash);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify ACK tag in constant time
///
/// # Arguments
/// * `expected` - Expected ACK tag
/// * `actual` - Actual ACK tag to verify
///
/// # Returns
/// `Ok(())` if tags match, `Err` otherwise
///
/// # Security
/// Uses constant-time comparison to prevent timing attacks
pub fn verify_ack_tag(expected: &[u8], actual: &[u8]) -> Result<()> {
    if expected.len() != actual.len() {
        return Err(Error::CryptoError("ACK tag length mismatch".into()));
    }

    if expected.ct_eq(actual).into() {
        Ok(())
    } else {
        Err(Error::CryptoError("ACK tag verification failed".into()))
    }
}

/// Derive traffic keys for bidirectional communication (sage v1.0.1)
///
/// This function derives separate keys for client-to-server and server-to-client
/// communication, as well as a channel binding value.
///
/// # Arguments
/// * `seed` - Combined secret (32 bytes)
///
/// # Returns
/// TrafficKeys structure containing C2S key/IV, S2C key/IV, and channel binding
///
/// # Derivation
/// - C2S Key = HKDF-Expand(seed, "SAGE-c2s:key", 32)
/// - C2S IV = HKDF-Expand(seed, "SAGE-c2s:iv", 12)
/// - S2C Key = HKDF-Expand(seed, "SAGE-s2c:key", 32)
/// - S2C IV = HKDF-Expand(seed, "SAGE-s2c:iv", 12)
/// - Channel Binding = HKDF-Expand(seed, "SAGE-cb-v1", 32)
pub fn derive_traffic_keys(seed: &[u8]) -> Result<TrafficKeys> {
    let c2s_key = hkdf_expand_array::<32>(seed, C2S_KEY_LABEL)?;
    let c2s_iv = hkdf_expand_array::<12>(seed, C2S_IV_LABEL)?;
    let s2c_key = hkdf_expand_array::<32>(seed, S2C_KEY_LABEL)?;
    let s2c_iv = hkdf_expand_array::<12>(seed, S2C_IV_LABEL)?;
    let channel_binding = hkdf_expand_array::<32>(seed, CB_LABEL)?;

    Ok(TrafficKeys {
        c2s_key,
        c2s_iv,
        s2c_key,
        s2c_iv,
        channel_binding,
    })
}

/// HKDF-Expand utility function
///
/// # Arguments
/// * `prk` - Pseudorandom key (typically from HKDF-Extract)
/// * `info` - Context and application specific information
/// * `length` - Length of output keying material in bytes
///
/// # Returns
/// Output keying material of specified length
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| Error::CryptoError(format!("HKDF from PRK failed: {e}")))?;

    let mut okm = Zeroizing::new(vec![0u8; length]);
    hkdf.expand(info, &mut okm)
        .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))?;

    Ok(okm)
}

/// HKDF-Expand into fixed-size array
///
/// # Arguments
/// * `prk` - Pseudorandom key
/// * `info` - Context information
///
/// # Returns
/// Fixed-size array of output keying material
fn hkdf_expand_array<const N: usize>(prk: &[u8], info: &[u8]) -> Result<[u8; N]> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| Error::CryptoError(format!("HKDF from PRK failed: {e}")))?;

    let mut okm = [0u8; N];
    hkdf.expand(info, &mut okm)
        .map_err(|e| Error::CryptoError(format!("HKDF expand failed: {e}")))?;

    Ok(okm)
}

/// Write length-prefixed data to HMAC
///
/// Format: 2-byte big-endian length || data
fn write_length_prefixed(mac: &mut HmacSha256, data: &[u8]) {
    let len = data.len() as u16;
    mac.update(&len.to_be_bytes());
    mac.update(data);
}

/// Check if a 32-byte array is all zeros (sage v1.0.1 security)
///
/// This is used to detect invalid ECDH outputs which should be rejected.
///
/// # Security
/// Uses constant-time comparison
pub fn is_all_zero_32(data: &[u8; 32]) -> bool {
    let zero = [0u8; 32];
    data.ct_eq(&zero).into()
}

/// Securely zero bytes in memory (sage v1.0.1 security)
///
/// This function is a wrapper around zeroize for explicit memory clearing.
///
/// # Arguments
/// * `data` - Mutable slice to zero
pub fn zero_bytes(data: &mut [u8]) {
    zeroize::Zeroize::zeroize(data);
}

/// Compute SHA256 hash
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// SHA256 hash (32 bytes)
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA256 hash and return as hex string
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// Hex-encoded SHA256 hash
pub fn sha256_hash_hex(data: &[u8]) -> String {
    hex::encode(sha256_hash(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_secrets() {
        let exporter = vec![1u8; 32];
        let ss_e2e = vec![2u8; 32];
        let export_ctx = b"test-export-context";

        let combined = combine_secrets(&exporter, &ss_e2e, export_ctx).unwrap();
        assert_eq!(combined.len(), 32);

        // Same inputs should produce same output
        let combined2 = combine_secrets(&exporter, &ss_e2e, export_ctx).unwrap();
        assert_eq!(*combined, *combined2);

        // Different inputs should produce different output
        let exporter2 = vec![3u8; 32];
        let combined3 = combine_secrets(&exporter2, &ss_e2e, export_ctx).unwrap();
        assert_ne!(*combined, *combined3);
    }

    #[test]
    fn test_make_ack_tag() {
        let seed = vec![0x42u8; 32];
        let ctx_id = "ctx-123";
        let nonce = "nonce-456";
        let kid = "kid-789";
        let binds = vec![b"bind1".as_ref(), b"bind2".as_ref()];

        let tag = make_ack_tag(&seed, ctx_id, nonce, kid, &binds).unwrap();
        assert_eq!(tag.len(), 32);

        // Same inputs should produce same tag
        let tag2 = make_ack_tag(&seed, ctx_id, nonce, kid, &binds).unwrap();
        assert_eq!(tag, tag2);

        // Different seed should produce different tag
        let seed2 = vec![0x43u8; 32];
        let tag3 = make_ack_tag(&seed2, ctx_id, nonce, kid, &binds).unwrap();
        assert_ne!(tag, tag3);
    }

    #[test]
    fn test_verify_ack_tag() {
        let tag1 = vec![0x42u8; 32];
        let tag2 = vec![0x42u8; 32];
        let tag3 = vec![0x43u8; 32];

        assert!(verify_ack_tag(&tag1, &tag2).is_ok());
        assert!(verify_ack_tag(&tag1, &tag3).is_err());
    }

    #[test]
    fn test_derive_traffic_keys() {
        let seed = vec![0x42u8; 32];
        let keys = derive_traffic_keys(&seed).unwrap();

        // All keys should be different
        assert_ne!(&keys.c2s_key[..], &keys.s2c_key[..]);
        assert_ne!(&keys.c2s_key[..], &keys.channel_binding[..]);
        assert_ne!(&keys.s2c_key[..], &keys.channel_binding[..]);

        // IVs should be 12 bytes
        assert_eq!(keys.c2s_iv.len(), 12);
        assert_eq!(keys.s2c_iv.len(), 12);

        // Keys should be deterministic
        let keys2 = derive_traffic_keys(&seed).unwrap();
        assert_eq!(keys.c2s_key, keys2.c2s_key);
        assert_eq!(keys.c2s_iv, keys2.c2s_iv);
        assert_eq!(keys.s2c_key, keys2.s2c_key);
        assert_eq!(keys.s2c_iv, keys2.s2c_iv);
        assert_eq!(keys.channel_binding, keys2.channel_binding);
    }

    #[test]
    fn test_is_all_zero_32() {
        let zero = [0u8; 32];
        let non_zero = {
            let mut arr = [0u8; 32];
            arr[15] = 1;
            arr
        };

        assert!(is_all_zero_32(&zero));
        assert!(!is_all_zero_32(&non_zero));
    }

    #[test]
    fn test_zero_bytes() {
        let mut data = vec![0x42u8; 32];
        zero_bytes(&mut data);
        assert_eq!(data, vec![0u8; 32]);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);

        let hash_hex = sha256_hash_hex(data);
        assert_eq!(hash_hex.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(
            hash_hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
