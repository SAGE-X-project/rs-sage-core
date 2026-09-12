//! FFI functions for the remaining sage-spec surfaces: JCS canonicalisation,
//! `did:sage` validation, key proof of possession, agent card verification
//! and session records.
//!
//! Output buffers follow the library convention: the caller passes a buffer
//! and its capacity in the in/out length; on a too-small buffer the required
//! length is written and `InvalidInput` returned.

use super::*;
use crate::session::{SecureSession, Session, SessionConfig};
use std::ffi::CStr;

/// Opaque handle for a session
pub struct SageSession {
    inner: SecureSession,
}

unsafe fn write_out(data: &[u8], out: *mut c_uchar, out_len: *mut size_t) -> SageResult {
    if out_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    if out.is_null() || *out_len < data.len() {
        *out_len = data.len();
        return fail_with(SageErrorCode::InvalidInput, "output buffer too small");
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    *out_len = data.len();
    SageErrorCode::Success.into()
}

unsafe fn input<'a>(p: *const c_uchar, len: size_t) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        slice::from_raw_parts(p, len)
    }
}

/// Canonicalise JSON (RFC 8785).
///
/// # Safety
/// `input` must point to `input_len` bytes; `out`/`out_len` follow the buffer convention.
#[no_mangle]
pub unsafe extern "C" fn sage_jcs_canonicalize(
    input_ptr: *const c_uchar,
    input_len: size_t,
    out: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    match crate::jcs::canonicalize(input(input_ptr, input_len)) {
        Ok(c) => write_out(&c, out, out_len),
        Err(e) => fail(e),
    }
}

/// Whether `did` is a well-formed `did:sage:<chain>:<identifier>`.
///
/// # Safety
/// `did` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sage_did_validate(did: *const c_char) -> SageResult {
    if did.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    match CStr::from_ptr(did).to_str().ok().map(crate::did::parse_did) {
        Some(Ok(_)) => SageErrorCode::Success.into(),
        Some(Err(e)) => fail(e),
        None => fail_with(SageErrorCode::InvalidInput, "did is not valid UTF-8"),
    }
}

/// Generate the key proof of possession of `keypair` for `did`
/// (64 bytes Ed25519, 65 bytes secp256k1).
///
/// # Safety
/// `keypair` must be valid; `did` NUL-terminated; buffer convention for `out`.
#[no_mangle]
pub unsafe extern "C" fn sage_key_pop_generate(
    keypair: *const SageKeyPair,
    did: *const c_char,
    out: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if keypair.is_null() || did.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let Ok(did) = CStr::from_ptr(did).to_str() else {
        return fail_with(SageErrorCode::InvalidInput, "did is not valid UTF-8");
    };
    match crate::did::generate_key_pop(did, &(*keypair).inner) {
        Ok(proof) => write_out(&proof, out, out_len),
        Err(e) => fail(e),
    }
}

/// Verify a key proof of possession.
///
/// # Safety
/// `key_data` and `proof` must point to their lengths; `did` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn sage_key_pop_verify(
    key_type: SageKeyType,
    key_data: *const c_uchar,
    key_len: size_t,
    did: *const c_char,
    proof: *const c_uchar,
    proof_len: size_t,
) -> SageResult {
    if did.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let Ok(did) = CStr::from_ptr(did).to_str() else {
        return fail_with(SageErrorCode::InvalidInput, "did is not valid UTF-8");
    };
    match crate::did::verify_key_pop(
        did,
        key_type.into(),
        input(key_data, key_len),
        input(proof, proof_len),
    ) {
        Ok(()) => SageErrorCode::Success.into(),
        Err(e) => {
            let msg = format!("{e}");
            fail_with(SageErrorCode::VerificationFailed, &msg)
        }
    }
}

/// Parse an A2A agent card and verify its proof.
///
/// # Safety
/// `json` must point to `json_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sage_a2a_card_verify(
    json: *const c_uchar,
    json_len: size_t,
) -> SageResult {
    let card = match crate::did::A2AAgentCard::from_json(input(json, json_len)) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match card.verify_proof() {
        Ok(()) => SageErrorCode::Success.into(),
        Err(e) => {
            let msg = format!("{e}");
            fail_with(SageErrorCode::VerificationFailed, &msg)
        }
    }
}

/// Session id for a seed and label (`base64url(SHA-256(label || seed)[0:16])`).
///
/// # Safety
/// `seed` must point to `seed_len` bytes; `label` NUL-terminated; buffer convention for `out`.
#[no_mangle]
pub unsafe extern "C" fn sage_session_id_from_seed(
    seed: *const c_uchar,
    seed_len: size_t,
    label: *const c_char,
    out: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    let Some(label) = (!label.is_null())
        .then(|| CStr::from_ptr(label).to_str().ok())
        .flatten()
    else {
        return fail_with(SageErrorCode::InvalidInput, "label is not a valid string");
    };
    match crate::session::compute_session_id(input(seed, seed_len), label) {
        Ok(id) => write_out(id.as_bytes(), out, out_len),
        Err(e) => fail(e),
    }
}

/// Create a session. `role` is 1 for the initiator, 0 for the responder and
/// -1 for a session without a role (shared keys only). `rekey_interval` 0
/// disables key rotation; 256 is the default.
///
/// # Safety
/// `session_id` NUL-terminated; `seed` must point to `seed_len` bytes; `out` valid.
#[no_mangle]
pub unsafe extern "C" fn sage_session_new(
    session_id: *const c_char,
    seed: *const c_uchar,
    seed_len: size_t,
    role: c_int,
    rekey_interval: u64,
    out: *mut *mut SageSession,
) -> SageResult {
    if session_id.is_null() || out.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let Ok(id) = CStr::from_ptr(session_id).to_str() else {
        return fail_with(SageErrorCode::InvalidInput, "session_id is not valid UTF-8");
    };
    let config = SessionConfig {
        rekey_interval,
        max_messages: 0,
        ..Default::default()
    };
    let result = match role {
        1 => SecureSession::with_role(id.to_string(), input(seed, seed_len), true, config),
        0 => SecureSession::with_role(id.to_string(), input(seed, seed_len), false, config),
        _ => SecureSession::new(id.to_string(), input(seed, seed_len), config),
    };
    match result {
        Ok(s) => {
            *out = Box::into_raw(Box::new(SageSession { inner: s }));
            SageErrorCode::Success.into()
        }
        Err(e) => fail(e),
    }
}

/// Free a session
///
/// # Safety
/// `session` must have been returned by `sage_session_new` or be NULL.
#[no_mangle]
pub unsafe extern "C" fn sage_session_free(session: *mut SageSession) {
    if !session.is_null() {
        let _ = Box::from_raw(session);
    }
}

/// Encrypt a record (outbound direction for role sessions). `aad` may be NULL.
///
/// # Safety
/// Pointers must be valid; buffer convention for `out`.
#[no_mangle]
pub unsafe extern "C" fn sage_session_encrypt(
    session: *const SageSession,
    plaintext: *const c_uchar,
    plaintext_len: size_t,
    aad: *const c_uchar,
    aad_len: size_t,
    out: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if session.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let s = &(*session).inner;
    let result = if s.is_initiator().is_some() {
        s.encrypt_with_aad_outbound(input(plaintext, plaintext_len), input(aad, aad_len))
    } else {
        s.encrypt_with_aad(input(plaintext, plaintext_len), input(aad, aad_len))
    };
    match result {
        Ok(r) => write_out(&r, out, out_len),
        Err(e) => fail(e),
    }
}

/// Decrypt a record (inbound direction for role sessions). `aad` may be NULL.
///
/// # Safety
/// Pointers must be valid; buffer convention for `out`.
#[no_mangle]
pub unsafe extern "C" fn sage_session_decrypt(
    session: *const SageSession,
    record: *const c_uchar,
    record_len: size_t,
    aad: *const c_uchar,
    aad_len: size_t,
    out: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if session.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let s = &(*session).inner;
    let result = if s.is_initiator().is_some() {
        s.decrypt_with_aad_inbound(input(record, record_len), input(aad, aad_len))
    } else {
        s.decrypt_with_aad(input(record, record_len), input(aad, aad_len))
    };
    match result {
        Ok(r) => write_out(&r, out, out_len),
        Err(e) => {
            let msg = format!("{e}");
            fail_with(SageErrorCode::VerificationFailed, &msg)
        }
    }
}

/// Records sent plus received.
///
/// # Safety
/// `session` must be valid.
#[no_mangle]
pub unsafe extern "C" fn sage_session_message_count(session: *const SageSession) -> size_t {
    if session.is_null() {
        return 0;
    }
    (*session).inner.get_message_count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn jcs_and_did_and_session_roundtrip() {
        unsafe {
            let input_json = br#"{"b":1,"a":[2,3]}"#;
            let mut buf = vec![0u8; 64];
            let mut len = buf.len();
            assert_eq!(
                sage_jcs_canonicalize(
                    input_json.as_ptr(),
                    input_json.len(),
                    buf.as_mut_ptr(),
                    &mut len
                ),
                0
            );
            assert_eq!(&buf[..len], br#"{"a":[2,3],"b":1}"#);
            let did = CString::new("did:sage:ethereum:0xabc").unwrap();
            assert_eq!(sage_did_validate(did.as_ptr()), 0);
            let bad = CString::new("did:web:x").unwrap();
            assert_ne!(sage_did_validate(bad.as_ptr()), 0);
            assert!(!sage_last_error().is_null());

            let seed = [7u8; 32];
            let id = CString::new("sid").unwrap();
            let mut a: *mut SageSession = ptr::null_mut();
            let mut b: *mut SageSession = ptr::null_mut();
            assert_eq!(
                sage_session_new(id.as_ptr(), seed.as_ptr(), 32, 1, 256, &mut a),
                0
            );
            assert_eq!(
                sage_session_new(id.as_ptr(), seed.as_ptr(), 32, 0, 256, &mut b),
                0
            );
            let mut rec = vec![0u8; 128];
            let mut rec_len = rec.len();
            assert_eq!(
                sage_session_encrypt(
                    a,
                    b"hi".as_ptr(),
                    2,
                    ptr::null(),
                    0,
                    rec.as_mut_ptr(),
                    &mut rec_len
                ),
                0
            );
            let mut pt = vec![0u8; 16];
            let mut pt_len = pt.len();
            assert_eq!(
                sage_session_decrypt(
                    b,
                    rec.as_ptr(),
                    rec_len,
                    ptr::null(),
                    0,
                    pt.as_mut_ptr(),
                    &mut pt_len
                ),
                0
            );
            assert_eq!(&pt[..pt_len], b"hi");
            assert_ne!(
                sage_session_decrypt(
                    b,
                    rec.as_ptr(),
                    rec_len,
                    ptr::null(),
                    0,
                    pt.as_mut_ptr(),
                    &mut pt_len
                ),
                0,
                "replay"
            );
            sage_session_free(a);
            sage_session_free(b);
        }
    }
}
