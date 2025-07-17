//! FFI functions for signature operations

use super::*;
use crate::crypto::{Signer, Verifier};

/// Sign a message
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `message` is a valid pointer to message bytes
/// - `message_len` is the correct length
/// - `out_signature` is a valid pointer to a `*mut SageSignature`
#[no_mangle]
pub unsafe extern "C" fn sage_sign(
    keypair: *const SageKeyPair,
    message: *const c_uchar,
    message_len: size_t,
    out_signature: *mut *mut SageSignature,
) -> SageResult {
    if keypair.is_null() || message.is_null() || out_signature.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    let message_slice = slice::from_raw_parts(message, message_len);

    match keypair.sign(message_slice) {
        Ok(signature) => {
            let boxed = Box::new(SageSignature { inner: signature });
            *out_signature = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Verify a signature with a key pair
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `message` is a valid pointer to message bytes
/// - `message_len` is the correct length
/// - `signature` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_verify_with_keypair(
    keypair: *const SageKeyPair,
    message: *const c_uchar,
    message_len: size_t,
    signature: *const SageSignature,
) -> SageResult {
    if keypair.is_null() || message.is_null() || signature.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    let message_slice = slice::from_raw_parts(message, message_len);
    let signature = &(*signature).inner;

    match keypair.verify(message_slice, signature) {
        Ok(()) => SageErrorCode::Success.into(),
        Err(_) => SageErrorCode::VerificationFailed.into(),
    }
}

/// Verify a signature with a public key
///
/// # Safety
/// The caller must ensure that:
/// - `public_key` is a valid pointer
/// - `message` is a valid pointer to message bytes
/// - `message_len` is the correct length
/// - `signature` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_verify_with_public_key(
    public_key: *const SagePublicKey,
    message: *const c_uchar,
    message_len: size_t,
    signature: *const SageSignature,
) -> SageResult {
    if public_key.is_null() || message.is_null() || signature.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let public_key = &(*public_key).inner;
    let message_slice = slice::from_raw_parts(message, message_len);
    let signature = &(*signature).inner;

    match public_key.verify(message_slice, signature) {
        Ok(()) => SageErrorCode::Success.into(),
        Err(_) => SageErrorCode::VerificationFailed.into(),
    }
}

/// Free a signature
///
/// # Safety
/// The caller must ensure that `signature` is a valid pointer obtained from `sage_sign`.
#[no_mangle]
pub unsafe extern "C" fn sage_signature_free(signature: *mut SageSignature) {
    if !signature.is_null() {
        let _ = Box::from_raw(signature);
    }
}

/// Export a signature to bytes
///
/// # Safety
/// The caller must ensure that:
/// - `signature` is a valid pointer
/// - `out_bytes` is a valid pointer with sufficient space (up to 72 bytes for DER-encoded signatures)
/// - `out_len` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_signature_export(
    signature: *const SageSignature,
    out_bytes: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if signature.is_null() || out_bytes.is_null() || out_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let signature = &(*signature).inner;
    let sig_bytes = signature.to_bytes();

    if sig_bytes.len() > *out_len {
        *out_len = sig_bytes.len();
        return SageErrorCode::InvalidInput.into();
    }

    ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_bytes, sig_bytes.len());
    *out_len = sig_bytes.len();
    SageErrorCode::Success.into()
}

/// Free a public key
///
/// # Safety
/// The caller must ensure that `public_key` is a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_free(public_key: *mut SagePublicKey) {
    if !public_key.is_null() {
        let _ = Box::from_raw(public_key);
    }
}

/// Export a public key to bytes
///
/// # Safety
/// The caller must ensure that:
/// - `public_key` is a valid pointer
/// - `out_bytes` is a valid pointer with sufficient space (32-33 bytes)
/// - `out_len` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_export(
    public_key: *const SagePublicKey,
    out_bytes: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if public_key.is_null() || out_bytes.is_null() || out_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let public_key = &(*public_key).inner;
    let key_bytes = public_key.to_bytes();

    if key_bytes.len() > *out_len {
        *out_len = key_bytes.len();
        return SageErrorCode::InvalidInput.into();
    }

    ptr::copy_nonoverlapping(key_bytes.as_ptr(), out_bytes, key_bytes.len());
    *out_len = key_bytes.len();
    SageErrorCode::Success.into()
}

/// Import a public key from bytes
///
/// # Safety
/// The caller must ensure that:
/// - `key_type` is a valid key type
/// - `bytes` is a valid pointer to public key bytes
/// - `bytes_len` is the correct length for the key type
/// - `out_public_key` is a valid pointer to a `*mut SagePublicKey`
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_import(
    key_type: SageKeyType,
    bytes: *const c_uchar,
    bytes_len: size_t,
    out_public_key: *mut *mut SagePublicKey,
) -> SageResult {
    if bytes.is_null() || out_public_key.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let bytes_slice = slice::from_raw_parts(bytes, bytes_len);
    
    match PublicKey::from_bytes(key_type.into(), bytes_slice) {
        Ok(public_key) => {
            let boxed = Box::new(SagePublicKey { inner: public_key });
            *out_public_key = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}