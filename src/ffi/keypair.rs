//! FFI functions for key pair operations

use super::*;
use crate::crypto::KeyPair;

/// Generate a new key pair
///
/// # Safety
/// The caller must ensure that `out_keypair` is a valid pointer to a `*mut SageKeyPair`.
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_generate(
    key_type: SageKeyType,
    out_keypair: *mut *mut SageKeyPair,
) -> SageResult {
    if out_keypair.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    match KeyPair::generate(key_type.into()) {
        Ok(keypair) => {
            let boxed = Box::new(SageKeyPair { inner: keypair });
            *out_keypair = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Free a key pair
///
/// # Safety
/// The caller must ensure that `keypair` is a valid pointer obtained from `sage_keypair_generate`.
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_free(keypair: *mut SageKeyPair) {
    if !keypair.is_null() {
        let _ = Box::from_raw(keypair);
    }
}

/// Get the public key from a key pair
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `out_public_key` is a valid pointer to a `*mut SagePublicKey`
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_get_public_key(
    keypair: *const SageKeyPair,
    out_public_key: *mut *mut SagePublicKey,
) -> SageResult {
    if keypair.is_null() || out_public_key.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    let public_key = keypair.public_key().clone();
    let boxed = Box::new(SagePublicKey { inner: public_key });
    *out_public_key = Box::into_raw(boxed);
    SageErrorCode::Success.into()
}

/// Get the key ID from a key pair
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `out_key_id` is a valid pointer with sufficient space (at least 64 bytes)
/// - `out_len` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_get_key_id(
    keypair: *const SageKeyPair,
    out_key_id: *mut c_char,
    out_len: *mut size_t,
) -> SageResult {
    if keypair.is_null() || out_key_id.is_null() || out_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    let key_id = keypair.key_id();
    let key_id_bytes = key_id.as_bytes();

    if key_id_bytes.len() > *out_len {
        *out_len = key_id_bytes.len();
        return SageErrorCode::InvalidInput.into();
    }

    ptr::copy_nonoverlapping(key_id_bytes.as_ptr(), out_key_id as *mut u8, key_id_bytes.len());
    *out_len = key_id_bytes.len();
    SageErrorCode::Success.into()
}

/// Get the key type from a key pair
///
/// # Safety
/// The caller must ensure that `keypair` is a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_get_type(keypair: *const SageKeyPair) -> SageKeyType {
    if keypair.is_null() {
        return SageKeyType::Ed25519; // Default, though this is an error case
    }

    let keypair = &(*keypair).inner;
    keypair.key_type().into()
}

/// Export a key pair to bytes
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `out_private_key` is a valid pointer with sufficient space (32 bytes)
/// - `private_key_len` is a valid pointer
/// - `out_public_key` is a valid pointer with sufficient space (32-33 bytes)
/// - `public_key_len` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_export(
    keypair: *const SageKeyPair,
    out_private_key: *mut c_uchar,
    private_key_len: *mut size_t,
    out_public_key: *mut c_uchar,
    public_key_len: *mut size_t,
) -> SageResult {
    if keypair.is_null() 
        || out_private_key.is_null() 
        || private_key_len.is_null()
        || out_public_key.is_null()
        || public_key_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    
    // Export private key
    let private_bytes = keypair.private_key_bytes();
    if private_bytes.len() > *private_key_len {
        *private_key_len = private_bytes.len();
        return SageErrorCode::InvalidInput.into();
    }
    ptr::copy_nonoverlapping(private_bytes.as_ptr(), out_private_key, private_bytes.len());
    *private_key_len = private_bytes.len();

    // Export public key
    let public_bytes = keypair.public_key_bytes();
    if public_bytes.len() > *public_key_len {
        *public_key_len = public_bytes.len();
        return SageErrorCode::InvalidInput.into();
    }
    ptr::copy_nonoverlapping(public_bytes.as_ptr(), out_public_key, public_bytes.len());
    *public_key_len = public_bytes.len();

    SageErrorCode::Success.into()
}

/// Import a key pair from bytes
///
/// # Safety
/// The caller must ensure that:
/// - `key_type` is a valid key type
/// - `private_key` is a valid pointer to private key bytes
/// - `private_key_len` is the correct length for the key type
/// - `out_keypair` is a valid pointer to a `*mut SageKeyPair`
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_import(
    key_type: SageKeyType,
    private_key: *const c_uchar,
    private_key_len: size_t,
    out_keypair: *mut *mut SageKeyPair,
) -> SageResult {
    if private_key.is_null() || out_keypair.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let private_key_slice = slice::from_raw_parts(private_key, private_key_len);
    
    match KeyPair::from_private_key_bytes(key_type.into(), private_key_slice) {
        Ok(keypair) => {
            let boxed = Box::new(SageKeyPair { inner: keypair });
            *out_keypair = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}