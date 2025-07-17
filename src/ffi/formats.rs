//! FFI functions for key format operations (PEM, DER, etc.)

use super::*;
use crate::formats::{KeyExporter, KeyFormat};

/// Key format enum for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum SageKeyFormat {
    /// Raw binary format
    Raw = 0,
    /// PEM format
    Pem = 1,
    /// DER format
    Der = 2,
    /// JWK format
    Jwk = 3,
}

impl From<SageKeyFormat> for KeyFormat {
    fn from(format: SageKeyFormat) -> Self {
        match format {
            SageKeyFormat::Raw => KeyFormat::Raw,
            SageKeyFormat::Pem => KeyFormat::Pem,
            SageKeyFormat::Der => KeyFormat::Der,
            SageKeyFormat::Jwk => KeyFormat::Jwk,
        }
    }
}

/// Export a key pair to a specific format
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `format` is a valid format
/// - `out_data` is a valid pointer with sufficient space
/// - `out_len` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_export_format(
    keypair: *const SageKeyPair,
    format: SageKeyFormat,
    out_data: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if keypair.is_null() || out_data.is_null() || out_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    let key_format = KeyFormat::from(format);

    match keypair.private_key().export(key_format) {
        Ok(exported_data) => {
            if exported_data.len() > *out_len {
                *out_len = exported_data.len();
                return SageErrorCode::InvalidInput.into();
            }

            ptr::copy_nonoverlapping(exported_data.as_ptr(), out_data, exported_data.len());
            *out_len = exported_data.len();
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Import a key pair from a specific format
///
/// # Safety
/// The caller must ensure that:
/// - `key_type` is a valid key type
/// - `format` is a valid format
/// - `data` is a valid pointer to the key data
/// - `data_len` is the correct length
/// - `out_keypair` is a valid pointer to a `*mut SageKeyPair`
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_import_format(
    key_type: SageKeyType,
    format: SageKeyFormat,
    data: *const c_uchar,
    data_len: size_t,
    out_keypair: *mut *mut SageKeyPair,
) -> SageResult {
    if data.is_null() || out_keypair.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let data_slice = slice::from_raw_parts(data, data_len);
    let _key_format = KeyFormat::from(format);

    match KeyPair::from_private_key_bytes(key_type.into(), data_slice) {
        Ok(keypair) => {
            let boxed = Box::new(SageKeyPair { inner: keypair });
            *out_keypair = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Export a public key to a specific format
///
/// # Safety
/// The caller must ensure that:
/// - `public_key` is a valid pointer
/// - `format` is a valid format
/// - `out_data` is a valid pointer with sufficient space
/// - `out_len` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_export_format(
    public_key: *const SagePublicKey,
    format: SageKeyFormat,
    out_data: *mut c_uchar,
    out_len: *mut size_t,
) -> SageResult {
    if public_key.is_null() || out_data.is_null() || out_len.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let public_key = &(*public_key).inner;
    let key_format = KeyFormat::from(format);

    match public_key.export(key_format) {
        Ok(exported_data) => {
            if exported_data.len() > *out_len {
                *out_len = exported_data.len();
                return SageErrorCode::InvalidInput.into();
            }

            ptr::copy_nonoverlapping(exported_data.as_ptr(), out_data, exported_data.len());
            *out_len = exported_data.len();
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Import a public key from a specific format
///
/// # Safety
/// The caller must ensure that:
/// - `key_type` is a valid key type
/// - `format` is a valid format
/// - `data` is a valid pointer to the key data
/// - `data_len` is the correct length
/// - `out_public_key` is a valid pointer to a `*mut SagePublicKey`
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_import_format(
    key_type: SageKeyType,
    format: SageKeyFormat,
    data: *const c_uchar,
    data_len: size_t,
    out_public_key: *mut *mut SagePublicKey,
) -> SageResult {
    if data.is_null() || out_public_key.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let data_slice = slice::from_raw_parts(data, data_len);
    let _key_format = KeyFormat::from(format);

    match PublicKey::from_bytes(key_type.into(), data_slice) {
        Ok(public_key) => {
            let boxed = Box::new(SagePublicKey { inner: public_key });
            *out_public_key = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Export a key pair to PEM format (convenience function)
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `out_pem` is a valid pointer to receive the PEM string
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_to_pem(
    keypair: *const SageKeyPair,
    out_pem: *mut *mut c_char,
) -> SageResult {
    if keypair.is_null() || out_pem.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;

    match keypair.private_key().export(KeyFormat::Pem) {
        Ok(pem_data) => {
            let pem_str = String::from_utf8_lossy(&pem_data);
            *out_pem = string_to_c(&pem_str);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Import a key pair from PEM format (convenience function)
///
/// # Safety
/// The caller must ensure that:
/// - `key_type` is a valid key type
/// - `pem_data` is a valid null-terminated string
/// - `out_keypair` is a valid pointer to a `*mut SageKeyPair`
#[no_mangle]
pub unsafe extern "C" fn sage_keypair_from_pem(
    key_type: SageKeyType,
    pem_data: *const c_char,
    out_keypair: *mut *mut SageKeyPair,
) -> SageResult {
    if pem_data.is_null() || out_keypair.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let pem_str = match CStr::from_ptr(pem_data).to_str() {
        Ok(s) => s,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };

    match KeyPair::from_private_key_bytes(key_type.into(), pem_str.as_bytes()) {
        Ok(keypair) => {
            let boxed = Box::new(SageKeyPair { inner: keypair });
            *out_keypair = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Export a public key to PEM format (convenience function)
///
/// # Safety
/// The caller must ensure that:
/// - `public_key` is a valid pointer
/// - `out_pem` is a valid pointer to receive the PEM string
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_to_pem(
    public_key: *const SagePublicKey,
    out_pem: *mut *mut c_char,
) -> SageResult {
    if public_key.is_null() || out_pem.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let public_key = &(*public_key).inner;

    match public_key.export(KeyFormat::Pem) {
        Ok(pem_data) => {
            let pem_str = String::from_utf8_lossy(&pem_data);
            *out_pem = string_to_c(&pem_str);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Import a public key from PEM format (convenience function)
///
/// # Safety
/// The caller must ensure that:
/// - `key_type` is a valid key type
/// - `pem_data` is a valid null-terminated string
/// - `out_public_key` is a valid pointer to a `*mut SagePublicKey`
#[no_mangle]
pub unsafe extern "C" fn sage_public_key_from_pem(
    key_type: SageKeyType,
    pem_data: *const c_char,
    out_public_key: *mut *mut SagePublicKey,
) -> SageResult {
    if pem_data.is_null() || out_public_key.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let pem_str = match CStr::from_ptr(pem_data).to_str() {
        Ok(s) => s,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };

    match PublicKey::from_bytes(key_type.into(), pem_str.as_bytes()) {
        Ok(public_key) => {
            let boxed = Box::new(SagePublicKey { inner: public_key });
            *out_public_key = Box::into_raw(boxed);
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}
