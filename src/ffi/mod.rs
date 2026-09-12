//! FFI (Foreign Function Interface) bindings for C/C++ integration

use crate::crypto::{KeyPair, KeyType, PublicKey};
use crate::error::Error;
use libc::{c_char, c_int, c_uchar, size_t};
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;

pub mod formats;
pub mod http;
pub mod keypair;
pub mod signature;
pub mod spec;
pub mod utils;

pub use formats::*;
pub use http::*;
pub use keypair::*;
pub use signature::*;
pub use spec::*;
pub use utils::*;

/// Error codes for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SageErrorCode {
    /// Success
    Success = 0,
    /// Invalid input parameter
    InvalidInput = 1,
    /// Cryptographic operation failed
    CryptoError = 2,
    /// Memory allocation failed
    AllocationError = 3,
    /// Unsupported operation
    Unsupported = 4,
    /// Verification failed
    VerificationFailed = 5,
    /// Unknown error
    UnknownError = 99,
}

impl From<Error> for SageErrorCode {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidInput(_) => SageErrorCode::InvalidInput,
            Error::CryptoError(_) => SageErrorCode::CryptoError,
            Error::Verification(_) => SageErrorCode::VerificationFailed,
            Error::Unsupported(_) => SageErrorCode::Unsupported,
            Error::Serialization(_) => SageErrorCode::InvalidInput,
            Error::Other(_) => SageErrorCode::UnknownError,
            Error::KeyGeneration(_) => SageErrorCode::CryptoError,
            Error::Signature(_) => SageErrorCode::CryptoError,
            Error::InvalidKeyFormat(_) => SageErrorCode::InvalidInput,
            Error::Base64(_) => SageErrorCode::InvalidInput,
            Error::Pem(_) => SageErrorCode::InvalidInput,
            Error::HttpSignature(_) => SageErrorCode::InvalidInput,
            Error::InvalidKeyType(_) => SageErrorCode::InvalidInput,
            Error::Io(_) => SageErrorCode::UnknownError,
            Error::ParseError(_) => SageErrorCode::InvalidInput,
            Error::ResolutionError(_) => SageErrorCode::UnknownError,
            Error::ValidationError(_) => SageErrorCode::InvalidInput,
            Error::NotFound(_) => SageErrorCode::InvalidInput,
            Error::StorageError(_) => SageErrorCode::UnknownError,
        }
    }
}

/// Result type for FFI functions
pub type SageResult = c_int;

/// Convert SageErrorCode to SageResult
impl From<SageErrorCode> for SageResult {
    fn from(code: SageErrorCode) -> Self {
        code as c_int
    }
}

/// Key type enum for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum SageKeyType {
    /// Ed25519 key type
    Ed25519 = 0,
    /// Secp256k1 key type
    Secp256k1 = 1,
    /// P-256 key type
    P256 = 2,
}

impl From<SageKeyType> for KeyType {
    fn from(key_type: SageKeyType) -> Self {
        match key_type {
            SageKeyType::Ed25519 => KeyType::Ed25519,
            SageKeyType::Secp256k1 => KeyType::Secp256k1,
            SageKeyType::P256 => KeyType::P256,
        }
    }
}

impl From<KeyType> for SageKeyType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => SageKeyType::Ed25519,
            KeyType::Secp256k1 => SageKeyType::Secp256k1,
            KeyType::P256 => SageKeyType::P256,
        }
    }
}

/// Opaque handle for KeyPair
pub struct SageKeyPair {
    inner: KeyPair,
}

/// Opaque handle for PublicKey
pub struct SagePublicKey {
    inner: PublicKey,
}

/// Opaque handle for Signature
pub struct SageSignature {
    inner: crate::crypto::Signature,
}

/// Initialize the library (currently no-op, reserved for future use)
#[no_mangle]
pub extern "C" fn sage_init() -> SageResult {
    SageErrorCode::Success.into()
}

/// Get the version string of the library
#[no_mangle]
pub extern "C" fn sage_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

use std::cell::RefCell;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Set the thread-local error message
/// Record the message of `err` for `sage_last_error` and return its code.
pub(crate) fn fail(err: Error) -> SageResult {
    let message = format!("{err}");
    let code: SageErrorCode = SageErrorCode::from(err);
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = CString::new(message).ok();
    });
    code.into()
}

/// Record a message for `sage_last_error` and return `code`.
pub(crate) fn fail_with(code: SageErrorCode, message: &str) -> SageResult {
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = CString::new(message).ok();
    });
    code.into()
}

/// Clear the thread-local error message
fn clear_last_error() {
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = None;
    });
}

/// Get the last error message (thread-local)
#[no_mangle]
pub extern "C" fn sage_last_error() -> *const c_char {
    LAST_ERROR.with(|last| {
        last.borrow()
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null())
    })
}

/// Clear the last error message
#[no_mangle]
pub extern "C" fn sage_clear_error() {
    clear_last_error();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(
            SageErrorCode::from(Error::InvalidInput("test".to_string())),
            SageErrorCode::InvalidInput
        );
        assert_eq!(
            SageErrorCode::from(Error::CryptoError("test".to_string())),
            SageErrorCode::CryptoError
        );
    }

    #[test]
    fn test_key_type_conversion() {
        assert_eq!(KeyType::from(SageKeyType::Ed25519), KeyType::Ed25519);
        assert_eq!(KeyType::from(SageKeyType::Secp256k1), KeyType::Secp256k1);
    }
}
