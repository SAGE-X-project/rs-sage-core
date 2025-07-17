//! FFI (Foreign Function Interface) bindings for C/C++ integration

use crate::crypto::{KeyPair, KeyType, PublicKey};
use crate::error::Error;
use libc::{c_char, c_int, c_uchar, size_t};
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;

pub mod keypair;
pub mod signature;
pub mod utils;

pub use keypair::*;
pub use signature::*;
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
            Error::SerializationError(_) => SageErrorCode::InvalidInput,
            Error::Other(_) => SageErrorCode::UnknownError,
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
}

impl From<SageKeyType> for KeyType {
    fn from(key_type: SageKeyType) -> Self {
        match key_type {
            SageKeyType::Ed25519 => KeyType::Ed25519,
            SageKeyType::Secp256k1 => KeyType::Secp256k1,
        }
    }
}

impl From<KeyType> for SageKeyType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => SageKeyType::Ed25519,
            KeyType::Secp256k1 => SageKeyType::Secp256k1,
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

/// Get the last error message (thread-local)
#[no_mangle]
pub extern "C" fn sage_last_error() -> *const c_char {
    // TODO: Implement thread-local error storage
    ptr::null()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(SageErrorCode::from(Error::InvalidInput("test".to_string())), SageErrorCode::InvalidInput);
        assert_eq!(SageErrorCode::from(Error::CryptoError("test".to_string())), SageErrorCode::CryptoError);
    }

    #[test]
    fn test_key_type_conversion() {
        assert_eq!(KeyType::from(SageKeyType::Ed25519), KeyType::Ed25519);
        assert_eq!(KeyType::from(SageKeyType::Secp256k1), KeyType::Secp256k1);
    }
}