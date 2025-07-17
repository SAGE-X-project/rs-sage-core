//! FFI utility functions

use super::*;
use std::sync::Mutex;

// Thread-local storage for error messages
thread_local! {
    static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
}

/// Set the last error message
pub(crate) fn set_last_error(error: String) {
    LAST_ERROR.with(|e| {
        if let Ok(mut last_error) = e.lock() {
            *last_error = Some(error);
        }
    });
}

/// Free a C string allocated by this library
///
/// # Safety
/// The caller must ensure that `str` is a valid pointer allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn sage_string_free(str: *mut c_char) {
    if !str.is_null() {
        let _ = CString::from_raw(str);
    }
}

/// Allocate and copy a string for C
///
/// # Safety
/// The caller must free the returned string with `sage_string_free`.
pub(crate) unsafe fn string_to_c(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Generate a random nonce
///
/// # Safety
/// The caller must ensure that:
/// - `out_nonce` is a valid pointer with at least `len` bytes
/// - `len` is the desired length of the nonce
#[no_mangle]
pub unsafe extern "C" fn sage_generate_nonce(out_nonce: *mut c_uchar, len: size_t) -> SageResult {
    if out_nonce.is_null() || len == 0 {
        return SageErrorCode::InvalidInput.into();
    }

    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let nonce_slice = slice::from_raw_parts_mut(out_nonce, len);
    rng.fill_bytes(nonce_slice);
    
    SageErrorCode::Success.into()
}

/// Clear sensitive memory
///
/// # Safety
/// The caller must ensure that:
/// - `ptr` is a valid pointer
/// - `len` is the correct length
#[no_mangle]
pub unsafe extern "C" fn sage_secure_zero(ptr: *mut c_uchar, len: size_t) {
    if !ptr.is_null() && len > 0 {
        let slice = slice::from_raw_parts_mut(ptr, len);
        for byte in slice.iter_mut() {
            *byte = 0;
        }
        // Prevent compiler optimization
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}