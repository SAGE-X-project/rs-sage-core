//! FFI utility functions

use super::*;
use std::cell::RefCell;

// Thread-local storage for error messages
thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

/// Set the last error message
pub(crate) fn set_last_error(error: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(error);
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
        
        // Use volatile writes to prevent optimization
        for i in 0..len {
            std::ptr::write_volatile(slice.as_mut_ptr().add(i), 0);
        }
        
        // Additional fence to ensure ordering
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}