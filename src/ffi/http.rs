//! FFI functions for HTTP signature operations (RFC 9421)

use super::*;
use crate::rfc9421::{HttpSigner, HttpVerifier};
use ::http::Request;
use std::ffi::CStr;

/// Opaque handle for HTTP signer
pub struct SageHttpSigner {
    inner: HttpSigner,
}

/// Opaque handle for HTTP verifier
pub struct SageHttpVerifier {
    inner: HttpVerifier,
}

/// HTTP request structure for FFI
#[repr(C)]
pub struct SageHttpRequest {
    method: *const c_char,
    uri: *const c_char,
    headers: *const SageHttpHeader,
    headers_count: size_t,
    body: *const c_uchar,
    body_len: size_t,
}

/// HTTP response structure for FFI
#[repr(C)]
pub struct SageHttpResponse {
    status: c_int,
    headers: *const SageHttpHeader,
    headers_count: size_t,
    body: *const c_uchar,
    body_len: size_t,
}

/// HTTP header structure for FFI
#[repr(C)]
pub struct SageHttpHeader {
    name: *const c_char,
    value: *const c_char,
}

/// Create a new HTTP signer
///
/// # Safety
/// The caller must ensure that:
/// - `keypair` is a valid pointer
/// - `out_signer` is a valid pointer to a `*mut SageHttpSigner`
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_new(
    keypair: *const SageKeyPair,
    out_signer: *mut *mut SageHttpSigner,
) -> SageResult {
    if keypair.is_null() || out_signer.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let keypair = &(*keypair).inner;
    let signer = HttpSigner::new(keypair.clone());
    let boxed = Box::new(SageHttpSigner { inner: signer });
    *out_signer = Box::into_raw(boxed);
    SageErrorCode::Success.into()
}

/// Free an HTTP signer
///
/// # Safety
/// The caller must ensure that `signer` is a valid pointer obtained from `sage_http_signer_new`.
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_free(signer: *mut SageHttpSigner) {
    if !signer.is_null() {
        let _ = Box::from_raw(signer);
    }
}

/// Sign an HTTP request
///
/// # Safety
/// The caller must ensure that:
/// - `signer` is a valid pointer
/// - `request` is a valid pointer to a properly initialized SageHttpRequest
/// - `out_signed_headers` is a valid pointer with sufficient space
/// - `out_headers_count` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_sign_request(
    signer: *const SageHttpSigner,
    request: *const SageHttpRequest,
    out_signed_headers: *mut SageHttpHeader,
    out_headers_count: *mut size_t,
) -> SageResult {
    if signer.is_null()
        || request.is_null()
        || out_signed_headers.is_null()
        || out_headers_count.is_null()
    {
        return SageErrorCode::InvalidInput.into();
    }

    let signer = &(*signer).inner;
    let request = &*request;

    // Convert FFI request to Rust HTTP request
    let method_str = match CStr::from_ptr(request.method).to_str() {
        Ok(s) => s,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };
    let uri_str = match CStr::from_ptr(request.uri).to_str() {
        Ok(s) => s,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };

    // Build HTTP request
    let mut builder = Request::builder().method(method_str).uri(uri_str);

    // Add headers
    let headers_slice = slice::from_raw_parts(request.headers, request.headers_count);
    for header in headers_slice {
        let name = match CStr::from_ptr(header.name).to_str() {
            Ok(s) => s,
            Err(_) => return SageErrorCode::InvalidInput as SageResult,
        };
        let value = match CStr::from_ptr(header.value).to_str() {
            Ok(s) => s,
            Err(_) => return SageErrorCode::InvalidInput as SageResult,
        };
        builder = builder.header(name, value);
    }

    // Add body
    let body = if request.body.is_null() {
        Vec::new()
    } else {
        slice::from_raw_parts(request.body, request.body_len).to_vec()
    };

    let http_request = match builder.body(body) {
        Ok(req) => req,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };

    // Sign the request
    match signer.sign_request(http_request) {
        Ok(signed_request) => {
            // Extract signature headers
            let headers = signed_request.headers();
            let mut header_count = 0;

            // Count signature-related headers
            if headers.contains_key("signature") {
                header_count += 1;
            }
            if headers.contains_key("signature-input") {
                header_count += 1;
            }

            if header_count > *out_headers_count {
                *out_headers_count = header_count;
                return SageErrorCode::InvalidInput.into();
            }

            // Fill output headers
            let mut idx = 0;
            if let Some(sig_header) = headers.get("signature") {
                let sig_name = string_to_c("signature");
                let sig_value = string_to_c(sig_header.to_str().unwrap());
                (*out_signed_headers.add(idx)).name = sig_name;
                (*out_signed_headers.add(idx)).value = sig_value;
                idx += 1;
            }

            if let Some(sig_input_header) = headers.get("signature-input") {
                let sig_input_name = string_to_c("signature-input");
                let sig_input_value = string_to_c(sig_input_header.to_str().unwrap());
                (*out_signed_headers.add(idx)).name = sig_input_name;
                (*out_signed_headers.add(idx)).value = sig_input_value;
                idx += 1;
            }

            *out_headers_count = idx;
            SageErrorCode::Success.into()
        }
        Err(e) => SageErrorCode::from(e).into(),
    }
}

/// Create a new HTTP verifier
///
/// # Safety
/// The caller must ensure that:
/// - `public_key` is a valid pointer
/// - `out_verifier` is a valid pointer to a `*mut SageHttpVerifier`
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_new(
    public_key: *const SagePublicKey,
    out_verifier: *mut *mut SageHttpVerifier,
) -> SageResult {
    if public_key.is_null() || out_verifier.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let public_key = &(*public_key).inner;
    let verifier = HttpVerifier::new(public_key.clone());
    let boxed = Box::new(SageHttpVerifier { inner: verifier });
    *out_verifier = Box::into_raw(boxed);
    SageErrorCode::Success.into()
}

/// Free an HTTP verifier
///
/// # Safety
/// The caller must ensure that `verifier` is a valid pointer obtained from `sage_http_verifier_new`.
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_free(verifier: *mut SageHttpVerifier) {
    if !verifier.is_null() {
        let _ = Box::from_raw(verifier);
    }
}

/// Verify an HTTP request signature
///
/// # Safety
/// The caller must ensure that:
/// - `verifier` is a valid pointer
/// - `request` is a valid pointer to a properly initialized SageHttpRequest
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_verify_request(
    verifier: *const SageHttpVerifier,
    request: *const SageHttpRequest,
) -> SageResult {
    if verifier.is_null() || request.is_null() {
        return SageErrorCode::InvalidInput.into();
    }

    let verifier = &(*verifier).inner;
    let request = &*request;

    // Convert FFI request to Rust HTTP request
    let method_str = match CStr::from_ptr(request.method).to_str() {
        Ok(s) => s,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };
    let uri_str = match CStr::from_ptr(request.uri).to_str() {
        Ok(s) => s,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };

    // Build HTTP request
    let mut builder = Request::builder().method(method_str).uri(uri_str);

    // Add headers
    let headers_slice = slice::from_raw_parts(request.headers, request.headers_count);
    for header in headers_slice {
        let name = match CStr::from_ptr(header.name).to_str() {
            Ok(s) => s,
            Err(_) => return SageErrorCode::InvalidInput as SageResult,
        };
        let value = match CStr::from_ptr(header.value).to_str() {
            Ok(s) => s,
            Err(_) => return SageErrorCode::InvalidInput as SageResult,
        };
        builder = builder.header(name, value);
    }

    // Add body
    let body = if request.body.is_null() {
        Vec::new()
    } else {
        slice::from_raw_parts(request.body, request.body_len).to_vec()
    };

    let http_request = match builder.body(body) {
        Ok(req) => req,
        Err(_) => return SageErrorCode::InvalidInput as SageResult,
    };

    // Verify the request
    match verifier.verify_request(&http_request) {
        Ok(()) => SageErrorCode::Success.into(),
        Err(_) => SageErrorCode::VerificationFailed.into(),
    }
}

/// Free HTTP headers allocated by this library
///
/// # Safety
/// The caller must ensure that `headers` is a valid pointer with `count` elements.
#[no_mangle]
pub unsafe extern "C" fn sage_http_headers_free(headers: *mut SageHttpHeader, count: size_t) {
    if !headers.is_null() {
        for i in 0..count {
            let header = &mut *headers.add(i);
            if !header.name.is_null() {
                sage_string_free(header.name as *mut c_char);
            }
            if !header.value.is_null() {
                sage_string_free(header.value as *mut c_char);
            }
        }
    }
}
