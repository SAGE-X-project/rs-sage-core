//! FFI functions for HTTP message signatures (RFC 9421, sage-spec 03).
//!
//! Requests and responses are passed as `SageHttpRequest` /
//! `SageHttpResponse` views over caller-owned memory. Signing returns the
//! headers to add to the message (`content-digest` when a body was given,
//! `signature-input`, `signature`) as `SageHttpHeader` entries whose strings
//! are owned by the library and freed with `sage_http_headers_free`.

use super::*;
use crate::rfc9421::{HttpSigner, HttpVerifier, VerifyOptions};
use ::http::{Request, Response};
use std::ffi::CStr;
use std::time::Duration;

/// Opaque handle for HTTP signer
pub struct SageHttpSigner {
    inner: HttpSigner,
}

/// Opaque handle for HTTP verifier
pub struct SageHttpVerifier {
    inner: HttpVerifier,
}

/// HTTP request view for FFI
#[repr(C)]
pub struct SageHttpRequest {
    /// Method (`POST`)
    pub method: *const c_char,
    /// Absolute target URI
    pub uri: *const c_char,
    /// Headers
    pub headers: *const SageHttpHeader,
    /// Number of headers
    pub headers_count: size_t,
    /// Body bytes (may be NULL)
    pub body: *const c_uchar,
    /// Body length
    pub body_len: size_t,
}

/// HTTP response view for FFI
#[repr(C)]
pub struct SageHttpResponse {
    /// Status code
    pub status: c_int,
    /// Headers
    pub headers: *const SageHttpHeader,
    /// Number of headers
    pub headers_count: size_t,
    /// Body bytes (may be NULL)
    pub body: *const c_uchar,
    /// Body length
    pub body_len: size_t,
}

/// HTTP header (name, value) for FFI
#[repr(C)]
pub struct SageHttpHeader {
    /// Header name
    pub name: *const c_char,
    /// Header value
    pub value: *const c_char,
}

/// Verification policy for FFI. `strict` enables the sage-spec strict
/// request or response policy; `max_age_secs < 0` disables the age check;
/// `expected_did` may be NULL.
#[repr(C)]
pub struct SageVerifyOptions {
    /// Non-zero for the strict policy
    pub strict: c_int,
    /// Maximum signature age in seconds; negative disables the check
    pub max_age_secs: i64,
    /// DID the `keyid` must carry (NULL to skip)
    pub expected_did: *const c_char,
    /// Non-zero to skip the replay check
    pub disable_replay_check: c_int,
}

unsafe fn c_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

unsafe fn headers_of(
    ptr: *const SageHttpHeader,
    count: size_t,
) -> Result<Vec<(String, String)>, SageResult> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(fail_with(SageErrorCode::InvalidInput, "headers is NULL"));
    }
    let mut out = Vec::with_capacity(count);
    for h in slice::from_raw_parts(ptr, count) {
        let (Some(n), Some(v)) = (c_str(h.name), c_str(h.value)) else {
            return Err(fail_with(
                SageErrorCode::InvalidInput,
                "invalid header string",
            ));
        };
        out.push((n.to_string(), v.to_string()));
    }
    Ok(out)
}

unsafe fn body_of(ptr: *const c_uchar, len: size_t) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(ptr, len).to_vec()
    }
}

unsafe fn build_request(r: &SageHttpRequest) -> Result<Request<Vec<u8>>, SageResult> {
    let (Some(method), Some(uri)) = (c_str(r.method), c_str(r.uri)) else {
        return Err(fail_with(SageErrorCode::InvalidInput, "method/uri missing"));
    };
    let mut b = Request::builder().method(method).uri(uri);
    for (n, v) in headers_of(r.headers, r.headers_count)? {
        b = b.header(n, v);
    }
    b.body(body_of(r.body, r.body_len)).map_err(|e| {
        fail_with(
            SageErrorCode::InvalidInput,
            &format!("invalid request: {e}"),
        )
    })
}

unsafe fn build_response(r: &SageHttpResponse) -> Result<Response<Vec<u8>>, SageResult> {
    let mut b = Response::builder().status(r.status as u16);
    for (n, v) in headers_of(r.headers, r.headers_count)? {
        b = b.header(n, v);
    }
    b.body(body_of(r.body, r.body_len)).map_err(|e| {
        fail_with(
            SageErrorCode::InvalidInput,
            &format!("invalid response: {e}"),
        )
    })
}

unsafe fn options_of(o: *const SageVerifyOptions, response: bool) -> VerifyOptions {
    let mut opts = if o.is_null() {
        VerifyOptions::default()
    } else if (*o).strict != 0 {
        if response {
            VerifyOptions::strict_response()
        } else {
            VerifyOptions::strict_request()
        }
    } else {
        VerifyOptions::default()
    };
    if !o.is_null() {
        let o = &*o;
        if o.max_age_secs < 0 {
            opts = opts.without_age_check();
        } else {
            opts.max_age = Some(Duration::from_secs(o.max_age_secs as u64));
        }
        if let Some(did) = c_str(o.expected_did) {
            opts.expected_did = Some(did.to_string());
        }
        opts.disable_replay_check = o.disable_replay_check != 0;
    }
    opts
}

/// Write the headers added by signing into caller-provided entries.
unsafe fn emit_headers(
    original: &[(String, String)],
    signed: &::http::HeaderMap,
    out: *mut SageHttpHeader,
    out_count: *mut size_t,
) -> SageResult {
    let had_digest = original
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-digest"));
    let mut names: Vec<&str> = Vec::new();
    if !had_digest && signed.contains_key("content-digest") {
        names.push("content-digest");
    }
    names.push("signature-input");
    names.push("signature");
    if names.len() > *out_count {
        *out_count = names.len();
        return fail_with(
            SageErrorCode::InvalidInput,
            "output header buffer too small",
        );
    }
    for (i, name) in names.iter().enumerate() {
        let value = signed
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        (*out.add(i)).name = string_to_c(name);
        (*out.add(i)).value = string_to_c(value);
    }
    *out_count = names.len();
    SageErrorCode::Success.into()
}

/// Create a new HTTP signer. The `keyid` parameter defaults to the key id;
/// set the agent DID with `sage_http_signer_set_key_id`.
///
/// # Safety
/// `keypair` and `out_signer` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_new(
    keypair: *const SageKeyPair,
    out_signer: *mut *mut SageHttpSigner,
) -> SageResult {
    if keypair.is_null() || out_signer.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let signer = HttpSigner::new((*keypair).inner.clone());
    *out_signer = Box::into_raw(Box::new(SageHttpSigner { inner: signer }));
    SageErrorCode::Success.into()
}

/// Set the `keyid` parameter (`did:sage:…` or `did:sage:…#key-1`).
///
/// # Safety
/// `signer` must be a valid signer and `key_id` a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_set_key_id(
    signer: *mut SageHttpSigner,
    key_id: *const c_char,
) -> SageResult {
    if signer.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let Some(key_id) = c_str(key_id) else {
        return fail_with(SageErrorCode::InvalidInput, "key_id is not a valid string");
    };
    (*signer).inner.set_key_id(key_id);
    SageErrorCode::Success.into()
}

/// Free an HTTP signer
///
/// # Safety
/// `signer` must have been returned by `sage_http_signer_new` or be NULL.
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_free(signer: *mut SageHttpSigner) {
    if !signer.is_null() {
        let _ = Box::from_raw(signer);
    }
}

/// Sign a request with the sage-spec default components. Returns the
/// headers to add (`content-digest` when a body was given,
/// `signature-input`, `signature`). On a too-small buffer the required
/// count is written to `out_headers_count` and `InvalidInput` returned.
///
/// # Safety
/// All pointers must be valid; `out_signed_headers` must have room for
/// `*out_headers_count` entries.
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
    let request = &*request;
    let original = match headers_of(request.headers, request.headers_count) {
        Ok(h) => h,
        Err(code) => return code,
    };
    let http_request = match build_request(request) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let body = http_request.body().clone();
    let body_opt = if body.is_empty() {
        None
    } else {
        Some(body.as_slice())
    };
    match (*signer).inner.sign_request(http_request, body_opt) {
        Ok(signed) => emit_headers(
            &original,
            signed.headers(),
            out_signed_headers,
            out_headers_count,
        ),
        Err(e) => fail(e),
    }
}

/// Sign a response bound to the request it answers (reference responder
/// component set). Returns the headers to add to the response.
///
/// # Safety
/// All pointers must be valid; `out_signed_headers` must have room for
/// `*out_headers_count` entries.
#[no_mangle]
pub unsafe extern "C" fn sage_http_signer_sign_response(
    signer: *const SageHttpSigner,
    request: *const SageHttpRequest,
    response: *const SageHttpResponse,
    out_signed_headers: *mut SageHttpHeader,
    out_headers_count: *mut size_t,
) -> SageResult {
    if signer.is_null()
        || request.is_null()
        || response.is_null()
        || out_signed_headers.is_null()
        || out_headers_count.is_null()
    {
        return SageErrorCode::InvalidInput.into();
    }
    let response = &*response;
    let original = match headers_of(response.headers, response.headers_count) {
        Ok(h) => h,
        Err(code) => return code,
    };
    let (req, resp) = match (build_request(&*request), build_response(response)) {
        (Ok(r), Ok(s)) => (r, s),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let body = resp.body().clone();
    let body_opt = if body.is_empty() {
        None
    } else {
        Some(body.as_slice())
    };
    match (*signer).inner.sign_response(resp, &req, body_opt) {
        Ok(signed) => emit_headers(
            &original,
            signed.headers(),
            out_signed_headers,
            out_headers_count,
        ),
        Err(e) => fail(e),
    }
}

/// Create a new HTTP verifier for `public_key` (with an in-memory replay guard).
///
/// # Safety
/// `public_key` and `out_verifier` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_new(
    public_key: *const SagePublicKey,
    out_verifier: *mut *mut SageHttpVerifier,
) -> SageResult {
    if public_key.is_null() || out_verifier.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let verifier = HttpVerifier::new((*public_key).inner.clone());
    *out_verifier = Box::into_raw(Box::new(SageHttpVerifier { inner: verifier }));
    SageErrorCode::Success.into()
}

/// Free an HTTP verifier
///
/// # Safety
/// `verifier` must have been returned by `sage_http_verifier_new` or be NULL.
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_free(verifier: *mut SageHttpVerifier) {
    if !verifier.is_null() {
        let _ = Box::from_raw(verifier);
    }
}

/// Verify a request with the default options (see
/// `sage_http_verifier_verify_request_with` for the strict policy).
///
/// # Safety
/// `verifier` and `request` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_verify_request(
    verifier: *const SageHttpVerifier,
    request: *const SageHttpRequest,
) -> SageResult {
    sage_http_verifier_verify_request_with(verifier, request, ptr::null())
}

/// Verify a request with explicit options. The body of `request` is
/// checked against `Content-Digest` when it is covered.
///
/// # Safety
/// `verifier` and `request` must be valid; `options` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_verify_request_with(
    verifier: *const SageHttpVerifier,
    request: *const SageHttpRequest,
    options: *const SageVerifyOptions,
) -> SageResult {
    if verifier.is_null() || request.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let req = match build_request(&*request) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let body = req.body().clone();
    let body_opt = if body.is_empty() {
        None
    } else {
        Some(body.as_slice())
    };
    let opts = options_of(options, false);
    match (*verifier).inner.verify_request_with(&req, body_opt, &opts) {
        Ok(()) => SageErrorCode::Success.into(),
        Err(e) => {
            let msg = format!("{e}");
            fail_with(SageErrorCode::VerificationFailed, &msg)
        }
    }
}

/// Verify a response against the request it answers.
///
/// # Safety
/// `verifier`, `request` and `response` must be valid; `options` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn sage_http_verifier_verify_response(
    verifier: *const SageHttpVerifier,
    request: *const SageHttpRequest,
    response: *const SageHttpResponse,
    options: *const SageVerifyOptions,
) -> SageResult {
    if verifier.is_null() || request.is_null() || response.is_null() {
        return SageErrorCode::InvalidInput.into();
    }
    let (req, resp) = match (build_request(&*request), build_response(&*response)) {
        (Ok(r), Ok(s)) => (r, s),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let body = resp.body().clone();
    let body_opt = if body.is_empty() {
        None
    } else {
        Some(body.as_slice())
    };
    let opts = options_of(options, true);
    match (*verifier)
        .inner
        .verify_response(&resp, &req, body_opt, &opts)
    {
        Ok(()) => SageErrorCode::Success.into(),
        Err(e) => {
            let msg = format!("{e}");
            fail_with(SageErrorCode::VerificationFailed, &msg)
        }
    }
}

/// Free headers returned by the signing functions.
///
/// # Safety
/// `headers` must point to `count` entries whose strings were allocated by
/// this library.
#[no_mangle]
pub unsafe extern "C" fn sage_http_headers_free(headers: *mut SageHttpHeader, count: size_t) {
    if !headers.is_null() {
        for i in 0..count {
            let header = &mut *headers.add(i);
            if !header.name.is_null() {
                let _ = CString::from_raw(header.name as *mut c_char);
                header.name = ptr::null();
            }
            if !header.value.is_null() {
                let _ = CString::from_raw(header.value as *mut c_char);
                header.value = ptr::null();
            }
        }
    }
}
