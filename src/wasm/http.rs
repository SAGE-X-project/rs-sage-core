//! WASM bindings for HTTP message signatures (RFC 9421, sage-spec 03).
//!
//! Headers are exchanged as JSON objects encoded in strings
//! (`{"content-type":"application/json", ...}`) to keep the binding free
//! of JavaScript object plumbing; bodies as byte arrays.

use super::*;
use crate::rfc9421::{HttpSigner, HttpVerifier, VerifyOptions};
use std::collections::BTreeMap;

fn headers_from_json(json: &str) -> WasmResult<BTreeMap<String, String>> {
    if json.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str::<BTreeMap<String, String>>(json).map_err(|e| WasmError {
        message: format!("headers must be a JSON object of strings: {e}"),
    })
}

fn build_request(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> WasmResult<::http::Request<Vec<u8>>> {
    let mut b = ::http::Request::builder().method(method).uri(url);
    for (k, v) in headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(body.to_vec()).map_err(|e| WasmError {
        message: format!("invalid request: {e}"),
    })
}

fn build_response(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> WasmResult<::http::Response<Vec<u8>>> {
    let mut b = ::http::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(body.to_vec()).map_err(|e| WasmError {
        message: format!("invalid response: {e}"),
    })
}

fn added_headers(original: &BTreeMap<String, String>, signed: &::http::HeaderMap) -> String {
    let mut out = BTreeMap::new();
    for name in ["content-digest", "signature-input", "signature"] {
        if name == "content-digest" && original.keys().any(|k| k.eq_ignore_ascii_case(name)) {
            continue;
        }
        if let Some(v) = signed.get(name).and_then(|v| v.to_str().ok()) {
            out.insert(name.to_string(), v.to_string());
        }
    }
    serde_json::to_string(&out).unwrap_or_default()
}

fn body_opt(body: &[u8]) -> Option<&[u8]> {
    if body.is_empty() {
        None
    } else {
        Some(body)
    }
}

/// Signs requests and responses.
#[wasm_bindgen]
pub struct WasmHttpSigner {
    inner: HttpSigner,
}

#[wasm_bindgen]
impl WasmHttpSigner {
    /// Create a signer; `keyId` defaults to the key id, set the DID with `setKeyId`.
    #[wasm_bindgen(constructor)]
    pub fn new(keypair: &WasmKeyPair) -> WasmHttpSigner {
        WasmHttpSigner {
            inner: HttpSigner::new(keypair.inner.clone()),
        }
    }

    /// Set the `keyid` parameter (`did:sage:…` or `did:sage:…#key-1`).
    #[wasm_bindgen(js_name = setKeyId)]
    pub fn set_key_id(&mut self, key_id: &str) {
        self.inner.set_key_id(key_id);
    }

    /// The `keyid` this signer uses.
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.inner.key_id().to_string()
    }

    /// Sign a request. Returns a JSON object of the headers to add
    /// (`content-digest` when a body was given, `signature-input`, `signature`).
    #[wasm_bindgen(js_name = signRequest)]
    pub fn sign_request(
        &self,
        method: &str,
        url: &str,
        headers_json: &str,
        body: &[u8],
    ) -> WasmResult<String> {
        let headers = headers_from_json(headers_json)?;
        let req = build_request(method, url, &headers, body)?;
        let signed = self.inner.sign_request(req, body_opt(body))?;
        Ok(added_headers(&headers, signed.headers()))
    }

    /// Sign a response bound to the request it answers. Returns the headers to add.
    #[wasm_bindgen(js_name = signResponse)]
    pub fn sign_response(
        &self,
        request_method: &str,
        request_url: &str,
        request_headers_json: &str,
        status: u16,
        response_headers_json: &str,
        body: &[u8],
    ) -> WasmResult<String> {
        let req = build_request(
            request_method,
            request_url,
            &headers_from_json(request_headers_json)?,
            &[],
        )?;
        let headers = headers_from_json(response_headers_json)?;
        let resp = build_response(status, &headers, body)?;
        let signed = self.inner.sign_response(resp, &req, body_opt(body))?;
        Ok(added_headers(&headers, signed.headers()))
    }
}

/// Verifies requests and responses against one public key.
#[wasm_bindgen]
pub struct WasmHttpVerifier {
    inner: HttpVerifier,
}

/// Verification policy for the WASM verifier.
#[wasm_bindgen]
#[derive(Debug, Clone, Default)]
pub struct WasmVerifyOptions {
    /// Strict sage-spec policy
    pub strict: bool,
    /// Skip the freshness check (archived messages)
    #[wasm_bindgen(js_name = ignoreAge)]
    pub ignore_age: bool,
    /// Skip the replay check
    #[wasm_bindgen(js_name = disableReplayCheck)]
    pub disable_replay_check: bool,
    expected_did: Option<String>,
}

#[wasm_bindgen]
impl WasmVerifyOptions {
    /// Default options
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmVerifyOptions {
        Self::default()
    }

    /// Bind the signer's DID.
    #[wasm_bindgen(setter, js_name = expectedDid)]
    pub fn set_expected_did(&mut self, did: Option<String>) {
        self.expected_did = did;
    }

    /// The bound DID.
    #[wasm_bindgen(getter, js_name = expectedDid)]
    pub fn expected_did(&self) -> Option<String> {
        self.expected_did.clone()
    }

    fn to_options(&self, response: bool) -> VerifyOptions {
        let mut o = if self.strict {
            if response {
                VerifyOptions::strict_response()
            } else {
                VerifyOptions::strict_request()
            }
        } else {
            VerifyOptions::default()
        };
        if self.ignore_age {
            o = o.without_age_check();
        }
        o.disable_replay_check = self.disable_replay_check;
        o.expected_did = self.expected_did.clone();
        o
    }
}

#[wasm_bindgen]
impl WasmHttpVerifier {
    /// Create a verifier with an in-memory replay guard.
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: &WasmPublicKey) -> WasmHttpVerifier {
        WasmHttpVerifier {
            inner: HttpVerifier::new(public_key.inner.clone()),
        }
    }

    /// Verify a request; `headersJson` must include the signature headers.
    #[wasm_bindgen(js_name = verifyRequest)]
    pub fn verify_request(
        &self,
        method: &str,
        url: &str,
        headers_json: &str,
        body: &[u8],
        options: Option<WasmVerifyOptions>,
    ) -> WasmResult<()> {
        let req = build_request(method, url, &headers_from_json(headers_json)?, body)?;
        let opts = options.unwrap_or_default().to_options(false);
        self.inner
            .verify_request_with(&req, body_opt(body), &opts)
            .map_err(Into::into)
    }

    /// Verify a response against the request it answers.
    #[wasm_bindgen(js_name = verifyResponse)]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_response(
        &self,
        request_method: &str,
        request_url: &str,
        request_headers_json: &str,
        status: u16,
        response_headers_json: &str,
        body: &[u8],
        options: Option<WasmVerifyOptions>,
    ) -> WasmResult<()> {
        let req = build_request(
            request_method,
            request_url,
            &headers_from_json(request_headers_json)?,
            &[],
        )?;
        let resp = build_response(status, &headers_from_json(response_headers_json)?, body)?;
        let opts = options.unwrap_or_default().to_options(true);
        self.inner
            .verify_response(&resp, &req, body_opt(body), &opts)
            .map_err(Into::into)
    }
}

/// `Content-Digest` header value for a body.
#[wasm_bindgen(js_name = contentDigest)]
pub fn content_digest(body: &[u8]) -> String {
    crate::rfc9421::content_digest(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_over_json_headers() {
        let kp = WasmKeyPair::generate_ed25519().unwrap();
        let mut signer = WasmHttpSigner::new(&kp);
        signer.set_key_id("did:sage:ethereum:0x1234");
        let body = br#"{"hello":"world"}"#;
        let headers = r#"{"content-type":"application/json"}"#;
        let added = signer
            .sign_request("POST", "https://example.com/api?x=1", headers, body)
            .unwrap();
        let added: BTreeMap<String, String> = serde_json::from_str(&added).unwrap();
        assert!(added.contains_key("content-digest"));
        assert!(added.contains_key("signature-input"));
        assert!(added.contains_key("signature"));

        let mut all: BTreeMap<String, String> = serde_json::from_str(headers).unwrap();
        all.extend(added);
        let all_json = serde_json::to_string(&all).unwrap();

        let verifier = WasmHttpVerifier::new(&kp.get_public_key());
        let mut opts = WasmVerifyOptions::new();
        opts.strict = true;
        opts.set_expected_did(Some("did:sage:ethereum:0x1234".into()));
        verifier
            .verify_request(
                "POST",
                "https://example.com/api?x=1",
                &all_json,
                body,
                Some(opts),
            )
            .unwrap();

        // Tampered body fails
        let mut opts = WasmVerifyOptions::new();
        opts.disable_replay_check = true;
        assert!(verifier
            .verify_request(
                "POST",
                "https://example.com/api?x=1",
                &all_json,
                b"{}",
                Some(opts)
            )
            .is_err());
    }

    #[test]
    fn response_round_trip_binds_request() {
        let kp = WasmKeyPair::generate_secp256k1().unwrap();
        let signer = WasmHttpSigner::new(&kp);
        let req_headers = r#"{"signature-input":"sig1=(\"@method\");created=1;keyid=\"k\"","signature":"sig1=:AA==:"}"#;
        let added = signer
            .sign_response(
                "GET",
                "https://example.com/r",
                req_headers,
                200,
                "{}",
                b"ok",
            )
            .unwrap();
        let all_json = added;
        let verifier = WasmHttpVerifier::new(&kp.get_public_key());
        verifier
            .verify_response(
                "GET",
                "https://example.com/r",
                req_headers,
                200,
                &all_json,
                b"ok",
                None,
            )
            .unwrap();
        assert!(verifier
            .verify_response(
                "GET",
                "https://example.com/r",
                req_headers,
                201,
                &all_json,
                b"ok",
                None
            )
            .is_err());
    }

    #[test]
    fn rejects_non_object_headers() {
        assert!(headers_from_json("[1,2]").is_err());
        assert!(headers_from_json("").unwrap().is_empty());
    }
}
