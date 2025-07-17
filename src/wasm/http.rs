//! WASM bindings for HTTP signature operations (RFC 9421)

use super::*;
use crate::rfc9421::{HttpSigner, HttpVerifier};
use wasm_bindgen::prelude::*;
use js_sys::{Array, Object, Reflect};
use web_sys::{Headers, Request, Response};

/// HTTP signer for WASM
#[wasm_bindgen]
pub struct WasmHttpSigner {
    inner: HttpSigner,
}

#[wasm_bindgen]
impl WasmHttpSigner {
    /// Create a new HTTP signer
    #[wasm_bindgen(constructor)]
    pub fn new(keypair: &WasmKeyPair) -> WasmHttpSigner {
        WasmHttpSigner {
            inner: HttpSigner::new(keypair.inner.clone()),
        }
    }

    /// Sign an HTTP request object
    #[wasm_bindgen(js_name = signRequest)]
    pub fn sign_request(&self, request: &Request) -> WasmResult<JsValue> {
        // Convert web_sys::Request to http::Request
        let method = request.method();
        let url = request.url();
        
        let mut builder = http::Request::builder()
            .method(method.as_str())
            .uri(url.as_str());

        // Add headers
        let headers = request.headers();
        let entries = js_sys::try_iter(&headers)
            .map_err(|e| WasmError { message: format!("Failed to iterate headers: {:?}", e) })?
            .ok_or_else(|| WasmError { message: "Headers not iterable".to_string() })?;

        for entry in entries {
            let entry = entry.map_err(|e| WasmError { message: format!("Header entry error: {:?}", e) })?;
            let pair = js_sys::Array::from(&entry);
            let name = pair.get(0).as_string().unwrap_or_default();
            let value = pair.get(1).as_string().unwrap_or_default();
            builder = builder.header(name, value);
        }

        let http_request = builder.body(Vec::new())
            .map_err(|e| WasmError { message: format!("Failed to build request: {}", e) })?;

        // Sign the request
        let signed_request = self.inner.sign_request(http_request)?;
        
        // Extract signature headers
        let result = Object::new();
        if let Some(signature) = signed_request.headers().get("signature") {
            Reflect::set(&result, &"signature".into(), &signature.to_str().unwrap().into())
                .map_err(|e| WasmError { message: format!("Failed to set signature: {:?}", e) })?;
        }
        if let Some(signature_input) = signed_request.headers().get("signature-input") {
            Reflect::set(&result, &"signature-input".into(), &signature_input.to_str().unwrap().into())
                .map_err(|e| WasmError { message: format!("Failed to set signature-input: {:?}", e) })?;
        }

        Ok(result.into())
    }

    /// Sign a simple request object
    #[wasm_bindgen(js_name = signSimpleRequest)]
    pub fn sign_simple_request(&self, request: &JsValue) -> WasmResult<JsValue> {
        let method = Reflect::get(request, &"method".into())
            .map_err(|e| WasmError { message: format!("Failed to get method: {:?}", e) })?
            .as_string()
            .unwrap_or_else(|| "GET".to_string());
        
        let url = Reflect::get(request, &"url".into())
            .map_err(|e| WasmError { message: format!("Failed to get url: {:?}", e) })?
            .as_string()
            .ok_or_else(|| WasmError { message: "URL is required".to_string() })?;

        let mut builder = http::Request::builder()
            .method(method.as_str())
            .uri(url.as_str());

        // Add headers if present
        if let Ok(headers) = Reflect::get(request, &"headers".into()) {
            if !headers.is_undefined() {
                let headers_obj = headers.dyn_into::<Object>()
                    .map_err(|_| WasmError { message: "Headers must be an object".to_string() })?;
                
                let keys = Object::keys(&headers_obj);
                for i in 0..keys.length() {
                    let key = keys.get(i).as_string().unwrap_or_default();
                    let value = Reflect::get(&headers_obj, &key.clone().into())
                        .map_err(|e| WasmError { message: format!("Failed to get header {}: {:?}", key, e) })?
                        .as_string()
                        .unwrap_or_default();
                    builder = builder.header(key, value);
                }
            }
        }

        let http_request = builder.body(Vec::new())
            .map_err(|e| WasmError { message: format!("Failed to build request: {}", e) })?;

        // Sign the request
        let signed_request = self.inner.sign_request(http_request)?;
        
        // Extract signature headers
        let result = Object::new();
        if let Some(signature) = signed_request.headers().get("signature") {
            Reflect::set(&result, &"signature".into(), &signature.to_str().unwrap().into())
                .map_err(|e| WasmError { message: format!("Failed to set signature: {:?}", e) })?;
        }
        if let Some(signature_input) = signed_request.headers().get("signature-input") {
            Reflect::set(&result, &"signature-input".into(), &signature_input.to_str().unwrap().into())
                .map_err(|e| WasmError { message: format!("Failed to set signature-input: {:?}", e) })?;
        }

        Ok(result.into())
    }
}

/// HTTP verifier for WASM
#[wasm_bindgen]
pub struct WasmHttpVerifier {
    inner: HttpVerifier,
}

#[wasm_bindgen]
impl WasmHttpVerifier {
    /// Create a new HTTP verifier
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: &WasmPublicKey) -> WasmHttpVerifier {
        WasmHttpVerifier {
            inner: HttpVerifier::new(public_key.inner.clone()),
        }
    }

    /// Verify an HTTP request object
    #[wasm_bindgen(js_name = verifyRequest)]
    pub fn verify_request(&self, request: &Request) -> bool {
        // Convert web_sys::Request to http::Request
        let method = request.method();
        let url = request.url();
        
        let mut builder = http::Request::builder()
            .method(method.as_str())
            .uri(url.as_str());

        // Add headers
        let headers = request.headers();
        if let Ok(Some(entries)) = js_sys::try_iter(&headers) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let pair = js_sys::Array::from(&entry);
                    let name = pair.get(0).as_string().unwrap_or_default();
                    let value = pair.get(1).as_string().unwrap_or_default();
                    builder = builder.header(name, value);
                }
            }
        }

        if let Ok(http_request) = builder.body(Vec::new()) {
            self.inner.verify_request(&http_request).is_ok()
        } else {
            false
        }
    }

    /// Verify a simple request object
    #[wasm_bindgen(js_name = verifySimpleRequest)]
    pub fn verify_simple_request(&self, request: &JsValue) -> bool {
        let method = Reflect::get(request, &"method".into())
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_else(|| "GET".to_string());
        
        let url = Reflect::get(request, &"url".into())
            .ok()
            .and_then(|v| v.as_string());

        if let Some(url) = url {
            let mut builder = http::Request::builder()
                .method(method.as_str())
                .uri(url.as_str());

            // Add headers if present
            if let Ok(headers) = Reflect::get(request, &"headers".into()) {
                if !headers.is_undefined() {
                    if let Ok(headers_obj) = headers.dyn_into::<Object>() {
                        let keys = Object::keys(&headers_obj);
                        for i in 0..keys.length() {
                            let key = keys.get(i).as_string().unwrap_or_default();
                            if let Ok(value) = Reflect::get(&headers_obj, &key.clone().into()) {
                                if let Some(value_str) = value.as_string() {
                                    builder = builder.header(key, value_str);
                                }
                            }
                        }
                    }
                }
            }

            if let Ok(http_request) = builder.body(Vec::new()) {
                return self.inner.verify_request(&http_request).is_ok();
            }
        }

        false
    }
}

/// Utility functions for HTTP signature operations
#[wasm_bindgen]
pub struct WasmHttpUtils;

#[wasm_bindgen]
impl WasmHttpUtils {
    /// Create a signed fetch request
    #[wasm_bindgen(js_name = createSignedFetch)]
    pub fn create_signed_fetch(
        signer: &WasmHttpSigner,
        method: &str,
        url: &str,
        headers: &JsValue,
    ) -> WasmResult<JsValue> {
        let request_obj = Object::new();
        
        // Set method and URL
        Reflect::set(&request_obj, &"method".into(), &method.into())
            .map_err(|e| WasmError { message: format!("Failed to set method: {:?}", e) })?;
        Reflect::set(&request_obj, &"url".into(), &url.into())
            .map_err(|e| WasmError { message: format!("Failed to set url: {:?}", e) })?;

        // Set headers
        if !headers.is_undefined() {
            Reflect::set(&request_obj, &"headers".into(), headers)
                .map_err(|e| WasmError { message: format!("Failed to set headers: {:?}", e) })?;
        }

        // Sign the request
        let signature_headers = signer.sign_simple_request(&request_obj)?;

        // Merge signature headers with existing headers
        let final_headers = if headers.is_undefined() {
            Object::new()
        } else {
            headers.dyn_into::<Object>()
                .map_err(|_| WasmError { message: "Headers must be an object".to_string() })?
        };

        // Add signature headers
        if let Ok(signature) = Reflect::get(&signature_headers, &"signature".into()) {
            Reflect::set(&final_headers, &"signature".into(), &signature)
                .map_err(|e| WasmError { message: format!("Failed to set signature header: {:?}", e) })?;
        }
        if let Ok(signature_input) = Reflect::get(&signature_headers, &"signature-input".into()) {
            Reflect::set(&final_headers, &"signature-input".into(), &signature_input)
                .map_err(|e| WasmError { message: format!("Failed to set signature-input header: {:?}", e) })?;
        }

        // Create final request object
        let result = Object::new();
        Reflect::set(&result, &"method".into(), &method.into())
            .map_err(|e| WasmError { message: format!("Failed to set result method: {:?}", e) })?;
        Reflect::set(&result, &"url".into(), &url.into())
            .map_err(|e| WasmError { message: format!("Failed to set result url: {:?}", e) })?;
        Reflect::set(&result, &"headers".into(), &final_headers)
            .map_err(|e| WasmError { message: format!("Failed to set result headers: {:?}", e) })?;

        Ok(result.into())
    }

    /// Parse signature headers from a response
    #[wasm_bindgen(js_name = parseSignatureHeaders)]
    pub fn parse_signature_headers(headers: &JsValue) -> WasmResult<JsValue> {
        let headers_obj = headers.dyn_into::<Object>()
            .map_err(|_| WasmError { message: "Headers must be an object".to_string() })?;

        let result = Object::new();
        
        // Extract signature header
        if let Ok(signature) = Reflect::get(&headers_obj, &"signature".into()) {
            if !signature.is_undefined() {
                Reflect::set(&result, &"signature".into(), &signature)
                    .map_err(|e| WasmError { message: format!("Failed to set signature: {:?}", e) })?;
            }
        }

        // Extract signature-input header
        if let Ok(signature_input) = Reflect::get(&headers_obj, &"signature-input".into()) {
            if !signature_input.is_undefined() {
                Reflect::set(&result, &"signature-input".into(), &signature_input)
                    .map_err(|e| WasmError { message: format!("Failed to set signature-input: {:?}", e) })?;
            }
        }

        Ok(result.into())
    }
}