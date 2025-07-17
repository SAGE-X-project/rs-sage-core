//! WASM bindings for HTTP signature operations (RFC 9421)

use super::*;
use js_sys::{Object, Reflect};

/// HTTP signer for WASM
#[wasm_bindgen]
pub struct WasmHttpSigner {
    keypair: WasmKeyPair,
}

#[wasm_bindgen]
impl WasmHttpSigner {
    /// Create a new HTTP signer
    #[wasm_bindgen(constructor)]
    pub fn new(keypair: WasmKeyPair) -> WasmHttpSigner {
        WasmHttpSigner { keypair }
    }

    /// Get the key ID
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.keypair.key_id()
    }

    /// Sign a message (basic signature without HTTP semantics for now)
    #[wasm_bindgen(js_name = signMessage)]
    pub fn sign_message(&self, message: &str) -> WasmResult<String> {
        let signature = self.keypair.sign_string(message)?;
        Ok(signature.to_hex())
    }
}

/// HTTP verifier for WASM
#[wasm_bindgen]
pub struct WasmHttpVerifier {
    public_key: WasmPublicKey,
}

#[wasm_bindgen]
impl WasmHttpVerifier {
    /// Create a new HTTP verifier
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: WasmPublicKey) -> WasmHttpVerifier {
        WasmHttpVerifier { public_key }
    }

    /// Verify a message signature
    #[wasm_bindgen(js_name = verifyMessage)]
    pub fn verify_message(&self, message: &str, signature_hex: &str) -> WasmResult<bool> {
        let signature = WasmSignature::from_hex(self.public_key.key_type(), signature_hex)?;
        Ok(self.public_key.verify_string(message, &signature))
    }
}

/// Utility functions for HTTP signature operations
#[wasm_bindgen]
pub struct WasmHttpUtils;

#[wasm_bindgen]
impl WasmHttpUtils {
    /// Create signature input string
    #[wasm_bindgen(js_name = createSignatureInput)]
    pub fn create_signature_input(components: Vec<String>, key_id: &str) -> String {
        let comp_str = components.join(" ");
        format!("({comp_str}); keyid=\"{key_id}\"; alg=\"ed25519\"")
    }

    /// Parse signature headers from a response
    #[wasm_bindgen(js_name = parseSignatureHeaders)]
    pub fn parse_signature_headers(headers: &JsValue) -> WasmResult<JsValue> {
        let headers_obj = headers
            .clone()
            .dyn_into::<Object>()
            .map_err(|_| WasmError {
                message: "Headers must be an object".to_string(),
            })?;

        let result = Object::new();

        // Extract signature header
        if let Ok(signature) = Reflect::get(&headers_obj, &"signature".into()) {
            if !signature.is_undefined() {
                Reflect::set(&result, &"signature".into(), &signature).map_err(|e| WasmError {
                    message: format!("Failed to set signature: {e:?}"),
                })?;
            }
        }

        // Extract signature-input header
        if let Ok(signature_input) = Reflect::get(&headers_obj, &"signature-input".into()) {
            if !signature_input.is_undefined() {
                Reflect::set(&result, &"signature-input".into(), &signature_input).map_err(
                    |e| WasmError {
                        message: format!("Failed to set signature-input: {e:?}"),
                    },
                )?;
            }
        }

        Ok(result.into())
    }
}
