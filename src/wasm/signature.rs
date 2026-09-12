//! WASM bindings for signature operations

use super::*;

/// Signature for WASM
#[wasm_bindgen]
pub struct WasmSignature {
    pub(crate) inner: Signature,
}

#[wasm_bindgen]
impl WasmSignature {
    /// Export signature as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.inner.to_bytes())
    }

    /// Export signature as Uint8Array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Import signature from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(key_type: WasmKeyType, hex_sig: &str) -> WasmResult<WasmSignature> {
        let bytes = hex::decode(hex_sig).map_err(|e| WasmError {
            message: format!("Invalid hex: {e}"),
        })?;
        Self::from_bytes(key_type, &bytes)
    }

    /// Import signature from bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(key_type: WasmKeyType, bytes: &[u8]) -> WasmResult<WasmSignature> {
        let signature = Signature::from_bytes(key_type.into(), bytes).map_err(|e| WasmError {
            message: format!("Invalid signature: {e}"),
        })?;
        Ok(WasmSignature { inner: signature })
    }
}
