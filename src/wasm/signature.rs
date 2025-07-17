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
        let signature = match key_type {
            WasmKeyType::Ed25519 => {
                if bytes.len() != 64 {
                    return Err(WasmError {
                        message: "Ed25519 signature must be 64 bytes".to_string(),
                    });
                }
                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(bytes);
                Signature::Ed25519(ed25519_dalek::Signature::from_bytes(&sig_bytes))
            }
            WasmKeyType::Secp256k1 => Signature::Secp256k1(
                k256::ecdsa::Signature::from_der(bytes)
                    .or_else(|_| {
                        if bytes.len() == 64 {
                            k256::ecdsa::Signature::try_from(bytes)
                        } else {
                            Err(k256::ecdsa::Error::new())
                        }
                    })
                    .map_err(|e| WasmError {
                        message: format!("Invalid Secp256k1 signature: {e}"),
                    })?,
            ),
        };

        Ok(WasmSignature { inner: signature })
    }
}
