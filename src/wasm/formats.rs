//! WASM bindings for key format operations

use super::*;
use crate::formats::KeyFormat;

/// Key format enum for WASM
#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum WasmKeyFormat {
    /// Raw binary format
    Raw = 0,
    /// PEM format (Base64 encoded with headers)
    Pem = 1,
    /// DER format (binary ASN.1)
    Der = 2,
    /// JWK format (JSON Web Key)
    Jwk = 3,
}

impl From<WasmKeyFormat> for KeyFormat {
    fn from(format: WasmKeyFormat) -> Self {
        match format {
            WasmKeyFormat::Raw => KeyFormat::Raw,
            WasmKeyFormat::Pem => KeyFormat::Pem,
            WasmKeyFormat::Der => KeyFormat::Der,
            WasmKeyFormat::Jwk => KeyFormat::Jwk,
        }
    }
}

/// Key format utilities for WASM
#[wasm_bindgen]
pub struct WasmKeyFormats;

#[wasm_bindgen]
impl WasmKeyFormats {
    /// Get supported formats for a key type
    #[wasm_bindgen(js_name = getSupportedFormats)]
    pub fn get_supported_formats(_key_type: WasmKeyType) -> Vec<WasmKeyFormat> {
        // All key types support all formats in this implementation
        vec![
            WasmKeyFormat::Raw,
            WasmKeyFormat::Pem,
            WasmKeyFormat::Der,
            WasmKeyFormat::Jwk,
        ]
    }
}
