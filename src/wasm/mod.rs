//! WebAssembly bindings for browser and Node.js integration

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use crate::crypto::{KeyPair, KeyType, PublicKey, Signature};
use crate::crypto::{Signer, Verifier};

pub mod keypair;
pub mod signature;
pub mod utils;

pub use keypair::*;
pub use signature::*;
pub use utils::*;

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    // Set panic hook for better error messages in browser
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the version string
#[wasm_bindgen]
pub fn version() -> String {
    crate::VERSION.to_string()
}

/// Key type enum for WASM
#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum WasmKeyType {
    Ed25519 = 0,
    Secp256k1 = 1,
}

impl From<WasmKeyType> for KeyType {
    fn from(key_type: WasmKeyType) -> Self {
        match key_type {
            WasmKeyType::Ed25519 => KeyType::Ed25519,
            WasmKeyType::Secp256k1 => KeyType::Secp256k1,
        }
    }
}

impl From<KeyType> for WasmKeyType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => WasmKeyType::Ed25519,
            KeyType::Secp256k1 => WasmKeyType::Secp256k1,
        }
    }
}

/// Error type for WASM
#[wasm_bindgen]
pub struct WasmError {
    message: String,
}

#[wasm_bindgen]
impl WasmError {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl From<crate::error::Error> for WasmError {
    fn from(err: crate::error::Error) -> Self {
        WasmError {
            message: err.to_string(),
        }
    }
}

impl From<WasmError> for JsValue {
    fn from(err: WasmError) -> Self {
        JsValue::from_str(&err.message)
    }
}

/// Result type for WASM
pub type WasmResult<T> = Result<T, WasmError>;