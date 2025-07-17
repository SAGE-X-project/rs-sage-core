//! WASM utility functions

use super::*;

/// Generate random bytes
#[wasm_bindgen(js_name = generateRandomBytes)]
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a random hex string
#[wasm_bindgen(js_name = generateRandomHex)]
pub fn generate_random_hex(length: usize) -> String {
    hex::encode(generate_random_bytes(length))
}

/// Convert hex string to bytes
#[wasm_bindgen(js_name = hexToBytes)]
pub fn hex_to_bytes(hex: &str) -> WasmResult<Vec<u8>> {
    hex::decode(hex).map_err(|e| WasmError {
        message: format!("Invalid hex: {e}"),
    })
}

/// Convert bytes to hex string
#[wasm_bindgen(js_name = bytesToHex)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Hash data with SHA256
#[wasm_bindgen(js_name = sha256)]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash string with SHA256
#[wasm_bindgen(js_name = sha256String)]
pub fn sha256_string(data: &str) -> String {
    hex::encode(sha256(data.as_bytes()))
}
