//! WASM bindings for key pair operations

use super::*;
use wasm_bindgen::prelude::*;

/// Key pair for WASM
#[wasm_bindgen]
pub struct WasmKeyPair {
    pub(crate) inner: KeyPair,
}

#[wasm_bindgen]
impl WasmKeyPair {
    /// Generate a new key pair
    #[wasm_bindgen(constructor)]
    pub fn new(key_type: WasmKeyType) -> WasmResult<WasmKeyPair> {
        KeyPair::generate(key_type.into())
            .map(|keypair| WasmKeyPair { inner: keypair })
            .map_err(Into::into)
    }

    /// Generate a new Ed25519 key pair
    #[wasm_bindgen(js_name = generateEd25519)]
    pub fn generate_ed25519() -> WasmResult<WasmKeyPair> {
        Self::new(WasmKeyType::Ed25519)
    }

    /// Generate a new Secp256k1 key pair
    #[wasm_bindgen(js_name = generateSecp256k1)]
    pub fn generate_secp256k1() -> WasmResult<WasmKeyPair> {
        Self::new(WasmKeyType::Secp256k1)
    }

    /// Get the key type
    #[wasm_bindgen(getter, js_name = keyType)]
    pub fn key_type(&self) -> WasmKeyType {
        self.inner.key_type().into()
    }

    /// Get the key ID
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.inner.key_id().to_string()
    }

    /// Get the public key
    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> WasmPublicKey {
        WasmPublicKey {
            inner: self.inner.public_key().clone(),
        }
    }

    /// Export private key as hex string
    #[wasm_bindgen(js_name = exportPrivateKeyHex)]
    pub fn export_private_key_hex(&self) -> String {
        hex::encode(self.inner.private_key_bytes())
    }

    /// Export public key as hex string
    #[wasm_bindgen(js_name = exportPublicKeyHex)]
    pub fn export_public_key_hex(&self) -> String {
        hex::encode(self.inner.public_key_bytes())
    }

    /// Export private key as Uint8Array
    #[wasm_bindgen(js_name = exportPrivateKey)]
    pub fn export_private_key(&self) -> Vec<u8> {
        self.inner.private_key_bytes()
    }

    /// Export public key as Uint8Array
    #[wasm_bindgen(js_name = exportPublicKey)]
    pub fn export_public_key(&self) -> Vec<u8> {
        self.inner.public_key_bytes()
    }

    /// Import key pair from private key hex string
    #[wasm_bindgen(js_name = fromPrivateKeyHex)]
    pub fn from_private_key_hex(key_type: WasmKeyType, hex_key: &str) -> WasmResult<WasmKeyPair> {
        let bytes = hex::decode(hex_key).map_err(|e| WasmError {
            message: format!("Invalid hex: {}", e),
        })?;
        Self::from_private_key(key_type, &bytes)
    }

    /// Import key pair from private key bytes
    #[wasm_bindgen(js_name = fromPrivateKey)]
    pub fn from_private_key(key_type: WasmKeyType, private_key: &[u8]) -> WasmResult<WasmKeyPair> {
        KeyPair::from_private_key_bytes(key_type.into(), private_key)
            .map(|keypair| WasmKeyPair { inner: keypair })
            .map_err(Into::into)
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> WasmResult<WasmSignature> {
        self.inner
            .sign(message)
            .map(|sig| WasmSignature { inner: sig })
            .map_err(Into::into)
    }

    /// Sign a string message
    #[wasm_bindgen(js_name = signString)]
    pub fn sign_string(&self, message: &str) -> WasmResult<WasmSignature> {
        self.sign(message.as_bytes())
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &WasmSignature) -> bool {
        self.inner.verify(message, &signature.inner).is_ok()
    }

    /// Verify a signature on a string message
    #[wasm_bindgen(js_name = verifyString)]
    pub fn verify_string(&self, message: &str, signature: &WasmSignature) -> bool {
        self.verify(message.as_bytes(), signature)
    }
}

/// Public key for WASM
#[wasm_bindgen]
pub struct WasmPublicKey {
    pub(crate) inner: PublicKey,
}

#[wasm_bindgen]
impl WasmPublicKey {
    /// Get the key type
    #[wasm_bindgen(getter, js_name = keyType)]
    pub fn key_type(&self) -> WasmKeyType {
        self.inner.key_type().into()
    }

    /// Get the key ID
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.inner.key_id().to_string()
    }

    /// Export as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.inner.to_bytes())
    }

    /// Export as Uint8Array
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Import from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(key_type: WasmKeyType, hex_key: &str) -> WasmResult<WasmPublicKey> {
        let bytes = hex::decode(hex_key).map_err(|e| WasmError {
            message: format!("Invalid hex: {}", e),
        })?;
        Self::from_bytes(key_type, &bytes)
    }

    /// Import from bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(key_type: WasmKeyType, bytes: &[u8]) -> WasmResult<WasmPublicKey> {
        PublicKey::from_bytes(key_type.into(), bytes)
            .map(|key| WasmPublicKey { inner: key })
            .map_err(Into::into)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &WasmSignature) -> bool {
        self.inner.verify(message, &signature.inner).is_ok()
    }

    /// Verify a signature on a string message
    #[wasm_bindgen(js_name = verifyString)]
    pub fn verify_string(&self, message: &str, signature: &WasmSignature) -> bool {
        self.verify(message.as_bytes(), signature)
    }
}
