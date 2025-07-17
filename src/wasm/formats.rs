//! WASM bindings for key format operations

use super::*;
use crate::formats::{KeyFormat, KeyImporter, KeyExporter};
use wasm_bindgen::prelude::*;

/// Key format enum for WASM
#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum WasmKeyFormat {
    Raw = 0,
    Pem = 1,
    Der = 2,
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
pub struct WasmKeyFormat;

#[wasm_bindgen]
impl WasmKeyFormat {
    /// Export a key pair to a specific format
    #[wasm_bindgen(js_name = exportKeyPair)]
    pub fn export_keypair(
        keypair: &WasmKeyPair,
        format: WasmKeyFormat,
    ) -> WasmResult<Vec<u8>> {
        keypair.inner.export_private_key(format.into())
            .map_err(Into::into)
    }

    /// Import a key pair from a specific format
    #[wasm_bindgen(js_name = importKeyPair)]
    pub fn import_keypair(
        key_type: WasmKeyType,
        format: WasmKeyFormat,
        data: &[u8],
    ) -> WasmResult<WasmKeyPair> {
        KeyPair::import_private_key(key_type.into(), format.into(), data)
            .map(|keypair| WasmKeyPair { inner: keypair })
            .map_err(Into::into)
    }

    /// Export a public key to a specific format
    #[wasm_bindgen(js_name = exportPublicKey)]
    pub fn export_public_key(
        public_key: &WasmPublicKey,
        format: WasmKeyFormat,
    ) -> WasmResult<Vec<u8>> {
        public_key.inner.export(format.into())
            .map_err(Into::into)
    }

    /// Import a public key from a specific format
    #[wasm_bindgen(js_name = importPublicKey)]
    pub fn import_public_key(
        key_type: WasmKeyType,
        format: WasmKeyFormat,
        data: &[u8],
    ) -> WasmResult<WasmPublicKey> {
        PublicKey::import(key_type.into(), format.into(), data)
            .map(|public_key| WasmPublicKey { inner: public_key })
            .map_err(Into::into)
    }

    /// Export a key pair to PEM format
    #[wasm_bindgen(js_name = exportKeyPairToPem)]
    pub fn export_keypair_to_pem(keypair: &WasmKeyPair) -> WasmResult<String> {
        let pem_data = keypair.inner.export_private_key(KeyFormat::Pem)?;
        String::from_utf8(pem_data)
            .map_err(|e| WasmError { message: format!("Invalid UTF-8 in PEM: {}", e) })
    }

    /// Import a key pair from PEM format
    #[wasm_bindgen(js_name = importKeyPairFromPem)]
    pub fn import_keypair_from_pem(
        key_type: WasmKeyType,
        pem_data: &str,
    ) -> WasmResult<WasmKeyPair> {
        KeyPair::import_private_key(key_type.into(), KeyFormat::Pem, pem_data.as_bytes())
            .map(|keypair| WasmKeyPair { inner: keypair })
            .map_err(Into::into)
    }

    /// Export a public key to PEM format
    #[wasm_bindgen(js_name = exportPublicKeyToPem)]
    pub fn export_public_key_to_pem(public_key: &WasmPublicKey) -> WasmResult<String> {
        let pem_data = public_key.inner.export(KeyFormat::Pem)?;
        String::from_utf8(pem_data)
            .map_err(|e| WasmError { message: format!("Invalid UTF-8 in PEM: {}", e) })
    }

    /// Import a public key from PEM format
    #[wasm_bindgen(js_name = importPublicKeyFromPem)]
    pub fn import_public_key_from_pem(
        key_type: WasmKeyType,
        pem_data: &str,
    ) -> WasmResult<WasmPublicKey> {
        PublicKey::import(key_type.into(), KeyFormat::Pem, pem_data.as_bytes())
            .map(|public_key| WasmPublicKey { inner: public_key })
            .map_err(Into::into)
    }

    /// Export a key pair to JWK format
    #[wasm_bindgen(js_name = exportKeyPairToJwk)]
    pub fn export_keypair_to_jwk(keypair: &WasmKeyPair) -> WasmResult<String> {
        let jwk_data = keypair.inner.export_private_key(KeyFormat::Jwk)?;
        String::from_utf8(jwk_data)
            .map_err(|e| WasmError { message: format!("Invalid UTF-8 in JWK: {}", e) })
    }

    /// Import a key pair from JWK format
    #[wasm_bindgen(js_name = importKeyPairFromJwk)]
    pub fn import_keypair_from_jwk(
        key_type: WasmKeyType,
        jwk_data: &str,
    ) -> WasmResult<WasmKeyPair> {
        KeyPair::import_private_key(key_type.into(), KeyFormat::Jwk, jwk_data.as_bytes())
            .map(|keypair| WasmKeyPair { inner: keypair })
            .map_err(Into::into)
    }

    /// Export a public key to JWK format
    #[wasm_bindgen(js_name = exportPublicKeyToJwk)]
    pub fn export_public_key_to_jwk(public_key: &WasmPublicKey) -> WasmResult<String> {
        let jwk_data = public_key.inner.export(KeyFormat::Jwk)?;
        String::from_utf8(jwk_data)
            .map_err(|e| WasmError { message: format!("Invalid UTF-8 in JWK: {}", e) })
    }

    /// Import a public key from JWK format
    #[wasm_bindgen(js_name = importPublicKeyFromJwk)]
    pub fn import_public_key_from_jwk(
        key_type: WasmKeyType,
        jwk_data: &str,
    ) -> WasmResult<WasmPublicKey> {
        PublicKey::import(key_type.into(), KeyFormat::Jwk, jwk_data.as_bytes())
            .map(|public_key| WasmPublicKey { inner: public_key })
            .map_err(Into::into)
    }

    /// Convert between different key formats
    #[wasm_bindgen(js_name = convertKeyFormat)]
    pub fn convert_key_format(
        key_type: WasmKeyType,
        from_format: WasmKeyFormat,
        to_format: WasmKeyFormat,
        data: &[u8],
    ) -> WasmResult<Vec<u8>> {
        // Import from source format
        let keypair = KeyPair::import_private_key(key_type.into(), from_format.into(), data)?;
        
        // Export to target format
        keypair.export_private_key(to_format.into())
            .map_err(Into::into)
    }

    /// Validate key format
    #[wasm_bindgen(js_name = validateKeyFormat)]
    pub fn validate_key_format(
        key_type: WasmKeyType,
        format: WasmKeyFormat,
        data: &[u8],
    ) -> bool {
        KeyPair::import_private_key(key_type.into(), format.into(), data).is_ok()
    }

    /// Get supported formats for a key type
    #[wasm_bindgen(js_name = getSupportedFormats)]
    pub fn get_supported_formats(key_type: WasmKeyType) -> Vec<WasmKeyFormat> {
        // All key types support all formats in this implementation
        vec![
            WasmKeyFormat::Raw,
            WasmKeyFormat::Pem,
            WasmKeyFormat::Der,
            WasmKeyFormat::Jwk,
        ]
    }
}