//! Key resolvers for the handshake: a memory table for tests and gateways,
//! and an adapter over the DID-document resolver.

use crate::crypto::PublicKey;
use crate::error::{Error, Result};
use crate::hpke::types::{DIDResolver, KemKeyResolver, SigningKeyResolver};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Signing key and KEM key registered for a DID.
type KeyEntry = (Option<PublicKey>, Option<[u8; 32]>);

/// Fixed DID -> (signing key, KEM key) table.
#[derive(Default)]
pub struct MemoryKeyResolver {
    keys: RwLock<HashMap<String, KeyEntry>>,
}

impl MemoryKeyResolver {
    /// Empty table
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a signing key.
    pub fn add_signing_key(&self, did: &str, key: PublicKey) {
        let mut m = self.keys.write().unwrap();
        m.entry(did.to_string()).or_insert((None, None)).0 = Some(key);
    }

    /// Register a KEM key.
    pub fn add_kem_key(&self, did: &str, key: [u8; 32]) {
        let mut m = self.keys.write().unwrap();
        m.entry(did.to_string()).or_insert((None, None)).1 = Some(key);
    }
}

impl KemKeyResolver for MemoryKeyResolver {
    fn resolve_kem_key(&self, did: &str) -> Result<[u8; 32]> {
        self.keys
            .read()
            .unwrap()
            .get(did)
            .and_then(|e| e.1)
            .ok_or_else(|| Error::ResolutionError(format!("no KEM key for {did}")))
    }
}

impl SigningKeyResolver for MemoryKeyResolver {
    fn resolve_signing_key(&self, did: &str) -> Result<PublicKey> {
        self.keys
            .read()
            .unwrap()
            .get(did)
            .and_then(|e| e.0.clone())
            .ok_or_else(|| Error::ResolutionError(format!("no signing key for {did}")))
    }
}

/// Adapter that reads the X25519 key out of a DID document.
pub struct DidDocumentKemResolver(pub Arc<dyn DIDResolver>);

impl KemKeyResolver for DidDocumentKemResolver {
    fn resolve_kem_key(&self, did: &str) -> Result<[u8; 32]> {
        let result = self.0.resolve(&did.to_string())?;
        let doc = result
            .document
            .ok_or_else(|| Error::ResolutionError(format!("DID not found: {did}")))?;
        for vm in &doc.verification_method {
            if vm.method_type.contains("X25519") {
                if let Some(mb) = &vm.public_key_multibase {
                    if let Some(stripped) = mb.strip_prefix('z') {
                        let bytes = bs58::decode(stripped)
                            .into_vec()
                            .map_err(|e| Error::ParseError(format!("multibase: {e}")))?;
                        return bytes
                            .try_into()
                            .map_err(|_| Error::CryptoError("X25519 key must be 32 bytes".into()));
                    }
                }
            }
        }
        Err(Error::ResolutionError(format!(
            "no X25519 key in the DID document of {did}"
        )))
    }
}
