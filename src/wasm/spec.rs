//! WASM bindings for JCS, `did:sage`, proofs of possession, agent cards and
//! session records.

use super::*;
use crate::session::{SecureSession, Session, SessionConfig};

/// Canonicalise JSON (RFC 8785).
#[wasm_bindgen(js_name = jcsCanonicalize)]
pub fn jcs_canonicalize(json: &str) -> WasmResult<String> {
    let out = crate::jcs::canonicalize(json.as_bytes())?;
    Ok(String::from_utf8(out).unwrap_or_default())
}

/// Parse `did:sage:<chain>:<identifier>`; returns `{"chain":…,"identifier":…}` as JSON.
#[wasm_bindgen(js_name = parseDid)]
pub fn parse_did(did: &str) -> WasmResult<String> {
    let (chain, id) = crate::did::parse_did(did)?;
    Ok(format!(
        "{{\"chain\":\"{}\",\"identifier\":{}}}",
        chain.as_str(),
        serde_json::to_string(&id).unwrap_or_default()
    ))
}

/// Build `did:sage:<chain>:<identifier>` (`chain` accepts aliases).
#[wasm_bindgen(js_name = generateDid)]
pub fn generate_did(chain: &str, identifier: &str) -> WasmResult<String> {
    Ok(crate::did::generate_did(
        crate::did::parse_chain(chain)?,
        identifier,
    ))
}

/// Key proof of possession of `keypair` for `did`.
#[wasm_bindgen(js_name = generateKeyPop)]
pub fn generate_key_pop(did: &str, keypair: &WasmKeyPair) -> WasmResult<Vec<u8>> {
    crate::did::generate_key_pop(did, &keypair.inner).map_err(Into::into)
}

/// Verify a key proof of possession.
#[wasm_bindgen(js_name = verifyKeyPop)]
pub fn verify_key_pop(
    did: &str,
    key_type: WasmKeyType,
    key_data: &[u8],
    proof: &[u8],
) -> WasmResult<()> {
    crate::did::verify_key_pop(did, key_type.into(), key_data, proof).map_err(Into::into)
}

/// Parse an A2A agent card and verify its proof.
#[wasm_bindgen(js_name = verifyAgentCard)]
pub fn verify_agent_card(json: &str) -> WasmResult<()> {
    crate::did::A2AAgentCard::from_json(json.as_bytes())?
        .verify_proof()
        .map_err(Into::into)
}

/// Session id for a seed and label.
#[wasm_bindgen(js_name = sessionIdFromSeed)]
pub fn session_id_from_seed(seed: &[u8], label: &str) -> WasmResult<String> {
    crate::session::compute_session_id(seed, label).map_err(Into::into)
}

/// A session over the sage-spec record format.
#[wasm_bindgen]
pub struct WasmSession {
    inner: SecureSession,
}

#[wasm_bindgen]
impl WasmSession {
    /// Create a session. `role` is 1 for the initiator, 0 for the responder
    /// and -1 for a session without a role; `rekeyInterval` 0 disables rotation.
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_id: &str,
        seed: &[u8],
        role: i32,
        rekey_interval: u64,
    ) -> WasmResult<WasmSession> {
        let config = SessionConfig {
            rekey_interval,
            max_messages: 0,
            ..Default::default()
        };
        let inner = match role {
            1 => SecureSession::with_role(session_id.to_string(), seed, true, config)?,
            0 => SecureSession::with_role(session_id.to_string(), seed, false, config)?,
            _ => SecureSession::new(session_id.to_string(), seed, config)?,
        };
        Ok(WasmSession { inner })
    }

    /// Encrypt a record (outbound for role sessions); `aad` may be empty.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> WasmResult<Vec<u8>> {
        if self.inner.is_initiator().is_some() {
            self.inner
                .encrypt_with_aad_outbound(plaintext, aad)
                .map_err(Into::into)
        } else {
            self.inner
                .encrypt_with_aad(plaintext, aad)
                .map_err(Into::into)
        }
    }

    /// Decrypt a record (inbound for role sessions); `aad` may be empty.
    pub fn decrypt(&self, record: &[u8], aad: &[u8]) -> WasmResult<Vec<u8>> {
        if self.inner.is_initiator().is_some() {
            self.inner
                .decrypt_with_aad_inbound(record, aad)
                .map_err(Into::into)
        } else {
            self.inner.decrypt_with_aad(record, aad).map_err(Into::into)
        }
    }

    /// Records sent plus received.
    #[wasm_bindgen(getter, js_name = messageCount)]
    pub fn message_count(&self) -> usize {
        self.inner.get_message_count()
    }

    /// Session id
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.get_id().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jcs_and_did_helpers() {
        assert_eq!(
            jcs_canonicalize(r#"{"b":1,"a":[2, 1.0]}"#).unwrap(),
            r#"{"a":[2,1],"b":1}"#
        );
        assert!(jcs_canonicalize("{").is_err());
        let did = generate_did("eth", "0xabc").unwrap();
        assert_eq!(did, "did:sage:ethereum:0xabc");
        assert_eq!(
            parse_did(&did).unwrap(),
            r#"{"chain":"ethereum","identifier":"0xabc"}"#
        );
        assert!(parse_did("did:web:x").is_err());
    }

    #[test]
    fn pop_round_trip() {
        let kp = WasmKeyPair::generate_secp256k1().unwrap();
        let did = "did:sage:ethereum:0x1";
        let proof = generate_key_pop(did, &kp).unwrap();
        let pk = kp.get_public_key();
        verify_key_pop(did, WasmKeyType::Secp256k1, &pk.to_bytes(), &proof).unwrap();
        assert!(verify_key_pop(
            "did:sage:ethereum:0x2",
            WasmKeyType::Secp256k1,
            &pk.to_bytes(),
            &proof
        )
        .is_err());
    }

    #[test]
    fn session_round_trip_between_roles() {
        let seed = [7u8; 32];
        let id = session_id_from_seed(&seed, "sage/hpke+e2e v1").unwrap();
        let client = WasmSession::new(&id, &seed, 1, 0).unwrap();
        let server = WasmSession::new(&id, &seed, 0, 0).unwrap();
        let rec = client.encrypt(b"hi", b"aad").unwrap();
        assert_eq!(server.decrypt(&rec, b"aad").unwrap(), b"hi");
        assert!(server.decrypt(&rec, b"other").is_err());
        assert_eq!(client.message_count(), 1);
        assert_eq!(client.id(), id);
        let plain = WasmSession::new(&id, &seed, -1, 0).unwrap();
        let rec = plain.encrypt(b"x", &[]).unwrap();
        assert_eq!(plain.decrypt(&rec, &[]).unwrap(), b"x");
    }
}
