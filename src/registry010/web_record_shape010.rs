//! Structural REG-08 record checks; no origin trust or proof verification.

use crate::error::{Error, Result};
use crate::jcs::{self, Value};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::{BTreeMap, HashSet};

use super::web_envelope010::check_web_registry_envelope_010;

const MAX_RECORD: usize = 65_536;
const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_991;

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

fn object(value: &Value) -> Result<&[(String, Value)]> {
    if let Value::Object(fields) = value {
        Ok(fields)
    } else {
        Err(invalid())
    }
}

fn array(value: &Value) -> Result<&[Value]> {
    if let Value::Array(items) = value {
        Ok(items)
    } else {
        Err(invalid())
    }
}

fn string(value: &Value) -> Result<&str> {
    if let Value::String(text) = value {
        Ok(text)
    } else {
        Err(invalid())
    }
}

fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Result<&'a Value> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or_else(invalid)
}

fn closed(fields: &[(String, Value)], required: &[&str], optional: Option<&str>) -> bool {
    if fields.len() < required.len()
        || fields.len() > required.len() + usize::from(optional.is_some())
    {
        return false;
    }
    required
        .iter()
        .all(|name| fields.iter().any(|(key, _)| key == name))
        && fields
            .iter()
            .all(|(key, _)| required.contains(&key.as_str()) || optional == Some(key.as_str()))
}

fn ascii(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && text.is_ascii()
}

fn key_id(text: &str) -> bool {
    (1..=32).contains(&text.len())
        && text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn web_did(did: &str) -> bool {
    if did.len() > 256 {
        return false;
    }
    let Some(rest) = did.strip_prefix("did:sage:web:") else {
        return false;
    };
    let Some((domain, agent)) = rest.split_once(':') else {
        return false;
    };
    if rest.matches(':').count() != 1
        || !(1..=64).contains(&domain.len())
        || !(1..=64).contains(&agent.len())
        || agent == "."
        || agent == ".."
        || !agent
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
    {
        return false;
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    domain.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    })
}

fn canonical_base64(text: &str, expected_len: Option<usize>) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    if bytes.is_empty()
        || expected_len.is_some_and(|size| bytes.len() != size)
        || URL_SAFE_NO_PAD.encode(&bytes) != text
    {
        return None;
    }
    Some(bytes)
}

fn service_uri(text: &str) -> bool {
    if !ascii(text, 1, 2048) {
        return false;
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte <= 0x20 || byte == 0x7f || matches!(byte, b'#' | b'\\') {
            return false;
        }
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 2;
        }
        index += 1;
    }
    let Ok(uri) = text.parse::<http::Uri>() else {
        return false;
    };
    uri.scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
        && uri.authority().is_some_and(|authority| {
            !authority.host().is_empty() && !authority.as_str().contains('@')
        })
}

/// Validate the bounded web record structure inside a fresh JSON envelope.
/// A trusted adapter must enforce body/media/TLS rules. This does not validate
/// key points, proofs, historic immutability, or controller authority; success
/// must never authorize a protected operation.
pub fn check_web_registry_record_shape_010(raw: &[u8], expected_did: &str, now: i64) -> Result<()> {
    check_web_registry_envelope_010(raw, now)?;
    if !web_did(expected_did) {
        return Err(invalid());
    }
    let wrapper: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(raw).map_err(|_| invalid())?;
    let record_raw = wrapper.get("record").ok_or_else(invalid)?.get();
    if record_raw.len() > MAX_RECORD {
        return Err(Error::ValidationError("size.exceeded".into()));
    }
    let record = jcs::parse(record_raw).map_err(|_| invalid())?;
    let fields = object(&record)?;
    if !closed(
        fields,
        &["id", "controller", "keys", "services", "state", "version"],
        None,
    ) || string(field(fields, "id")?)? != expected_did
        || !ascii(string(field(fields, "controller")?)?, 1, 256)
    {
        return Err(invalid());
    }
    let version = string(field(fields, "version")?)?;
    if version.starts_with('0')
        || version.parse::<u64>().ok().filter(|n| *n > 0).is_none()
        || !version.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(invalid());
    }
    let state = string(field(fields, "state")?)?;
    if !matches!(state, "created" | "active" | "deactivated") {
        return Err(invalid());
    }
    let keys = array(field(fields, "keys")?)?;
    if !(1..=128).contains(&keys.len()) {
        return Err(invalid());
    }
    let mut names = HashSet::new();
    let mut materials = HashSet::new();
    let mut previous = "";
    let mut active_signing = false;
    for entry in keys {
        let key = object(entry)?;
        if !closed(
            key,
            &["name", "alg", "key", "proof", "state"],
            Some("expires"),
        ) {
            return Err(invalid());
        }
        let name = string(field(key, "name")?)?;
        if !key_id(name) || (!previous.is_empty() && name <= previous) {
            return Err(invalid());
        }
        previous = name;
        names.insert(name);
        let alg = string(field(key, "alg")?)?;
        let want = match alg {
            "ed25519" | "x25519" => 32,
            "sage-secp256k1-keccak256" | "ecdsa-p256-sha256" => 65,
            _ => return Err(invalid()),
        };
        let encoded = string(field(key, "key")?)?;
        let material = canonical_base64(encoded, Some(want)).ok_or_else(invalid)?;
        if (want == 65 && material[0] != 4) || !materials.insert(encoded) {
            return Err(invalid());
        }
        let key_state = string(field(key, "state")?)?;
        if !matches!(key_state, "accepted" | "revoked") {
            return Err(invalid());
        }
        let expires = if let Some((_, value)) = key.iter().find(|(name, _)| name == "expires") {
            let number = super::web_envelope010::exact_integer(value).ok_or_else(invalid)?;
            if !(0..=MAX_EXACT_INTEGER).contains(&number) {
                return Err(invalid());
            }
            Some(number)
        } else {
            None
        };
        let proof = object(field(key, "proof")?)?;
        if !closed(proof, &["signer", "value"], None) {
            return Err(invalid());
        }
        let signer = string(field(proof, "signer")?)?;
        let Some(signer_name) = signer.strip_prefix(&format!("{expected_did}#")) else {
            return Err(invalid());
        };
        if !key_id(signer_name)
            || (alg != "x25519" && signer_name != name)
            || (alg == "x25519" && signer_name == name)
        {
            return Err(invalid());
        }
        let signature = string(field(proof, "value")?)?;
        if signature.len() > 87 || canonical_base64(signature, None).is_none() {
            return Err(invalid());
        }
        if alg != "x25519" && key_state == "accepted" && expires.is_none_or(|expiry| now < expiry) {
            active_signing = true;
        }
    }
    if state == "active" && !active_signing {
        return Err(invalid());
    }
    let services = array(field(fields, "services")?)?;
    if services.len() > 16 {
        return Err(invalid());
    }
    previous = "";
    for entry in services {
        let service = object(entry)?;
        if !closed(service, &["name", "type", "uri"], None) {
            return Err(invalid());
        }
        let name = string(field(service, "name")?)?;
        if !key_id(name) || names.contains(name) || (!previous.is_empty() && name <= previous) {
            return Err(invalid());
        }
        previous = name;
        if !ascii(string(field(service, "type")?)?, 1, 64)
            || !service_uri(string(field(service, "uri")?)?)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value as JsonValue};

    const DID: &str = "did:sage:web:agents.example.com:billing-bot";

    fn fixture() -> JsonValue {
        json!({
            "id": DID, "controller": "operator", "state": "active", "version": "1",
            "keys": [{
                "name": "sign-1", "alg": "ed25519",
                "key": URL_SAFE_NO_PAD.encode([0u8; 32]),
                "proof": {"signer": format!("{DID}#sign-1"), "value": URL_SAFE_NO_PAD.encode([0u8; 64])},
                "state": "accepted"
            }],
            "services": [{"name": "api", "type": "A2A", "uri": "https://api.example.com/v1"}]
        })
    }

    fn check(record: &JsonValue) -> Result<()> {
        let body = json!({"record": record, "issued": 100, "expires": 105}).to_string();
        check_web_registry_record_shape_010(body.as_bytes(), DID, 100)
    }

    #[test]
    fn record_fields_keys_and_services() {
        assert!(check(&fixture()).is_ok());
        for (name, edit) in [
            ("id", "did:sage:web:other.example.com:billing-bot"),
            ("version", "01"),
            ("state", "unknown"),
        ] {
            let mut record = fixture();
            record[name] = json!(edit);
            assert!(check(&record).is_err(), "{name}");
        }
        let mut record = fixture();
        record["version"] = json!("18446744073709551615");
        assert!(check(&record).is_ok());
        record["version"] = json!("18446744073709551616");
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][0]["alg"] = json!("X25519");
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][0]["proof"]["signer"] = json!(format!("{DID}#other"));
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][0]["expires"] = json!(100);
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["keys"][0]["expires"] = json!(100.5);
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["services"][0]["name"] = json!("sign-1");
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["services"][0]["uri"] = json!("http://api.example.com");
        assert!(check(&record).is_err());
        let mut record = fixture();
        record["services"][0]["uri"] = json!("https://127.0.0.1:8443/v1");
        assert!(check(&record).is_ok());
    }

    #[test]
    fn exact_encoded_record_limit() {
        let encoded = fixture().to_string();
        let spaces = " ".repeat(MAX_RECORD - encoded.len());
        let record = format!("{{{spaces}{}", &encoded[1..]);
        let body = format!(r#"{{"record":{record},"issued":100,"expires":105}}"#);
        assert!(check_web_registry_record_shape_010(body.as_bytes(), DID, 100).is_ok());
        let too_large_record = format!("{{{spaces} {}", &encoded[1..]);
        let too_large = format!(r#"{{"record":{too_large_record},"issued":100,"expires":105}}"#);
        assert!(
            matches!(check_web_registry_record_shape_010(too_large.as_bytes(), DID, 100), Err(Error::ValidationError(ref code)) if code == "size.exceeded")
        );
    }
}
