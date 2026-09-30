//! Structural lifecycle checks for authenticated web Registry history.

use crate::error::{Error, Result};
use crate::jcs;

use super::web_envelope010::exact_integer;
use super::web_record_proofs010::check_web_registry_proofs_010;
use super::web_record_shape010::{array, field, object, string};

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

#[derive(PartialEq, Eq)]
struct Key {
    name: String,
    alg: String,
    material: String,
    signer: String,
    proof: String,
    state: String,
    expires: Option<i64>,
}

impl Key {
    fn same_material(&self, other: &Self) -> bool {
        self.name == other.name
            && self.alg == other.alg
            && self.material == other.material
            && self.signer == other.signer
            && self.proof == other.proof
            && self.expires == other.expires
    }
}

#[derive(PartialEq, Eq)]
struct Service {
    name: String,
    kind: String,
    uri: String,
}

#[derive(PartialEq, Eq)]
struct Record {
    id: String,
    controller: String,
    keys: Vec<Key>,
    services: Vec<Service>,
    state: String,
    version: String,
}

fn read_record(raw: &[u8], did: &str, now: i64) -> Result<Record> {
    check_web_registry_proofs_010(raw, did, now)?;
    let value =
        jcs::parse(std::str::from_utf8(raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
    let wrapper = object(&value)?;
    let record = object(field(wrapper, "record")?)?;
    let keys = array(field(record, "keys")?)?
        .iter()
        .map(|value| {
            let key = object(value)?;
            let proof = object(field(key, "proof")?)?;
            let expires = key
                .iter()
                .find(|(name, _)| name == "expires")
                .map(|(_, value)| exact_integer(value).ok_or_else(invalid))
                .transpose()?;
            Ok(Key {
                name: string(field(key, "name")?)?.to_owned(),
                alg: string(field(key, "alg")?)?.to_owned(),
                material: string(field(key, "key")?)?.to_owned(),
                signer: string(field(proof, "signer")?)?.to_owned(),
                proof: string(field(proof, "value")?)?.to_owned(),
                state: string(field(key, "state")?)?.to_owned(),
                expires,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let services = array(field(record, "services")?)?
        .iter()
        .map(|value| {
            let service = object(value)?;
            Ok(Service {
                name: string(field(service, "name")?)?.to_owned(),
                kind: string(field(service, "type")?)?.to_owned(),
                uri: string(field(service, "uri")?)?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Record {
        id: string(field(record, "id")?)?.to_owned(),
        controller: string(field(record, "controller")?)?.to_owned(),
        keys,
        services,
        state: string(field(record, "state")?)?.to_owned(),
        version: string(field(record, "version")?)?.to_owned(),
    })
}

fn usable_signer(record: &Record, signer: &str, now: i64) -> bool {
    record.keys.iter().any(|key| {
        signer == format!("{}#{}", record.id, key.name)
            && key.alg != "x25519"
            && key.state == "accepted"
            && key.expires.is_none_or(|expires| now < expires)
    })
}

fn has_usable_signer(record: &Record, now: i64) -> bool {
    record
        .keys
        .iter()
        .any(|key| usable_signer(record, &format!("{}#{}", record.id, key.name), now))
}

/// Check the initial version and proof conditions for a created record.
/// The caller must bind `now` to creation time; controller authentication,
/// name reservation and atomic commit are external.
pub fn check_web_registry_creation_shape_010(raw: &[u8], did: &str, now: i64) -> Result<()> {
    let record = read_record(raw, did, now)?;
    if record.state != "created" || record.version != "1" || !has_usable_signer(&record, now) {
        return Err(invalid());
    }
    for key in &record.keys {
        if key.alg == "x25519" && !usable_signer(&record, &key.signer, now) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Check one proposed mutation between authenticated historical envelopes.
/// This does not authenticate an actor, prove complete source history, or
/// atomically write the record. The source must bind `candidate_now` to the
/// historical mutation time, particularly when a KEM endorser later expires
/// or is revoked; the trusted Registry deployment owns those checks.
pub fn check_web_registry_transition_shape_010(
    previous: &[u8],
    candidate: &[u8],
    did: &str,
    previous_now: i64,
    candidate_now: i64,
    operation: &str,
) -> Result<()> {
    let before = read_record(previous, did, previous_now)?;
    let after = read_record(candidate, did, candidate_now)?;
    let next_version = before
        .version
        .parse::<u64>()
        .ok()
        .and_then(|version| version.checked_add(1))
        .ok_or_else(invalid)?;
    if after.version != next_version.to_string()
        || before.controller != after.controller
        || before.state == "deactivated"
    {
        return Err(invalid());
    }
    let mut revoked = 0;
    for old in &before.keys {
        let current = after
            .keys
            .iter()
            .find(|key| key.name == old.name)
            .ok_or_else(invalid)?;
        if !old.same_material(current) {
            return Err(invalid());
        }
        if old.state != current.state {
            if old.state != "accepted" || current.state != "revoked" {
                return Err(invalid());
            }
            revoked += 1;
        }
    }
    let added = after
        .keys
        .len()
        .checked_sub(before.keys.len())
        .ok_or_else(invalid)?;
    let services_equal = before.services == after.services;
    let permitted = match operation {
        "activate" => {
            before.state == "created"
                && after.state == "active"
                && added == 0
                && revoked == 0
                && services_equal
        }
        "add-key" => {
            before.state == "active"
                && after.state == "active"
                && added == 1
                && revoked == 0
                && services_equal
                && after
                    .keys
                    .iter()
                    .filter(|key| !before.keys.iter().any(|old| old.name == key.name))
                    .all(|key| {
                        key.state == "accepted"
                            && (key.alg != "x25519"
                                || usable_signer(&after, &key.signer, candidate_now))
                    })
        }
        "revoke-key" => {
            let usable = has_usable_signer(&after, candidate_now);
            before.state == "active"
                && added == 0
                && revoked == 1
                && services_equal
                && ((usable && after.state == "active")
                    || (!usable && after.state == "deactivated"))
        }
        "update-services" => {
            before.state == "active" && after.state == "active" && added == 0 && revoked == 0
        }
        "deactivate" => {
            matches!(before.state.as_str(), "created" | "active")
                && after.state == "deactivated"
                && added == 0
                && revoked == 0
                && services_equal
        }
        _ => false,
    };
    if permitted {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// One caller-supplied historical envelope and its trusted mutation time.
/// The first operation must be `create`.
pub struct WebRegistryHistoryEntry010<'a> {
    /// A complete historical Registry envelope.
    pub envelope: &'a [u8],
    /// Trusted Unix second when this version was created.
    pub at: i64,
    /// The mutation that produced this version.
    pub operation: &'a str,
}

/// Check an asserted sequence from version-1 creation to the current record.
/// A trusted source must supply every envelope and bind each timestamp to the
/// actual mutation. This predicate cannot establish the source's authenticity
/// or completeness, authenticate actors, or perform an atomic Registry write.
pub fn check_web_registry_history_continuity_010(
    history: &[WebRegistryHistoryEntry010<'_>],
    current: &[u8],
    did: &str,
    current_now: i64,
) -> Result<()> {
    let first = history.first().ok_or_else(invalid)?;
    if first.operation != "create" || first.at > current_now {
        return Err(invalid());
    }
    check_web_registry_creation_shape_010(first.envelope, did, first.at)?;
    for pair in history.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if next.at < previous.at || next.at > current_now {
            return Err(invalid());
        }
        check_web_registry_transition_shape_010(
            previous.envelope,
            next.envelope,
            did,
            previous.at,
            next.at,
            next.operation,
        )?;
    }
    let last = history.last().ok_or_else(invalid)?;
    if read_record(last.envelope, did, last.at)? != read_record(current, did, current_now)? {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer;
    use serde_json::{json, Value as JsonValue};

    const DID: &str = "did:sage:web:agents.example.com:billing-bot";

    fn fixture() -> JsonValue {
        let first = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let second = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let signing = |name: &str, private: &ed25519_dalek::SigningKey| {
            let public = private.verifying_key().to_bytes();
            let challenge = super::super::proof::pop_challenge010(
                "web:agents.example.com",
                "billing-bot",
                name,
                "ed25519",
                &public,
            )
            .unwrap();
            json!({"name": name, "alg": "ed25519", "key": URL_SAFE_NO_PAD.encode(public),
                "proof": {"signer": format!("{DID}#{name}"),
                          "value": URL_SAFE_NO_PAD.encode(private.sign(&challenge).to_bytes())},
                "state": "accepted"})
        };
        let kem_public = x25519_dalek::x25519([7u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let challenge = super::super::proof::pop_challenge010(
            "web:agents.example.com",
            "billing-bot",
            "b-kem",
            "x25519",
            &kem_public,
        )
        .unwrap();
        let kem = json!({"name": "b-kem", "alg": "x25519",
            "key": URL_SAFE_NO_PAD.encode(kem_public),
            "proof": {"signer": format!("{DID}#a-ed"),
                      "value": URL_SAFE_NO_PAD.encode(first.sign(&challenge).to_bytes())},
            "state": "accepted"});
        json!({"id": DID, "controller": "operator", "keys": [
            signing("a-ed", &first), kem, signing("c-ed", &second)],
            "services": [], "state": "created", "version": "1"})
    }

    fn body(record: &JsonValue) -> Vec<u8> {
        json!({"record": record, "issued": 100, "expires": 105})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn creation_requires_active_kem_endorser() {
        let record = fixture();
        assert!(check_web_registry_creation_shape_010(&body(&record), DID, 100).is_ok());
        let mut changed = record;
        changed["keys"][0]["state"] = json!("revoked");
        assert!(check_web_registry_creation_shape_010(&body(&changed), DID, 100).is_err());
    }

    #[test]
    fn transition_preserves_controller_version_and_key_history() {
        let before = fixture();
        let mut after = before.clone();
        after["state"] = json!("active");
        after["version"] = json!("2");
        let check = |old: &JsonValue, next: &JsonValue, operation: &str| {
            check_web_registry_transition_shape_010(
                &body(old),
                &body(next),
                DID,
                100,
                100,
                operation,
            )
        };
        assert!(check(&before, &after, "activate").is_ok());
        let mut wrong = after.clone();
        wrong["version"] = json!("3");
        assert!(check(&before, &wrong, "activate").is_err());
        wrong = after.clone();
        wrong["controller"] = json!("other");
        assert!(check(&before, &wrong, "activate").is_err());
        wrong = after.clone();
        wrong["version"] = json!("3");
        wrong["keys"].as_array_mut().unwrap().remove(1);
        assert!(check(&after, &wrong, "update-services").is_err());

        let mut no_kem = after.clone();
        no_kem["keys"].as_array_mut().unwrap().remove(1);
        let mut added = after.clone();
        added["version"] = json!("3");
        assert!(check(&no_kem, &added, "add-key").is_ok());
        no_kem["keys"][0]["state"] = json!("revoked");
        added["keys"][0]["state"] = json!("revoked");
        assert!(check(&no_kem, &added, "add-key").is_err());

        let mut terminal = after.clone();
        terminal["version"] = json!("3");
        terminal["state"] = json!("deactivated");
        assert!(check(&after, &terminal, "deactivate").is_ok());
        assert!(check(&terminal, &after, "activate").is_err());
    }

    #[test]
    fn history_requires_contiguous_versions_and_current_record() {
        let created = fixture();
        let mut active = created.clone();
        active["state"] = json!("active");
        active["version"] = json!("2");
        let mut updated = active.clone();
        updated["version"] = json!("3");
        updated["services"] = json!([{"name": "api", "type": "Agent",
            "uri": "https://agents.example.com/api"}]);
        let snapshots = [body(&created), body(&active), body(&updated)];
        let history = [
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[0],
                at: 100,
                operation: "create",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[1],
                at: 101,
                operation: "activate",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[2],
                at: 102,
                operation: "update-services",
            },
        ];
        let check = |entries: &[WebRegistryHistoryEntry010<'_>], current: &[u8]| {
            check_web_registry_history_continuity_010(entries, current, DID, 103)
        };
        assert!(check(&history, &snapshots[2]).is_ok());
        assert!(check(&[], &snapshots[2]).is_err());
        assert!(check(&history[1..], &snapshots[2]).is_err());
        let skipped = [
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[0],
                at: 100,
                operation: "create",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[2],
                at: 102,
                operation: "update-services",
            },
        ];
        assert!(check(&skipped, &snapshots[2]).is_err());
        assert!(check(&history, &snapshots[1]).is_err());
        let regressed = [
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[0],
                at: 100,
                operation: "create",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[1],
                at: 101,
                operation: "activate",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[2],
                at: 99,
                operation: "update-services",
            },
        ];
        assert!(check(&regressed, &snapshots[2]).is_err());
        let mut terminal = updated.clone();
        terminal["version"] = json!("4");
        terminal["state"] = json!("deactivated");
        let mut after_terminal = terminal.clone();
        after_terminal["version"] = json!("5");
        let terminal_body = body(&terminal);
        let after_body = body(&after_terminal);
        let impossible = [
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[0],
                at: 100,
                operation: "create",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[1],
                at: 101,
                operation: "activate",
            },
            WebRegistryHistoryEntry010 {
                envelope: &snapshots[2],
                at: 102,
                operation: "update-services",
            },
            WebRegistryHistoryEntry010 {
                envelope: &terminal_body,
                at: 103,
                operation: "deactivate",
            },
            WebRegistryHistoryEntry010 {
                envelope: &after_body,
                at: 103,
                operation: "update-services",
            },
        ];
        assert!(check(&impossible, &after_body).is_err());
    }
}
