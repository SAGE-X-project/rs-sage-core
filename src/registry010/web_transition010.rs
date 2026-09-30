//! Structural lifecycle checks for authenticated web Registry history.

use crate::error::{Error, Result};
use crate::jcs;

use super::web_envelope010::exact_integer;
use super::web_record_proofs010::check_web_registry_proofs_with_policy_010;
use super::web_record_shape010::{array, field, object, string};

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

/// Deployment-provided administration authority. Actor identity must come
/// from verified transport credentials, never from a record or JSON field.
/// Delegation must come from controller-authorized, operation-scoped
/// management state bound to the expected version.
pub trait WebRegistryAdminAuthority010 {
    /// Return the authenticated actor's authorization identifier.
    fn authenticated_actor(&self) -> Result<String>;
    /// Check one delegated operation at the expected Registry version.
    fn delegated(
        &self,
        controller: &str,
        actor: &str,
        did: &str,
        operation: &str,
        expected_version: &str,
    ) -> Result<bool>;
}

fn admin_actor(authority: &dyn WebRegistryAdminAuthority010) -> Result<String> {
    let actor = authority
        .authenticated_actor()
        .map_err(|_| super::rejected())?;
    if actor.is_empty() || actor.len() > 256 || !actor.is_ascii() {
        return Err(super::rejected());
    }
    Ok(actor)
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
    read_record_with_policy(raw, did, now, true)
}

fn read_record_with_policy(
    raw: &[u8],
    did: &str,
    now: i64,
    require_usable_signing: bool,
) -> Result<Record> {
    check_web_registry_proofs_with_policy_010(raw, did, now, require_usable_signing)?;
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
    check_web_registry_transition_shape_with_policy_010(
        previous,
        candidate,
        did,
        previous_now,
        candidate_now,
        operation,
        true,
    )
}

fn check_web_registry_transition_shape_with_policy_010(
    previous: &[u8],
    candidate: &[u8],
    did: &str,
    previous_now: i64,
    candidate_now: i64,
    operation: &str,
    require_previous_usable_signing: bool,
) -> Result<()> {
    let before =
        read_record_with_policy(previous, did, previous_now, require_previous_usable_signing)?;
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

/// Check creation by the deployment-authenticated controller. The deployment
/// must still reserve the name and repeat admission inside an atomic write.
pub fn check_web_registry_creation_admission_010(
    authority: &dyn WebRegistryAdminAuthority010,
    candidate: &[u8],
    did: &str,
    now: i64,
) -> Result<()> {
    let actor = admin_actor(authority)?;
    check_web_registry_creation_shape_010(candidate, did, now)?;
    let record = read_record(candidate, did, now)?;
    if actor != record.controller {
        return Err(super::rejected());
    }
    Ok(())
}

/// Check expected-version and actor policy for one proposed mutation. An
/// operator must have the exact operation in trusted management state.
/// Authentication, delegation, version and write still require one atomic
/// deployment transaction; this predicate grants no durable write authority.
pub fn check_web_registry_mutation_admission_010(
    authority: &dyn WebRegistryAdminAuthority010,
    previous: &[u8],
    candidate: &[u8],
    did: &str,
    now: i64,
    expected_version: &str,
    operation: &str,
) -> Result<()> {
    let actor = admin_actor(authority)?;
    let before = read_record_with_policy(previous, did, now, false)?;
    if expected_version != before.version {
        return Err(super::stale());
    }
    if actor != before.controller
        && !authority
            .delegated(&before.controller, &actor, did, operation, expected_version)
            .unwrap_or(false)
    {
        return Err(super::rejected());
    }
    check_web_registry_transition_shape_with_policy_010(
        previous, candidate, did, now, now, operation, false,
    )
}

/// One committed Registry version at its trusted mutation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRegistryOwnedHistoryEntry010 {
    /// The complete response envelope as accepted at mutation time.
    pub envelope: Vec<u8>,
    /// Trusted Unix second when the version was created.
    pub at: i64,
    /// The operation that produced the version.
    pub operation: String,
}

/// The complete state supplied and replaced by one trusted transaction.
/// `envelope` must be a fresh response for the current record; historical
/// envelopes retain the trusted time at which each version was committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRegistryWriteState010 {
    /// Authenticated source identity pinned by local deployment configuration.
    pub source: String,
    /// Fresh response envelope for the current record, empty when absent.
    pub envelope: Vec<u8>,
    /// Every committed version, starting with creation.
    pub history: Vec<WebRegistryOwnedHistoryEntry010>,
    /// Deactivated identifiers remain reserved forever.
    pub tombstoned: bool,
}

/// Current state and management authority read inside the same transaction.
pub struct WebRegistryWriteSnapshot010<'a> {
    /// Complete Registry state at this transaction's serialization point.
    pub state: WebRegistryWriteState010,
    /// Actor from verified credentials and controller-authorized delegation.
    pub authority: &'a dyn WebRegistryAdminAuthority010,
}

/// A deployment store must serialize writes for each identifier, obtain a
/// snapshot from its authenticated source, call `decide` exactly once, and
/// durably replace the complete state only when `decide` succeeds. All errors
/// leave state unchanged. The
/// authority must never be built from caller-supplied JSON fields.
pub trait WebRegistryWriteStore010 {
    /// Execute one complete Registry write transaction.
    fn update(
        &mut self,
        did: &str,
        decide: &mut dyn for<'a> FnMut(
            WebRegistryWriteSnapshot010<'a>,
        ) -> Result<WebRegistryWriteState010>,
    ) -> Result<()>;
}

/// Build the complete next state inside a deployment transaction. The source
/// identity is local configuration, never request data. This function does
/// not itself implement a durable store or credential verifier.
pub fn apply_web_registry_write_010(
    store: &mut dyn WebRegistryWriteStore010,
    trusted_source: &str,
    did: &str,
    candidate: &[u8],
    now: i64,
    expected_version: &str,
    operation: &str,
) -> Result<()> {
    if trusted_source.is_empty() || did.is_empty() {
        return Err(super::rejected());
    }
    store.update(did, &mut |snapshot| {
        let mut state = snapshot.state;
        if state.source != trusted_source {
            return Err(super::unreachable());
        }
        if state.envelope.is_empty() {
            if !state.history.is_empty()
                || state.tombstoned
                || operation != "create"
                || !expected_version.is_empty()
            {
                return Err(super::stale());
            }
            check_web_registry_creation_admission_010(snapshot.authority, candidate, did, now)?;
        } else {
            let last = state.history.last().ok_or_else(invalid)?;
            if operation == "create" || last.at > now {
                return Err(invalid());
            }
            let history: Vec<_> = state
                .history
                .iter()
                .map(|entry| WebRegistryHistoryEntry010 {
                    envelope: &entry.envelope,
                    at: entry.at,
                    operation: &entry.operation,
                })
                .collect();
            check_web_registry_history_continuity_010(&history, &last.envelope, did, last.at)?;
            let historical = read_record(&last.envelope, did, last.at)?;
            let current = read_record_with_policy(&state.envelope, did, now, false)?;
            if historical != current || state.tombstoned != (current.state == "deactivated") {
                return Err(invalid());
            }
            check_web_registry_mutation_admission_010(
                snapshot.authority,
                &state.envelope,
                candidate,
                did,
                now,
                expected_version,
                operation,
            )?;
        }
        let record = read_record(candidate, did, now)?;
        state.envelope = candidate.to_vec();
        state.history.push(WebRegistryOwnedHistoryEntry010 {
            envelope: candidate.to_vec(),
            at: now,
            operation: operation.to_owned(),
        });
        state.tombstoned = record.state == "deactivated";
        Ok(state)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer;
    use serde_json::{json, Value as JsonValue};
    use std::cell::Cell;

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

    struct TestAuthority {
        actor: &'static str,
        scope: &'static str,
        fail: bool,
        calls: Cell<usize>,
    }

    impl WebRegistryAdminAuthority010 for TestAuthority {
        fn authenticated_actor(&self) -> Result<String> {
            if self.fail {
                return Err(invalid());
            }
            Ok(self.actor.to_owned())
        }

        fn delegated(
            &self,
            controller: &str,
            actor: &str,
            did: &str,
            operation: &str,
            expected_version: &str,
        ) -> Result<bool> {
            self.calls.set(self.calls.get() + 1);
            Ok(controller == "operator"
                && actor == "assistant"
                && did == DID
                && expected_version == "1"
                && self.scope == operation)
        }
    }

    struct MemoryTransaction {
        state: WebRegistryWriteState010,
        authority: TestAuthority,
    }

    impl WebRegistryWriteStore010 for MemoryTransaction {
        fn update(
            &mut self,
            _did: &str,
            decide: &mut dyn for<'a> FnMut(
                WebRegistryWriteSnapshot010<'a>,
            ) -> Result<WebRegistryWriteState010>,
        ) -> Result<()> {
            let next = decide(WebRegistryWriteSnapshot010 {
                state: self.state.clone(),
                authority: &self.authority,
            })?;
            self.state = next;
            Ok(())
        }
    }

    fn memory_transaction() -> MemoryTransaction {
        MemoryTransaction {
            state: WebRegistryWriteState010 {
                source: "trusted-web-origin".to_owned(),
                envelope: Vec::new(),
                history: Vec::new(),
                tombstoned: false,
            },
            authority: TestAuthority {
                actor: "operator",
                scope: "",
                fail: false,
                calls: Cell::new(0),
            },
        }
    }

    #[test]
    fn transactional_write_commits_complete_state_and_rejects_stale_versions() {
        let created = fixture();
        let mut active = created.clone();
        active["state"] = json!("active");
        active["version"] = json!("2");
        let mut terminal = active.clone();
        terminal["state"] = json!("deactivated");
        terminal["version"] = json!("3");
        let create = body(&created);
        let activate = body(&active);
        let deactivate = body(&terminal);
        let mut store = memory_transaction();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &create,
            100,
            "",
            "create"
        )
        .is_ok());
        assert_eq!(store.state.history.len(), 1);
        assert!(!store.state.tombstoned);
        let before = store.state.clone();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &activate,
            100,
            "2",
            "activate"
        )
        .is_err());
        assert_eq!(store.state, before);
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &activate,
            100,
            "1",
            "activate"
        )
        .is_ok());
        assert_eq!(store.state.history.len(), 2);
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &deactivate,
            100,
            "2",
            "deactivate"
        )
        .is_ok());
        assert_eq!(store.state.history.len(), 3);
        assert!(store.state.tombstoned);
        let before = store.state.clone();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &create,
            100,
            "",
            "create"
        )
        .is_err());
        assert_eq!(store.state, before);
    }

    #[test]
    fn transactional_write_requires_bound_source_history_and_authority() {
        let created = fixture();
        let mut active = created.clone();
        active["state"] = json!("active");
        active["version"] = json!("2");
        let create = body(&created);
        let activate = body(&active);
        let mut store = memory_transaction();
        store.state.source = "other-origin".to_owned();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &create,
            100,
            "",
            "create"
        )
        .is_err());
        assert!(store.state.history.is_empty());
        store.state.source = "trusted-web-origin".to_owned();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &create,
            100,
            "",
            "create"
        )
        .is_ok());
        store.state.history[0].envelope = activate.clone();
        let before = store.state.clone();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &activate,
            100,
            "1",
            "activate"
        )
        .is_err());
        assert_eq!(store.state, before);
        store.state.history[0].envelope = create;
        store.authority.actor = "assistant";
        let before = store.state.clone();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &activate,
            100,
            "1",
            "activate"
        )
        .is_err());
        assert_eq!(store.state, before);
    }

    #[test]
    fn transactional_write_recovers_expired_signer_and_checks_tombstone() {
        let base = fixture();
        let mut created = base.clone();
        created["keys"].as_array_mut().unwrap().pop();
        created["keys"][0]["expires"] = json!(101);
        let mut active = created.clone();
        active["state"] = json!("active");
        active["version"] = json!("2");
        let mut repaired = active.clone();
        repaired["version"] = json!("3");
        repaired["keys"]
            .as_array_mut()
            .unwrap()
            .push(base["keys"][2].clone());
        let create = body(&created);
        let before = body(&active);
        let after = body(&repaired);
        let mut store = memory_transaction();
        store.state.envelope = before.clone();
        store.state.history = vec![
            WebRegistryOwnedHistoryEntry010 {
                envelope: create,
                at: 100,
                operation: "create".into(),
            },
            WebRegistryOwnedHistoryEntry010 {
                envelope: before,
                at: 100,
                operation: "activate".into(),
            },
        ];
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &after,
            102,
            "2",
            "add-key"
        )
        .is_ok());
        assert_eq!(store.state.history.len(), 3);
        assert!(!store.state.tombstoned);
        assert!(read_record(&store.state.envelope, DID, 102).is_ok());
        store.state.tombstoned = true;
        let prior = store.state.clone();
        assert!(apply_web_registry_write_010(
            &mut store,
            "trusted-web-origin",
            DID,
            &after,
            102,
            "3",
            "add-key"
        )
        .is_err());
        assert_eq!(store.state, prior);
    }

    #[test]
    fn write_admission_requires_authenticated_controller_or_exact_scope() {
        let created = fixture();
        let mut active = created.clone();
        active["state"] = json!("active");
        active["version"] = json!("2");
        let before = body(&created);
        let after = body(&active);
        let mut authority = TestAuthority {
            actor: "operator",
            scope: "",
            fail: false,
            calls: Cell::new(0),
        };
        assert!(check_web_registry_creation_admission_010(&authority, &before, DID, 100).is_ok());
        assert!(check_web_registry_mutation_admission_010(
            &authority, &before, &after, DID, 100, "1", "activate"
        )
        .is_ok());
        assert_eq!(authority.calls.get(), 0);
        assert!(check_web_registry_mutation_admission_010(
            &authority, &before, &after, DID, 100, "2", "activate"
        )
        .is_err());
        authority.actor = "assistant";
        authority.scope = "activate";
        assert!(check_web_registry_creation_admission_010(&authority, &before, DID, 100).is_err());
        assert!(check_web_registry_mutation_admission_010(
            &authority, &before, &after, DID, 100, "1", "activate"
        )
        .is_ok());
        assert_eq!(authority.calls.get(), 1);
        authority.scope = "update-services";
        assert!(check_web_registry_mutation_admission_010(
            &authority, &before, &after, DID, 100, "1", "activate"
        )
        .is_err());
        authority.scope = "activate";
        let mut invalid_version = active;
        invalid_version["version"] = json!("3");
        assert!(check_web_registry_mutation_admission_010(
            &authority,
            &before,
            &body(&invalid_version),
            DID,
            100,
            "1",
            "activate"
        )
        .is_err());
        authority.fail = true;
        assert!(check_web_registry_mutation_admission_010(
            &authority, &before, &after, DID, 100, "1", "activate"
        )
        .is_err());
    }

    #[test]
    fn expired_signing_key_can_be_replaced_by_authenticated_controller() {
        let base = fixture();
        let mut created = base.clone();
        created["keys"].as_array_mut().unwrap().pop();
        created["keys"][0]["expires"] = json!(101);
        let mut active = created.clone();
        active["state"] = json!("active");
        active["version"] = json!("2");
        let mut repaired = active.clone();
        repaired["version"] = json!("3");
        repaired["keys"]
            .as_array_mut()
            .unwrap()
            .push(base["keys"][2].clone());
        let before = body(&active);
        let after = body(&repaired);
        assert!(check_web_registry_creation_shape_010(&body(&created), DID, 100).is_ok());
        assert!(check_web_registry_transition_shape_010(
            &body(&created),
            &before,
            DID,
            100,
            100,
            "activate"
        )
        .is_ok());
        assert!(
            super::super::web_record_proofs010::check_web_registry_proofs_010(&before, DID, 102)
                .is_err()
        );
        assert!(
            check_web_registry_transition_shape_010(&before, &after, DID, 100, 102, "add-key")
                .is_ok()
        );
        assert!(
            check_web_registry_transition_shape_010(&before, &after, DID, 102, 102, "add-key")
                .is_err()
        );
        let authority = TestAuthority {
            actor: "operator",
            scope: "",
            fail: false,
            calls: Cell::new(0),
        };
        assert!(check_web_registry_mutation_admission_010(
            &authority, &before, &after, DID, 102, "2", "add-key"
        )
        .is_ok());
        assert!(
            super::super::web_record_proofs010::check_web_registry_proofs_010(&after, DID, 102)
                .is_ok()
        );
        let mut broken = active;
        broken["keys"][0]["proof"]["value"] = json!("invalid");
        assert!(check_web_registry_mutation_admission_010(
            &authority,
            &body(&broken),
            &after,
            DID,
            102,
            "2",
            "add-key"
        )
        .is_err());
        let mut revoked = created;
        revoked["state"] = json!("active");
        revoked["version"] = json!("2");
        revoked["keys"][0]["state"] = json!("revoked");
        assert!(check_web_registry_mutation_admission_010(
            &authority,
            &body(&revoked),
            &after,
            DID,
            102,
            "2",
            "add-key"
        )
        .is_err());
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
