//! Local Inspector adapter for bounded web Registry lifecycle checks.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sage_crypto_core::error::Error;
use sage_crypto_core::registry010::{
    apply_web_registry_write_010, check_web_registry_creation_admission_010,
    check_web_registry_creation_shape_010, check_web_registry_history_continuity_010,
    check_web_registry_mutation_admission_010, check_web_registry_transition_shape_010,
    WebRegistryAdminAuthority010, WebRegistryHistoryEntry010, WebRegistryOwnedHistoryEntry010,
    WebRegistryWriteSnapshot010, WebRegistryWriteState010, WebRegistryWriteStore010,
};
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    did: String,
    #[serde(default)]
    previous: Option<String>,
    candidate: String,
    #[serde(default)]
    previous_now: i64,
    candidate_now: i64,
    #[serde(default)]
    operation: String,
    #[serde(default)]
    expected_version: String,
    #[serde(default)]
    fixture_actor: String,
    #[serde(default)]
    fixture_scope: String,
    #[serde(default)]
    fixture_authenticated: bool,
    #[serde(default)]
    fixture_source: String,
    #[serde(default)]
    trusted_source: String,
    #[serde(default)]
    fixture_tombstoned: bool,
    #[serde(default)]
    history: Vec<HistoryItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryItem {
    envelope: String,
    at: i64,
    operation: String,
}

// Local Inspector fixture only; no transport credentials are inspected here.
struct FixtureAuthority<'a> {
    actor: &'a str,
    scope: &'a str,
    authenticated: bool,
}

impl WebRegistryAdminAuthority010 for FixtureAuthority<'_> {
    fn authenticated_actor(&self) -> sage_crypto_core::error::Result<String> {
        if !self.authenticated {
            return Err(Error::ValidationError("record.rejected".into()));
        }
        Ok(self.actor.to_owned())
    }

    fn delegated(
        &self,
        controller: &str,
        actor: &str,
        _did: &str,
        operation: &str,
        _expected_version: &str,
    ) -> sage_crypto_core::error::Result<bool> {
        Ok(controller == "operator" && actor == "assistant" && self.scope == operation)
    }
}

// Process-local Inspector fixture only; no durable Registry state is used.
struct FixtureWriteStore<'a> {
    state: WebRegistryWriteState010,
    authority: FixtureAuthority<'a>,
}

impl WebRegistryWriteStore010 for FixtureWriteStore<'_> {
    fn update(
        &mut self,
        _did: &str,
        decide: &mut dyn for<'a> FnMut(
            WebRegistryWriteSnapshot010<'a>,
        )
            -> sage_crypto_core::error::Result<WebRegistryWriteState010>,
    ) -> sage_crypto_core::error::Result<()> {
        let next = decide(WebRegistryWriteSnapshot010 {
            state: self.state.clone(),
            authority: &self.authority,
        })?;
        self.state = next;
        Ok(())
    }
}

fn main() {
    let mut raw = Vec::new();
    if io::stdin().take(150_001).read_to_end(&mut raw).is_err() || raw.len() > 150_000 {
        std::process::exit(2);
    }
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let candidate = match URL_SAFE_NO_PAD.decode(&request.candidate) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let mut transaction_state = None;
    let result = match request.action.as_str() {
        "create" => {
            check_web_registry_creation_shape_010(&candidate, &request.did, request.candidate_now)
        }
        "transition" => {
            let previous = match request
                .previous
                .as_ref()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            {
                Some(value) => value,
                None => std::process::exit(2),
            };
            check_web_registry_transition_shape_010(
                &previous,
                &candidate,
                &request.did,
                request.previous_now,
                request.candidate_now,
                &request.operation,
            )
        }
        "history" => {
            let decoded = request
                .history
                .iter()
                .map(|item| URL_SAFE_NO_PAD.decode(&item.envelope))
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap_or_else(|_| std::process::exit(2));
            let history = request
                .history
                .iter()
                .zip(decoded.iter())
                .map(|(item, envelope)| WebRegistryHistoryEntry010 {
                    envelope,
                    at: item.at,
                    operation: &item.operation,
                })
                .collect::<Vec<_>>();
            check_web_registry_history_continuity_010(
                &history,
                &candidate,
                &request.did,
                request.candidate_now,
            )
        }
        "admission-create" => {
            let authority = FixtureAuthority {
                actor: &request.fixture_actor,
                scope: &request.fixture_scope,
                authenticated: request.fixture_authenticated,
            };
            check_web_registry_creation_admission_010(
                &authority,
                &candidate,
                &request.did,
                request.candidate_now,
            )
        }
        "admission-transition" => {
            let previous = match request
                .previous
                .as_ref()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            {
                Some(value) => value,
                None => std::process::exit(2),
            };
            let authority = FixtureAuthority {
                actor: &request.fixture_actor,
                scope: &request.fixture_scope,
                authenticated: request.fixture_authenticated,
            };
            check_web_registry_mutation_admission_010(
                &authority,
                &previous,
                &candidate,
                &request.did,
                request.candidate_now,
                &request.expected_version,
                &request.operation,
            )
        }
        "transaction" => {
            let previous = request
                .previous
                .as_ref()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .unwrap_or_else(|| std::process::exit(2));
            let history = request
                .history
                .iter()
                .map(|item| {
                    let envelope = URL_SAFE_NO_PAD
                        .decode(&item.envelope)
                        .unwrap_or_else(|_| std::process::exit(2));
                    WebRegistryOwnedHistoryEntry010 {
                        envelope,
                        at: item.at,
                        operation: item.operation.clone(),
                    }
                })
                .collect();
            let mut store = FixtureWriteStore {
                state: WebRegistryWriteState010 {
                    source: request.fixture_source.clone(),
                    envelope: previous,
                    history,
                    tombstoned: request.fixture_tombstoned,
                },
                authority: FixtureAuthority {
                    actor: &request.fixture_actor,
                    scope: &request.fixture_scope,
                    authenticated: request.fixture_authenticated,
                },
            };
            let before = store.state.clone();
            let result = apply_web_registry_write_010(
                &mut store,
                &request.trusted_source,
                &request.did,
                &candidate,
                request.candidate_now,
                &request.expected_version,
                &request.operation,
            );
            transaction_state = Some((
                store.state != before,
                store.state.history.len(),
                store.state.tombstoned,
            ));
            result
        }
        _ => std::process::exit(2),
    };
    let verdict = match result {
        Ok(()) => "TRANSITION_ACCEPT",
        Err(Error::ValidationError(code)) if code == "size.exceeded" => "SIZE_EXCEEDED",
        Err(Error::ValidationError(code)) if code == "record.stale" => "RECORD_STALE",
        Err(Error::ValidationError(code)) if code == "record.rejected" => "WRITE_REJECTED",
        Err(Error::ValidationError(code)) if code == "record.unreachable" => "RECORD_UNREACHABLE",
        Err(_) => "RECORD_INVALID",
    };
    if let Some((committed, history_len, tombstoned)) = transaction_state {
        println!(
            "{}",
            serde_json::json!({"verdict": verdict, "committed": committed,
            "history_len": history_len, "tombstoned": tombstoned})
        );
    } else {
        println!("{}", serde_json::json!({"verdict": verdict}));
    }
}
