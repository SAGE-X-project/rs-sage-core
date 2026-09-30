//! Local Inspector adapter for bounded web Registry lifecycle checks.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sage_crypto_core::error::Error;
use sage_crypto_core::registry010::{
    check_web_registry_creation_admission_010, check_web_registry_creation_shape_010,
    check_web_registry_history_continuity_010, check_web_registry_mutation_admission_010,
    check_web_registry_transition_shape_010, WebRegistryAdminAuthority010,
    WebRegistryHistoryEntry010,
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
        _ => std::process::exit(2),
    };
    let verdict = match result {
        Ok(()) => "TRANSITION_ACCEPT",
        Err(Error::ValidationError(code)) if code == "size.exceeded" => "SIZE_EXCEEDED",
        Err(Error::ValidationError(code)) if code == "record.stale" => "RECORD_STALE",
        Err(Error::ValidationError(code)) if code == "record.rejected" => "WRITE_REJECTED",
        Err(_) => "RECORD_INVALID",
    };
    println!("{}", serde_json::json!({"verdict": verdict}));
}
