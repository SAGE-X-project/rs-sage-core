//! Local Inspector adapter for bounded web Registry lifecycle checks.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sage_crypto_core::error::Error;
use sage_crypto_core::registry010::{
    check_web_registry_creation_shape_010, check_web_registry_transition_shape_010,
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
        _ => std::process::exit(2),
    };
    let verdict = match result {
        Ok(()) => "TRANSITION_ACCEPT",
        Err(Error::ValidationError(code)) if code == "size.exceeded" => "SIZE_EXCEEDED",
        Err(_) => "RECORD_INVALID",
    };
    println!("{}", serde_json::json!({"verdict": verdict}));
}
