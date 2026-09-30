//! Local Inspector adapter for the untrusted REG-08 JSON envelope only.

use sage_crypto_core::error::Error;
use sage_crypto_core::registry010::check_web_registry_envelope_010;
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    body: String,
    now: i64,
}

fn main() {
    let mut raw = Vec::new();
    if io::stdin().take(280_001).read_to_end(&mut raw).is_err() || raw.len() > 280_000 {
        std::process::exit(2);
    }
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let verdict = match check_web_registry_envelope_010(request.body.as_bytes(), request.now) {
        Ok(()) => "ENVELOPE_ACCEPT",
        Err(Error::ValidationError(code)) if code == "size.exceeded" => "SIZE_EXCEEDED",
        Err(_) => "RECORD_INVALID",
    };
    println!("{}", serde_json::json!({"verdict": verdict}));
}
