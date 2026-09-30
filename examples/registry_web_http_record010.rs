//! Local Inspector adapter for a bounded authenticated Registry HTTP read.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sage_crypto_core::error::Error;
use sage_crypto_core::registry010::fetch_web_registry_record_010;
use serde::Deserialize;
use std::io::{self, Read};
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    expected_did: String,
    allowed_origins: Vec<String>,
    destination: String,
    allowed_destinations: Vec<String>,
    root_der: String,
    now: i64,
}

fn main() {
    let mut raw = Vec::new();
    if io::stdin().take(16_385).read_to_end(&mut raw).is_err() || raw.len() > 16_384 {
        std::process::exit(2);
    }
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let destination: SocketAddr = match request.destination.parse() {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let allowed_destinations: Vec<SocketAddr> = match request
        .allowed_destinations
        .iter()
        .map(|entry| entry.parse())
        .collect()
    {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let root = match URL_SAFE_NO_PAD.decode(&request.root_der) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let origins: Vec<&str> = request.allowed_origins.iter().map(String::as_str).collect();
    let verdict = match fetch_web_registry_record_010(
        &request.expected_did,
        &origins,
        destination,
        &allowed_destinations,
        &root,
        request.now,
    ) {
        Ok(_) => "RECORD_ACCEPT",
        Err(Error::ValidationError(code)) if code == "record.invalid" => "RECORD_INVALID",
        Err(Error::ValidationError(code)) if code == "size.exceeded" => "SIZE_EXCEEDED",
        Err(_) => "RECORD_UNREACHABLE",
    };
    println!("{}", serde_json::json!({"verdict": verdict}));
}
