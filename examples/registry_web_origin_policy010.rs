//! Local Inspector adapter for REG-08 request and response policy only.

use sage_crypto_core::error::Error;
use sage_crypto_core::registry010::{
    check_web_registry_response_policy_010, web_registry_request_url_010, HeaderField010,
};
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireField {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    expected_did: String,
    allowed_origins: Vec<String>,
    status: u16,
    headers: Vec<WireField>,
    trailers: Vec<WireField>,
}

fn fields(fields: Vec<WireField>) -> Vec<HeaderField010> {
    fields
        .into_iter()
        .map(|field| HeaderField010 {
            name: field.name,
            value: field.value,
        })
        .collect()
}

fn main() {
    let mut raw = Vec::new();
    if io::stdin().take(8193).read_to_end(&mut raw).is_err() || raw.len() > 8192 {
        std::process::exit(2);
    }
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let origins: Vec<&str> = request.allowed_origins.iter().map(String::as_str).collect();
    let result = web_registry_request_url_010(&request.expected_did, &origins).and_then(|url| {
        check_web_registry_response_policy_010(
            request.status,
            &fields(request.headers),
            &fields(request.trailers),
        )?;
        Ok(url)
    });
    let (verdict, url) = match result {
        Ok(url) => ("POLICY_ACCEPT", url),
        Err(Error::ValidationError(code)) if code == "record.unreachable" => {
            ("RECORD_UNREACHABLE", String::new())
        }
        Err(_) => ("RECORD_INVALID", String::new()),
    };
    println!("{}", serde_json::json!({"verdict": verdict, "url": url}));
}
