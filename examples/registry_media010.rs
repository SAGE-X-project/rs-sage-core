//! Local Inspector adapter for the REG-08 media subcondition only.

use sage_crypto_core::registry010::{check_web_registry_media_010, HeaderField010};
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    header_lines: Vec<(String, String)>,
    #[serde(default)]
    trailer_lines: Vec<(String, String)>,
}

fn fields(lines: Vec<(String, String)>) -> Vec<HeaderField010> {
    lines
        .into_iter()
        .map(|(name, value)| HeaderField010 { name, value })
        .collect()
}

fn main() {
    let mut raw = Vec::new();
    if io::stdin()
        .take(16 * 1024 + 1)
        .read_to_end(&mut raw)
        .is_err()
        || raw.len() > 16 * 1024
    {
        std::process::exit(2);
    }
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let verdict = if check_web_registry_media_010(
        &fields(request.header_lines),
        &fields(request.trailer_lines),
    )
    .is_ok()
    {
        "MEDIA_ACCEPT"
    } else {
        "RECORD_INVALID"
    };
    println!("{{\"verdict\":\"{verdict}\"}}");
}
