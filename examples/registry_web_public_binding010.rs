//! Local readback adapter for one journal and one authenticated HTTPS origin.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sage_crypto_core::registry010::{
    observe_web_registry_journal_010, WebRegistryAdminAuthority010, WebRegistryWriteJournal010,
};
use serde::Deserialize;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    journal_path: String,
    did: String,
    source: String,
    allowed_origins: Vec<String>,
    destination: String,
    allowed_destinations: Vec<String>,
    root: String,
    now: i64,
}

struct ReadOnlyAuthority;

impl WebRegistryAdminAuthority010 for ReadOnlyAuthority {
    fn authenticated_actor(&self) -> sage_crypto_core::error::Result<String> {
        Err(sage_crypto_core::error::Error::ValidationError(
            "record.rejected".into(),
        ))
    }

    fn delegated(
        &self,
        _controller: &str,
        _actor: &str,
        _did: &str,
        _operation: &str,
        _expected_version: &str,
    ) -> sage_crypto_core::error::Result<bool> {
        Ok(false)
    }
}

fn main() {
    let mut input = Vec::new();
    if io::stdin().take(32_769).read_to_end(&mut input).is_err() || input.len() > 32_768 {
        std::process::exit(2);
    }
    let cfg: Configuration =
        serde_json::from_slice(&input).unwrap_or_else(|_| std::process::exit(2));
    let destination: SocketAddr = cfg
        .destination
        .parse()
        .unwrap_or_else(|_| std::process::exit(2));
    let approved: Vec<SocketAddr> = cfg
        .allowed_destinations
        .iter()
        .map(|value| value.parse().unwrap_or_else(|_| std::process::exit(2)))
        .collect();
    let root = URL_SAFE_NO_PAD
        .decode(&cfg.root)
        .unwrap_or_else(|_| std::process::exit(2));
    let authority = ReadOnlyAuthority;
    let mut journal = match WebRegistryWriteJournal010::open(
        Path::new(&cfg.journal_path),
        &cfg.did,
        &cfg.source,
        &authority,
        false,
    ) {
        Ok(journal) => journal,
        Err(_) => {
            println!("{}", serde_json::json!({"verdict":"RECORD_UNREACHABLE"}));
            return;
        }
    };
    let origins: Vec<&str> = cfg.allowed_origins.iter().map(String::as_str).collect();
    let result = observe_web_registry_journal_010(
        &journal,
        &origins,
        destination,
        &approved,
        &root,
        cfg.now,
    );
    let close = journal.close();
    let verdict = if close.is_err() {
        "RECORD_UNREACHABLE"
    } else {
        match result {
            Ok(_) => "MATCH",
            Err(sage_crypto_core::error::Error::ValidationError(ref code))
                if code == "record.stale" =>
            {
                "RECORD_STALE"
            }
            Err(_) => "RECORD_UNREACHABLE",
        }
    };
    println!("{}", serde_json::json!({"verdict":verdict}));
}
