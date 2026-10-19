//! Local reference adapter for one verified mTLS Registry write.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sage_crypto_core::registry010::{
    apply_web_registry_write_010, WebRegistryAdminMTLSSession010, WebRegistryWriteJournal010,
};
use serde::Deserialize;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    server_cert: String,
    server_key: String,
    client_root: String,
    client_pin: String,
    actor: String,
    journal_path: String,
    did: String,
    source: String,
    now: i64,
    create: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    candidate: String,
    operation: String,
    expected_version: String,
}

fn decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).ok()
}

fn print_result(verdict: &str, committed: bool) {
    println!(
        "{}",
        serde_json::json!({"verdict":verdict,"committed":committed})
    );
}

fn main() {
    let mut input = Vec::new();
    if io::stdin().take(32_769).read_to_end(&mut input).is_err() || input.len() > 32_768 {
        std::process::exit(2);
    }
    let cfg: Configuration =
        serde_json::from_slice(&input).unwrap_or_else(|_| std::process::exit(2));
    let cert = decode(&cfg.server_cert).unwrap_or_else(|| std::process::exit(2));
    let key = decode(&cfg.server_key).unwrap_or_else(|| std::process::exit(2));
    let root = decode(&cfg.client_root).unwrap_or_else(|| std::process::exit(2));
    let pin = hex::decode(&cfg.client_pin).unwrap_or_else(|_| std::process::exit(2));
    let pin: [u8; 32] = pin.try_into().unwrap_or_else(|_| std::process::exit(2));
    let key = PrivateKeyDer::try_from(key).unwrap_or_else(|_| std::process::exit(2));
    if cfg.actor.is_empty()
        || cfg.did.is_empty()
        || cfg.source.is_empty()
        || cfg.journal_path.is_empty()
    {
        std::process::exit(2);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| std::process::exit(2));
    println!("PORT {}", listener.local_addr().unwrap().port());
    io::stdout()
        .flush()
        .unwrap_or_else(|_| std::process::exit(2));
    let (socket, _) = listener.accept().unwrap_or_else(|_| std::process::exit(2));
    let mut session = match WebRegistryAdminMTLSSession010::accept(
        socket,
        vec![CertificateDer::from(cert)],
        key,
        &root,
        &[(pin, cfg.actor)],
    ) {
        Ok(session) => session,
        Err(_) => {
            print_result("WRITE_REJECTED", false);
            return;
        }
    };
    let mut line = Vec::new();
    let read = BufReader::new((&mut session).take(150_001)).read_until(b'\n', &mut line);
    if read.is_err() || line.len() > 150_000 || !line.ends_with(b"\n") {
        print_result("WRITE_REJECTED", false);
        return;
    }
    let request: Request = match serde_json::from_slice(&line[..line.len() - 1]) {
        Ok(value) => value,
        Err(_) => {
            print_result("WRITE_REJECTED", false);
            return;
        }
    };
    let candidate = match decode(&request.candidate) {
        Some(value) if value.len() <= 69_632 => value,
        _ => {
            print_result("WRITE_REJECTED", false);
            return;
        }
    };
    let mut journal = match WebRegistryWriteJournal010::open(
        std::path::Path::new(&cfg.journal_path),
        &cfg.did,
        &cfg.source,
        &session,
        cfg.create,
    ) {
        Ok(value) => value,
        Err(_) => {
            print_result("RECORD_UNREACHABLE", false);
            return;
        }
    };
    let before = journal.inspect();
    let result = apply_web_registry_write_010(
        &mut journal,
        &cfg.source,
        &cfg.did,
        &candidate,
        cfg.now,
        &request.expected_version,
        &request.operation,
    );
    let after = journal.inspect();
    if journal.close().is_err() {
        print_result("RECORD_UNREACHABLE", false);
        return;
    }
    let verdict = match result {
        Ok(()) => "TRANSITION_ACCEPT",
        Err(sage_crypto_core::error::Error::ValidationError(ref code))
            if code == "record.rejected" =>
        {
            "WRITE_REJECTED"
        }
        Err(sage_crypto_core::error::Error::ValidationError(ref code))
            if code == "record.stale" =>
        {
            "RECORD_STALE"
        }
        Err(_) => "RECORD_INVALID",
    };
    print_result(verdict, after.history.len() != before.history.len());
}
