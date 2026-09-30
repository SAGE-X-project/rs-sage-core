//! Local single-request HTTPS publisher backed by a Registry write journal.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sage_crypto_core::registry010::{WebRegistryAdminAuthority010, WebRegistryWriteJournal010};
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    server_cert: String,
    server_key: String,
    journal_path: String,
    did: String,
    source: String,
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
    let cert = URL_SAFE_NO_PAD
        .decode(&cfg.server_cert)
        .unwrap_or_else(|_| std::process::exit(2));
    let key = URL_SAFE_NO_PAD
        .decode(&cfg.server_key)
        .unwrap_or_else(|_| std::process::exit(2));
    let key = PrivateKeyDer::try_from(key).unwrap_or_else(|_| std::process::exit(2));
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
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert)], key)
        .unwrap_or_else(|_| std::process::exit(2));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| std::process::exit(2));
    println!("PORT {}", listener.local_addr().unwrap().port());
    io::stdout()
        .flush()
        .unwrap_or_else(|_| std::process::exit(2));
    let (socket, _) = listener.accept().unwrap_or_else(|_| std::process::exit(2));
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap_or_else(|_| std::process::exit(2));
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap_or_else(|_| std::process::exit(2));
    let connection =
        ServerConnection::new(Arc::new(config)).unwrap_or_else(|_| std::process::exit(2));
    let mut stream = StreamOwned::new(connection, socket);
    let (domain, agent) = cfg
        .did
        .strip_prefix("did:sage:web:")
        .and_then(|rest| rest.split_once(':'))
        .unwrap_or_else(|| std::process::exit(2));
    let request = format!("GET /.well-known/sage/agents/{agent} HTTP/1.1\r\nHost: {domain}\r\nAccept: application/json\r\nCache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n");
    let mut actual = vec![0; request.len()];
    if stream.read_exact(&mut actual).is_err() || actual != request.as_bytes() {
        println!("{}", serde_json::json!({"verdict":"RECORD_UNREACHABLE"}));
        return;
    }
    let response = match journal.public_envelope(&cfg.did, &cfg.source, cfg.now) {
        Ok(response) => response,
        Err(_) => {
            println!("{}", serde_json::json!({"verdict":"RECORD_UNREACHABLE"}));
            return;
        }
    };
    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\n\r\n", response.len());
    if stream.write_all(header.as_bytes()).is_err() || stream.write_all(&response).is_err() {
        println!("{}", serde_json::json!({"verdict":"RECORD_UNREACHABLE"}));
        return;
    }
    println!("{}", serde_json::json!({"verdict":"PUBLISHED"}));
    journal.close().unwrap_or_else(|_| std::process::exit(2));
}
