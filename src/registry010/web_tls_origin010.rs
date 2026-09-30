//! Authenticated TLS connection to an explicitly approved web Registry target.

use crate::error::{Error, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::web_origin_policy010::web_registry_request_url_010;

fn unreachable() -> Error {
    Error::ValidationError("record.unreachable".into())
}

/// Establish a new TLS connection to an exact, locally approved IP endpoint
/// and authenticate the web DID's DNS name against an explicitly trusted root.
/// This does not send HTTP or validate a Registry response. Success alone is
/// neither an authoritative observation nor an authorization decision.
pub fn check_web_registry_tls_origin_010(
    did: &str,
    allowed_origins: &[&str],
    destination: SocketAddr,
    allowed_destinations: &[SocketAddr],
    root_der: &[u8],
) -> Result<()> {
    web_registry_request_url_010(did, allowed_origins)?;
    if destination.port() == 0
        || destination.ip().is_unspecified()
        || !allowed_destinations.contains(&destination)
    {
        return Err(unreachable());
    }
    let rest = did.strip_prefix("did:sage:web:").ok_or_else(unreachable)?;
    let (domain, _) = rest.split_once(':').ok_or_else(unreachable)?;
    let server_name = ServerName::try_from(domain.to_owned()).map_err(|_| unreachable())?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .map_err(|_| unreachable())?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let timeout = Duration::from_secs(5);
    let mut socket =
        TcpStream::connect_timeout(&destination, timeout).map_err(|_| unreachable())?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| unreachable())?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|_| unreachable())?;
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| unreachable())?;
    let deadline = Instant::now() + timeout;
    while connection.is_handshaking() {
        if Instant::now() >= deadline {
            return Err(unreachable());
        }
        connection
            .complete_io(&mut socket)
            .map_err(|_| unreachable())?;
    }
    if connection
        .peer_certificates()
        .is_none_or(|certs| certs.is_empty())
    {
        return Err(unreachable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_unapproved_destinations_before_connecting() {
        let did = "did:sage:web:agents.example.com:billing-bot";
        let endpoint: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(check_web_registry_tls_origin_010(
            did,
            &["https://agents.example.com"],
            endpoint,
            &[],
            &[]
        )
        .is_err());
        assert!(check_web_registry_tls_origin_010(did, &[], endpoint, &[endpoint], &[]).is_err());
    }
}
