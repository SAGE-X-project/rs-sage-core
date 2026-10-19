//! Verified administrator identity on a single server-side TLS connection.

use super::{rejected, WebRegistryAdminAuthority010};
use crate::error::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A verified actor and the same TLS channel carrying the administrative
/// request. The deployment must frame and validate the exact request bytes
/// before invoking the Registry write transaction. This binding permits only
/// controller writes; it does not define delegated management state.
pub struct WebRegistryAdminMTLSSession010 {
    stream: StreamOwned<ServerConnection, TcpStream>,
    actor: String,
    closed: bool,
}

fn pinned_actor(leaf: &[u8], actor_pins: &[([u8; 32], String)]) -> Result<String> {
    if actor_pins.is_empty() || actor_pins.len() > 128 {
        return Err(rejected());
    }
    let digest: [u8; 32] = Sha256::digest(leaf).into();
    let mut matched = actor_pins.iter().filter(|(pin, _)| *pin == digest);
    let actor = matched.next().ok_or_else(rejected)?.1.clone();
    if matched.next().is_some() || actor.is_empty() || actor.len() > 256 || !actor.is_ascii() {
        return Err(rejected());
    }
    Ok(actor)
}

impl WebRegistryAdminMTLSSession010 {
    /// Perform a fresh server-side mTLS handshake using a trusted client CA.
    /// Pins map the verified leaf certificate's SHA-256 to a configured actor.
    /// Certificate material and pins must come from deployment configuration.
    pub fn accept(
        mut socket: TcpStream,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_root_der: &[u8],
        actor_pins: &[([u8; 32], String)],
    ) -> Result<Self> {
        if actor_pins.is_empty() || actor_pins.len() > 128 {
            return Err(rejected());
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(client_root_der.to_vec()))
            .map_err(|_| rejected())?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| rejected())?;
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .map_err(|_| rejected())?;
        let mut connection = ServerConnection::new(Arc::new(config)).map_err(|_| rejected())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while connection.is_handshaking() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(rejected)?;
            socket
                .set_read_timeout(Some(remaining))
                .map_err(|_| rejected())?;
            socket
                .set_write_timeout(Some(remaining))
                .map_err(|_| rejected())?;
            connection
                .complete_io(&mut socket)
                .map_err(|_| rejected())?;
        }
        let leaf = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(rejected)?;
        let actor = pinned_actor(leaf.as_ref(), actor_pins)?;
        Ok(Self {
            stream: StreamOwned::new(connection, socket),
            actor,
            closed: false,
        })
    }

    /// Close the channel and retire its authority.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.stream.sock.shutdown(Shutdown::Both)
    }
}

impl Read for WebRegistryAdminMTLSSession010 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.stream.read(buf)
    }
}

impl Write for WebRegistryAdminMTLSSession010 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.stream.flush()
    }
}

impl WebRegistryAdminAuthority010 for WebRegistryAdminMTLSSession010 {
    fn authenticated_actor(&self) -> Result<String> {
        if self.closed {
            return Err(rejected());
        }
        Ok(self.actor.clone())
    }

    fn delegated(
        &self,
        _controller: &str,
        _actor: &str,
        _did: &str,
        _operation: &str,
        _expected_version: &str,
    ) -> Result<bool> {
        Ok(false)
    }
}

impl Drop for WebRegistryAdminMTLSSession010 {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_only_one_valid_actor_for_exact_leaf() {
        let pin: [u8; 32] = Sha256::digest(b"leaf").into();
        let allowed = vec![(pin, "operator".to_owned())];
        assert_eq!(pinned_actor(b"leaf", &allowed).unwrap(), "operator");
        assert!(pinned_actor(b"other", &allowed).is_err());
        assert!(pinned_actor(b"leaf", &[]).is_err());
        assert!(pinned_actor(b"leaf", &[(pin, String::new())]).is_err());
        assert!(pinned_actor(b"leaf", &[(pin, "\u{00e9}".into())]).is_err());
        assert!(pinned_actor(b"leaf", &[allowed[0].clone(), allowed[0].clone()]).is_err());
    }
}
