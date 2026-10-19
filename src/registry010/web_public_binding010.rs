//! Compare one authenticated HTTPS record with the local administrator journal.

use super::web_http_record010::fetch_web_registry_record_010;
use super::web_origin_policy010::web_registry_request_url_010;
use super::web_write_journal010::WebRegistryWriteJournal010;
use super::{stale, unreachable};
use crate::error::Result;
use serde_json::Value;
use std::net::SocketAddr;

/// One bounded publication consistency observation. The HTTPS fetch is fresh
/// and authenticated, but a match does not authorize a later operation or
/// establish a full REG-08 deployment binding.
pub fn observe_web_registry_journal_010(
    journal: &WebRegistryWriteJournal010<'_>,
    allowed_origins: &[&str],
    destination: SocketAddr,
    allowed_destinations: &[SocketAddr],
    root_der: &[u8],
    now: i64,
) -> Result<Vec<u8>> {
    let (did, source, ready) = journal.binding();
    let state = journal.inspect();
    if !ready || state.history.is_empty() {
        return Err(unreachable());
    }
    let url = web_registry_request_url_010(did, allowed_origins)?;
    let (domain, _) = did
        .strip_prefix("did:sage:web:")
        .and_then(|rest| rest.split_once(':'))
        .ok_or_else(unreachable)?;
    if source != format!("https://{domain}")
        || !url.starts_with(&format!("{source}/.well-known/sage/agents/"))
    {
        return Err(unreachable());
    }
    let observed = fetch_web_registry_record_010(
        did,
        allowed_origins,
        destination,
        allowed_destinations,
        root_der,
        now,
    )?;
    let written: Value = serde_json::from_slice(&state.envelope).map_err(|_| unreachable())?;
    let public: Value = serde_json::from_slice(&observed).map_err(|_| unreachable())?;
    if written.get("record") != public.get("record") {
        return Err(stale());
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry010::WebRegistryAdminAuthority010;

    struct Authority;
    impl WebRegistryAdminAuthority010 for Authority {
        fn authenticated_actor(&self) -> Result<String> {
            Ok("operator".into())
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

    #[test]
    fn empty_or_closed_journal_cannot_supply_public_authority() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Authority;
        let mut journal = WebRegistryWriteJournal010::open(
            &dir.path().join("writes.log"),
            "did:sage:web:agents.example.com:billing-bot",
            "https://agents.example.com",
            &authority,
            true,
        )
        .unwrap();
        let destination: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let observe = |journal: &WebRegistryWriteJournal010<'_>| {
            observe_web_registry_journal_010(
                journal,
                &["https://agents.example.com"],
                destination,
                &[destination],
                &[],
                100,
            )
        };
        assert!(observe(&journal).is_err());
        journal.close().unwrap();
        assert!(observe(&journal).is_err());
    }
}
