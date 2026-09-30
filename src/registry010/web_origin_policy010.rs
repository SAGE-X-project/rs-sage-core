//! Bounded request target and response policy checks for the web Registry.

use crate::error::{Error, Result};

use super::web_media010::{check_web_registry_media_010, HeaderField010};
use super::web_record_shape010::web_did;

fn invalid() -> Error {
    Error::ValidationError("record.invalid".into())
}

fn unreachable() -> Error {
    Error::ValidationError("record.unreachable".into())
}

/// Construct the sole REG-08 read target from a web DID and a locally
/// configured origin allowlist. A trusted TLS transport must still check the
/// connected destination and avoid caches and redirects; this is not an
/// authoritative observation.
pub fn web_registry_request_url_010(did: &str, allowed_origins: &[&str]) -> Result<String> {
    if !web_did(did) {
        return Err(invalid());
    }
    let rest = did.strip_prefix("did:sage:web:").ok_or_else(invalid)?;
    let (domain, agent) = rest.split_once(':').ok_or_else(invalid)?;
    let origin = format!("https://{domain}");
    if !allowed_origins.contains(&origin.as_str()) {
        return Err(unreachable());
    }
    Ok(format!("{origin}/.well-known/sage/agents/{agent}"))
}

/// Check status, media, and the origin's no-store directive before accepting
/// a body. The trusted transport must retain field lines and trailers, avoid
/// intermediary caches, and reject redirects. This does not establish TLS
/// origin, connected destination, or Registry authority.
pub fn check_web_registry_response_policy_010(
    status: u16,
    header: &[HeaderField010],
    trailer: &[HeaderField010],
) -> Result<()> {
    if status != 200 {
        return Err(unreachable());
    }
    check_web_registry_media_010(header, trailer)?;
    if header.iter().any(|field| {
        field.name.eq_ignore_ascii_case("cache-control")
            && field.value.split(',').any(|value| {
                value
                    .trim_matches([' ', '\t'])
                    .eq_ignore_ascii_case("no-store")
            })
    }) {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(name: &str, value: &str) -> HeaderField010 {
        HeaderField010 {
            name: name.into(),
            value: value.into(),
        }
    }

    #[test]
    fn exact_origin_target() {
        let did = "did:sage:web:agents.example.com:billing-bot";
        assert_eq!(
            web_registry_request_url_010(
                did,
                &["https://other.example.com", "https://agents.example.com"]
            )
            .unwrap(),
            "https://agents.example.com/.well-known/sage/agents/billing-bot"
        );
        for origin in [
            "http://agents.example.com",
            "https://agents.example.com:443",
            "https://agents.example.com/",
            "https://other.example.com",
        ] {
            assert!(web_registry_request_url_010(did, &[origin]).is_err());
        }
        for did in [
            "did:sage:web:127.0.0.1:a",
            "did:sage:web:Agents.example.com:a",
            "did:sage:web:agents.example.com:..",
            "did:sage:chain:x:a",
        ] {
            assert!(web_registry_request_url_010(did, &["https://agents.example.com"]).is_err());
        }
    }

    #[test]
    fn response_requires_direct_fresh_json_policy() {
        let header = [
            line("Content-Type", "application/json"),
            line("Cache-Control", "private, NO-STORE"),
        ];
        assert!(check_web_registry_response_policy_010(200, &header, &[]).is_ok());
        for status in [0, 301, 304, 404] {
            assert!(check_web_registry_response_policy_010(status, &header, &[]).is_err());
        }
        for bad in [
            vec![line("Content-Type", "application/json")],
            vec![
                line("Content-Type", "application/json"),
                line("Cache-Control", "no-store=1"),
            ],
            vec![
                line("Content-Type", "text/plain"),
                line("Cache-Control", "no-store"),
            ],
        ] {
            assert!(check_web_registry_response_policy_010(200, &bad, &[]).is_err());
        }
        assert!(check_web_registry_response_policy_010(
            200,
            &header,
            &[line("Content-Type", "application/json")]
        )
        .is_err());
    }
}
