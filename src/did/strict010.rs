//! Canonical 0.10.0 DID and key-URL syntax, separate from legacy DID parsing.
//! Parsing does not resolve a record or establish registry authority.

use crate::error::{Error, Result};
use std::net::Ipv4Addr;

/// A canonical 0.10.0 DID, without a resolved record or authority claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Did010 {
    /// Registry profile kind (`eip155` or `web`).
    pub kind: String,
    /// Canonical profile locator.
    pub locator: String,
    /// Agent name within the registry.
    pub agent_id: String,
}

/// A canonical 0.10.0 key reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl010 {
    /// The DID part of the reference.
    pub did: Did010,
    /// The exact key fragment.
    pub key_id: String,
}

fn malformed() -> Error {
    Error::InvalidInput("id.malformed".into())
}

fn unknown_kind() -> Error {
    Error::InvalidInput("id.unknown-kind".into())
}

/// Parse an exact 0.10.0 DID without changing the legacy `parse_did` API.
pub fn parse_did_010(raw: &str) -> Result<Did010> {
    if raw.len() > 256 {
        return Err(malformed());
    }
    let rest = raw.strip_prefix("did:sage:").ok_or_else(malformed)?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 3 || !valid_kind(parts[0]) {
        return Err(malformed());
    }
    let (locator, agent_id) = match parts[0] {
        "eip155" if parts.len() == 4 && valid_chain(parts[1]) && valid_address(parts[2]) => {
            (format!("{}:{}", parts[1], parts[2]), parts[3])
        }
        "web" if parts.len() == 3 && valid_domain(parts[1]) => (parts[1].to_owned(), parts[2]),
        "eip155" | "web" => return Err(malformed()),
        _ => return Err(unknown_kind()),
    };
    if !valid_agent(agent_id) {
        return Err(malformed());
    }
    Ok(Did010 {
        kind: parts[0].to_owned(),
        locator,
        agent_id: agent_id.to_owned(),
    })
}

/// Parse a DID URL with exactly one canonical key fragment.
pub fn parse_did_url_010(raw: &str) -> Result<DidUrl010> {
    if raw.len() > 289 {
        return Err(malformed());
    }
    let (did, key_id) = raw.split_once('#').ok_or_else(malformed)?;
    if !valid_key_id(key_id) {
        return Err(malformed());
    }
    Ok(DidUrl010 {
        did: parse_did_010(did)?,
        key_id: key_id.to_owned(),
    })
}

fn valid_kind(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_agent(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

fn valid_chain(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && (b'1'..=b'9').contains(&bytes[0])
        && bytes[1..].iter().all(u8::is_ascii_digit)
}

fn valid_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value.as_bytes()[2..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.parse::<Ipv4Addr>().is_err()
        && value.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && ascii_lower_alnum(bytes[0])
                && ascii_lower_alnum(bytes[bytes.len() - 1])
                && (bytes.len() == 1
                    || bytes[1..bytes.len() - 1]
                        .iter()
                        .all(|c| ascii_lower_alnum(*c) || *c == b'-'))
        })
}

fn ascii_lower_alnum(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_dids_and_legacy_separation() {
        let web = parse_did_010("did:sage:web:agents.example.com:billing-bot").unwrap();
        assert_eq!(web.kind, "web");
        assert_eq!(web.locator, "agents.example.com");
        assert_eq!(web.agent_id, "billing-bot");
        let address = format!("0x{}", "a".repeat(40));
        let chain =
            parse_did_010(&format!("did:sage:eip155:11155111:{address}:0x1234abcd")).unwrap();
        assert_eq!(chain.locator, format!("11155111:{address}"));
        assert!(super::super::parse_did("did:sage:ETH:0xabc").is_ok());
        assert!(parse_did_010("did:sage:ETH:0xabc").is_err());
    }

    #[test]
    fn rejects_noncanonical_identity_and_key_urls() {
        let address = format!("0x{}", "a".repeat(40));
        for input in [
            "DID:sage:web:agents.example.com:a".to_owned(),
            "did:SAGE:web:agents.example.com:a".to_owned(),
            "did:sage:web:Agents.example.com:a".to_owned(),
            "did:sage:web:127.0.0.1:a".to_owned(),
            "did:sage:web:-bad.example:a".to_owned(),
            "did:sage:web:bad-.example:a".to_owned(),
            "did:sage:web:example.com.:a".to_owned(),
            "did:sage:web:example.com:..".to_owned(),
            "did:sage:web:example.com:a?x=1".to_owned(),
            "did:sage:web:example.com:a#key".to_owned(),
            "did:sage:web:example.com:a:extra".to_owned(),
            format!("did:sage:eip155:0:{address}:a"),
            format!("did:sage:eip155:01:{address}:a"),
            format!("did:sage:eip155:1:0x{}:a", "A".repeat(40)),
            format!("did:sage:web:example.com:{}", "a".repeat(65)),
        ] {
            assert!(parse_did_010(&input).is_err(), "{input}");
        }
        for input in ["did:sage:solana:abc:agent", "did:sage:other:loc:agent"] {
            assert!(parse_did_010(input)
                .unwrap_err()
                .to_string()
                .contains("id.unknown-kind"));
        }
        let url = "did:sage:web:agents.example.com:billing-bot#key-1";
        assert_eq!(parse_did_url_010(url).unwrap().key_id, "key-1");
        for input in [
            "did:sage:web:agents.example.com:billing-bot".to_owned(),
            format!("{url}#other"),
            "did:sage:web:agents.example.com:billing-bot#".to_owned(),
            "did:sage:web:agents.example.com:billing-bot#key.1".to_owned(),
            format!(
                "did:sage:web:agents.example.com:billing-bot#{}",
                "x".repeat(33)
            ),
            format!("{url}/path"),
        ] {
            assert!(parse_did_url_010(&input).is_err(), "{input}");
        }
    }
}
