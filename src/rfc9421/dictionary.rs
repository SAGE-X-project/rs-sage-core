//! Parsing of the `Signature-Input` and `Signature` header fields, which are
//! RFC 8941 dictionaries: `label=(…);params, label2=(…)` and
//! `label=:base64:, label2=:base64:`.

use crate::error::{Error, Result};
use crate::rfc9421::{parse_signature_input_value, SignatureComponent, SignatureParams};
use base64::{engine::general_purpose, Engine as _};
use std::collections::BTreeMap;

/// One `Signature-Input` member.
#[derive(Debug, Clone)]
pub struct SignatureInputMember {
    /// The components as parsed
    pub components: Vec<SignatureComponent>,
    /// The parameters as parsed
    pub params: SignatureParams,
    /// The member value exactly as received (used verbatim in the base)
    pub raw: String,
}

/// Split a dictionary header into `(key, raw value)` pairs at top-level commas.
fn split_members(header: &str) -> Vec<(String, String)> {
    let mut members = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut in_quotes = false;
    let mut in_bytes = false;
    for c in header.chars() {
        match c {
            '"' if !in_bytes => in_quotes = !in_quotes,
            ':' if !in_quotes && depth == 0 => in_bytes = !in_bytes,
            '(' if !in_quotes && !in_bytes => depth += 1,
            ')' if !in_quotes && !in_bytes => depth -= 1,
            ',' if !in_quotes && !in_bytes && depth == 0 => {
                push_member(&mut members, std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    push_member(&mut members, cur);
    members
}

fn push_member(members: &mut Vec<(String, String)>, raw: String) {
    let raw = raw.trim();
    if raw.is_empty() {
        return;
    }
    match raw.split_once('=') {
        Some((k, v)) => members.push((k.trim().to_string(), v.trim().to_string())),
        None => members.push((raw.to_string(), String::new())),
    }
}

/// Parse a `Signature-Input` header into its labelled members, sorted by
/// label so that the first entry is the lexicographically first label.
pub fn parse_signature_input(header: &str) -> Result<BTreeMap<String, SignatureInputMember>> {
    let mut out = BTreeMap::new();
    for (label, raw) in split_members(header) {
        let (components, params) = parse_signature_input_value(&raw)?;
        out.insert(
            label,
            SignatureInputMember {
                components,
                params,
                raw,
            },
        );
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("empty Signature-Input".into()));
    }
    Ok(out)
}

/// Parse a `Signature` header into `label -> signature bytes`
/// (`label=:base64:`).
pub fn parse_signature_header(header: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for (label, raw) in split_members(header) {
        let b64 = raw
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(|| {
                Error::InvalidInput(format!("signature {label} is not a byte sequence"))
            })?;
        let bytes = general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| Error::InvalidInput(format!("signature {label} is not valid base64")))?;
        out.insert(label, bytes);
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("empty Signature header".into()));
    }
    Ok(out)
}

/// Format a `Signature` member: `label=:base64:`.
pub fn format_signature_member(label: &str, signature: &[u8]) -> String {
    format!("{label}=:{}:", general_purpose::STANDARD.encode(signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_labels() {
        let h =
            "sig2=(\"@status\");keyid=\"b\", sig1=(\"@method\" \"@path\");keyid=\"a\";created=1";
        let m = parse_signature_input(h).unwrap();
        let labels: Vec<&String> = m.keys().collect();
        assert_eq!(labels, ["sig1", "sig2"]);
        assert_eq!(m["sig1"].components.len(), 2);
        assert_eq!(
            m["sig1"].raw,
            "(\"@method\" \"@path\");keyid=\"a\";created=1"
        );
    }

    #[test]
    fn signature_bytes() {
        let m = parse_signature_header("sig1=:AQID:, sig2=:BAU=:").unwrap();
        assert_eq!(m["sig1"], vec![1, 2, 3]);
        assert_eq!(m["sig2"], vec![4, 5]);
        assert!(parse_signature_header("sig1=:AQID").is_err());
        assert_eq!(format_signature_member("sig1", &[1, 2, 3]), "sig1=:AQID:");
    }
}
