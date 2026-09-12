//! Signature components and parameters for RFC 9421 (sage-spec `03-rfc9421.md`).

use crate::error::{Error, Result};
use std::fmt;

/// A covered component: a derived component, a header, or one of those
/// bound to the request of a response (`;req`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureComponent {
    /// `@method`
    Method,
    /// `@target-uri`
    TargetUri,
    /// `@authority`
    Authority,
    /// `@scheme`
    Scheme,
    /// `@request-target`
    RequestTarget,
    /// `@path`
    Path,
    /// `@query`
    Query,
    /// `@query-param;name="…"`
    QueryParam(String),
    /// `@status` (responses only)
    Status,
    /// An HTTP header field (name is lower-cased)
    Header(String),
    /// A request component covered by a response signature (`;req`)
    Req(Box<SignatureComponent>),
}

impl SignatureComponent {
    /// The component name without quotes or parameters (`@method`, `date`).
    pub fn name(&self) -> String {
        match self {
            SignatureComponent::Method => "@method".into(),
            SignatureComponent::TargetUri => "@target-uri".into(),
            SignatureComponent::Authority => "@authority".into(),
            SignatureComponent::Scheme => "@scheme".into(),
            SignatureComponent::RequestTarget => "@request-target".into(),
            SignatureComponent::Path => "@path".into(),
            SignatureComponent::Query => "@query".into(),
            SignatureComponent::QueryParam(_) => "@query-param".into(),
            SignatureComponent::Status => "@status".into(),
            SignatureComponent::Header(name) => name.to_lowercase(),
            SignatureComponent::Req(inner) => inner.name(),
        }
    }

    /// The component identifier as it appears in `Signature-Input` and in
    /// the signature base: quoted name plus parameters, for example
    /// `"@method"`, `"@method";req`, `"@query-param";name="id"`.
    pub fn identifier(&self) -> String {
        match self {
            SignatureComponent::QueryParam(p) => format!("\"@query-param\";name=\"{p}\""),
            SignatureComponent::Req(inner) => format!("{};req", inner.identifier()),
            other => format!("\"{}\"", other.name()),
        }
    }

    /// Bind this component to the request of a response signature.
    pub fn req(self) -> Self {
        SignatureComponent::Req(Box::new(self))
    }

    /// Whether the component carries the `;req` flag.
    pub fn is_req(&self) -> bool {
        matches!(self, SignatureComponent::Req(_))
    }

    /// Parse an identifier as it appears in `Signature-Input`
    /// (`"@method"`, `"content-digest";req`, `"@query-param";name="id"`).
    pub fn parse(identifier: &str) -> Result<Self> {
        let s = identifier.trim();
        let (quoted, rest) = if let Some(stripped) = s.strip_prefix('"') {
            let end = stripped
                .find('"')
                .ok_or_else(|| Error::InvalidInput(format!("unterminated component {s}")))?;
            (&stripped[..end], &stripped[end + 1..])
        } else {
            // tolerate unquoted identifiers without parameters
            (s, "")
        };
        let mut req = false;
        let mut name_param: Option<String> = None;
        for p in rest.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            if p == "req" {
                req = true;
            } else if let Some(v) = p.strip_prefix("name=") {
                name_param = Some(v.trim_matches('"').to_string());
            } else {
                return Err(Error::Unsupported(format!(
                    "unsupported component parameter {p}"
                )));
            }
        }
        let base = match quoted {
            "@method" => SignatureComponent::Method,
            "@target-uri" => SignatureComponent::TargetUri,
            "@authority" => SignatureComponent::Authority,
            "@scheme" => SignatureComponent::Scheme,
            "@request-target" => SignatureComponent::RequestTarget,
            "@path" => SignatureComponent::Path,
            "@query" => SignatureComponent::Query,
            "@status" => SignatureComponent::Status,
            "@query-param" => SignatureComponent::QueryParam(name_param.ok_or_else(|| {
                Error::InvalidInput("@query-param requires a name parameter".into())
            })?),
            other if other.starts_with('@') => {
                return Err(Error::Unsupported(format!(
                    "unsupported derived component {other}"
                )))
            }
            header => SignatureComponent::Header(header.to_lowercase()),
        };
        Ok(if req { base.req() } else { base })
    }
}

impl fmt::Display for SignatureComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.identifier())
    }
}

/// Signature parameters (`keyid`, `alg`, `created`, `expires`, `nonce`, `tag`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureParams {
    /// `keyid`: the signer's DID, optionally with `#fragment`
    pub key_id: Option<String>,
    /// `alg`
    pub alg: Option<String>,
    /// `created` (Unix seconds)
    pub created: Option<i64>,
    /// `expires` (Unix seconds)
    pub expires: Option<i64>,
    /// `nonce`
    pub nonce: Option<String>,
    /// `tag` (not used by SAGE; accepted for interoperability)
    pub tag: Option<String>,
}

impl SignatureParams {
    /// The DID part of `keyid` (everything before the first `#`).
    pub fn key_id_did(&self) -> Option<&str> {
        self.key_id
            .as_deref()
            .map(|k| k.split('#').next().unwrap_or(k))
    }

    /// Parse the parameter list that follows the component list
    /// (`;keyid="…";alg="…";created=…;nonce="…"`).
    pub fn parse(params: &str) -> Result<Self> {
        let mut out = SignatureParams::default();
        for p in params.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = p
                .split_once('=')
                .ok_or_else(|| Error::InvalidInput(format!("invalid signature parameter {p}")))?;
            let unquoted = v.trim_matches('"').to_string();
            match k {
                "keyid" => out.key_id = Some(unquoted),
                "alg" => out.alg = Some(unquoted),
                "nonce" => out.nonce = Some(unquoted),
                "tag" => out.tag = Some(unquoted),
                "created" => {
                    out.created =
                        Some(v.parse().map_err(|_| {
                            Error::InvalidInput(format!("invalid created value {v}"))
                        })?)
                }
                "expires" => {
                    out.expires =
                        Some(v.parse().map_err(|_| {
                            Error::InvalidInput(format!("invalid expires value {v}"))
                        })?)
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "unsupported signature parameter {other}"
                    )))
                }
            }
        }
        Ok(out)
    }
}

impl fmt::Display for SignatureParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut params = Vec::new();
        if let Some(ref key_id) = self.key_id {
            params.push(format!("keyid=\"{key_id}\""));
        }
        if let Some(ref alg) = self.alg {
            params.push(format!("alg=\"{alg}\""));
        }
        if let Some(created) = self.created {
            params.push(format!("created={created}"));
        }
        if let Some(expires) = self.expires {
            params.push(format!("expires={expires}"));
        }
        if let Some(ref nonce) = self.nonce {
            params.push(format!("nonce=\"{nonce}\""));
        }
        if let Some(ref tag) = self.tag {
            params.push(format!("tag=\"{tag}\""));
        }
        write!(f, "{}", params.join(";"))
    }
}

/// Format the inner value of a `Signature-Input` member:
/// `("@method" "@target-uri");keyid="…";alg="…";created=…;nonce="…"`.
pub fn format_signature_input(
    components: &[SignatureComponent],
    params: &SignatureParams,
) -> String {
    let ids: Vec<String> = components.iter().map(|c| c.identifier()).collect();
    let p = params.to_string();
    if p.is_empty() {
        format!("({})", ids.join(" "))
    } else {
        format!("({});{}", ids.join(" "), p)
    }
}

/// Parse the inner value of a `Signature-Input` member.
pub fn parse_signature_input_value(
    value: &str,
) -> Result<(Vec<SignatureComponent>, SignatureParams)> {
    let v = value.trim();
    let inner = v
        .strip_prefix('(')
        .ok_or_else(|| Error::InvalidInput("signature input must start with (".into()))?;
    let close = inner
        .find(')')
        .ok_or_else(|| Error::InvalidInput("signature input missing )".into()))?;
    let list = &inner[..close];
    let rest = &inner[close + 1..];
    let mut components = Vec::new();
    for id in split_identifiers(list) {
        components.push(SignatureComponent::parse(&id)?);
    }
    let params = SignatureParams::parse(rest.trim_start_matches(';'))?;
    Ok((components, params))
}

/// Split `"a" "b";req "@query-param";name="x y"` into identifiers,
/// respecting quotes.
fn split_identifiers(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in list.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ' ' if !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        assert_eq!(SignatureComponent::Method.identifier(), "\"@method\"");
        assert_eq!(
            SignatureComponent::Header("Content-Digest".into()).identifier(),
            "\"content-digest\""
        );
        assert_eq!(
            SignatureComponent::Method.req().identifier(),
            "\"@method\";req"
        );
        assert_eq!(
            SignatureComponent::QueryParam("id".into()).identifier(),
            "\"@query-param\";name=\"id\""
        );
    }

    #[test]
    fn parse_roundtrip() {
        for id in [
            "\"@method\"",
            "\"@target-uri\";req",
            "\"@query-param\";name=\"q\"",
            "\"x-sage-did\"",
        ] {
            let c = SignatureComponent::parse(id).unwrap();
            assert_eq!(c.identifier(), id);
        }
        assert!(SignatureComponent::parse("\"@unknown\"").is_err());
        assert!(SignatureComponent::parse("\"@query-param\"").is_err());
    }

    #[test]
    fn signature_input_value() {
        let v = "(\"@method\" \"@target-uri\" \"content-digest\";req);keyid=\"did:sage:ethereum:0x1#key-1\";alg=\"ed25519\";created=1788609600;nonce=\"n1\"";
        let (components, params) = parse_signature_input_value(v).unwrap();
        assert_eq!(components.len(), 3);
        assert!(components[2].is_req());
        assert_eq!(params.key_id_did(), Some("did:sage:ethereum:0x1"));
        assert_eq!(params.created, Some(1788609600));
        assert_eq!(params.nonce.as_deref(), Some("n1"));
        assert_eq!(format_signature_input(&components, &params), v);
    }

    #[test]
    fn params_order() {
        let p = SignatureParams {
            key_id: Some("k".into()),
            alg: Some("ed25519".into()),
            created: Some(1),
            expires: Some(2),
            nonce: Some("n".into()),
            tag: None,
        };
        assert_eq!(
            p.to_string(),
            "keyid=\"k\";alg=\"ed25519\";created=1;expires=2;nonce=\"n\""
        );
    }
}
