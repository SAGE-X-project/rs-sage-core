//! Signature base construction for RFC 9421 (sage-spec `03-rfc9421.md` §2).

use crate::error::{Error, Result};
use crate::rfc9421::SignatureComponent;
use http::{HeaderMap, Request, Response};
use sha2::{Digest, Sha256};

/// `Content-Digest` header value for a body: `sha-256=:base64:`.
pub fn content_digest(body: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    format!(
        "sha-256=:{}:",
        general_purpose::STANDARD.encode(Sha256::digest(body))
    )
}

/// Check a received `Content-Digest` header against a body: the `sha-256`
/// member must be present and match.
pub fn verify_content_digest(header: &str, body: &[u8]) -> Result<()> {
    let want = content_digest(body);
    let want_member = want.trim_start_matches("sha-256=");
    for member in header.split(',') {
        if let Some(v) = member.trim().strip_prefix("sha-256=") {
            if v.trim() == want_member {
                return Ok(());
            }
            return Err(Error::Verification("content-digest mismatch".into()));
        }
    }
    Err(Error::Verification(
        "content-digest has no sha-256 member".into(),
    ))
}

/// Canonical value of one request component.
pub fn request_component_value<B>(
    request: &Request<B>,
    component: &SignatureComponent,
) -> Result<String> {
    match component {
        SignatureComponent::Method => Ok(request.method().as_str().to_string()),
        SignatureComponent::TargetUri => Ok(request.uri().to_string()),
        SignatureComponent::Authority => request
            .uri()
            .authority()
            .map(|a| a.to_string().to_lowercase())
            .or_else(|| {
                request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.to_lowercase())
            })
            .ok_or_else(|| Error::InvalidInput("missing authority in URI".into())),
        SignatureComponent::Scheme => request
            .uri()
            .scheme_str()
            .map(|s| s.to_lowercase())
            .ok_or_else(|| Error::InvalidInput("missing scheme in URI".into())),
        SignatureComponent::RequestTarget => {
            let path = request.uri().path();
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            Ok(format!("{path}{query}"))
        }
        SignatureComponent::Path => Ok(request.uri().path().to_string()),
        SignatureComponent::Query => Ok(request
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_else(|| "?".to_string())),
        SignatureComponent::QueryParam(name) => {
            let query = request.uri().query().unwrap_or("");
            for pair in query.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                if k == name {
                    return Ok(v.to_string());
                }
            }
            Err(Error::InvalidInput(format!(
                "query parameter {name} not found"
            )))
        }
        SignatureComponent::Status => Err(Error::InvalidInput(
            "@status is not valid for requests".into(),
        )),
        SignatureComponent::Header(name) => header_value(request.headers(), name),
        SignatureComponent::Req(_) => Err(Error::InvalidInput(
            "the req parameter is only valid in response signatures".into(),
        )),
    }
}

/// Canonical value of one response component; `;req` components are taken
/// from the request the response answers.
pub fn response_component_value<B, R>(
    response: &Response<B>,
    request: Option<&Request<R>>,
    component: &SignatureComponent,
) -> Result<String> {
    match component {
        SignatureComponent::Status => Ok(response.status().as_u16().to_string()),
        SignatureComponent::Header(name) => header_value(response.headers(), name),
        SignatureComponent::Req(inner) => {
            let req = request.ok_or_else(|| {
                Error::InvalidInput(
                    "response signature covers request components but no request was given".into(),
                )
            })?;
            request_component_value(req, inner)
        }
        other => Err(Error::InvalidInput(format!(
            "{} is not valid for responses",
            other.identifier()
        ))),
    }
}

/// Header value as covered by a signature: all values joined with `, `,
/// trimmed.
pub fn header_value(headers: &HeaderMap, name: &str) -> Result<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidInput(format!("invalid header value for {name}")))?;
    if values.is_empty() {
        return Err(Error::InvalidInput(format!("header {name} not found")));
    }
    Ok(values
        .iter()
        .map(|v| v.trim())
        .collect::<Vec<_>>()
        .join(", "))
}

/// Canonical values of every component of a request.
pub fn canonicalize_request<B>(
    request: &Request<B>,
    components: &[SignatureComponent],
) -> Result<Vec<(String, String)>> {
    components
        .iter()
        .map(|c| Ok((c.identifier(), request_component_value(request, c)?)))
        .collect()
}

/// Canonical values of every component of a response.
pub fn canonicalize_response<B, R>(
    response: &Response<B>,
    request: Option<&Request<R>>,
    components: &[SignatureComponent],
) -> Result<Vec<(String, String)>> {
    components
        .iter()
        .map(|c| {
            Ok((
                c.identifier(),
                response_component_value(response, request, c)?,
            ))
        })
        .collect()
}

/// Build the signature base: one `identifier: value` line per component,
/// then the `"@signature-params"` line with the `Signature-Input` member
/// value verbatim.
pub fn build_signature_base(components: &[(String, String)], signature_input: &str) -> String {
    let mut lines: Vec<String> = components
        .iter()
        .map(|(id, value)| format!("{id}: {value}"))
        .collect();
    lines.push(format!("\"@signature-params\": {signature_input}"));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest() {
        let d = content_digest(b"{}");
        assert!(d.starts_with("sha-256=:") && d.ends_with(':'));
        assert!(verify_content_digest(&d, b"{}").is_ok());
        assert!(verify_content_digest(&d, b"{ }").is_err());
        assert!(verify_content_digest("sha-512=:AA==:", b"{}").is_err());
    }

    #[test]
    fn request_values() {
        let req = Request::builder()
            .method("POST")
            .uri("https://Agent-B.example/mcp/tools/call?id=7&x=1")
            .header("Date", " Tue, 01 Sep 2026 12:00:00 GMT ")
            .body(())
            .unwrap();
        let v = |c| request_component_value(&req, &c).unwrap();
        assert_eq!(v(SignatureComponent::Method), "POST");
        assert_eq!(v(SignatureComponent::Authority), "agent-b.example");
        assert_eq!(v(SignatureComponent::Path), "/mcp/tools/call");
        assert_eq!(v(SignatureComponent::Query), "?id=7&x=1");
        assert_eq!(v(SignatureComponent::QueryParam("id".into())), "7");
        assert_eq!(
            v(SignatureComponent::Header("date".into())),
            "Tue, 01 Sep 2026 12:00:00 GMT"
        );
        assert!(request_component_value(&req, &SignatureComponent::Status).is_err());
        assert!(request_component_value(&req, &SignatureComponent::Method.req()).is_err());
    }

    #[test]
    fn response_values_bound_to_request() {
        let req = Request::builder()
            .method("GET")
            .uri("https://a.example/x")
            .body(())
            .unwrap();
        let resp = Response::builder()
            .status(201)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let v = |c| response_component_value(&resp, Some(&req), &c).unwrap();
        assert_eq!(v(SignatureComponent::Status), "201");
        assert_eq!(v(SignatureComponent::Method.req()), "GET");
        assert_eq!(
            v(SignatureComponent::Header("content-type".into())),
            "text/plain"
        );
        assert!(
            response_component_value::<(), ()>(&resp, None, &SignatureComponent::Method.req())
                .is_err()
        );
        let base = build_signature_base(
            &[("\"@status\"".into(), "201".into())],
            "(\"@status\");created=1",
        );
        assert_eq!(
            base,
            "\"@status\": 201\n\"@signature-params\": (\"@status\");created=1"
        );
    }
}
