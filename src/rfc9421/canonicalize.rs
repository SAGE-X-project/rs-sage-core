//! HTTP message canonicalization for RFC 9421

use crate::error::{Error, Result};
use http::{HeaderMap, Method, Request, Response, Uri};
use std::collections::BTreeMap;

/// Canonicalize an HTTP request for signing
pub fn canonicalize_request<B>(
    request: &Request<B>,
    components: &[super::SignatureComponent],
) -> Result<Vec<(String, String)>> {
    let mut values = Vec::new();

    for component in components {
        let (name, value) = match component {
            super::SignatureComponent::Method => {
                ("@method".to_string(), request.method().as_str().to_string())
            }
            super::SignatureComponent::TargetUri => {
                ("@target-uri".to_string(), request.uri().to_string())
            }
            super::SignatureComponent::Authority => {
                let authority = request
                    .uri()
                    .authority()
                    .ok_or_else(|| Error::InvalidInput("Missing authority in URI".to_string()))?
                    .to_string();
                ("@authority".to_string(), authority)
            }
            super::SignatureComponent::Scheme => {
                let scheme = request
                    .uri()
                    .scheme_str()
                    .ok_or_else(|| Error::InvalidInput("Missing scheme in URI".to_string()))?
                    .to_string();
                ("@scheme".to_string(), scheme)
            }
            super::SignatureComponent::RequestTarget => {
                let path = request.uri().path();
                let query = request
                    .uri()
                    .query()
                    .map(|q| format!("?{}", q))
                    .unwrap_or_default();
                ("@request-target".to_string(), format!("{}{}", path, query))
            }
            super::SignatureComponent::Path => {
                ("@path".to_string(), request.uri().path().to_string())
            }
            super::SignatureComponent::Query => {
                let query = request
                    .uri()
                    .query()
                    .map(|q| format!("?{}", q))
                    .unwrap_or_else(|| "?".to_string());
                ("@query".to_string(), query)
            }
            super::SignatureComponent::Status => {
                return Err(Error::InvalidInput(
                    "@status component not valid for requests".to_string(),
                ));
            }
            super::SignatureComponent::Header(name) => {
                let header_value = get_header_value(request.headers(), name)?;
                (name.to_lowercase(), header_value)
            }
            super::SignatureComponent::DerivedComponent { .. } => {
                return Err(Error::Unsupported(
                    "Custom derived components not yet supported".to_string(),
                ));
            }
        };

        values.push((name, value));
    }

    Ok(values)
}

/// Canonicalize an HTTP response for signing
pub fn canonicalize_response<B>(
    response: &Response<B>,
    components: &[super::SignatureComponent],
) -> Result<Vec<(String, String)>> {
    let mut values = Vec::new();

    for component in components {
        let (name, value) = match component {
            super::SignatureComponent::Status => (
                "@status".to_string(),
                response.status().as_u16().to_string(),
            ),
            super::SignatureComponent::Header(name) => {
                let header_value = get_header_value(response.headers(), name)?;
                (name.to_lowercase(), header_value)
            }
            super::SignatureComponent::Method
            | super::SignatureComponent::TargetUri
            | super::SignatureComponent::Authority
            | super::SignatureComponent::Scheme
            | super::SignatureComponent::RequestTarget
            | super::SignatureComponent::Path
            | super::SignatureComponent::Query => {
                return Err(Error::InvalidInput(format!(
                    "{:?} component not valid for responses",
                    component
                )));
            }
            super::SignatureComponent::DerivedComponent { .. } => {
                return Err(Error::Unsupported(
                    "Custom derived components not yet supported".to_string(),
                ));
            }
        };

        values.push((name, value));
    }

    Ok(values)
}

/// Get a header value, handling multiple values according to RFC 9421
fn get_header_value(headers: &HeaderMap, name: &str) -> Result<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidInput(format!("Invalid header value for {}", name)))?;

    if values.is_empty() {
        return Err(Error::InvalidInput(format!("Header {} not found", name)));
    }

    // Join multiple values with comma and space
    Ok(values.join(", "))
}

/// Build the signature base string from canonicalized components
pub fn build_signature_base(components: &[(String, String)], signature_params: &str) -> String {
    let mut lines = Vec::new();

    for (name, value) in components {
        lines.push(format!("\"{}\": {}", name, value));
    }

    lines.push(format!("\"@signature-params\": {}", signature_params));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn test_canonicalize_method() {
        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Method];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@method");
        assert_eq!(result[0].1, "POST");
    }

    #[test]
    fn test_canonicalize_header() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Header(
            "content-type".to_string(),
        )];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "content-type");
        assert_eq!(result[0].1, "application/json");
    }
}
