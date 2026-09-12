//! HTTP message canonicalization for RFC 9421

use crate::error::{Error, Result};
use http::{HeaderMap, Request, Response};

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
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default();
                ("@request-target".to_string(), format!("{path}{query}"))
            }
            super::SignatureComponent::Path => {
                ("@path".to_string(), request.uri().path().to_string())
            }
            super::SignatureComponent::Query => {
                let query = request
                    .uri()
                    .query()
                    .map(|q| format!("?{q}"))
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
                    "{component:?} component not valid for responses"
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
        .map_err(|_| Error::InvalidInput(format!("Invalid header value for {name}")))?;

    if values.is_empty() {
        return Err(Error::InvalidInput(format!("Header {name} not found")));
    }

    // Join multiple values with comma and space
    Ok(values.join(", "))
}

/// Build the signature base string from canonicalized components
pub fn build_signature_base(components: &[(String, String)], signature_params: &str) -> String {
    let mut lines = Vec::new();

    for (name, value) in components {
        lines.push(format!("\"{name}\": {value}"));
    }

    lines.push(format!("\"@signature-params\": {signature_params}"));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response, StatusCode};

    // ===== Request Component Tests =====

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
    fn test_canonicalize_target_uri() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo?bar=baz")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::TargetUri];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@target-uri");
        assert_eq!(result[0].1, "https://example.com/foo?bar=baz");
    }

    #[test]
    fn test_canonicalize_authority() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com:8080/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Authority];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@authority");
        assert_eq!(result[0].1, "example.com:8080");
    }

    #[test]
    fn test_canonicalize_authority_missing() {
        let request = Request::builder()
            .method("GET")
            .uri("/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Authority];
        let result = canonicalize_request(&request, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_canonicalize_scheme() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Scheme];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@scheme");
        assert_eq!(result[0].1, "https");
    }

    #[test]
    fn test_canonicalize_scheme_missing() {
        let request = Request::builder()
            .method("GET")
            .uri("/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Scheme];
        let result = canonicalize_request(&request, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_canonicalize_request_target() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo?bar=baz")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::RequestTarget];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@request-target");
        assert_eq!(result[0].1, "/foo?bar=baz");
    }

    #[test]
    fn test_canonicalize_request_target_no_query() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::RequestTarget];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@request-target");
        assert_eq!(result[0].1, "/foo");
    }

    #[test]
    fn test_canonicalize_path() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo/bar")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Path];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@path");
        assert_eq!(result[0].1, "/foo/bar");
    }

    #[test]
    fn test_canonicalize_query() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo?bar=baz&qux=quux")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Query];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@query");
        assert_eq!(result[0].1, "?bar=baz&qux=quux");
    }

    #[test]
    fn test_canonicalize_query_empty() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/foo")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Query];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@query");
        assert_eq!(result[0].1, "?");
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

    #[test]
    fn test_canonicalize_header_multiple_values() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com")
            .header("X-Custom", "value1")
            .header("X-Custom", "value2")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Header(
            "x-custom".to_string(),
        )];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-custom");
        assert_eq!(result[0].1, "value1, value2");
    }

    #[test]
    fn test_canonicalize_header_missing() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Header(
            "missing-header".to_string(),
        )];
        let result = canonicalize_request(&request, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_canonicalize_request_status_error() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Status];
        let result = canonicalize_request(&request, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_canonicalize_request_derived_component_error() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec![],
        }];
        let result = canonicalize_request(&request, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    #[test]
    fn test_canonicalize_request_multiple_components() {
        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/foo?bar=baz")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        let components = vec![
            super::super::SignatureComponent::Method,
            super::super::SignatureComponent::Path,
            super::super::SignatureComponent::Header("content-type".to_string()),
        ];
        let result = canonicalize_request(&request, &components).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "@method");
        assert_eq!(result[0].1, "POST");
        assert_eq!(result[1].0, "@path");
        assert_eq!(result[1].1, "/foo");
        assert_eq!(result[2].0, "content-type");
        assert_eq!(result[2].1, "application/json");
    }

    // ===== Response Component Tests =====

    #[test]
    fn test_canonicalize_response_status() {
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();

        let components = vec![super::super::SignatureComponent::Status];
        let result = canonicalize_response(&response, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@status");
        assert_eq!(result[0].1, "200");
    }

    #[test]
    fn test_canonicalize_response_status_404() {
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Status];
        let result = canonicalize_response(&response, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "@status");
        assert_eq!(result[0].1, "404");
    }

    #[test]
    fn test_canonicalize_response_header() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Header(
            "content-type".to_string(),
        )];
        let result = canonicalize_response(&response, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "content-type");
        assert_eq!(result[0].1, "application/json");
    }

    #[test]
    fn test_canonicalize_response_multiple_headers() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "no-cache")
            .header("Cache-Control", "no-store")
            .body(())
            .unwrap();

        let components = vec![super::super::SignatureComponent::Header(
            "cache-control".to_string(),
        )];
        let result = canonicalize_response(&response, &components).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "cache-control");
        assert_eq!(result[0].1, "no-cache, no-store");
    }

    #[test]
    fn test_canonicalize_response_method_error() {
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();

        let components = vec![super::super::SignatureComponent::Method];
        let result = canonicalize_response(&response, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_canonicalize_response_path_error() {
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();

        let components = vec![super::super::SignatureComponent::Path];
        let result = canonicalize_response(&response, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }

    #[test]
    fn test_canonicalize_response_derived_component_error() {
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();

        let components = vec![super::super::SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec![],
        }];
        let result = canonicalize_response(&response, &components);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unsupported(_)));
    }

    // ===== Signature Base Tests =====

    #[test]
    fn test_build_signature_base_single() {
        let components = vec![("@method".to_string(), "POST".to_string())];
        let params = "(\"@method\");created=1618884473";
        let result = build_signature_base(&components, params);

        assert_eq!(
            result,
            "\"@method\": POST\n\"@signature-params\": (\"@method\");created=1618884473"
        );
    }

    #[test]
    fn test_build_signature_base_multiple() {
        let components = vec![
            ("@method".to_string(), "POST".to_string()),
            ("@path".to_string(), "/foo".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let params = "(\"@method\" \"@path\" \"content-type\");created=1618884473";
        let result = build_signature_base(&components, params);

        let expected = concat!(
            "\"@method\": POST\n",
            "\"@path\": /foo\n",
            "\"content-type\": application/json\n",
            "\"@signature-params\": (\"@method\" \"@path\" \"content-type\");created=1618884473"
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_signature_base_empty() {
        let components = vec![];
        let params = "();created=1618884473";
        let result = build_signature_base(&components, params);

        assert_eq!(result, "\"@signature-params\": ();created=1618884473");
    }

    // ===== Helper Function Tests =====

    #[test]
    fn test_get_header_value_single() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());

        let result = get_header_value(&headers, "content-type").unwrap();
        assert_eq!(result, "application/json");
    }

    #[test]
    fn test_get_header_value_multiple() {
        let mut headers = HeaderMap::new();
        headers.append("x-custom", "value1".parse().unwrap());
        headers.append("x-custom", "value2".parse().unwrap());
        headers.append("x-custom", "value3".parse().unwrap());

        let result = get_header_value(&headers, "x-custom").unwrap();
        assert_eq!(result, "value1, value2, value3");
    }

    #[test]
    fn test_get_header_value_missing() {
        let headers = HeaderMap::new();

        let result = get_header_value(&headers, "missing");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidInput(_)));
    }
}
