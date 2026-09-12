//! HTTP signature components for RFC 9421

use std::fmt;

/// Signature component identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureComponent {
    /// HTTP method
    Method,
    /// Target URI
    TargetUri,
    /// Authority (host)
    Authority,
    /// Scheme (http/https)
    Scheme,
    /// Request target (path + query)
    RequestTarget,
    /// Path
    Path,
    /// Query string
    Query,
    /// Status code (for responses)
    Status,
    /// Header field
    Header(String),
    /// Derived component with parameters
    DerivedComponent {
        /// The name of the derived component
        name: String,
        /// Parameters associated with the derived component
        params: Vec<String>,
    },
}

impl SignatureComponent {
    /// Get the component identifier string
    pub fn identifier(&self) -> String {
        match self {
            SignatureComponent::Method => "@method".to_string(),
            SignatureComponent::TargetUri => "@target-uri".to_string(),
            SignatureComponent::Authority => "@authority".to_string(),
            SignatureComponent::Scheme => "@scheme".to_string(),
            SignatureComponent::RequestTarget => "@request-target".to_string(),
            SignatureComponent::Path => "@path".to_string(),
            SignatureComponent::Query => "@query".to_string(),
            SignatureComponent::Status => "@status".to_string(),
            SignatureComponent::Header(name) => name.to_lowercase(),
            SignatureComponent::DerivedComponent { name, params } => {
                if params.is_empty() {
                    format!("@{name}")
                } else {
                    format!("@{};{}", name, params.join(";"))
                }
            }
        }
    }
}

/// Signature parameters
#[derive(Debug, Clone, Default)]
pub struct SignatureParams {
    /// Key identifier
    pub key_id: Option<String>,
    /// Algorithm identifier
    pub alg: Option<String>,
    /// Creation timestamp (Unix timestamp)
    pub created: Option<i64>,
    /// Expiration timestamp (Unix timestamp)
    pub expires: Option<i64>,
    /// Nonce value
    pub nonce: Option<String>,
    /// Tag value
    pub tag: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    // ===== SignatureComponent Identifier Tests =====

    #[test]
    fn test_component_identifier_method() {
        assert_eq!(SignatureComponent::Method.identifier(), "@method");
    }

    #[test]
    fn test_component_identifier_target_uri() {
        assert_eq!(SignatureComponent::TargetUri.identifier(), "@target-uri");
    }

    #[test]
    fn test_component_identifier_authority() {
        assert_eq!(SignatureComponent::Authority.identifier(), "@authority");
    }

    #[test]
    fn test_component_identifier_scheme() {
        assert_eq!(SignatureComponent::Scheme.identifier(), "@scheme");
    }

    #[test]
    fn test_component_identifier_request_target() {
        assert_eq!(
            SignatureComponent::RequestTarget.identifier(),
            "@request-target"
        );
    }

    #[test]
    fn test_component_identifier_path() {
        assert_eq!(SignatureComponent::Path.identifier(), "@path");
    }

    #[test]
    fn test_component_identifier_query() {
        assert_eq!(SignatureComponent::Query.identifier(), "@query");
    }

    #[test]
    fn test_component_identifier_status() {
        assert_eq!(SignatureComponent::Status.identifier(), "@status");
    }

    #[test]
    fn test_component_identifier_header() {
        assert_eq!(
            SignatureComponent::Header("Content-Type".to_string()).identifier(),
            "content-type"
        );
    }

    #[test]
    fn test_component_identifier_header_lowercase() {
        assert_eq!(
            SignatureComponent::Header("x-custom-header".to_string()).identifier(),
            "x-custom-header"
        );
    }

    #[test]
    fn test_component_identifier_header_mixed_case() {
        assert_eq!(
            SignatureComponent::Header("X-Custom-HEADER".to_string()).identifier(),
            "x-custom-header"
        );
    }

    #[test]
    fn test_component_identifier_derived_no_params() {
        let component = SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec![],
        };
        assert_eq!(component.identifier(), "@custom");
    }

    #[test]
    fn test_component_identifier_derived_with_params() {
        let component = SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec!["param1".to_string(), "param2".to_string()],
        };
        assert_eq!(component.identifier(), "@custom;param1;param2");
    }

    #[test]
    fn test_component_identifier_derived_single_param() {
        let component = SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec!["param1".to_string()],
        };
        assert_eq!(component.identifier(), "@custom;param1");
    }

    // ===== SignatureComponent Trait Tests =====

    #[test]
    fn test_component_clone() {
        let component = SignatureComponent::Method;
        let cloned = component.clone();
        assert_eq!(component, cloned);
    }

    #[test]
    fn test_component_equality() {
        assert_eq!(SignatureComponent::Method, SignatureComponent::Method);
        assert_ne!(SignatureComponent::Method, SignatureComponent::Path);
    }

    #[test]
    fn test_component_header_equality() {
        let header1 = SignatureComponent::Header("content-type".to_string());
        let header2 = SignatureComponent::Header("content-type".to_string());
        let header3 = SignatureComponent::Header("x-custom".to_string());

        assert_eq!(header1, header2);
        assert_ne!(header1, header3);
    }

    #[test]
    fn test_component_derived_equality() {
        let derived1 = SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec!["p1".to_string()],
        };
        let derived2 = SignatureComponent::DerivedComponent {
            name: "custom".to_string(),
            params: vec!["p1".to_string()],
        };
        let derived3 = SignatureComponent::DerivedComponent {
            name: "other".to_string(),
            params: vec!["p1".to_string()],
        };

        assert_eq!(derived1, derived2);
        assert_ne!(derived1, derived3);
    }

    #[test]
    fn test_component_debug() {
        let component = SignatureComponent::Method;
        let debug_str = format!("{component:?}");
        assert!(debug_str.contains("Method"));
    }

    // ===== SignatureParams Tests =====

    #[test]
    fn test_signature_params_default() {
        let params = SignatureParams::default();
        assert!(params.key_id.is_none());
        assert!(params.alg.is_none());
        assert!(params.created.is_none());
        assert!(params.expires.is_none());
        assert!(params.nonce.is_none());
        assert!(params.tag.is_none());
    }

    #[test]
    fn test_signature_params_clone() {
        let params = SignatureParams {
            key_id: Some("key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1000),
            expires: Some(2000),
            nonce: Some("nonce123".to_string()),
            tag: Some("tag".to_string()),
        };
        let cloned = params.clone();
        assert_eq!(params.key_id, cloned.key_id);
        assert_eq!(params.alg, cloned.alg);
        assert_eq!(params.created, cloned.created);
    }

    #[test]
    fn test_signature_params_display_all_fields() {
        let params = SignatureParams {
            key_id: Some("test-key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1_234_567_890),
            expires: Some(1_234_567_990),
            nonce: Some("abc123".to_string()),
            tag: Some("my-tag".to_string()),
        };

        let display = params.to_string();
        assert!(display.contains("keyid=\"test-key\""));
        assert!(display.contains("alg=\"ed25519\""));
        assert!(display.contains("created=1234567890"));
        assert!(display.contains("expires=1234567990"));
        assert!(display.contains("nonce=\"abc123\""));
        assert!(display.contains("tag=\"my-tag\""));
    }

    #[test]
    fn test_signature_params_display_partial() {
        let params = SignatureParams {
            key_id: Some("test-key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1_234_567_890),
            expires: None,
            nonce: None,
            tag: None,
        };

        let display = params.to_string();
        assert!(display.contains("keyid=\"test-key\""));
        assert!(display.contains("alg=\"ed25519\""));
        assert!(display.contains("created=1234567890"));
        assert!(!display.contains("expires"));
        assert!(!display.contains("nonce"));
        assert!(!display.contains("tag"));
    }

    #[test]
    fn test_signature_params_display_empty() {
        let params = SignatureParams::default();
        let display = params.to_string();
        assert_eq!(display, "");
    }

    #[test]
    fn test_signature_params_display_only_created() {
        let params = SignatureParams {
            key_id: None,
            alg: None,
            created: Some(1618884473),
            expires: None,
            nonce: None,
            tag: None,
        };

        let display = params.to_string();
        assert_eq!(display, "created=1618884473");
    }

    #[test]
    fn test_signature_params_display_only_expires() {
        let params = SignatureParams {
            key_id: None,
            alg: None,
            created: None,
            expires: Some(1618884773),
            nonce: None,
            tag: None,
        };

        let display = params.to_string();
        assert_eq!(display, "expires=1618884773");
    }

    #[test]
    fn test_signature_params_display_only_nonce() {
        let params = SignatureParams {
            key_id: None,
            alg: None,
            created: None,
            expires: None,
            nonce: Some("test-nonce".to_string()),
            tag: None,
        };

        let display = params.to_string();
        assert_eq!(display, "nonce=\"test-nonce\"");
    }

    #[test]
    fn test_signature_params_display_only_tag() {
        let params = SignatureParams {
            key_id: None,
            alg: None,
            created: None,
            expires: None,
            nonce: None,
            tag: Some("test-tag".to_string()),
        };

        let display = params.to_string();
        assert_eq!(display, "tag=\"test-tag\"");
    }

    #[test]
    fn test_signature_params_debug() {
        let params = SignatureParams {
            key_id: Some("key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1000),
            expires: None,
            nonce: None,
            tag: None,
        };

        let debug_str = format!("{params:?}");
        assert!(debug_str.contains("SignatureParams"));
    }
}
