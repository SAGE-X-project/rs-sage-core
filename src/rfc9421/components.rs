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

    #[test]
    fn test_component_identifier() {
        assert_eq!(SignatureComponent::Method.identifier(), "@method");
        assert_eq!(
            SignatureComponent::Header("Content-Type".to_string()).identifier(),
            "content-type"
        );
    }

    #[test]
    fn test_signature_params_display() {
        let params = SignatureParams {
            key_id: Some("test-key".to_string()),
            alg: Some("ed25519".to_string()),
            created: Some(1234567890),
            expires: None,
            nonce: None,
            tag: None,
        };

        let display = params.to_string();
        assert!(display.contains("keyid=\"test-key\""));
        assert!(display.contains("alg=\"ed25519\""));
        assert!(display.contains("created=1234567890"));
    }
}
