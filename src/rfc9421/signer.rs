//! HTTP message signing for RFC 9421 (sage-spec `03-rfc9421.md`).

use crate::crypto::{KeyPair, KeyType, Signer as CryptoSigner};
use crate::error::{Error, Result};
use crate::rfc9421::canonicalize::{
    build_signature_base, canonicalize_request, canonicalize_response, content_digest,
};
use crate::rfc9421::dictionary::format_signature_member;
use crate::rfc9421::{
    format_signature_input, SignatureAlgorithm, SignatureComponent, SignatureParams,
};
use http::{HeaderValue, Request, Response};
use std::time::{SystemTime, UNIX_EPOCH};

/// Components SAGE signers cover on a request with a body
/// (`03-rfc9421.md` §3). `content-type` and `content-digest` are dropped
/// when the request has no body.
pub fn default_request_components() -> Vec<SignatureComponent> {
    vec![
        SignatureComponent::Method,
        SignatureComponent::TargetUri,
        SignatureComponent::Authority,
        SignatureComponent::Header("content-type".into()),
        SignatureComponent::Header("content-digest".into()),
        SignatureComponent::Header("x-sage-did".into()),
        SignatureComponent::Header("date".into()),
    ]
}

/// Components the reference responder covers (`03-rfc9421.md` §4): the
/// status, the request's method/target/authority bound with `;req`, the
/// request's `content-digest` and `signature` when present, and the
/// response's `content-type` and `content-digest` when present.
pub fn default_response_components<B, R>(
    response: &Response<B>,
    request: &Request<R>,
    has_body: bool,
) -> Vec<SignatureComponent> {
    let mut covered = vec![
        SignatureComponent::Status,
        SignatureComponent::Method.req(),
        SignatureComponent::TargetUri.req(),
        SignatureComponent::Authority.req(),
    ];
    if request.headers().contains_key("content-digest") {
        covered.push(SignatureComponent::Header("content-digest".into()).req());
    }
    if request.headers().contains_key("signature") {
        covered.push(SignatureComponent::Header("signature".into()).req());
    }
    if response.headers().contains_key("content-type") {
        covered.push(SignatureComponent::Header("content-type".into()));
    }
    if has_body {
        covered.push(SignatureComponent::Header("content-digest".into()));
    }
    covered
}

/// RFC 9421 `alg` identifier for a key type (sage-spec `01-crypto.md` §3).
pub fn algorithm_for(key_type: KeyType) -> SignatureAlgorithm {
    match key_type {
        KeyType::Ed25519 => SignatureAlgorithm::Ed25519,
        KeyType::Secp256k1 => SignatureAlgorithm::EcdsaSecp256k1Sha256,
        KeyType::P256 => SignatureAlgorithm::EcdsaP256Sha256,
    }
}

/// Signs HTTP requests and responses.
pub struct HttpSigner {
    keypair: KeyPair,
    key_id: String,
    label: String,
    default_components: Vec<SignatureComponent>,
}

impl HttpSigner {
    /// Create a signer. The `keyid` parameter defaults to the key's id;
    /// SAGE deployments set the agent DID with [`HttpSigner::with_key_id`].
    pub fn new(keypair: KeyPair) -> Self {
        let key_id = keypair.public_key().key_id();
        Self {
            keypair,
            key_id,
            label: "sig1".into(),
            default_components: default_request_components(),
        }
    }

    /// Set the `keyid` parameter (`did:sage:…` or `did:sage:…#fragment`).
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = key_id.into();
        self
    }

    /// Change the `keyid` parameter in place.
    pub fn set_key_id(&mut self, key_id: impl Into<String>) {
        self.key_id = key_id.into();
    }

    /// Set the signature label (default `sig1`).
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Replace the default covered components for requests.
    pub fn with_default_components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.default_components = components;
        self
    }

    /// The `keyid` this signer uses.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Fresh parameters: `keyid`, `alg`, `created = now`, random `nonce`.
    pub fn fresh_params(&self) -> Result<SignatureParams> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Other("system time error".into()))?
            .as_secs() as i64;
        Ok(SignatureParams {
            key_id: Some(self.key_id.clone()),
            alg: Some(
                algorithm_for(self.keypair.key_type())
                    .identifier()
                    .to_string(),
            ),
            created: Some(now),
            expires: None,
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            tag: None,
        })
    }

    /// Sign a request with the default components. `body` sets
    /// `Content-Digest`; pass `None` for a request without a body, in which
    /// case the `content-type` and `content-digest` components are dropped.
    pub fn sign_request<B>(&self, request: Request<B>, body: Option<&[u8]>) -> Result<Request<B>> {
        let params = self.fresh_params()?;
        // Header components the request does not carry are omitted (the
        // receiver's policy decides what must be covered); content-digest
        // is covered whenever a body is given because it is added here.
        let components: Vec<SignatureComponent> = self
            .default_components
            .iter()
            .filter(|c| match c {
                SignatureComponent::Header(h) if h == "content-digest" => {
                    body.is_some() || request.headers().contains_key("content-digest")
                }
                SignatureComponent::Header(h) => request.headers().contains_key(h.as_str()),
                _ => true,
            })
            .cloned()
            .collect();
        self.sign_request_with(request, body, &components, &params)
    }

    /// Sign a request with explicit components and parameters (used by the
    /// test vectors and by callers that manage `created`/`nonce`).
    pub fn sign_request_with<B>(
        &self,
        mut request: Request<B>,
        body: Option<&[u8]>,
        components: &[SignatureComponent],
        params: &SignatureParams,
    ) -> Result<Request<B>> {
        if let Some(body) = body {
            if !request.headers().contains_key("content-digest") {
                request.headers_mut().insert(
                    "content-digest",
                    HeaderValue::from_str(&content_digest(body))
                        .map_err(|_| Error::InvalidInput("invalid content-digest".into()))?,
                );
            }
        }
        let values = canonicalize_request(&request, components)?;
        let sig_input = format_signature_input(components, params);
        let base = build_signature_base(&values, &sig_input);
        let signature = self.keypair.sign(base.as_bytes())?;
        insert_headers(
            request.headers_mut(),
            &self.label,
            &sig_input,
            &signature.to_bytes(),
        )?;
        Ok(request)
    }

    /// Sign a response bound to the request it answers, with the reference
    /// responder's component set.
    pub fn sign_response<B, R>(
        &self,
        response: Response<B>,
        request: &Request<R>,
        body: Option<&[u8]>,
    ) -> Result<Response<B>> {
        let params = self.fresh_params()?;
        let components = default_response_components(&response, request, body.is_some());
        self.sign_response_with(response, request, body, &components, &params)
    }

    /// Sign a response with explicit components and parameters.
    pub fn sign_response_with<B, R>(
        &self,
        mut response: Response<B>,
        request: &Request<R>,
        body: Option<&[u8]>,
        components: &[SignatureComponent],
        params: &SignatureParams,
    ) -> Result<Response<B>> {
        if let Some(body) = body {
            if !response.headers().contains_key("content-digest") {
                response.headers_mut().insert(
                    "content-digest",
                    HeaderValue::from_str(&content_digest(body))
                        .map_err(|_| Error::InvalidInput("invalid content-digest".into()))?,
                );
            }
        }
        let values = canonicalize_response(&response, Some(request), components)?;
        let sig_input = format_signature_input(components, params);
        let base = build_signature_base(&values, &sig_input);
        let signature = self.keypair.sign(base.as_bytes())?;
        insert_headers(
            response.headers_mut(),
            &self.label,
            &sig_input,
            &signature.to_bytes(),
        )?;
        Ok(response)
    }

    /// The signature base a request would be signed over (for diagnostics).
    pub fn signature_base<B>(
        request: &Request<B>,
        components: &[SignatureComponent],
        params: &SignatureParams,
    ) -> Result<String> {
        let values = canonicalize_request(request, components)?;
        Ok(build_signature_base(
            &values,
            &format_signature_input(components, params),
        ))
    }
}

fn insert_headers(
    headers: &mut http::HeaderMap,
    label: &str,
    sig_input: &str,
    signature: &[u8],
) -> Result<()> {
    headers.insert(
        "signature-input",
        HeaderValue::from_str(&format!("{label}={sig_input}"))
            .map_err(|_| Error::InvalidInput("invalid signature input".into()))?,
    );
    headers.insert(
        "signature",
        HeaderValue::from_str(&format_signature_member(label, signature))
            .map_err(|_| Error::InvalidInput("invalid signature value".into()))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyType;

    #[test]
    fn signs_with_digest_nonce_and_byte_sequence() {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(kp).with_key_id("did:sage:ethereum:0xabc#key-1");
        let req = Request::builder()
            .method("POST")
            .uri("https://agent-b.example/mcp")
            .header("content-type", "application/json")
            .header("x-sage-did", "did:sage:ethereum:0xabc")
            .header("date", "Tue, 01 Sep 2026 12:00:00 GMT")
            .body(())
            .unwrap();
        let signed = signer.sign_request(req, Some(b"{}")).unwrap();
        let sig = signed.headers()["signature"].to_str().unwrap();
        assert!(sig.starts_with("sig1=:") && sig.ends_with(':'));
        let input = signed.headers()["signature-input"].to_str().unwrap();
        assert!(input.starts_with("sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-type\" \"content-digest\" \"x-sage-did\" \"date\");keyid=\"did:sage:ethereum:0xabc#key-1\";alg=\"ed25519\";created="));
        assert!(input.contains(";nonce=\""));
        assert_eq!(signed.headers()["content-digest"], content_digest(b"{}"));
    }

    #[test]
    fn no_body_drops_content_components() {
        let kp = KeyPair::generate(KeyType::Secp256k1).unwrap();
        let signer = HttpSigner::new(kp);
        let req = Request::builder()
            .method("GET")
            .uri("https://agent-b.example/health")
            .header("x-sage-did", "did:sage:ethereum:0xabc")
            .header("date", "Tue, 01 Sep 2026 12:00:00 GMT")
            .body(())
            .unwrap();
        let signed = signer.sign_request(req, None).unwrap();
        let input = signed.headers()["signature-input"].to_str().unwrap();
        assert!(input.starts_with(
            "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"x-sage-did\" \"date\")"
        ));
        assert!(input.contains("alg=\"es256k\""));
        assert!(!signed.headers().contains_key("content-digest"));
    }
}
