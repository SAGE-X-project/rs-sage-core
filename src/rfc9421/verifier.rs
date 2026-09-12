//! HTTP message signature verification for RFC 9421 (sage-spec
//! `03-rfc9421.md` §5).

use crate::crypto::{PublicKey, Signature, Verifier as CryptoVerifier};
use crate::error::{Error, Result};
use crate::rfc9421::canonicalize::{
    build_signature_base, canonicalize_request, canonicalize_response, verify_content_digest,
};
use crate::rfc9421::dictionary::{
    parse_signature_header, parse_signature_input, SignatureInputMember,
};
use crate::rfc9421::replay::{MemoryReplayGuard, ReplayGuard};
use crate::rfc9421::{algorithm_for, SignatureComponent, SignatureParams};
use http::{HeaderMap, Request, Response};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default freshness window and clock skew (5 minutes).
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);

/// Verification policy, mirroring the Go core's `HTTPVerificationOptions`.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Signature label to verify; `None` selects the lexicographically first.
    pub label: Option<String>,
    /// Maximum age of `created`; `None` disables the age check (archived
    /// messages and test vectors).
    pub max_age: Option<Duration>,
    /// How far in the future `created` may be.
    pub max_clock_skew: Duration,
    /// Components that must be covered (identifiers such as `"@method"`).
    pub required_components: Vec<SignatureComponent>,
    /// Require `content-digest` to be covered when the message has a body.
    pub require_content_digest: bool,
    /// Require a `nonce` parameter.
    pub require_nonce: bool,
    /// Skip the replay check even when a guard is configured.
    pub disable_replay_check: bool,
    /// The DID the `keyid` must carry (`did` or `did#fragment`).
    pub expected_did: Option<String>,
    /// The exact `keyid` expected.
    pub expected_key_id: Option<String>,
    /// `@authority` must be covered and equal one of these.
    pub expected_authorities: Vec<String>,
    /// Responses must cover at least one `;req` component.
    pub require_request_binding: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            label: None,
            max_age: Some(DEFAULT_MAX_AGE),
            max_clock_skew: DEFAULT_MAX_AGE,
            required_components: Vec::new(),
            require_content_digest: false,
            require_nonce: false,
            disable_replay_check: false,
            expected_did: None,
            expected_key_id: None,
            expected_authorities: Vec::new(),
            require_request_binding: false,
        }
    }
}

impl VerifyOptions {
    /// Strict request policy: `@method`, `@target-uri`, `@authority`
    /// covered, `content-digest` covered when there is a body, nonce
    /// required.
    pub fn strict_request() -> Self {
        Self {
            required_components: vec![
                SignatureComponent::Method,
                SignatureComponent::TargetUri,
                SignatureComponent::Authority,
            ],
            require_content_digest: true,
            require_nonce: true,
            ..Default::default()
        }
    }

    /// Strict response policy: `@status` covered, `content-digest` covered
    /// when there is a body, bound to the request.
    pub fn strict_response() -> Self {
        Self {
            required_components: vec![SignatureComponent::Status],
            require_content_digest: true,
            require_request_binding: true,
            ..Default::default()
        }
    }

    /// Bind the signer's DID.
    pub fn expected_did(mut self, did: impl Into<String>) -> Self {
        self.expected_did = Some(did.into());
        self
    }

    /// Disable the age check.
    pub fn without_age_check(mut self) -> Self {
        self.max_age = None;
        self.max_clock_skew = Duration::from_secs(100 * 365 * 24 * 3600);
        self
    }
}

/// Verifies HTTP requests and responses against one public key.
pub struct HttpVerifier {
    public_key: PublicKey,
    replay: Option<Arc<dyn ReplayGuard>>,
}

impl HttpVerifier {
    /// A verifier with an in-memory replay guard sized to the default age.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            replay: Some(Arc::new(MemoryReplayGuard::new(DEFAULT_MAX_AGE))),
        }
    }

    /// A verifier with a shared replay guard, or none (`None` disables
    /// replay detection).
    pub fn with_replay_guard(public_key: PublicKey, guard: Option<Arc<dyn ReplayGuard>>) -> Self {
        Self {
            public_key,
            replay: guard,
        }
    }

    /// The key this verifier checks against.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Verify a request with the default options and no body.
    pub fn verify_request<B>(&self, request: &Request<B>) -> Result<()> {
        self.verify_request_with(request, None, &VerifyOptions::default())
    }

    /// Verify a request; `body` enables the `Content-Digest` check.
    pub fn verify_request_with<B>(
        &self,
        request: &Request<B>,
        body: Option<&[u8]>,
        opts: &VerifyOptions,
    ) -> Result<()> {
        let (label, member, signature) =
            select(request.headers(), opts, self.public_key.key_type())?;
        if member.components.iter().any(SignatureComponent::is_req) {
            return Err(Error::Verification(
                "the req parameter is only valid in response signatures".into(),
            ));
        }
        check_policy(&member, body, opts)?;
        check_params(&member.params, opts, &self.public_key)?;
        if let Some(did) = request
            .headers()
            .get("x-sage-did")
            .and_then(|v| v.to_str().ok())
        {
            if member.params.key_id_did() != Some(did) {
                return Err(Error::Verification(
                    "X-SAGE-DID does not match keyid".into(),
                ));
            }
        }
        if !opts.expected_authorities.is_empty() {
            let covered = member.components.contains(&SignatureComponent::Authority);
            let authority = request
                .uri()
                .authority()
                .map(|a| a.to_string().to_lowercase())
                .unwrap_or_default();
            if !covered
                || !opts
                    .expected_authorities
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&authority))
            {
                return Err(Error::Verification(
                    "authority is not covered or not expected".into(),
                ));
            }
        }
        let values = canonicalize_request(request, &member.components)?;
        let base = build_signature_base(&values, &member.raw);
        self.public_key.verify(base.as_bytes(), &signature)?;
        if let Some(body) = body {
            if member
                .components
                .contains(&SignatureComponent::Header("content-digest".into()))
            {
                let header = request
                    .headers()
                    .get("content-digest")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::Verification("content-digest header missing".into()))?;
                verify_content_digest(header, body)?;
            }
        }
        self.check_replay(&label, &member.params, opts)
    }

    /// Verify a response bound to its request.
    pub fn verify_response<B, R>(
        &self,
        response: &Response<B>,
        request: &Request<R>,
        body: Option<&[u8]>,
        opts: &VerifyOptions,
    ) -> Result<()> {
        let (label, member, signature) =
            select(response.headers(), opts, self.public_key.key_type())?;
        if opts.require_request_binding && !member.components.iter().any(SignatureComponent::is_req)
        {
            return Err(Error::Verification(
                "response signature is not bound to the request".into(),
            ));
        }
        check_policy(&member, body, opts)?;
        check_params(&member.params, opts, &self.public_key)?;
        let values = canonicalize_response(response, Some(request), &member.components)?;
        let base = build_signature_base(&values, &member.raw);
        self.public_key.verify(base.as_bytes(), &signature)?;
        if let Some(body) = body {
            if member
                .components
                .contains(&SignatureComponent::Header("content-digest".into()))
            {
                let header = response
                    .headers()
                    .get("content-digest")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::Verification("content-digest header missing".into()))?;
                verify_content_digest(header, body)?;
            }
        }
        self.check_replay(&label, &member.params, opts)
    }

    fn check_replay(
        &self,
        _label: &str,
        params: &SignatureParams,
        opts: &VerifyOptions,
    ) -> Result<()> {
        if opts.disable_replay_check {
            return Ok(());
        }
        if let (Some(guard), Some(nonce)) = (&self.replay, &params.nonce) {
            let scope = params.key_id.clone().unwrap_or_default();
            if !guard.check_and_mark(&scope, nonce) {
                return Err(Error::Verification("nonce already used".into()));
            }
        }
        Ok(())
    }
}

fn select(
    headers: &HeaderMap,
    opts: &VerifyOptions,
    key_type: crate::crypto::KeyType,
) -> Result<(String, SignatureInputMember, Signature)> {
    let sig_input = headers
        .get("signature-input")
        .ok_or_else(|| Error::InvalidInput("missing signature-input header".into()))?
        .to_str()
        .map_err(|_| Error::InvalidInput("invalid signature-input header".into()))?;
    let sig_header = headers
        .get("signature")
        .ok_or_else(|| Error::InvalidInput("missing signature header".into()))?
        .to_str()
        .map_err(|_| Error::InvalidInput("invalid signature header".into()))?;
    let inputs = parse_signature_input(sig_input)?;
    let signatures = parse_signature_header(sig_header)?;
    let label = match &opts.label {
        Some(l) => l.clone(),
        None => inputs.keys().next().cloned().unwrap(),
    };
    let member = inputs
        .get(&label)
        .cloned()
        .ok_or_else(|| Error::InvalidInput(format!("signature {label} not in Signature-Input")))?;
    let bytes = signatures
        .get(&label)
        .ok_or_else(|| Error::InvalidInput(format!("signature {label} not in Signature")))?;
    Ok((label, member, Signature::from_bytes(key_type, bytes)?))
}

fn check_policy(
    member: &SignatureInputMember,
    body: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<()> {
    for required in &opts.required_components {
        if !member
            .components
            .iter()
            .any(|c| c.name() == required.name())
        {
            return Err(Error::Verification(format!(
                "required component {} is not covered",
                required.identifier()
            )));
        }
    }
    if opts.require_content_digest && body.is_some_and(|b| !b.is_empty()) {
        let covered = member
            .components
            .iter()
            .any(|c| matches!(c, SignatureComponent::Header(h) if h == "content-digest"));
        if !covered {
            return Err(Error::Verification("content-digest is not covered".into()));
        }
    }
    if opts.require_nonce && member.params.nonce.as_deref().unwrap_or("").is_empty() {
        return Err(Error::Verification("nonce is required".into()));
    }
    Ok(())
}

fn check_params(
    params: &SignatureParams,
    opts: &VerifyOptions,
    public_key: &PublicKey,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Other("system time error".into()))?
        .as_secs() as i64;
    if let Some(created) = params.created {
        if let Some(max_age) = opts.max_age {
            if now - created > max_age.as_secs() as i64 {
                return Err(Error::Verification("signature expired".into()));
            }
        }
        if created > now + opts.max_clock_skew.as_secs() as i64 {
            return Err(Error::Verification(
                "signature created in the future".into(),
            ));
        }
    }
    if let Some(expires) = params.expires {
        if now > expires {
            return Err(Error::Verification("signature expired".into()));
        }
    }
    if let Some(alg) = &params.alg {
        if alg != algorithm_for(public_key.key_type()).identifier() {
            return Err(Error::Verification(format!(
                "alg {alg} does not match the key type"
            )));
        }
    }
    if let Some(expected) = &opts.expected_key_id {
        if params.key_id.as_deref() != Some(expected.as_str()) {
            return Err(Error::Verification("keyid mismatch".into()));
        }
    }
    if let Some(did) = &opts.expected_did {
        if params.key_id_did() != Some(did.as_str()) {
            return Err(Error::Verification(
                "keyid does not carry the expected DID".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, KeyType};
    use crate::rfc9421::HttpSigner;

    fn request() -> Request<()> {
        Request::builder()
            .method("POST")
            .uri("https://agent-b.example/mcp")
            .header("content-type", "application/json")
            .header("x-sage-did", "did:sage:ethereum:0xabc")
            .header("date", "Tue, 01 Sep 2026 12:00:00 GMT")
            .body(())
            .unwrap()
    }

    #[test]
    fn strict_round_trip_and_replay() {
        for kt in [KeyType::Ed25519, KeyType::Secp256k1, KeyType::P256] {
            let kp = KeyPair::generate(kt).unwrap();
            let signer = HttpSigner::new(kp.clone()).with_key_id("did:sage:ethereum:0xabc#key-1");
            let signed = signer.sign_request(request(), Some(b"{}")).unwrap();
            let verifier = HttpVerifier::new(kp.public_key().clone());
            let opts = VerifyOptions::strict_request().expected_did("did:sage:ethereum:0xabc");
            verifier
                .verify_request_with(&signed, Some(b"{}"), &opts)
                .unwrap();
            // same nonce again: replay
            assert!(verifier
                .verify_request_with(&signed, Some(b"{}"), &opts)
                .is_err());
            // tampered body
            let v2 = HttpVerifier::new(kp.public_key().clone());
            assert!(v2
                .verify_request_with(&signed, Some(b"{ }"), &opts)
                .is_err());
            // wrong DID expectation
            let v3 = HttpVerifier::new(kp.public_key().clone());
            assert!(v3
                .verify_request_with(
                    &signed,
                    Some(b"{}"),
                    &VerifyOptions::strict_request().expected_did("did:sage:ethereum:0xdef")
                )
                .is_err());
        }
    }

    #[test]
    fn response_bound_to_request() {
        let a = KeyPair::generate(KeyType::Ed25519).unwrap();
        let b = KeyPair::generate(KeyType::Ed25519).unwrap();
        let req = HttpSigner::new(a.clone())
            .with_key_id("did:sage:ethereum:0xaaa")
            .sign_request(request(), Some(b"{}"))
            .unwrap();
        let resp = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let body = br#"{"ok":true}"#;
        let signed = HttpSigner::new(b.clone())
            .with_key_id("did:sage:ethereum:0xbbb#key-1")
            .sign_response(resp, &req, Some(body))
            .unwrap();
        let input = signed.headers()["signature-input"].to_str().unwrap();
        assert!(input.contains("\"@method\";req") && input.contains("\"signature\";req"));
        let verifier = HttpVerifier::new(b.public_key().clone());
        verifier
            .verify_response(
                &signed,
                &req,
                Some(body),
                &VerifyOptions::strict_response().expected_did("did:sage:ethereum:0xbbb"),
            )
            .unwrap();
        // a different request does not verify
        let other = request();
        assert!(verifier
            .verify_response(
                &signed,
                &other,
                Some(body),
                &VerifyOptions::strict_response()
            )
            .is_err());
    }

    #[test]
    fn rejects_missing_nonce_and_wrong_alg() {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = HttpSigner::new(kp.clone());
        let params = SignatureParams {
            key_id: Some("did:sage:ethereum:0xabc".into()),
            alg: Some("es256k".into()),
            created: Some(1_788_609_600),
            ..Default::default()
        };
        let signed = signer
            .sign_request_with(
                request(),
                Some(b"{}"),
                &crate::rfc9421::default_request_components(),
                &params,
            )
            .unwrap();
        let verifier = HttpVerifier::new(kp.public_key().clone());
        let lenient = VerifyOptions::default().without_age_check();
        assert!(verifier
            .verify_request_with(&signed, Some(b"{}"), &lenient)
            .is_err()); // alg mismatch
        assert!(verifier
            .verify_request_with(
                &signed,
                Some(b"{}"),
                &VerifyOptions::strict_request().without_age_check()
            )
            .is_err()); // nonce missing
    }
}
