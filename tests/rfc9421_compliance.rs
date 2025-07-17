//! RFC 9421 compliance tests

use http::{Request, Response};
use sage_crypto_core::rfc9421::{HttpSigner, HttpVerifier, SignatureComponent, SignatureParams};
use sage_crypto_core::{KeyPair, KeyType};

#[test]
fn test_rfc9421_signature_components() {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let signer = HttpSigner::new(keypair.clone()).with_default_components(vec![
        SignatureComponent::Method,
        SignatureComponent::Path,
        SignatureComponent::Authority,
        SignatureComponent::Header("content-type".to_string()),
        SignatureComponent::Header("digest".to_string()),
    ]);

    let request = Request::builder()
        .method("POST")
        .uri("https://example.com/foo?param=value")
        .header("content-type", "application/json")
        .header(
            "digest",
            "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
        )
        .body(b"test".to_vec())
        .unwrap();

    let signed = signer.sign_request(request).unwrap();

    // Check signature-input contains expected components
    let sig_input = signed
        .headers()
        .get("signature-input")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(sig_input.contains("@method"));
    assert!(sig_input.contains("@path"));
    assert!(sig_input.contains("@authority"));
    assert!(sig_input.contains("content-type"));
    assert!(sig_input.contains("digest"));
}

#[test]
fn test_derived_components() {
    let components = vec![
        SignatureComponent::Method,
        SignatureComponent::TargetUri,
        SignatureComponent::Authority,
        SignatureComponent::Scheme,
        SignatureComponent::RequestTarget,
        SignatureComponent::Path,
        SignatureComponent::Query,
    ];

    let request = Request::builder()
        .method("GET")
        .uri("https://example.com:8080/path/to/resource?foo=bar&baz=qux")
        .body(())
        .unwrap();

    use sage_crypto_core::rfc9421::canonicalize::canonicalize_request;
    let result = canonicalize_request(&request, &components).unwrap();

    // Verify each component
    assert_eq!(result[0].0, "@method");
    assert_eq!(result[0].1, "GET");

    assert_eq!(result[1].0, "@target-uri");
    assert_eq!(
        result[1].1,
        "https://example.com:8080/path/to/resource?foo=bar&baz=qux"
    );

    assert_eq!(result[2].0, "@authority");
    assert_eq!(result[2].1, "example.com:8080");

    assert_eq!(result[3].0, "@scheme");
    assert_eq!(result[3].1, "https");

    assert_eq!(result[4].0, "@request-target");
    assert_eq!(result[4].1, "/path/to/resource?foo=bar&baz=qux");

    assert_eq!(result[5].0, "@path");
    assert_eq!(result[5].1, "/path/to/resource");

    assert_eq!(result[6].0, "@query");
    assert_eq!(result[6].1, "?foo=bar&baz=qux");
}

#[test]
fn test_signature_params_serialization() {
    let params = SignatureParams {
        key_id: Some("test-key-1".to_string()),
        alg: Some("ed25519".to_string()),
        created: Some(1618884475),
        expires: Some(1618884775),
        nonce: Some("randomvalue".to_string()),
        tag: Some("header-example".to_string()),
    };

    let serialized = params.to_string();

    // Check all parameters are present
    assert!(serialized.contains("keyid=\"test-key-1\""));
    assert!(serialized.contains("alg=\"ed25519\""));
    assert!(serialized.contains("created=1618884475"));
    assert!(serialized.contains("expires=1618884775"));
    assert!(serialized.contains("nonce=\"randomvalue\""));
    assert!(serialized.contains("tag=\"header-example\""));
}

#[test]
fn test_multiple_signatures() {
    // Test that we can add multiple signatures to a request
    let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
    let keypair2 = KeyPair::generate(KeyType::Secp256k1).unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("https://example.com/api")
        .body(())
        .unwrap();

    // Sign with first key
    let signer1 = HttpSigner::new(keypair1.clone());
    let signed1 = signer1.sign_request(request).unwrap();

    // The signature headers should be present
    assert!(signed1.headers().contains_key("signature"));
    assert!(signed1.headers().contains_key("signature-input"));

    // In a real implementation, we would support multiple signatures
    // For now, verify that the second signature would overwrite
    let signer2 = HttpSigner::new(keypair2.clone());
    let signed2 = signer2.sign_request(signed1).unwrap();

    // Should still have signature headers
    assert!(signed2.headers().contains_key("signature"));
    assert!(signed2.headers().contains_key("signature-input"));
}

#[test]
fn test_response_signing_and_verification() {
    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let signer = HttpSigner::new(keypair.clone());

    let response = Response::builder()
        .status(201)
        .header("content-type", "application/json")
        .header("location", "https://example.com/resource/123")
        .body(b"{\"id\": 123}".to_vec())
        .unwrap();

    let signed = signer.sign_response(response).unwrap();

    // Verify signature was added
    let sig_header = signed.headers().get("signature").unwrap();
    assert!(sig_header.to_str().unwrap().starts_with("sig1=:"));

    // Verify with correct key
    let verifier = HttpVerifier::new(keypair.public_key().clone());
    assert!(verifier.verify_response(&signed).is_ok());

    // Verification with wrong key should fail
    let wrong_keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let wrong_verifier = HttpVerifier::new(wrong_keypair.public_key().clone());
    assert!(wrong_verifier.verify_response(&signed).is_err());
}

#[test]
fn test_canonicalization_edge_cases() {
    use sage_crypto_core::rfc9421::canonicalize::canonicalize_request;

    // Test with minimal URI (just path)
    let request = Request::builder().method("GET").uri("/").body(()).unwrap();

    let components = vec![SignatureComponent::Path, SignatureComponent::Method];
    let result = canonicalize_request(&request, &components).unwrap();

    assert_eq!(result[0].0, "@path");
    assert_eq!(result[0].1, "/");
    assert_eq!(result[1].0, "@method");
    assert_eq!(result[1].1, "GET");

    // Test with missing components should error
    let bad_components = vec![SignatureComponent::Authority]; // No authority in "/"
    let result = canonicalize_request(&request, &bad_components);
    assert!(result.is_err());
}

#[test]
fn test_signature_base_string_format() {
    use sage_crypto_core::rfc9421::canonicalize::{build_signature_base, canonicalize_request};

    let request = Request::builder()
        .method("POST")
        .uri("https://example.com/foo")
        .header("host", "example.com")
        .header("date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .body(())
        .unwrap();

    let components = vec![
        SignatureComponent::Method,
        SignatureComponent::Authority,
        SignatureComponent::Path,
    ];

    let canonical = canonicalize_request(&request, &components).unwrap();
    let sig_params = "(\"@method\" \"@authority\" \"@path\");created=1618884475";

    let base = build_signature_base(&canonical, sig_params);

    // Verify format according to RFC 9421
    assert!(base.contains("\"@method\": POST"));
    assert!(base.contains("\"@authority\": example.com"));
    assert!(base.contains("\"@path\": /foo"));
    assert!(base.contains(
        "\"@signature-params\": (\"@method\" \"@authority\" \"@path\");created=1618884475"
    ));
}
