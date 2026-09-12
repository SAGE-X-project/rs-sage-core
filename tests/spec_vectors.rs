//! Runs the sage-spec test vectors (https://github.com/SAGE-X-project/sage-spec)
//! against this crate. The vectors directory is found through
//! `SAGE_SPEC_VECTORS`, else `.sage-spec/vectors` (CI checkout), else
//! `../sage-spec/vectors` (sibling checkout). Suites the crate does not
//! implement yet are listed in `NOT_YET` and reported, not failed; the list
//! shrinks with every alignment step.

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct File {
    suite: String,
    spec_version: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    mode: String,
    input: serde_json::Value,
    output: serde_json::Value,
}

/// Suites and vectors this crate does not implement yet (F-03 steps 3-7).
const NOT_YET: &[&str] = &["hpke", "session", "did"];

fn vectors_dir() -> PathBuf {
    if let Ok(d) = std::env::var("SAGE_SPEC_VECTORS") {
        return PathBuf::from(d);
    }
    for c in [".sage-spec/vectors", "../sage-spec/vectors"] {
        let p = PathBuf::from(c);
        if p.join("jcs.json").exists() {
            return p;
        }
    }
    panic!("sage-spec vectors not found: set SAGE_SPEC_VECTORS or check out sage-spec next to this repository");
}

fn load(suite: &str) -> File {
    let path = vectors_dir().join(format!("{suite}.json"));
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let f: File = serde_json::from_slice(&data).unwrap();
    assert_eq!(f.suite, suite);
    f
}

fn str_field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

#[test]
fn jcs_suite() {
    let f = load("jcs");
    println!("jcs: spec {}", f.spec_version);
    let mut failures = Vec::new();
    for v in &f.vectors {
        assert_eq!(v.mode, "deterministic", "{}", v.name);
        let input = str_field(&v.input, "json");
        let want = str_field(&v.output, "canonical");
        let want_hex = str_field(&v.output, "canonical_hex");
        match sage_crypto_core::jcs::canonicalize(input.as_bytes()) {
            Ok(got) => {
                if got != want.as_bytes() || hex::encode(&got) != want_hex {
                    failures.push(format!(
                        "{}: got {:?}, want {:?}",
                        v.name,
                        String::from_utf8_lossy(&got),
                        want
                    ));
                } else {
                    println!("pass jcs/{}", v.name);
                }
            }
            Err(e) => failures.push(format!("{}: {e}", v.name)),
        }
    }
    assert!(
        failures.is_empty(),
        "jcs vectors failed:\n{}",
        failures.join("\n")
    );
}

fn seed_from_label(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.finalize().into()
}

fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(str_field(v, key)).unwrap_or_else(|e| panic!("{key}: {e}"))
}

#[test]
fn crypto_suite() {
    use sage_crypto_core::crypto::{KeyPair, KeyType, PublicKey, Signature, Signer, Verifier};
    let f = load("crypto");
    let mut failures = Vec::new();
    let mut check = |name: &str, ok: bool, detail: String| {
        if ok {
            println!("pass crypto/{name}");
        } else {
            failures.push(format!("{name}: {detail}"));
        }
    };
    for v in &f.vectors {
        match v.name.as_str() {
            "ed25519-sign" => {
                let seed = seed_from_label(str_field(&v.input, "seed_label"));
                let kp = KeyPair::from_private_key_bytes(KeyType::Ed25519, &seed).unwrap();
                let msg = hex_field(&v.input, "message");
                let sig = kp.sign(&msg).unwrap();
                let ok = kp.public_key_bytes() == hex_field(&v.output, "public_key")
                    && sig.to_bytes() == hex_field(&v.output, "signature")
                    && kp.key_id() == str_field(&v.output, "key_id")
                    && kp.private_key_bytes() == hex_field(&v.output, "seed");
                check(
                    &v.name,
                    ok,
                    format!(
                        "pub {} sig {} kid {}",
                        hex::encode(kp.public_key_bytes()),
                        sig.to_base64(),
                        kp.key_id()
                    ),
                );
            }
            "secp256k1-keccak-sign" => {
                let scalar = seed_from_label(str_field(&v.input, "scalar_label"));
                let kp = KeyPair::from_private_key_bytes(KeyType::Secp256k1, &scalar).unwrap();
                let msg = hex_field(&v.input, "message");
                let sig = kp.sign(&msg).unwrap();
                let sig_bytes = sig.to_bytes();
                let mut detail = Vec::new();
                if kp.public_key_bytes() != hex_field(&v.output, "public_key") {
                    detail.push("public_key");
                }
                if kp.public_key().to_compressed_bytes()
                    != hex_field(&v.output, "public_key_compressed")
                {
                    detail.push("public_key_compressed");
                }
                if kp.private_key_bytes() != hex_field(&v.output, "private_scalar") {
                    detail.push("private_scalar");
                }
                if kp.key_id() != str_field(&v.output, "key_id") {
                    detail.push("key_id");
                }
                if kp.public_key().ethereum_address().unwrap()
                    != str_field(&v.output, "ethereum_address")
                {
                    detail.push("ethereum_address");
                }
                if sig_bytes != hex_field(&v.output, "signature") {
                    detail.push("signature");
                }
                if sig.rs_bytes() != hex_field(&v.output, "signature_rs") {
                    detail.push("signature_rs");
                }
                if i64::from(sig_bytes[64]) != v.output["recovery_id"].as_i64().unwrap() {
                    detail.push("recovery_id");
                }
                // 65- and 64-byte forms must both verify
                let sig64 = Signature::from_bytes(KeyType::Secp256k1, &sig_bytes[..64]).unwrap();
                if kp.verify(&msg, &sig).is_err() || kp.verify(&msg, &sig64).is_err() {
                    detail.push("verify");
                }
                check(&v.name, detail.is_empty(), detail.join(","));
            }
            "p256-sha256-sign" => {
                assert_eq!(v.mode, "verify");
                let pub_bytes = hex_field(&v.output, "public_key");
                let pk = PublicKey::from_bytes(KeyType::P256, &pub_bytes).unwrap();
                let sig = Signature::from_bytes(KeyType::P256, &hex_field(&v.output, "signature"))
                    .unwrap();
                let msg = hex_field(&v.input, "message");
                let ok = pk.verify(&msg, &sig).is_ok() && pk.to_bytes() == pub_bytes;
                // our own signature must also be raw 64 bytes and verify
                let scalar = seed_from_label(str_field(&v.input, "scalar_label"));
                let kp = KeyPair::from_private_key_bytes(KeyType::P256, &scalar).unwrap();
                let own = kp.sign(&msg).unwrap();
                let ok = ok
                    && own.to_bytes().len() == 64
                    && kp.verify(&msg, &own).is_ok()
                    && kp.public_key_bytes() == pub_bytes
                    && kp.private_key_bytes() == hex_field(&v.output, "private_scalar");
                check(&v.name, ok, "P-256 verification or key derivation".into());
            }
            "key-id" => {
                let pk =
                    PublicKey::from_bytes(KeyType::Ed25519, &hex_field(&v.input, "public_key"))
                        .unwrap();
                check(
                    &v.name,
                    pk.key_id() == str_field(&v.output, "key_id"),
                    pk.key_id(),
                );
            }
            other => check(other, false, "unknown vector".into()),
        }
    }
    assert!(
        failures.is_empty(),
        "crypto vectors failed:\n{}",
        failures.join("\n")
    );
}

fn keypair_for(alg: &str, label: &str) -> sage_crypto_core::crypto::KeyPair {
    use sage_crypto_core::crypto::{KeyPair, KeyType};
    let seed = seed_from_label(label);
    let kt = match alg {
        "ed25519" => KeyType::Ed25519,
        "es256k" => KeyType::Secp256k1,
        "ecdsa-p256-sha256" => KeyType::P256,
        other => panic!("unknown alg {other}"),
    };
    KeyPair::from_private_key_bytes(kt, &seed).unwrap()
}

fn components_of(v: &serde_json::Value) -> Vec<sage_crypto_core::rfc9421::SignatureComponent> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|c| sage_crypto_core::rfc9421::SignatureComponent::parse(c.as_str().unwrap()).unwrap())
        .collect()
}

fn params_of(v: &serde_json::Value) -> sage_crypto_core::rfc9421::SignatureParams {
    sage_crypto_core::rfc9421::SignatureParams {
        key_id: Some(str_field(v, "keyid").to_string()),
        alg: Some(str_field(v, "alg").to_string()),
        created: Some(v["created"].as_i64().unwrap()),
        expires: None,
        nonce: Some(str_field(v, "nonce").to_string()),
        tag: None,
    }
}

fn request_of(v: &serde_json::Value) -> http::Request<()> {
    let mut b = http::Request::builder()
        .method(str_field(v, "method"))
        .uri(str_field(v, "url"));
    for (k, val) in v["headers"].as_object().unwrap() {
        b = b.header(k.as_str(), val.as_str().unwrap());
    }
    b.body(()).unwrap()
}

fn header<'a>(h: &'a http::HeaderMap, name: &str) -> &'a str {
    h.get(name).map(|v| v.to_str().unwrap()).unwrap_or("")
}

#[test]
fn rfc9421_suite() {
    use sage_crypto_core::rfc9421::{HttpSigner, HttpVerifier, VerifyOptions};
    let f = load("rfc9421");
    let mut failures: Vec<String> = Vec::new();
    for v in &f.vectors {
        let mut detail: Vec<String> = Vec::new();
        if v.name.starts_with("request-") {
            let alg = str_field(&v.input, "alg");
            let kp = keypair_for(alg, str_field(&v.input, "key_label"));
            let did = str_field(&v.input, "keyid")
                .split('#')
                .next()
                .unwrap()
                .to_string();
            let body = str_field(&v.input, "body").as_bytes().to_vec();
            let components = components_of(&v.input["covered"]);
            let params = params_of(&v.input);
            let signer = HttpSigner::new(kp.clone()).with_key_id(str_field(&v.input, "keyid"));
            let signed = signer
                .sign_request_with(request_of(&v.input), Some(&body), &components, &params)
                .unwrap();
            let base = HttpSigner::signature_base(&signed, &components, &params).unwrap();
            if base != str_field(&v.output, "signature_base") {
                detail.push(format!("signature_base:\n{base}"));
            }
            if header(signed.headers(), "content-digest") != str_field(&v.output, "content_digest")
            {
                detail.push("content_digest".into());
            }
            if header(signed.headers(), "signature-input")
                != str_field(&v.output, "signature_input")
            {
                detail.push("signature_input".into());
            }
            if v.mode == "deterministic"
                && header(signed.headers(), "signature") != str_field(&v.output, "signature")
            {
                detail.push("signature".into());
            }
            // The Go core's headers must verify here (verify-only for P-256).
            let mut theirs = request_of(&v.input);
            theirs.headers_mut().insert(
                "content-digest",
                str_field(&v.output, "content_digest").parse().unwrap(),
            );
            theirs.headers_mut().insert(
                "signature-input",
                str_field(&v.output, "signature_input").parse().unwrap(),
            );
            theirs.headers_mut().insert(
                "signature",
                str_field(&v.output, "signature").parse().unwrap(),
            );
            let opts = VerifyOptions::strict_request()
                .without_age_check()
                .expected_did(&did);
            let verifier = HttpVerifier::with_replay_guard(kp.public_key().clone(), None);
            if let Err(e) = verifier.verify_request_with(&theirs, Some(&body), &opts) {
                detail.push(format!("verify Go signature: {e}"));
            }
            if let Err(e) = verifier.verify_request_with(&signed, Some(&body), &opts) {
                detail.push(format!("verify own signature: {e}"));
            }
        } else if v.name.starts_with("response-") {
            let req_in = &v.input["request"];
            let kp_a = keypair_for(str_field(req_in, "alg"), str_field(req_in, "key_label"));
            let req_body = str_field(req_in, "body").as_bytes().to_vec();
            let req = HttpSigner::new(kp_a)
                .with_key_id(str_field(req_in, "keyid"))
                .sign_request_with(
                    request_of(req_in),
                    Some(&req_body),
                    &components_of(&req_in["covered"]),
                    &params_of(req_in),
                )
                .unwrap();
            if header(req.headers(), "signature") != str_field(&v.output, "request_signature") {
                detail.push("request_signature".into());
            }
            let kp_b = keypair_for(str_field(&v.input, "alg"), str_field(&v.input, "key_label"));
            let did_b = str_field(&v.input, "keyid")
                .split('#')
                .next()
                .unwrap()
                .to_string();
            let body = str_field(&v.input, "body").as_bytes().to_vec();
            let mut rb =
                http::Response::builder().status(v.input["status"].as_u64().unwrap() as u16);
            for (k, val) in v.input["headers"].as_object().unwrap() {
                rb = rb.header(k.as_str(), val.as_str().unwrap());
            }
            let resp = rb.body(()).unwrap();
            let components = components_of(&v.input["covered"]);
            let params = params_of(&v.input);
            let signed = HttpSigner::new(kp_b.clone())
                .with_key_id(str_field(&v.input, "keyid"))
                .sign_response_with(resp, &req, Some(&body), &components, &params)
                .unwrap();
            if header(signed.headers(), "content-digest") != str_field(&v.output, "content_digest")
            {
                detail.push("content_digest".into());
            }
            if header(signed.headers(), "signature-input")
                != str_field(&v.output, "signature_input")
            {
                detail.push("signature_input".into());
            }
            if header(signed.headers(), "signature") != str_field(&v.output, "signature") {
                detail.push("signature".into());
            }
            let opts = VerifyOptions::strict_response()
                .without_age_check()
                .expected_did(&did_b);
            let verifier = HttpVerifier::with_replay_guard(kp_b.public_key().clone(), None);
            if let Err(e) = verifier.verify_response(&signed, &req, Some(&body), &opts) {
                detail.push(format!("verify: {e}"));
            }
        } else {
            detail.push("unknown vector".into());
        }
        if detail.is_empty() {
            println!("pass rfc9421/{}", v.name);
        } else {
            failures.push(format!("{}: {}", v.name, detail.join(", ")));
        }
    }
    assert!(
        failures.is_empty(),
        "rfc9421 vectors failed:\n{}",
        failures.join("\n")
    );
}

#[test]
fn unimplemented_suites_are_listed() {
    for suite in NOT_YET {
        let f = load(suite);
        println!(
            "skip {suite}: {} vectors not run yet (F-03)",
            f.vectors.len()
        );
    }
}
