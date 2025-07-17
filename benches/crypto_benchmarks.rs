//! Cryptographic operation benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use http::Request;
use sage_crypto_core::crypto::{Signer, Verifier};
use sage_crypto_core::rfc9421::{HttpSigner, SignatureComponent};
use sage_crypto_core::{KeyPair, KeyType};

fn bench_ed25519_keygen(c: &mut Criterion) {
    c.bench_function("ed25519_keygen", |b| {
        b.iter(|| KeyPair::generate(KeyType::Ed25519).unwrap());
    });
}

fn bench_secp256k1_keygen(c: &mut Criterion) {
    c.bench_function("secp256k1_keygen", |b| {
        b.iter(|| KeyPair::generate(KeyType::Secp256k1).unwrap());
    });
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let message = b"Benchmark message for signing performance test";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| keypair.sign(black_box(message)).unwrap());
    });
}

fn bench_secp256k1_sign(c: &mut Criterion) {
    let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();
    let message = b"Benchmark message for signing performance test";

    c.bench_function("secp256k1_sign", |b| {
        b.iter(|| keypair.sign(black_box(message)).unwrap());
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let message = b"Benchmark message for verification performance test";
    let signature = keypair.sign(message).unwrap();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            keypair
                .verify(black_box(message), black_box(&signature))
                .unwrap()
        });
    });
}

fn bench_http_sign_request(c: &mut Criterion) {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

    c.bench_function("http_sign_request", |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("POST")
                .uri("https://api.example.com/v1/test")
                .header("host", "api.example.com")
                .header("content-type", "application/json")
                .body(b"test body".to_vec())
                .unwrap();

            let signer = HttpSigner::new(keypair.clone()).with_default_components(vec![
                SignatureComponent::Method,
                SignatureComponent::Path,
                SignatureComponent::Authority,
                SignatureComponent::Header("content-type".to_string()),
            ]);

            signer.sign_request(request).unwrap()
        });
    });
}

criterion_group!(
    benches,
    bench_ed25519_keygen,
    bench_secp256k1_keygen,
    bench_ed25519_sign,
    bench_secp256k1_sign,
    bench_ed25519_verify,
    bench_http_sign_request
);
criterion_main!(benches);
