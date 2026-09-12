//! HPKE and Cryptographic Key Derivation Benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::OsRng;
use sage_crypto_core::hpke::{combine_secrets, derive_traffic_keys, make_ack_tag, verify_ack_tag};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn bench_x25519_key_generation(c: &mut Criterion) {
    c.bench_function("x25519_key_generation", |b| {
        b.iter(|| EphemeralSecret::random_from_rng(OsRng));
    });
}

fn bench_x25519_diffie_hellman(c: &mut Criterion) {
    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    c.bench_function("x25519_diffie_hellman", |b| {
        b.iter(|| {
            let alice_secret = EphemeralSecret::random_from_rng(OsRng);
            alice_secret.diffie_hellman(black_box(&bob_public))
        });
    });
}

fn bench_combine_secrets(c: &mut Criterion) {
    let exporter_hpke = vec![0x42u8; 32];
    let ss_e2e = vec![0x43u8; 32];
    let export_ctx = b"benchmark-context";

    c.bench_function("combine_secrets", |b| {
        b.iter(|| {
            combine_secrets(
                black_box(&exporter_hpke),
                black_box(&ss_e2e),
                black_box(export_ctx),
            )
            .unwrap()
        });
    });
}

fn bench_derive_traffic_keys(c: &mut Criterion) {
    let seed = vec![0x42u8; 32];

    c.bench_function("derive_traffic_keys", |b| {
        b.iter(|| derive_traffic_keys(black_box(&seed)).unwrap());
    });
}

fn bench_make_ack_tag(c: &mut Criterion) {
    let seed = vec![0x42u8; 32];
    let ctx_id = "benchmark-context";
    let nonce = "benchmark-nonce";
    let kid = "key-1";
    let bind1 = [0x01u8; 32];
    let bind2 = [0x02u8; 32];

    c.bench_function("make_ack_tag", |b| {
        b.iter(|| {
            make_ack_tag(
                black_box(&seed),
                black_box(ctx_id),
                black_box(nonce),
                black_box(kid),
                black_box(&[&bind1[..], &bind2[..]]),
            )
            .unwrap()
        });
    });
}

fn bench_verify_ack_tag(c: &mut Criterion) {
    let seed = vec![0x42u8; 32];
    let tag = make_ack_tag(&seed, "ctx", "nonce", "key", &[&[0x01u8; 32]]).unwrap();

    c.bench_function("verify_ack_tag", |b| {
        b.iter(|| verify_ack_tag(black_box(&tag), black_box(&tag)).unwrap());
    });
}

fn bench_traffic_key_derivation_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("traffic_key_derivation_sizes");

    for size in [32, 64, 128].iter() {
        let seed = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| derive_traffic_keys(black_box(&seed)).unwrap());
        });
    }

    group.finish();
}

fn bench_secret_combination_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_combination_overhead");

    for size in [16, 32, 64].iter() {
        let exporter = vec![0x42u8; *size];
        let ss = vec![0x43u8; *size];
        let ctx = b"benchmark-context";

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                combine_secrets(black_box(&exporter), black_box(&ss), black_box(ctx)).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_ack_tag_with_multiple_bindings(c: &mut Criterion) {
    let mut group = c.benchmark_group("ack_tag_multiple_bindings");
    let seed = vec![0x42u8; 32];

    for num_bindings in [1, 2, 4, 8].iter() {
        let bindings: Vec<Vec<u8>> = (0..*num_bindings).map(|i| vec![i as u8; 32]).collect();
        let binding_refs: Vec<&[u8]> = bindings.iter().map(|b| b.as_slice()).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_bindings),
            num_bindings,
            |b, _| {
                b.iter(|| {
                    make_ack_tag(
                        black_box(&seed),
                        "ctx",
                        "nonce",
                        "key",
                        black_box(&binding_refs),
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    hpke_benches,
    bench_x25519_key_generation,
    bench_x25519_diffie_hellman,
    bench_combine_secrets,
    bench_derive_traffic_keys,
    bench_make_ack_tag,
    bench_verify_ack_tag,
    bench_traffic_key_derivation_sizes,
    bench_secret_combination_overhead,
    bench_ack_tag_with_multiple_bindings,
);

criterion_main!(hpke_benches);
