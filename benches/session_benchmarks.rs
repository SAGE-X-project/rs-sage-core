//! Session Management Benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sage_crypto_core::session::{Session, SessionManager, SessionManagerConfig};

fn bench_session_creation_from_exporter(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];

    c.bench_function("session_creation_from_exporter", |b| {
        b.iter(|| {
            manager
                .ensure_session_from_exporter_with_role(
                    black_box(&exporter),
                    black_box("bench-context"),
                    black_box(true),
                    None,
                )
                .unwrap()
        });
    });
}

fn bench_session_encrypt(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();

    let plaintext = b"Benchmark message for encryption performance test with reasonable length";

    c.bench_function("session_encrypt", |b| {
        b.iter(|| session.encrypt(black_box(plaintext)).unwrap());
    });
}

fn bench_session_decrypt(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (alice_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();
    let (bob_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", false, None)
        .unwrap();

    let plaintext = b"Benchmark message for decryption performance test with reasonable length";
    let ciphertext = alice_session.encrypt(plaintext).unwrap();

    c.bench_function("session_decrypt", |b| {
        b.iter(|| bob_session.decrypt(black_box(&ciphertext)).unwrap());
    });
}

fn bench_session_encrypt_and_sign(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();

    let plaintext = b"Benchmark message for MAC authentication performance test";
    let covered = b"additional-authenticated-data";

    c.bench_function("session_encrypt_and_sign", |b| {
        b.iter(|| {
            session
                .encrypt_and_sign(black_box(plaintext), black_box(covered))
                .unwrap()
        });
    });
}

fn bench_session_decrypt_and_verify(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (alice_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();
    let (bob_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", false, None)
        .unwrap();

    let plaintext = b"Benchmark message for MAC authentication performance test";
    let covered = b"additional-authenticated-data";
    let (ciphertext, mac) = alice_session.encrypt_and_sign(plaintext, covered).unwrap();

    c.bench_function("session_decrypt_and_verify", |b| {
        b.iter(|| {
            bob_session
                .decrypt_and_verify(black_box(&ciphertext), black_box(covered), black_box(&mac))
                .unwrap()
        });
    });
}

fn bench_session_bidirectional_communication(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (alice_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();
    let (bob_session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", false, None)
        .unwrap();

    c.bench_function("session_bidirectional_communication", |b| {
        b.iter(|| {
            // Alice → Bob
            let msg1 = b"Hello Bob";
            let ciphertext1 = alice_session.encrypt(msg1).unwrap();
            let _plaintext1 = bob_session.decrypt(&ciphertext1).unwrap();

            // Bob → Alice
            let msg2 = b"Hello Alice";
            let ciphertext2 = bob_session.encrypt(msg2).unwrap();
            let _plaintext2 = alice_session.decrypt(&ciphertext2).unwrap();
        });
    });
}

fn bench_session_key_binding(c: &mut Criterion) {
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (_, session_id, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();

    c.bench_function("session_key_binding", |b| {
        b.iter(|| {
            manager.bind_key_id(black_box("test-key-id"), black_box(&session_id));
            manager.get_by_key_id(black_box("test-key-id")).unwrap()
        });
    });
}

fn bench_session_cleanup(c: &mut Criterion) {
    c.bench_function("session_cleanup", |b| {
        b.iter(|| {
            let manager = SessionManager::new(SessionManagerConfig::default());
            let exporter = vec![0x42u8; 32];

            // Create multiple sessions
            for i in 0..10 {
                let ctx = format!("ctx-{i}");
                let _ = manager
                    .ensure_session_from_exporter_with_role(&exporter, &ctx, true, None)
                    .unwrap();
            }

            // Cleanup
            manager.cleanup_expired();
        });
    });
}

fn bench_session_encryption_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_encryption_sizes");
    let manager = SessionManager::new(SessionManagerConfig::default());
    let exporter = vec![0x42u8; 32];
    let (session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| session.encrypt(black_box(&plaintext)).unwrap());
        });
    }

    group.finish();
}

fn bench_concurrent_session_access(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let manager = Arc::new(SessionManager::new(SessionManagerConfig::default()));
    let exporter = vec![0x42u8; 32];
    let (session, _, _) = manager
        .ensure_session_from_exporter_with_role(&exporter, "ctx", true, None)
        .unwrap();
    let session = Arc::new(session);

    c.bench_function("concurrent_session_access", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let session = Arc::clone(&session);
                    thread::spawn(move || {
                        let plaintext = b"Concurrent message";
                        let ciphertext = session.encrypt(plaintext).unwrap();
                        let _decrypted = session.decrypt(&ciphertext).unwrap();
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

criterion_group!(
    session_benches,
    bench_session_creation_from_exporter,
    bench_session_encrypt,
    bench_session_decrypt,
    bench_session_encrypt_and_sign,
    bench_session_decrypt_and_verify,
    bench_session_bidirectional_communication,
    bench_session_key_binding,
    bench_session_cleanup,
    bench_session_encryption_sizes,
    bench_concurrent_session_access,
);

criterion_main!(session_benches);
