//! Transport Layer Benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sage_crypto_core::transport::{
    MessageTransport, MockTransport, TransportManager, TransportMessage,
};
use std::sync::Arc;
use tokio::runtime::Runtime;

fn bench_mock_transport_send(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let transport = MockTransport::new();

    c.bench_function("mock_transport_send", |b| {
        b.iter(|| {
            rt.block_on(async {
                transport.send(
                    black_box("did:sage:alice"),
                    black_box(b"Benchmark message".to_vec()),
                ).await.unwrap()
            })
        });
    });
}

fn bench_mock_transport_send_message(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let transport = MockTransport::new();

    c.bench_function("mock_transport_send_message", |b| {
        b.iter(|| {
            let message = TransportMessage::new(
                "did:sage:alice",
                b"Benchmark message".to_vec(),
            )
            .with_id("msg-12345")
            .with_metadata("type", "benchmark");

            rt.block_on(async {
                transport.send_message(black_box(message)).await.unwrap()
            })
        });
    });
}

fn bench_transport_manager_send(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = TransportManager::new();
    manager.register_transport("mock", Arc::new(MockTransport::new()));
    manager.set_default_transport("mock").unwrap();

    c.bench_function("transport_manager_send", |b| {
        b.iter(|| {
            rt.block_on(async {
                manager.send(
                    black_box("did:sage:alice"),
                    black_box(b"Benchmark message".to_vec()),
                ).await.unwrap()
            })
        });
    });
}

fn bench_transport_manager_with_transport(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = TransportManager::new();
    manager.register_transport("mock1", Arc::new(MockTransport::new()));
    manager.register_transport("mock2", Arc::new(MockTransport::new()));

    c.bench_function("transport_manager_with_transport", |b| {
        b.iter(|| {
            rt.block_on(async {
                manager.send_with_transport(
                    black_box("mock1"),
                    black_box("did:sage:alice"),
                    black_box(b"Benchmark message".to_vec()),
                ).await.unwrap()
            })
        });
    });
}

fn bench_transport_manager_auto(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = TransportManager::new();
    manager.register_transport("http", Arc::new(MockTransport::new()));
    manager.set_default_transport("http").unwrap();

    c.bench_function("transport_manager_auto", |b| {
        b.iter(|| {
            rt.block_on(async {
                manager.send_auto(
                    black_box("https://api.example.com/agent"),
                    black_box(b"Benchmark message".to_vec()),
                ).await.unwrap()
            })
        });
    });
}

fn bench_transport_message_creation(c: &mut Criterion) {
    c.bench_function("transport_message_creation", |b| {
        b.iter(|| {
            TransportMessage::new(
                black_box("did:sage:alice"),
                black_box(b"Benchmark message".to_vec()),
            )
            .with_id(black_box("msg-12345"))
            .with_metadata(black_box("type"), black_box("test"))
            .with_metadata(black_box("priority"), black_box("high"))
        });
    });
}

fn bench_mock_transport_get_sent_messages(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let transport = MockTransport::new();

    // Send some messages first
    for i in 0..10 {
        let _ = rt.block_on(async {
            transport.send("did:sage:alice", format!("Message {}", i).into_bytes()).await
        });
    }

    c.bench_function("mock_transport_get_sent_messages", |b| {
        b.iter(|| {
            transport.get_sent_messages(black_box("did:sage:alice"))
        });
    });
}

fn bench_mock_transport_count_sent_messages(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let transport = MockTransport::new();

    // Send some messages first
    for i in 0..10 {
        let _ = rt.block_on(async {
            transport.send("did:sage:alice", format!("Message {}", i).into_bytes()).await
        });
    }

    c.bench_function("mock_transport_count_sent_messages", |b| {
        b.iter(|| {
            transport.count_sent_messages(black_box("did:sage:alice"))
        });
    });
}

fn bench_transport_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_message_sizes");
    let rt = Runtime::new().unwrap();
    let transport = MockTransport::new();

    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let payload = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    transport.send(
                        black_box("did:sage:alice"),
                        black_box(payload.clone()),
                    ).await.unwrap()
                })
            });
        });
    }

    group.finish();
}

fn bench_transport_manager_multiple_transports(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("transport_manager_multiple_transports", |b| {
        b.iter(|| {
            let manager = TransportManager::new();
            for i in 0..5 {
                let name = format!("transport-{}", i);
                manager.register_transport(&name, Arc::new(MockTransport::new()));
            }
            manager.set_default_transport("transport-0").unwrap();

            rt.block_on(async {
                for i in 0..5 {
                    let name = format!("transport-{}", i);
                    let _ = manager.send_with_transport(
                        &name,
                        "did:sage:alice",
                        b"Message".to_vec(),
                    ).await;
                }
            })
        });
    });
}

fn bench_concurrent_transport_sends(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let transport = Arc::new(MockTransport::new());

    c.bench_function("concurrent_transport_sends", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = vec![];

                for i in 0..10 {
                    let transport = Arc::clone(&transport);
                    let handle = tokio::spawn(async move {
                        transport.send(
                            "did:sage:alice",
                            format!("Concurrent message {}", i).into_bytes(),
                        ).await.unwrap()
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    handle.await.unwrap();
                }
            })
        });
    });
}

criterion_group!(
    transport_benches,
    bench_mock_transport_send,
    bench_mock_transport_send_message,
    bench_transport_manager_send,
    bench_transport_manager_with_transport,
    bench_transport_manager_auto,
    bench_transport_message_creation,
    bench_mock_transport_get_sent_messages,
    bench_mock_transport_count_sent_messages,
    bench_transport_message_sizes,
    bench_transport_manager_multiple_transports,
    bench_concurrent_transport_sends,
);

criterion_main!(transport_benches);
