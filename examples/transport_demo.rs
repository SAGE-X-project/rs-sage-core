//! Transport Layer Demo
//!
//! This example demonstrates the transport layer features:
//! - MockTransport for testing
//! - TransportManager for routing
//! - Multiple transport registration
//! - Automatic transport selection
//! - Message envelopes with metadata
//!
//! Run with: cargo run --example transport_demo

use sage_crypto_core::transport::{
    MessageTransport, MockTransport, TransportManager, TransportMessage, TransportResponse,
    TransportResult,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> TransportResult<()> {
    println!("=== SAGE Crypto Core - Transport Layer Demo ===\n");

    // 1. Create MockTransport for testing
    println!("1. Creating MockTransport...");
    let mock_transport = MockTransport::new();
    println!("   ✓ MockTransport created\n");

    // 2. Send messages using MockTransport
    println!("2. Sending messages using MockTransport...");
    let message1 = b"Hello, Alice!".to_vec();
    let response1 = mock_transport.send("did:sage:alice", message1.clone()).await?;
    println!("   ✓ Message sent to Alice");
    println!("     Status: {}", response1.status);
    println!("     Response: {:?}", String::from_utf8_lossy(&response1.payload));

    let message2 = b"Hello, Bob!".to_vec();
    let response2 = mock_transport.send("did:sage:bob", message2.clone()).await?;
    println!("   ✓ Message sent to Bob");
    println!("     Status: {}\n", response2.status);

    // 3. Inspect sent messages
    println!("3. Inspecting sent messages...");
    let alice_messages = mock_transport.get_sent_messages("did:sage:alice");
    println!("   Messages to Alice: {} message(s)", alice_messages.len());
    println!("     Content: {:?}", String::from_utf8_lossy(&alice_messages[0]));

    let bob_count = mock_transport.count_sent_messages("did:sage:bob");
    println!("   Messages to Bob: {} message(s)\n", bob_count);

    // 4. Configure custom responses
    println!("4. Configuring custom responses...");
    let custom_response = TransportResponse::new(b"Custom reply from Charlie".to_vec(), 201);
    mock_transport.set_response("did:sage:charlie", custom_response);

    let response3 = mock_transport
        .send("did:sage:charlie", b"Request".to_vec())
        .await?;
    println!("   ✓ Custom response configured");
    println!("     Status: {}", response3.status);
    println!("     Response: {:?}\n", String::from_utf8_lossy(&response3.payload));

    // 5. Use message envelopes with metadata
    println!("5. Using message envelopes with metadata...");
    let envelope = TransportMessage::new("did:sage:dave", b"Priority message".to_vec())
        .with_id("msg-12345")
        .with_metadata("priority", "high")
        .with_metadata("type", "alert");

    let response4 = mock_transport.send_message(envelope).await?;
    println!("   ✓ Message envelope sent");
    println!("     Message ID: {:?}", response4.message_id);
    println!("     Status: {}\n", response4.status);

    // 6. Create TransportManager
    println!("6. Creating TransportManager...");
    let manager = TransportManager::new();
    println!("   ✓ TransportManager created\n");

    // 7. Register multiple transports
    println!("7. Registering multiple transports...");
    let mock1 = Arc::new(MockTransport::new());
    let mock2 = Arc::new(MockTransport::new());

    manager.register_transport("primary", mock1.clone());
    manager.register_transport("backup", mock2.clone());

    println!("   ✓ Registered transports:");
    for name in manager.list_transports() {
        println!("     - {}", name);
    }
    println!("   Default transport: {:?}\n", manager.get_default_transport_name());

    // 8. Send using default transport
    println!("8. Sending via default transport...");
    let response5 = manager
        .send("did:sage:eve", b"Hello, Eve!".to_vec())
        .await?;
    println!("   ✓ Message sent via default transport");
    println!("     Status: {}", response5.status);
    println!("   Messages in primary: {}\n", mock1.count_sent_messages("did:sage:eve"));

    // 9. Send using specific transport
    println!("9. Sending via specific transport (backup)...");
    let response6 = manager
        .send_with_transport("backup", "did:sage:frank", b"Hello, Frank!".to_vec())
        .await?;
    println!("   ✓ Message sent via backup transport");
    println!("     Status: {}", response6.status);
    println!("   Messages in backup: {}\n", mock2.count_sent_messages("did:sage:frank"));

    // 10. Change default transport
    println!("10. Changing default transport...");
    manager.set_default_transport("backup")?;
    println!("    ✓ Default transport changed to: {:?}\n", manager.get_default_transport_name());

    // 11. Send with automatic transport selection
    println!("11. Automatic transport selection...");
    let response7 = manager
        .send_auto("did:sage:grace", b"Auto-routed message".to_vec())
        .await?;
    println!("    ✓ Message auto-routed");
    println!("      Status: {}", response7.status);
    println!("      Messages in backup: {}\n", mock2.count_sent_messages("did:sage:grace"));

    // 12. Transport statistics
    println!("12. Transport statistics...");
    println!("    Total transports: {}", manager.transport_count());
    println!("    Transport names: {:?}", manager.list_transports());

    println!("\n    Primary transport statistics:");
    let all_primary = mock1.get_all_sent_messages();
    for (dest, messages) in &all_primary {
        println!("      {} → {} message(s)", dest, messages.len());
    }

    println!("\n    Backup transport statistics:");
    let all_backup = mock2.get_all_sent_messages();
    for (dest, messages) in &all_backup {
        println!("      {} → {} message(s)", dest, messages.len());
    }

    println!("\n=== Transport Demo completed successfully! ===");
    Ok(())
}
