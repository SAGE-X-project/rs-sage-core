//! Session Management Example
//!
//! This example demonstrates session management features:
//! - Creating sessions from HPKE exporter secrets
//! - Encrypting and decrypting messages
//! - Session lifecycle management
//! - Key ID binding
//! - Session pool management
//!
//! Run with: cargo run --example session_management

use sage_crypto_core::session::{Session, SessionManager, SessionManagerConfig};
use sage_crypto_core::Result;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== SAGE Crypto Core - Session Management Example ===\n");

    // 1. Create session manager
    println!("1. Creating session manager...");
    let config = SessionManagerConfig {
        cleanup_interval: Duration::from_secs(30),
        ..Default::default()
    };
    let manager = SessionManager::new(config);
    println!("   ✓ Session manager created\n");

    // 2. Create sessions from HPKE exporter secrets
    println!("2. Creating sessions from HPKE exporter secrets...");

    // Simulate exporter secret from HPKE handshake (same for Alice and Bob)
    let shared_exporter = vec![0x42u8; 32]; // From successful HPKE handshake
    let exporter_charlie = vec![0x03u8; 32]; // Charlie uses different channel

    // Alice's session (initiator)
    let (session_alice, sid_alice, key_alice) = manager.ensure_session_from_exporter_with_role(
        &shared_exporter,
        "alice-bob-session",
        true,
        None,
    )?;
    println!("   ✓ Session created for Alice (initiator)");
    println!("     Session ID: {sid_alice}");
    println!("     Key: {}", hex::encode(&key_alice));

    // Bob's session (responder) - uses SAME exporter secret
    let (session_bob, sid_bob, key_bob) = manager.ensure_session_from_exporter_with_role(
        &shared_exporter,
        "alice-bob-session",
        false,
        None,
    )?;
    println!("   ✓ Session created for Bob (responder)");
    println!("     Session ID: {sid_bob}");
    println!("     Key: {}", hex::encode(&key_bob));

    // Charlie's session (separate channel)
    let (_session_charlie, sid_charlie, _key_charlie) = manager
        .ensure_session_from_exporter_with_role(&exporter_charlie, "charlie-session", true, None)?;
    println!("   ✓ Session created for Charlie");
    println!("     Session ID: {sid_charlie}\n");

    // 3. Bind key IDs to sessions
    println!("3. Binding key IDs to sessions...");
    manager.bind_key_id("alice-key-1", &sid_alice);
    manager.bind_key_id("bob-key-1", &sid_bob);
    manager.bind_key_id("charlie-key-1", &sid_charlie);
    println!("   ✓ Key IDs bound to sessions");
    println!("   Total sessions: {}", manager.session_count());
    println!("   Total key bindings: {}\n", manager.key_binding_count());

    // 4. Retrieve sessions by key ID
    println!("4. Retrieving sessions by key ID...");
    let alice_session_by_key = manager.get_by_key_id("alice-key-1");
    if let Some(session) = alice_session_by_key {
        println!("   ✓ Retrieved Alice's session by key ID");
        println!("     Session ID: {}", session.get_id());
        println!("     Expired: {}\n", session.is_expired());
    }

    // 5. Encrypt and decrypt messages (Alice → Bob)
    println!("5. Encrypting and decrypting messages...");
    let plaintext = b"Hello Bob, this is a message from Alice!";

    println!(
        "   Original message: {:?}",
        String::from_utf8_lossy(plaintext)
    );

    // Alice encrypts (initiator)
    let ciphertext = session_alice.encrypt(plaintext)?;
    println!("   ✓ Alice encrypted message");
    println!("     Ciphertext: {}", hex::encode(&ciphertext[..16]));

    // Bob decrypts (responder)
    let decrypted = session_bob.decrypt(&ciphertext)?;
    println!("   ✓ Bob decrypted message");
    println!(
        "     Decrypted: {:?}\n",
        String::from_utf8_lossy(&decrypted)
    );

    // Verify decryption matches original
    assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    println!("   ✓ Message integrity verified!\n");

    // 6. Encrypt with authentication (MAC) - Bob → Alice
    println!("6. Encrypting with MAC authentication (Bob → Alice)...");
    let plaintext2 = b"Reply from Bob with authentication";
    let covered = b"metadata-to-authenticate";

    // Bob encrypts and signs (responder → initiator)
    let (ciphertext2, mac) = session_bob.encrypt_and_sign(plaintext2, covered)?;
    println!("   ✓ Bob encrypted and signed message");
    println!("     MAC: {}", hex::encode(&mac[..16]));

    // Alice decrypts and verifies
    let decrypted2 = session_alice.decrypt_and_verify(&ciphertext2, covered, &mac)?;
    println!("   ✓ Alice decrypted and verified message");
    println!(
        "     Decrypted: {:?}\n",
        String::from_utf8_lossy(&decrypted2)
    );

    // 7. Session statistics
    println!("7. Session statistics...");
    println!("   Total active sessions: {}", manager.session_count());
    println!("   Total key bindings: {}", manager.key_binding_count());

    // Get session by ID
    if let Some(session) = manager.get_session(&sid_alice) {
        println!("   Alice's session status:");
        println!("     - Expired: {}", session.is_expired());
        println!("     - Created: {}", session.get_created_at());
        println!("     - Last used: {}", session.get_last_used_at());
    }
    println!();

    // 8. Remove a session
    println!("8. Removing Charlie's session...");
    let removed = manager.remove_session(&sid_charlie);
    if removed.is_some() {
        println!("   ✓ Session removed");
        println!("   Remaining sessions: {}\n", manager.session_count());
    }

    // 9. Remove key binding
    println!("9. Removing Bob's key binding...");
    manager.remove_key_binding("bob-key-1");
    println!("   ✓ Key binding removed");
    println!(
        "   Remaining key bindings: {}\n",
        manager.key_binding_count()
    );

    // 10. Session cleanup
    println!("10. Cleaning up expired sessions...");
    manager.cleanup_expired();
    println!("    ✓ Cleanup completed");
    println!("    Active sessions: {}\n", manager.session_count());

    println!("=== Session Management example completed successfully! ===");
    Ok(())
}
