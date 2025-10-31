# SAGE Crypto Core - API Usage Guide

**Version**: 0.2.0
**Last Updated**: 2025-10-12

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Transport Layer](#transport-layer)
3. [Session Management](#session-management)
4. [HPKE Handshake](#hpke-handshake)
5. [Error Handling](#error-handling)
6. [Common Pitfalls](#common-pitfalls)
7. [Best Practices](#best-practices)

---

## Quick Start

### Basic Cryptographic Operations

```rust
use sage_crypto_core::{KeyPair, KeyType, Result};
use sage_crypto_core::crypto::{Signer, Verifier};

fn main() -> Result<()> {
    // Generate a key pair
    let keypair = KeyPair::generate(KeyType::Ed25519)?;

    // Sign a message
    let message = b"Hello, SAGE!";
    let signature = keypair.sign(message)?;

    // Verify signature
    keypair.verify(message, &signature)?;

    // Export public key
    let public_bytes = keypair.public_key().to_bytes();

    Ok(())
}
```

### Key Generation Options

```rust
// Ed25519 (recommended for signatures)
let ed25519_key = KeyPair::generate(KeyType::Ed25519)?;

// Secp256k1 (for blockchain compatibility)
let secp256k1_key = KeyPair::generate(KeyType::Secp256k1)?;

// X25519 (for key exchange)
let x25519_key = KeyPair::generate(KeyType::X25519)?;
```

### Key Import/Export

```rust
use sage_crypto_core::formats::{KeyExporter, KeyFormat};

// Export as JWK
let jwk = keypair.public_key().export(KeyFormat::Jwk)?;

// Export as PEM
let pem = keypair.public_key().to_pem()?;

// Export raw bytes
let bytes = keypair.public_key().to_bytes();

// Import from PEM
let imported = KeyPair::from_pem(&pem)?;
```

---

## Transport Layer

### Using MockTransport for Testing

MockTransport is ideal for unit tests and offline development:

```rust
use sage_crypto_core::transport::{MessageTransport, MockTransport, TransportResult};

#[tokio::test]
async fn test_my_service() -> TransportResult<()> {
    // Create mock transport
    let transport = MockTransport::new();

    // Send message
    let response = transport.send(
        "did:sage:bob",
        b"Hello Bob".to_vec()
    ).await?;

    // Verify message was sent
    let sent_messages = transport.get_sent_messages("did:sage:bob");
    assert_eq!(sent_messages.len(), 1);
    assert_eq!(sent_messages[0], b"Hello Bob");

    // Check response
    assert_eq!(response.status, 200);

    Ok(())
}
```

### Custom Response Configuration

```rust
use sage_crypto_core::transport::TransportResponse;

// Configure specific response for destination
let custom_response = TransportResponse::new(
    b"Custom reply".to_vec(),
    201  // Custom status code
);
transport.set_response("did:sage:alice", custom_response);

// Next send to alice will get custom response
let response = transport.send("did:sage:alice", b"Request".to_vec()).await?;
assert_eq!(response.status, 201);
```

### Using HTTP Transport

```rust
use sage_crypto_core::transport::{HttpTransport, TransportConfig};
use std::time::Duration;

// Create HTTP transport with custom config
let config = TransportConfig {
    timeout: Duration::from_secs(30),
    max_retries: 3,
    retry_delay: Duration::from_millis(500),
    ..Default::default()
};

let transport = HttpTransport::with_config(config)?;

// Send to HTTP endpoint
let response = transport.send(
    "https://api.example.com/agent",
    b"Request payload".to_vec()
).await?;
```

### Transport Manager with Multiple Transports

```rust
use sage_crypto_core::transport::{TransportManager, MockTransport, HttpTransport};
use std::sync::Arc;

// Create manager
let manager = TransportManager::new();

// Register multiple transports
manager.register_transport("http", Arc::new(HttpTransport::new()?));
manager.register_transport("mock", Arc::new(MockTransport::new()));

// Set default
manager.set_default_transport("http")?;

// Automatic routing based on destination
let response = manager.send(
    "https://api.example.com/agent",  // Uses HTTP transport
    b"Request".to_vec()
).await?;

let response2 = manager.send(
    "did:sage:alice",  // Uses default transport
    b"Request".to_vec()
).await?;

// Explicit transport selection
let response3 = manager.send_with_transport(
    "mock",
    "did:sage:bob",
    b"Test message".to_vec()
).await?;
```

### Message Envelopes with Metadata

```rust
use sage_crypto_core::transport::TransportMessage;

// Create message with metadata
let message = TransportMessage::new("did:sage:alice", b"Priority alert".to_vec())
    .with_id("msg-12345")
    .with_metadata("priority", "high")
    .with_metadata("type", "alert")
    .with_metadata("timestamp", "2025-10-12T10:00:00Z");

// Send with metadata
let response = transport.send_message(message).await?;

// Access response metadata
println!("Message ID: {:?}", response.message_id);
```

---

## Session Management

### Creating Sessions from HPKE Exporter

After a successful HPKE handshake, both parties have the same exporter secret. Use it to create sessions:

```rust
use sage_crypto_core::session::{SessionManager, SessionManagerConfig, Session};
use std::time::Duration;

// Create session manager
let config = SessionManagerConfig {
    default_ttl: Duration::from_secs(3600),
    cleanup_interval: Duration::from_secs(60),
    max_idle_time: Duration::from_secs(600),
    ..Default::default()
};
let manager = SessionManager::new(config);

// Assume exporter_secret comes from HPKE handshake
let exporter_secret: Vec<u8> = vec![0x42; 32];  // From HPKE

// Alice (initiator) creates session
let (alice_session, session_id, _) = manager
    .ensure_session_from_exporter_with_role(
        &exporter_secret,
        "alice-bob-channel",
        true,  // Alice is initiator
        None
    )?;

// Bob (responder) creates session with SAME exporter
let (bob_session, _, _) = manager
    .ensure_session_from_exporter_with_role(
        &exporter_secret,
        "alice-bob-channel",
        false,  // Bob is responder
        None
    )?;
```

### Bidirectional Encrypted Communication

**Key Concept**: Initiator and responder use different keys automatically based on their role.

```rust
// Alice → Bob (initiator → responder)
let plaintext = b"Hello Bob!";
let ciphertext = alice_session.encrypt(plaintext)?;

// Bob decrypts (responder)
let decrypted = bob_session.decrypt(&ciphertext)?;
assert_eq!(plaintext.as_slice(), decrypted.as_slice());

// Bob → Alice (responder → initiator)
let reply = b"Hello Alice!";
let reply_ciphertext = bob_session.encrypt(reply)?;

// Alice decrypts
let decrypted_reply = alice_session.decrypt(&reply_ciphertext)?;
assert_eq!(reply.as_slice(), decrypted_reply.as_slice());
```

### MAC-Authenticated Encryption

Use `encrypt_and_sign` and `decrypt_and_verify` for authenticated encryption:

```rust
// Bob sends authenticated message to Alice
let plaintext = b"Important message";
let covered_data = b"metadata-to-authenticate";

// Encrypt and sign
let (ciphertext, mac) = bob_session.encrypt_and_sign(plaintext, covered_data)?;

// Alice decrypts and verifies
let decrypted = alice_session.decrypt_and_verify(
    &ciphertext,
    covered_data,
    &mac
)?;

// If MAC verification fails, decrypt_and_verify returns error
```

### Session Lifecycle Management

```rust
// Bind session to key ID for easy retrieval
manager.bind_key_id("alice-key-1", &session_id);

// Retrieve by key ID
if let Some(session) = manager.get_by_key_id("alice-key-1") {
    let ciphertext = session.encrypt(b"Message")?;
}

// Check session status
if let Some(session) = manager.get_session(&session_id) {
    println!("Expired: {}", session.is_expired());
    println!("Created: {}", session.get_created_at());
    println!("Last used: {}", session.get_last_used_at());
}

// Clean up expired sessions
manager.cleanup_expired();

// Remove specific session
manager.remove_session(&session_id);

// Remove key binding
manager.remove_key_binding("alice-key-1");
```

---

## HPKE Handshake

### Complete Handshake Flow

```rust
use sage_crypto_core::hpke::{HpkeClient, HpkeServer};
use sage_crypto_core::did::{DidDocument, DidResolver};

// Client side (Alice initiates to Bob)
let resolver = /* your DID resolver */;
let client = HpkeClient::new(resolver);

let ctx_id = "session-context-123";
let bob_did = "did:sage:bob";

// Step 1: Client initializes handshake
let (payload, eph_secret, exporter_client) =
    client.initialize(ctx_id, bob_did)?;

// Send payload to server...

// Server side (Bob receives from Alice)
let server = HpkeServer::new(server_keypair, None);

// Step 2: Server processes init
let (response, exporter_server) =
    server.process_init(ctx_id, &payload)?;

// Send response back to client...

// Step 3: Client verifies response
let exporter = client.verify_response(
    ctx_id,
    &payload,
    eph_secret,
    exporter_client,
    &response
)?;

// Both sides now have same exporter secret
assert_eq!(*exporter, *exporter_server);

// Step 4: Create sessions from exporter
let (alice_session, _, _) = session_manager
    .ensure_session_from_exporter_with_role(&exporter, ctx_id, true, None)?;
let (bob_session, _, _) = session_manager
    .ensure_session_from_exporter_with_role(&exporter_server, ctx_id, false, None)?;
```

### HPKE Security Properties

```rust
// Forward secrecy: Each handshake uses ephemeral keys
let (payload1, _, _) = client.initialize("ctx-1", "did:sage:bob")?;
let (payload2, _, _) = client.initialize("ctx-2", "did:sage:bob")?;
// payload1.eph_c != payload2.eph_c (different ephemeral keys)

// Replay protection: Each init has unique nonce
// payload1.nonce != payload2.nonce

// Bidirectional authentication: ACK tag verifies both parties
// Server proves it has Bob's private key (decapsulate)
// Client verifies ACK tag (proves server computed correct shared secret)
```

---

## Error Handling

### Error Types

```rust
use sage_crypto_core::{Error, Result};

fn example() -> Result<()> {
    match some_operation() {
        Ok(value) => Ok(value),
        Err(Error::InvalidKey(msg)) => {
            eprintln!("Key error: {}", msg);
            Err(Error::InvalidKey(msg))
        }
        Err(Error::SignatureVerificationFailed) => {
            eprintln!("Signature verification failed");
            Err(Error::SignatureVerificationFailed)
        }
        Err(Error::DidResolutionFailed(did)) => {
            eprintln!("Could not resolve DID: {}", did);
            Err(Error::DidResolutionFailed(did))
        }
        Err(e) => Err(e),
    }
}
```

### Transport Error Handling

```rust
use sage_crypto_core::transport::{TransportError, TransportResult};

async fn send_with_fallback(
    manager: &TransportManager,
    dest: &str,
    payload: Vec<u8>
) -> TransportResult<Vec<u8>> {
    match manager.send(dest, payload.clone()).await {
        Ok(response) => Ok(response.payload),
        Err(TransportError::Timeout) => {
            // Retry with different transport
            manager.send_with_transport("backup", dest, payload).await
                .map(|r| r.payload)
        }
        Err(TransportError::NetworkError(msg)) => {
            eprintln!("Network error: {}", msg);
            Err(TransportError::NetworkError(msg))
        }
        Err(e) => Err(e),
    }
}
```

### Session Error Handling

```rust
use sage_crypto_core::session::Session;

fn handle_session_errors(session: &impl Session, data: &[u8]) -> Result<Vec<u8>> {
    // Check expiration before use
    if session.is_expired() {
        return Err(Error::SessionExpired);
    }

    // Try encryption
    match session.encrypt(data) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(Error::SessionClosed) => {
            eprintln!("Session was closed");
            Err(Error::SessionClosed)
        }
        Err(e) => Err(e),
    }
}
```

---

## Common Pitfalls

### 1. Using Different Exporter Secrets for Initiator and Responder

**Wrong:**
```rust
// ❌ WRONG: Different secrets
let exporter_alice = vec![0x01; 32];
let exporter_bob = vec![0x02; 32];

let (alice_session, _, _) = manager
    .ensure_session_from_exporter_with_role(&exporter_alice, "ctx", true, None)?;
let (bob_session, _, _) = manager
    .ensure_session_from_exporter_with_role(&exporter_bob, "ctx", false, None)?;

// Encryption/decryption will fail!
```

**Correct:**
```rust
// ✅ CORRECT: Same secret, different roles
let shared_exporter = vec![0x42; 32];  // From HPKE handshake

let (alice_session, _, _) = manager
    .ensure_session_from_exporter_with_role(&shared_exporter, "ctx", true, None)?;
let (bob_session, _, _) = manager
    .ensure_session_from_exporter_with_role(&shared_exporter, "ctx", false, None)?;

// Now encryption/decryption works correctly
```

### 2. Forgetting to Verify Signatures

**Wrong:**
```rust
// ❌ WRONG: Not checking verification result
let _ = keypair.verify(message, &signature);
// Continue regardless of verification result
```

**Correct:**
```rust
// ✅ CORRECT: Handle verification result
match keypair.verify(message, &signature) {
    Ok(_) => {
        // Signature is valid, proceed
    }
    Err(Error::SignatureVerificationFailed) => {
        // Signature invalid, reject message
        return Err(Error::SignatureVerificationFailed);
    }
    Err(e) => return Err(e),
}
```

### 3. Not Checking Session Expiration

**Wrong:**
```rust
// ❌ WRONG: Using session without checking
let ciphertext = session.encrypt(data)?;  // May fail if expired
```

**Correct:**
```rust
// ✅ CORRECT: Check before use
if session.is_expired() {
    // Recreate session or return error
    return Err(Error::SessionExpired);
}
let ciphertext = session.encrypt(data)?;
```

### 4. Ignoring Transport Errors

**Wrong:**
```rust
// ❌ WRONG: Assuming send always succeeds
let _ = transport.send(dest, payload).await;
```

**Correct:**
```rust
// ✅ CORRECT: Handle transport errors
match transport.send(dest, payload).await {
    Ok(response) if response.status == 200 => {
        // Success
    }
    Ok(response) => {
        // Non-200 status
        eprintln!("Server returned status: {}", response.status);
    }
    Err(TransportError::Timeout) => {
        // Retry or use fallback
    }
    Err(e) => {
        eprintln!("Transport error: {:?}", e);
    }
}
```

### 5. Reusing Nonces in HPKE

**Wrong:**
```rust
// ❌ WRONG: Fixed nonce
let nonce = "fixed-nonce";
let (payload1, _, _) = client.initialize_with_nonce("ctx", "did", nonce)?;
let (payload2, _, _) = client.initialize_with_nonce("ctx", "did", nonce)?;
// Replay attack possible!
```

**Correct:**
```rust
// ✅ CORRECT: Let HPKE generate unique nonces
let (payload1, _, _) = client.initialize("ctx", "did:sage:bob")?;
let (payload2, _, _) = client.initialize("ctx", "did:sage:bob")?;
// Each has unique nonce
```

---

## Best Practices

### 1. Key Management

```rust
// Store keys securely
use sage_crypto_core::formats::KeyExporter;

// Export only public keys for distribution
let public_pem = keypair.public_key().to_pem()?;
store_public_key(&public_pem)?;

// Keep private keys in memory only
// Use Zeroizing types to clear memory on drop
use zeroize::Zeroizing;
let private_bytes = Zeroizing::new(keypair.to_bytes());
```

### 2. Session Cleanup

```rust
// Enable automatic cleanup
let config = SessionManagerConfig {
    cleanup_interval: Duration::from_secs(60),
    ..Default::default()
};
let manager = SessionManager::new(config);

// Or manual cleanup periodically
tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        manager.cleanup_expired();
    }
});
```

### 3. Transport Configuration

```rust
// Configure appropriate timeouts
let config = TransportConfig {
    timeout: Duration::from_secs(30),  // Match your network conditions
    max_retries: 3,                    // Balance reliability vs latency
    retry_delay: Duration::from_millis(500),
    ..Default::default()
};

// Use MockTransport in tests
#[cfg(test)]
use sage_crypto_core::transport::MockTransport;

#[cfg(not(test))]
use sage_crypto_core::transport::HttpTransport;
```

### 4. Error Propagation

```rust
// Use ? operator for cleaner code
fn process_message(keypair: &KeyPair, message: &[u8]) -> Result<Vec<u8>> {
    let signature = keypair.sign(message)?;
    keypair.verify(message, &signature)?;
    Ok(signature.to_bytes())
}
```

### 5. Type Safety

```rust
// Use type system to prevent errors
use sage_crypto_core::KeyType;

fn sign_with_ed25519(message: &[u8]) -> Result<Vec<u8>> {
    let keypair = KeyPair::generate(KeyType::Ed25519)?;
    let signature = keypair.sign(message)?;
    Ok(signature.to_bytes())
}

// Compiler ensures we use correct key type
```

### 6. Testing with MockTransport

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sage_crypto_core::transport::MockTransport;

    #[tokio::test]
    async fn test_send_message() {
        let transport = MockTransport::new();

        // Configure expected response
        let expected_response = TransportResponse::new(b"OK".to_vec(), 200);
        transport.set_response("did:sage:alice", expected_response);

        // Test your service
        let result = my_service(&transport, "did:sage:alice", b"Test").await;

        // Verify interactions
        assert!(result.is_ok());
        assert_eq!(transport.count_sent_messages("did:sage:alice"), 1);
    }
}
```

### 7. DID Resolution Caching

```rust
// Cache DID documents to reduce lookups
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

struct CachedResolver {
    cache: Arc<RwLock<HashMap<String, DidDocument>>>,
    resolver: Arc<dyn DidResolver>,
}

impl DidResolver for CachedResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument> {
        // Check cache first
        if let Some(doc) = self.cache.read().unwrap().get(did) {
            return Ok(doc.clone());
        }

        // Resolve and cache
        let doc = self.resolver.resolve(did)?;
        self.cache.write().unwrap().insert(did.to_string(), doc.clone());
        Ok(doc)
    }
}
```

---

## Additional Resources

- **API Documentation**: Run `cargo doc --open` for full API docs
- **Examples**: See `examples/` directory for working code
- **Phase 4 Documentation**: `docs/phase4_completion.md` - HPKE, Handshake, Session details
- **Phase 5 Documentation**: `docs/phase5_completion.md` - Transport Layer, Integration Tests
- **RFC 9180**: HPKE specification - https://www.rfc-editor.org/rfc/rfc9180.html
- **RFC 9421**: HTTP Message Signatures - https://www.rfc-editor.org/rfc/rfc9421.html

---

**Questions or Issues?**

- GitHub: https://github.com/sage-x-project/rs-sage-core
- Documentation: See `docs/` directory

