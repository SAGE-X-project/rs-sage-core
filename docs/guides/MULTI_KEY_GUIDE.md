# Multi-Key Management Guide

## Overview

The Multi-Key Management module provides support for agents to manage multiple cryptographic keys across different protocols and key types.

**Features:**
- Support up to 10 keys per agent
- Protocol-specific key selection (Ethereum, Solana)
- Multiple key types (Ed25519, Secp256k1, P256)
- Flexible key storage and retrieval
- Thread-safe operations

**Status:** ✅ Production Ready (v0.3.0)

---

## Quick Start

### 1. Setup

Add the core library to your `Cargo.toml`:

```toml
[dependencies]
sage_crypto_core = { version = "0.3" }
```

### 2. Create Multi-Key Manager

```rust
use sage_crypto_core::crypto::{MultiKeyManager, Protocol, KeyType, KeyPair};
use sage_crypto_core::storage::MemoryKeyStorage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create storage backend
    let storage = MemoryKeyStorage::new();

    // Create multi-key manager
    let manager = MultiKeyManager::new(storage);

    println!("Multi-key manager ready");
    Ok(())
}
```

### 3. Add Keys for an Agent

```rust
let agent_id = "agent-123";

// Generate Ed25519 key for Solana
let ed25519_key = KeyPair::generate(KeyType::Ed25519)?;
let key_id_1 = manager.add_key(agent_id, &ed25519_key)?;
println!("Added Ed25519 key: {}", key_id_1);

// Generate Secp256k1 key for Ethereum
let secp256k1_key = KeyPair::generate(KeyType::Secp256k1)?;
let key_id_2 = manager.add_key(agent_id, &secp256k1_key)?;
println!("Added Secp256k1 key: {}", key_id_2);

// Check total keys
let count = manager.count_keys(agent_id)?;
println!("Total keys: {}", count);
```

### 4. Get Protocol-Specific Key

```rust
// Get key for Ethereum (prefers Secp256k1 or P256)
if let Some(eth_key) = manager.get_protocol_key(agent_id, Protocol::Ethereum)? {
    println!("Ethereum key type: {:?}", eth_key.key_type());
}

// Get key for Solana (prefers Ed25519)
if let Some(sol_key) = manager.get_protocol_key(agent_id, Protocol::Solana)? {
    println!("Solana key type: {:?}", sol_key.key_type());
}
```

---

## API Reference

### MultiKeyManager

Main interface for managing multiple keys per agent.

```rust
// Create manager
let manager = MultiKeyManager::new(storage);

// Add key (returns storage ID)
let key_id = manager.add_key(agent_id, &keypair)?;

// Get all keys for an agent
let all_keys = manager.get_all_keys(agent_id)?;

// Get keys by type
let ed25519_keys = manager.get_keys_by_type(agent_id, KeyType::Ed25519)?;

// Get protocol-specific key
let key = manager.get_protocol_key(agent_id, Protocol::Ethereum)?;

// Remove specific key
manager.remove_key(&key_id)?;

// Remove all keys for an agent
manager.remove_all_keys(agent_id)?;

// Count keys
let count = manager.count_keys(agent_id)?;

// Check if agent has any keys
let has_keys = manager.has_keys(agent_id)?;
```

### Protocol Enum

Protocol-specific key preferences:

```rust
pub enum Protocol {
    /// Ethereum-compatible chains (prefers Secp256k1, then P256)
    Ethereum,

    /// Solana (prefers Ed25519)
    Solana,
}
```

### Key Limits

```rust
pub const MAX_KEYS_PER_AGENT: usize = 10;
```

---

## Examples

### Example 1: Multi-Protocol Agent Setup

```rust
use sage_crypto_core::crypto::{
    MultiKeyManager, Protocol, KeyType, KeyPair,
};
use sage_crypto_core::storage::MemoryKeyStorage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryKeyStorage::new();
    let manager = MultiKeyManager::new(storage);

    let agent_id = "multi-protocol-agent";

    // Add Ed25519 for Solana
    let ed25519 = KeyPair::generate(KeyType::Ed25519)?;
    manager.add_key(agent_id, &ed25519)?;

    // Add Secp256k1 for Ethereum
    let secp256k1 = KeyPair::generate(KeyType::Secp256k1)?;
    manager.add_key(agent_id, &secp256k1)?;

    // Add P256 as fallback
    let p256 = KeyPair::generate(KeyType::P256)?;
    manager.add_key(agent_id, &p256)?;

    // Protocol-specific retrieval
    let sol_key = manager
        .get_protocol_key(agent_id, Protocol::Solana)?
        .expect("Should have Solana key");
    assert_eq!(sol_key.key_type(), KeyType::Ed25519);

    let eth_key = manager
        .get_protocol_key(agent_id, Protocol::Ethereum)?
        .expect("Should have Ethereum key");
    assert_eq!(eth_key.key_type(), KeyType::Secp256k1);

    println!("✅ Multi-protocol agent configured");
    Ok(())
}
```

### Example 2: Key Type Filtering

```rust
use sage_crypto_core::crypto::{MultiKeyManager, KeyType, KeyPair};
use sage_crypto_core::storage::MemoryKeyStorage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryKeyStorage::new();
    let manager = MultiKeyManager::new(storage);

    let agent_id = "agent-with-multiple-keys";

    // Add multiple keys of different types
    for _ in 0..3 {
        manager.add_key(agent_id, &KeyPair::generate(KeyType::Ed25519)?)?;
    }
    for _ in 0..2 {
        manager.add_key(agent_id, &KeyPair::generate(KeyType::Secp256k1)?)?;
    }

    // Filter by type
    let ed25519_keys = manager.get_keys_by_type(agent_id, KeyType::Ed25519)?;
    let secp256k1_keys = manager.get_keys_by_type(agent_id, KeyType::Secp256k1)?;

    println!("Ed25519 keys: {}", ed25519_keys.len());
    println!("Secp256k1 keys: {}", secp256k1_keys.len());

    assert_eq!(ed25519_keys.len(), 3);
    assert_eq!(secp256k1_keys.len(), 2);

    Ok(())
}
```

### Example 3: Key Limit Enforcement

```rust
use sage_crypto_core::crypto::{MultiKeyManager, KeyType, KeyPair, MAX_KEYS_PER_AGENT};
use sage_crypto_core::storage::MemoryKeyStorage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryKeyStorage::new();
    let manager = MultiKeyManager::new(storage);

    let agent_id = "agent-max-keys";

    // Add maximum number of keys
    for i in 0..MAX_KEYS_PER_AGENT {
        let key = KeyPair::generate(KeyType::Ed25519)?;
        manager.add_key(agent_id, &key)?;
        println!("Added key {}/{}", i + 1, MAX_KEYS_PER_AGENT);
    }

    // Attempting to add one more should fail
    let extra_key = KeyPair::generate(KeyType::Ed25519)?;
    match manager.add_key(agent_id, &extra_key) {
        Ok(_) => panic!("Should have failed"),
        Err(e) => {
            println!("✅ Correctly rejected: {}", e);
            assert!(e.to_string().contains("maximum"));
        }
    }

    Ok(())
}
```

### Example 4: Key Rotation with Multi-Key

```rust
use sage_crypto_core::crypto::{
    MultiKeyManager, DefaultKeyRotator, KeyRotationConfig,
    KeyType, KeyPair, Protocol,
};
use sage_crypto_core::storage::MemoryKeyStorage;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryKeyStorage::new();
    let manager = MultiKeyManager::new(storage.clone());

    let agent_id = "rotating-agent";

    // Add initial Ethereum key
    let initial_key = KeyPair::generate(KeyType::Secp256k1)?;
    let old_key_id = manager.add_key(agent_id, &initial_key)?;

    // Setup key rotator
    let config = KeyRotationConfig {
        rotation_interval: Duration::from_secs(86400), // 24 hours
        overlap_period: Duration::from_secs(3600),     // 1 hour
        key_type: KeyType::Secp256k1,
    };

    let rotator = DefaultKeyRotator::new(storage, config);

    // Perform rotation
    let rotation = rotator.rotate_key(agent_id)?;

    // Add new rotated key
    let new_key_id = manager.add_key(agent_id, &rotation.new_key)?;

    println!("Rotated from {} to {}", old_key_id, new_key_id);

    // During overlap period, both keys are valid
    let all_keys = manager.get_all_keys(agent_id)?;
    assert_eq!(all_keys.len(), 2);

    // After overlap, remove old key
    manager.remove_key(&old_key_id)?;

    println!("✅ Key rotation completed");
    Ok(())
}
```

### Example 5: File-Based Persistent Storage

```rust
use sage_crypto_core::crypto::{MultiKeyManager, KeyType, KeyPair};
use sage_crypto_core::storage::FileKeyStorage;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create file-based storage
    let storage_path = Path::new("./agent_keys");
    let storage = FileKeyStorage::new(storage_path)?;

    let manager = MultiKeyManager::new(storage);

    let agent_id = "persistent-agent";

    // Add keys
    manager.add_key(agent_id, &KeyPair::generate(KeyType::Ed25519)?)?;
    manager.add_key(agent_id, &KeyPair::generate(KeyType::Secp256k1)?)?;

    println!("Keys stored in: {:?}", storage_path);

    // Keys are persisted to disk:
    // ./agent_keys/persistent-agent/key/0
    // ./agent_keys/persistent-agent/key/1

    Ok(())
}
```

---

## Best Practices

### 1. Protocol-Specific Keys

Always use protocol-specific key selection for cross-chain operations:

```rust
// ✅ Good: Protocol-aware
let key = manager.get_protocol_key(agent_id, Protocol::Ethereum)?;

// ❌ Bad: Manually filtering types
let all_keys = manager.get_all_keys(agent_id)?;
let secp_keys: Vec<_> = all_keys.into_iter()
    .filter(|k| k.key_type() == KeyType::Secp256k1)
    .collect();
```

### 2. Key Limit Management

Always check key count before adding new keys:

```rust
// ✅ Good: Check before adding
if manager.count_keys(agent_id)? < MAX_KEYS_PER_AGENT {
    manager.add_key(agent_id, &new_key)?;
} else {
    // Handle limit reached
}

// ❌ Bad: Add without checking
manager.add_key(agent_id, &new_key)?; // May fail
```

### 3. Graceful Fallback

Handle missing protocol keys gracefully:

```rust
// ✅ Good: Handle missing keys
match manager.get_protocol_key(agent_id, Protocol::Ethereum)? {
    Some(key) => {
        // Use key
    }
    None => {
        // Generate and add new key
        let new_key = KeyPair::generate(KeyType::Secp256k1)?;
        manager.add_key(agent_id, &new_key)?;
    }
}
```

### 4. Storage Backend Selection

Choose the right storage backend:

```rust
// Development/Testing: MemoryKeyStorage
let dev_storage = MemoryKeyStorage::new();

// Production: FileKeyStorage (persistent)
let prod_storage = FileKeyStorage::new("./secure/keys")?;

// Custom: Implement KeyStorage trait for database, HSM, etc.
```

### 5. Key Organization

Use consistent agent IDs:

```rust
// ✅ Good: Hierarchical IDs
let agent_id = "org:team:agent-name";
manager.add_key(agent_id, &key)?;

// ✅ Good: DID-based IDs
let agent_id = "did:sage:ethereum:0x1234...";
manager.add_key(agent_id, &key)?;

// ❌ Bad: Random/inconsistent IDs
let agent_id = uuid::Uuid::new_v4().to_string();
```

---

## Architecture

### Storage Hierarchy

```
Storage Root
└── {agent_id}/
    └── key/
        ├── 0  (First key)
        ├── 1  (Second key)
        ├── 2  (Third key)
        └── ...
```

### Protocol Key Selection Logic

```
┌─────────────────────────────┐
│  get_protocol_key()         │
└──────────┬──────────────────┘
           │
           v
    ┌──────────────┐
    │  Protocol?   │
    └──────┬───────┘
           │
    ┌──────┴──────┐
    │             │
    v             v
Ethereum      Solana
    │             │
    v             v
1. Secp256k1  1. Ed25519
2. P256       2. (none)
3. (none)
```

### Thread Safety

MultiKeyManager uses Arc-wrapped storage for thread-safe operations:

```rust
use std::sync::Arc;
use std::thread;

let storage = Arc::new(MemoryKeyStorage::new());
let manager1 = MultiKeyManager::new(storage.clone());
let manager2 = MultiKeyManager::new(storage.clone());

// Both managers share the same storage
thread::spawn(move || {
    manager1.add_key("agent-1", &key1)?;
});

thread::spawn(move || {
    manager2.add_key("agent-2", &key2)?;
});
```

---

## Integration Examples

### With Ethereum Client

```rust
use sage_crypto_core::crypto::{MultiKeyManager, Protocol};
use sage_crypto_core::blockchain::{EthereumClient, EthereumResolver};

async fn ethereum_example() -> Result<(), Box<dyn std::error::Error>> {
    let manager = MultiKeyManager::new(storage);
    let agent_id = "did:sage:ethereum:0x1234...";

    // Get Ethereum-compatible key
    let key = manager
        .get_protocol_key(agent_id, Protocol::Ethereum)?
        .expect("Need Ethereum key");

    // Use with Ethereum client
    let client = EthereumClient::new(rpc_url, registry_address).await?;
    let resolver = EthereumResolver::new(client);

    // Resolve agent
    let agent = resolver.resolve_agent(agent_id).await?;
    println!("Agent: {}", agent.name);

    Ok(())
}
```

### With Key Rotation

```rust
use sage_crypto_core::crypto::{
    MultiKeyManager, DefaultKeyRotator, KeyRotationConfig,
    KeyType,
};
use std::time::Duration;

fn rotation_example() -> Result<(), Box<dyn std::error::Error>> {
    let storage = MemoryKeyStorage::new();
    let manager = MultiKeyManager::new(storage.clone());

    let agent_id = "agent-rotate";

    // Setup rotation
    let config = KeyRotationConfig {
        rotation_interval: Duration::from_secs(86400),
        overlap_period: Duration::from_secs(3600),
        key_type: KeyType::Secp256k1,
    };

    let rotator = DefaultKeyRotator::new(storage, config);

    // Rotate and update multi-key manager
    let rotation = rotator.rotate_key(agent_id)?;
    manager.add_key(agent_id, &rotation.new_key)?;

    println!("Rotation complete, {} keys active", manager.count_keys(agent_id)?);

    Ok(())
}
```

---

## Troubleshooting

### "Agent already has maximum 10 keys"

**Problem:** Attempting to add more than MAX_KEYS_PER_AGENT keys

**Solution:**
```rust
// Remove unused keys first
let all_keys = manager.get_all_keys(agent_id)?;
if all_keys.len() >= MAX_KEYS_PER_AGENT {
    // Remove oldest or unused key
    let old_key_id = format!("{}/key/0", agent_id);
    manager.remove_key(&old_key_id)?;
}

// Now add new key
manager.add_key(agent_id, &new_key)?;
```

### "No suitable key found for protocol"

**Problem:** Agent doesn't have a compatible key for the requested protocol

**Solution:**
```rust
// Check and add if missing
if manager.get_protocol_key(agent_id, Protocol::Ethereum)?.is_none() {
    // Add Ethereum-compatible key
    let eth_key = KeyPair::generate(KeyType::Secp256k1)?;
    manager.add_key(agent_id, &eth_key)?;
}
```

### Storage errors

**Problem:** File I/O errors with FileKeyStorage

**Solution:**
```rust
use sage_crypto_core::storage::FileKeyStorage;
use std::fs;

// Ensure directory exists and has correct permissions
let storage_path = "./agent_keys";
fs::create_dir_all(storage_path)?;

#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(storage_path)?.permissions();
    perms.set_mode(0o700); // Owner only
    fs::set_permissions(storage_path, perms)?;
}

let storage = FileKeyStorage::new(storage_path)?;
```

---

## Performance Considerations

### Memory Usage

- MemoryKeyStorage: O(n) where n = total keys across all agents
- FileKeyStorage: O(1) memory, reads from disk as needed

### Operation Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `add_key()` | O(n) | n = keys for agent (max 10) |
| `get_all_keys()` | O(n) | n = keys for agent |
| `get_protocol_key()` | O(n) | n = keys for agent |
| `remove_key()` | O(1) | Direct storage access |
| `count_keys()` | O(n) | Iterates storage paths |

### Caching Recommendations

For frequent lookups, implement caching:

```rust
use dashmap::DashMap;
use std::sync::Arc;

struct CachedMultiKeyManager {
    manager: MultiKeyManager,
    cache: Arc<DashMap<String, Vec<KeyPair>>>,
}

impl CachedMultiKeyManager {
    fn get_all_keys_cached(&self, agent_id: &str) -> Result<Vec<KeyPair>> {
        if let Some(keys) = self.cache.get(agent_id) {
            return Ok(keys.clone());
        }

        let keys = self.manager.get_all_keys(agent_id)?;
        self.cache.insert(agent_id.to_string(), keys.clone());
        Ok(keys)
    }
}
```

---

## Security Considerations

### Key Storage

1. **File Permissions**: Set restrictive permissions (0600/0700)
2. **Encryption**: Consider encrypting keys at rest
3. **Access Control**: Implement agent-level access controls

### Key Lifecycle

1. **Generation**: Use cryptographically secure random generators
2. **Rotation**: Implement regular key rotation policies
3. **Deletion**: Securely wipe keys from memory/disk

### Protocol Selection

1. **Ethereum**: Secp256k1 is standard, P256 is fallback
2. **Solana**: Ed25519 only
3. **Future Protocols**: Extend Protocol enum as needed

---

## Related Documentation

- [Key Rotation Guide](KEY_ROTATION_GUIDE.md)
- [Ethereum Integration](ethereum_integration.md)
- [API Usage Guide](api_usage_guide.md)
- [Blockchain Types](blockchain_integration.md)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Source Code**: `rs-sage-core/src/crypto/multi_key.rs`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-27
**Status**: Production Ready
