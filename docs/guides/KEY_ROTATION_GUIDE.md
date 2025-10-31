# Key Rotation Guide

## Overview

The Key Rotation Infrastructure provides automated and manual cryptographic key rotation capabilities for SAGE Crypto Core. This guide covers the configuration, usage, and best practices for implementing secure key rotation in your applications.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Manual Rotation](#manual-rotation)
- [Automatic Rotation](#automatic-rotation)
- [Rotation History](#rotation-history)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Features

- **Manual Key Rotation**: Rotate keys on-demand with atomic operations
- **Automatic Key Rotation**: Background task that monitors and rotates keys based on configurable policies
- **Rotation History**: Track all rotation events with timestamps and reasons
- **Key Retention Policies**: Configurable archival or deletion of old keys
- **Thread-Safe Operations**: Concurrent-safe with DashMap and Arc
- **Multiple Key Types**: Support for Ed25519, Secp256k1, and P-256
- **Monitoring**: Add/remove keys from auto-rotation monitoring

## Quick Start

```rust
use sage_crypto_core::crypto::{
    KeyPair, KeyType,
    storage::MemoryKeyStorage,
    rotation::{DefaultKeyRotator, KeyRotationConfig},
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create storage backend
    let storage = Arc::new(MemoryKeyStorage::new());

    // 2. Generate and store initial key
    let key = KeyPair::generate(KeyType::Ed25519)?;
    storage.store("signing-key", &key)?;

    // 3. Create rotator with custom config
    let config = KeyRotationConfig {
        rotation_interval: Duration::from_secs(86400 * 30), // 30 days
        max_key_age: Duration::from_secs(86400 * 90),       // 90 days
        keep_old_keys: true,
    };
    let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

    // 4. Perform manual rotation
    let new_key = rotator.rotate("signing-key")?;
    println!("Rotated to new key: {}", new_key.key_id());

    Ok(())
}
```

## Configuration

### KeyRotationConfig

The `KeyRotationConfig` struct defines the rotation policy:

```rust
pub struct KeyRotationConfig {
    /// Time interval between automatic rotations
    pub rotation_interval: Duration,

    /// Maximum age a key can reach before forced rotation
    pub max_key_age: Duration,

    /// Whether to archive old keys after rotation
    pub keep_old_keys: bool,
}
```

### Default Configuration

```rust
KeyRotationConfig {
    rotation_interval: Duration::from_secs(86400 * 30), // 30 days
    max_key_age: Duration::from_secs(86400 * 90),       // 90 days
    keep_old_keys: true,
}
```

### Configuration Examples

#### High Security (Frequent Rotation)

```rust
let config = KeyRotationConfig {
    rotation_interval: Duration::from_secs(86400 * 7),  // 7 days
    max_key_age: Duration::from_secs(86400 * 14),       // 14 days
    keep_old_keys: true,
};
```

#### Moderate Security (Standard Rotation)

```rust
let config = KeyRotationConfig {
    rotation_interval: Duration::from_secs(86400 * 30), // 30 days
    max_key_age: Duration::from_secs(86400 * 90),       // 90 days
    keep_old_keys: true,
};
```

#### Low Frequency (Long-lived Keys)

```rust
let config = KeyRotationConfig {
    rotation_interval: Duration::from_secs(86400 * 90), // 90 days
    max_key_age: Duration::from_secs(86400 * 180),      // 180 days
    keep_old_keys: false, // Don't keep old keys
};
```

## Manual Rotation

Manual rotation allows you to rotate keys on-demand.

### Basic Usage

```rust
use sage_crypto_core::crypto::rotation::KeyRotator;

// Rotate a key
let new_key = rotator.rotate("my-key-id")?;

// The new key is now stored at "my-key-id"
// The old key is archived (if keep_old_keys is true)
println!("New key ID: {}", new_key.key_id());
```

### Atomic Operations

Key rotation is atomic - either the entire operation succeeds or it fails without modifying storage:

1. Load existing key
2. Generate new key of same type
3. Store new key (overwrites old key)
4. Archive old key (if `keep_old_keys` is true)
5. Record rotation event in history

If any step fails, the operation is rolled back.

### Error Handling

```rust
use sage_crypto_core::error::Error;

match rotator.rotate("my-key-id") {
    Ok(new_key) => {
        println!("Rotation successful: {}", new_key.key_id());
    },
    Err(Error::NotFound(msg)) => {
        eprintln!("Key not found: {}", msg);
    },
    Err(Error::StorageError(msg)) => {
        eprintln!("Storage error: {}", msg);
    },
    Err(e) => {
        eprintln!("Rotation failed: {}", e);
    }
}
```

## Automatic Rotation

Automatic rotation runs a background task that periodically checks monitored keys and rotates them when needed.

### Setting Up Auto-Rotation

```rust
use sage_crypto_core::crypto::rotation::DefaultKeyRotator;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rotator = DefaultKeyRotator::new(storage);

    // Add keys to monitor
    rotator.add_monitored_key("signing-key");
    rotator.add_monitored_key("encryption-key");
    rotator.add_monitored_key("backup-key");

    // Start auto-rotation
    rotator.start_auto_rotation().await?;

    println!("Auto-rotation started");

    // Your application runs...
    // Keys will be rotated automatically based on config

    // Stop when shutting down
    rotator.stop_auto_rotation().await?;

    Ok(())
}
```

### Monitoring Keys

```rust
// Add a key to monitoring
rotator.add_monitored_key("api-key");

// Remove a key from monitoring
rotator.remove_monitored_key("old-api-key");

// Check if auto-rotation is running
if rotator.is_auto_rotation_running() {
    println!("Auto-rotation is active");
}
```

### How Auto-Rotation Works

1. Background task checks monitored keys every `rotation_interval / 10`
2. For each key, checks if rotation is needed:
   - Age >= `rotation_interval`, OR
   - Age >= `max_key_age`
3. If rotation is needed:
   - Loads the key
   - Generates new key of same type
   - Stores new key
   - Archives old key (if configured)
   - Records rotation event with reason "auto"

### Graceful Shutdown

```rust
// Stop auto-rotation gracefully
rotator.stop_auto_rotation().await?;

// The background task will:
// 1. Complete current checks
// 2. Exit the loop
// 3. Clean up resources
```

## Rotation History

Track all rotation events for audit and compliance purposes.

### Viewing History

```rust
// Get rotation history for a key
let history = rotator.get_rotation_history("signing-key")?;

for event in history {
    println!("Timestamp: {}", event.timestamp);
    println!("  Old key: {}", event.old_key_id);
    println!("  New key: {}", event.new_key_id);
    println!("  Reason: {}", event.reason);
}
```

### Last Rotation Time

```rust
// Get the last rotation timestamp
let last_time = rotator.get_last_rotation_time("signing-key")?;

match last_time {
    Some(timestamp) => {
        println!("Last rotated: {}", timestamp);

        let age = Utc::now().signed_duration_since(timestamp);
        println!("Age: {} days", age.num_days());
    },
    None => {
        println!("Key has never been rotated");
    }
}
```

### Checking Rotation Status

```rust
// Check if a key needs rotation
let needs_rotation = rotator.needs_rotation("signing-key")?;

if needs_rotation {
    println!("Key should be rotated");
    rotator.rotate("signing-key")?;
}
```

## Best Practices

### 1. Choose Appropriate Rotation Intervals

- **High Security Systems**: 7-14 day intervals
- **Standard Applications**: 30-90 day intervals
- **Low Risk Systems**: 90-180 day intervals

Consider:
- Regulatory requirements (PCI DSS, HIPAA, etc.)
- Threat model and risk assessment
- Operational overhead
- Key usage patterns

### 2. Archive Old Keys

Always set `keep_old_keys: true` unless you have a specific reason not to:

```rust
let config = KeyRotationConfig {
    rotation_interval: Duration::from_secs(86400 * 30),
    max_key_age: Duration::from_secs(86400 * 90),
    keep_old_keys: true,  // Enable archival
};
```

**Benefits:**
- Verify old signatures
- Decrypt old data
- Audit trail
- Incident response

**Archived Key Naming:**
```
original-key-id.old.1698765432
```

### 3. Monitor Rotation Events

Implement monitoring and alerting:

```rust
// Check rotation history regularly
let history = rotator.get_rotation_history("critical-key")?;
if history.is_empty() {
    log::warn!("Key has never been rotated!");
}

// Log rotation events
for event in history {
    if event.reason == "manual" {
        log::info!("Manual rotation at {}: {} -> {}",
                   event.timestamp, event.old_key_id, event.new_key_id);
    }
}
```

### 4. Use Auto-Rotation for Production

Manual rotation is error-prone. Use auto-rotation:

```rust
// Add all critical keys to monitoring
for key_id in ["signing-key", "encryption-key", "backup-key"] {
    rotator.add_monitored_key(key_id);
}

rotator.start_auto_rotation().await?;
```

### 5. Handle Rotation During Operations

Design your application to handle rotation gracefully:

```rust
// Example: Retry with new key if signature verification fails
fn verify_with_rotation(
    message: &[u8],
    signature: &[u8],
    key_id: &str,
    rotator: &DefaultKeyRotator,
    storage: &dyn KeyStorage,
) -> Result<bool> {
    // Try current key
    let key = storage.load(key_id)?;
    if verify_signature(message, signature, &key) {
        return Ok(true);
    }

    // Try archived keys
    let history = rotator.get_rotation_history(key_id)?;
    for event in history.iter().rev() {
        let archived_id = format!("{}.old.{}",
                                  key_id,
                                  event.timestamp.timestamp());
        if let Ok(old_key) = storage.load(&archived_id) {
            if verify_signature(message, signature, &old_key) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}
```

### 6. Test Rotation in Staging

Always test rotation in a staging environment:

```rust
#[tokio::test]
async fn test_rotation_workflow() {
    let storage = Arc::new(MemoryKeyStorage::new());
    let config = KeyRotationConfig {
        rotation_interval: Duration::from_secs(1),
        max_key_age: Duration::from_secs(2),
        keep_old_keys: true,
    };
    let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

    // Generate initial key
    let key = KeyPair::generate(KeyType::Ed25519).unwrap();
    storage.store("test-key", &key).unwrap();

    // Rotate
    let new_key = rotator.rotate("test-key").unwrap();
    assert_ne!(key.key_id(), new_key.key_id());

    // Verify history
    let history = rotator.get_rotation_history("test-key").unwrap();
    assert_eq!(history.len(), 1);
}
```

### 7. Secure Storage Backend

Use appropriate storage for production:

```rust
// For production, use FileKeyStorage with proper permissions
use sage_crypto_core::crypto::storage::FileKeyStorage;

let storage = Arc::new(FileKeyStorage::new("/secure/keys")?);

// Ensure directory has restricted permissions:
// chmod 700 /secure/keys
// chown app-user:app-group /secure/keys
```

### 8. Update Key References

After rotation, update references in:
- DID Documents
- API configurations
- Service registrations
- Client configurations

Example for DID updates:

```rust
async fn rotate_and_update_did(
    key_id: &str,
    rotator: &DefaultKeyRotator,
    did_service: &mut DIDService,
) -> Result<()> {
    // Rotate the key
    let new_key = rotator.rotate(key_id)?;

    // Update DID document
    did_service.update_verification_method(
        key_id,
        &new_key.public_key().to_string(),
    ).await?;

    // Publish updated DID
    did_service.publish().await?;

    Ok(())
}
```

## API Reference

### KeyRotator Trait

```rust
pub trait KeyRotator: Send + Sync {
    /// Rotate a key, generating a new key of the same type
    fn rotate(&self, id: &str) -> Result<KeyPair>;

    /// Update the rotation configuration
    fn set_rotation_config(&mut self, config: KeyRotationConfig);

    /// Get the current rotation configuration
    fn get_rotation_config(&self) -> KeyRotationConfig;

    /// Get the rotation history for a key
    fn get_rotation_history(&self, id: &str) -> Result<Vec<KeyRotationEvent>>;

    /// Get the last rotation time for a key
    fn get_last_rotation_time(&self, id: &str) -> Result<Option<DateTime<Utc>>>;

    /// Check if a key needs rotation
    fn needs_rotation(&self, id: &str) -> Result<bool>;
}
```

### DefaultKeyRotator

```rust
impl DefaultKeyRotator {
    /// Create a new rotator with default config
    pub fn new(storage: Arc<dyn KeyStorage>) -> Self;

    /// Create a new rotator with custom config
    pub fn with_config(
        storage: Arc<dyn KeyStorage>,
        config: KeyRotationConfig
    ) -> Self;

    /// Add a key to auto-rotation monitoring
    pub fn add_monitored_key(&self, key_id: &str);

    /// Remove a key from auto-rotation monitoring
    pub fn remove_monitored_key(&self, key_id: &str);

    /// Start automatic key rotation
    pub async fn start_auto_rotation(&self) -> Result<()>;

    /// Stop automatic key rotation
    pub async fn stop_auto_rotation(&self) -> Result<()>;

    /// Check if auto-rotation is running
    pub fn is_auto_rotation_running(&self) -> bool;
}
```

### KeyRotationEvent

```rust
pub struct KeyRotationEvent {
    /// When the rotation occurred
    pub timestamp: DateTime<Utc>,

    /// ID of the key that was rotated out
    pub old_key_id: String,

    /// ID of the new key
    pub new_key_id: String,

    /// Reason for rotation
    pub reason: String,
}
```

## Examples

### Example 1: Simple Manual Rotation

```rust
use sage_crypto_core::crypto::{
    KeyPair, KeyType,
    storage::MemoryKeyStorage,
    rotation::DefaultKeyRotator,
};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let storage = Arc::new(MemoryKeyStorage::new());
    let rotator = DefaultKeyRotator::new(storage.clone());

    // Create initial key
    let key = KeyPair::generate(KeyType::Ed25519)?;
    storage.store("my-key", &key)?;
    println!("Initial key: {}", key.key_id());

    // Rotate
    let new_key = rotator.rotate("my-key")?;
    println!("New key: {}", new_key.key_id());

    // View history
    let history = rotator.get_rotation_history("my-key")?;
    println!("Rotation history: {} events", history.len());

    Ok(())
}
```

### Example 2: Auto-Rotation with Monitoring

```rust
use sage_crypto_core::crypto::rotation::{DefaultKeyRotator, KeyRotationConfig};
use std::time::Duration;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup with short intervals for demo
    let storage = Arc::new(MemoryKeyStorage::new());
    let config = KeyRotationConfig {
        rotation_interval: Duration::from_secs(60),  // 1 minute
        max_key_age: Duration::from_secs(300),       // 5 minutes
        keep_old_keys: true,
    };
    let rotator = DefaultKeyRotator::with_config(storage.clone(), config);

    // Create and monitor keys
    for i in 0..3 {
        let key_id = format!("key-{}", i);
        let key = KeyPair::generate(KeyType::Ed25519)?;
        storage.store(&key_id, &key)?;
        rotator.add_monitored_key(&key_id);

        // Initial rotation to establish history
        rotator.rotate(&key_id)?;
    }

    // Start auto-rotation
    rotator.start_auto_rotation().await?;
    println!("Auto-rotation started, monitoring 3 keys");

    // Run for 5 minutes
    tokio::time::sleep(Duration::from_secs(300)).await;

    // Stop and report
    rotator.stop_auto_rotation().await?;

    for i in 0..3 {
        let key_id = format!("key-{}", i);
        let history = rotator.get_rotation_history(&key_id)?;
        println!("{}: {} rotations", key_id, history.len());
    }

    Ok(())
}
```

### Example 3: Multi-Key Type Rotation

```rust
use sage_crypto_core::crypto::{KeyPair, KeyType};
use sage_crypto_core::crypto::rotation::DefaultKeyRotator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(MemoryKeyStorage::new());
    let rotator = DefaultKeyRotator::new(storage.clone());

    // Create keys of different types
    let key_types = vec![
        ("ed25519-key", KeyType::Ed25519),
        ("secp256k1-key", KeyType::Secp256k1),
        ("p256-key", KeyType::P256),
    ];

    for (key_id, key_type) in key_types {
        let key = KeyPair::generate(key_type)?;
        storage.store(key_id, &key)?;

        // Rotate preserves key type
        let new_key = rotator.rotate(key_id)?;
        assert_eq!(new_key.key_type(), key_type);

        println!("Rotated {} to {}", key_id, new_key.key_id());
    }

    Ok(())
}
```

### Example 4: Concurrent Rotation

```rust
use std::sync::Arc;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(MemoryKeyStorage::new());
    let rotator = Arc::new(DefaultKeyRotator::new(storage.clone()));

    // Create keys
    for i in 0..10 {
        let key = KeyPair::generate(KeyType::Ed25519)?;
        storage.store(&format!("key-{}", i), &key)?;
    }

    // Spawn threads to rotate concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let rotator_clone = Arc::clone(&rotator);
        let handle = thread::spawn(move || {
            for _ in 0..5 {
                rotator_clone.rotate(&format!("key-{}", i)).unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all rotations
    for i in 0..10 {
        let history = rotator.get_rotation_history(&format!("key-{}", i))?;
        assert_eq!(history.len(), 5);
        println!("key-{}: {} rotations completed", i, history.len());
    }

    Ok(())
}
```

### Example 5: Production Setup with Monitoring

```rust
use sage_crypto_core::crypto::rotation::{DefaultKeyRotator, KeyRotationConfig};
use sage_crypto_core::crypto::storage::FileKeyStorage;
use std::time::Duration;
use log::{info, warn, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Production configuration
    let config = KeyRotationConfig {
        rotation_interval: Duration::from_secs(86400 * 30), // 30 days
        max_key_age: Duration::from_secs(86400 * 90),       // 90 days
        keep_old_keys: true,
    };

    let storage = Arc::new(FileKeyStorage::new("/var/lib/sage/keys")?);
    let rotator = Arc::new(DefaultKeyRotator::with_config(
        storage.clone(),
        config,
    ));

    // Monitor critical keys
    let critical_keys = vec![
        "primary-signing-key",
        "backup-signing-key",
        "encryption-key",
        "did-key",
    ];

    for key_id in &critical_keys {
        rotator.add_monitored_key(key_id);
        info!("Monitoring key: {}", key_id);
    }

    // Start auto-rotation
    rotator.start_auto_rotation().await?;
    info!("Auto-rotation started");

    // Periodic health checks
    let rotator_clone = Arc::clone(&rotator);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await; // Every hour

            for key_id in &critical_keys {
                match rotator_clone.get_last_rotation_time(key_id) {
                    Ok(Some(timestamp)) => {
                        let age = chrono::Utc::now()
                            .signed_duration_since(timestamp);
                        info!("{}: last rotated {} days ago",
                              key_id, age.num_days());

                        if age.num_days() > 60 {
                            warn!("{}: approaching rotation deadline", key_id);
                        }
                    },
                    Ok(None) => {
                        warn!("{}: never rotated", key_id);
                    },
                    Err(e) => {
                        error!("{}: failed to check rotation status: {}",
                               key_id, e);
                    }
                }
            }
        }
    });

    // Run application
    // ...

    Ok(())
}
```

## Troubleshooting

### Issue: Auto-rotation not triggering

**Symptoms:**
- Keys are monitored but not rotating
- History shows no new events

**Solutions:**

1. **Check rotation interval:** Ensure enough time has passed
   ```rust
   let config = rotator.get_rotation_config();
   println!("Rotation interval: {:?}", config.rotation_interval);

   let last_time = rotator.get_last_rotation_time("key-id")?;
   println!("Last rotation: {:?}", last_time);
   ```

2. **Verify key is monitored:**
   ```rust
   rotator.add_monitored_key("key-id");
   ```

3. **Check if auto-rotation is running:**
   ```rust
   if !rotator.is_auto_rotation_running() {
       rotator.start_auto_rotation().await?;
   }
   ```

### Issue: Rotation fails with storage errors

**Symptoms:**
- `Error::StorageError` during rotation
- Keys not being stored

**Solutions:**

1. **Check storage permissions:**
   ```bash
   ls -la /var/lib/sage/keys
   # Should show rwx------ (700) for app user
   ```

2. **Verify storage is accessible:**
   ```rust
   let test_key = KeyPair::generate(KeyType::Ed25519)?;
   storage.store("test", &test_key)?;
   storage.load("test")?;
   storage.delete("test")?;
   ```

3. **Check disk space:**
   ```bash
   df -h /var/lib/sage/keys
   ```

### Issue: Old keys not being archived

**Symptoms:**
- `keep_old_keys: true` but archived keys not found
- Storage only has current key

**Solutions:**

1. **Verify configuration:**
   ```rust
   let config = rotator.get_rotation_config();
   assert!(config.keep_old_keys);
   ```

2. **List all keys to find archived ones:**
   ```rust
   let all_keys = storage.list()?;
   for key_id in all_keys {
       if key_id.contains(".old.") {
           println!("Archived key: {}", key_id);
       }
   }
   ```

3. **Check rotation history for timestamps:**
   ```rust
   let history = rotator.get_rotation_history("key-id")?;
   for event in history {
       let archived_id = format!("key-id.old.{}",
                                 event.timestamp.timestamp());
       println!("Should exist: {}", archived_id);
   }
   ```

### Issue: Memory usage growing over time

**Symptoms:**
- Application memory increases
- Many archived keys accumulating

**Solutions:**

1. **Implement key cleanup policy:**
   ```rust
   async fn cleanup_old_keys(
       storage: &dyn KeyStorage,
       max_age_days: i64,
   ) -> Result<usize> {
       let cutoff = Utc::now() - chrono::Duration::days(max_age_days);
       let all_keys = storage.list()?;
       let mut deleted = 0;

       for key_id in all_keys {
           if let Some(timestamp_str) = key_id.strip_prefix("*.old.") {
               if let Ok(timestamp) = timestamp_str.parse::<i64>() {
                   let key_time = DateTime::from_timestamp(timestamp, 0)
                       .unwrap();
                   if key_time < cutoff {
                       storage.delete(&key_id)?;
                       deleted += 1;
                   }
               }
           }
       }

       Ok(deleted)
   }

   // Run cleanup weekly
   let deleted = cleanup_old_keys(&*storage, 365).await?;
   info!("Cleaned up {} archived keys", deleted);
   ```

2. **Or set `keep_old_keys: false`:**
   ```rust
   let mut rotator = DefaultKeyRotator::new(storage);
   let mut config = rotator.get_rotation_config();
   config.keep_old_keys = false;
   rotator.set_rotation_config(config);
   ```

### Issue: Concurrent rotation conflicts

**Symptoms:**
- Rotation sometimes fails
- Inconsistent key states

**Solutions:**

The library handles concurrency internally, but ensure you're not:
- Manually modifying storage during rotation
- Running multiple rotators on the same keys
- Accessing keys without proper synchronization

```rust
// Good: Use the rotator's methods
let new_key = rotator.rotate("key-id")?;

// Bad: Don't bypass the rotator
// storage.delete("key-id")?;  // DON'T DO THIS
```

## Related Documentation

- [API Usage Guide](api_usage_guide.md)
- [Blockchain Integration Guide](blockchain_integration.md)
- [Performance Analysis](performance_analysis.md)
- [Security Audit Report](security_audit_phase6_2.md)

## Support

For issues, questions, or contributions:

- GitHub Issues: https://github.com/sage-x-project/sage/issues
- Documentation: https://github.com/sage-x-project/sage/tree/main/docs
- Source Code: https://github.com/sage-x-project/sage/tree/main/rs-sage-core

---

**Last Updated:** 2025-10-27
**Version:** 0.3.0
