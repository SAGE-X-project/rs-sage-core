# Ethereum Integration Guide

## Overview

The Ethereum integration module provides client and resolver functionality for interacting with the **AgentCardRegistry** smart contract on Ethereum networks.

**Features:**
- Agent registration and resolution via DID
- Multi-key support (Ed25519, Secp256k1, P256)
- Public key verification
- Caching layer for performance
- ERC-8004 compliant

**Status:** ✅ Read-only operations (v0.3.0)
- Write operations (registration, key rotation) planned for future release

---

## Quick Start

### 1. Setup

Add the blockchain feature to your `Cargo.toml`:

```toml
[dependencies]
sage_crypto_core = { version = "0.3", features = ["blockchain"] }
```

### 2. Create Client

```rust
use sage_crypto_core::blockchain::{EthereumClient, EthereumResolver};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Ethereum Sepolia testnet
    let client = EthereumClient::new(
        "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
        "0x1234567890123456789012345678901234567890", // Registry address
    ).await?;

    println!("Connected to registry: {:?}", client.registry_address());
    Ok(())
}
```

### 3. Resolve Agent by DID

```rust
let resolver = EthereumResolver::new(client);

// Resolve agent metadata
let agent = resolver
    .resolve_agent("did:sage:ethereum:0xabcd1234...")
    .await?;

println!("Agent: {}", agent.name);
println!("Description: {}", agent.description);
println!("Endpoint: {}", agent.endpoint);
println!("Owner: {}", agent.owner);
println!("Active: {}", agent.is_active);
```

### 4. Query Public Keys

```rust
// Get all public keys
let keys = resolver
    .resolve_all_public_keys("did:sage:ethereum:0xabcd1234...")
    .await?;

println!("Total keys: {}", keys.len());

for key in keys {
    println!("  Type: {:?}", key.key_type);
    println!("  Verified: {}", key.verified);
}
```

---

## API Reference

### EthereumClient

Main client for blockchain queries.

```rust
// Create client
let client = EthereumClient::new(rpc_url, registry_address).await?;

// Get agent by ID
let agent = client.get_agent(&agent_id_bytes).await?;

// Get agent by DID
let agent = client.get_agent_by_did("did:sage:ethereum:0x...").await?;

// Check if active
let is_active = client.is_agent_active(&agent_id_bytes).await?;

// Get registration stake amount
let stake = client.get_registration_stake().await?;
```

### EthereumResolver

High-level resolver with caching.

```rust
// Create resolver
let resolver = EthereumResolver::new(client);

// With custom cache TTL
let resolver = EthereumResolver::with_cache_ttl(
    client,
    Duration::from_secs(600), // 10 minutes
);

// Without caching
let resolver = EthereumResolver::without_cache(client);

// Resolve agent
let agent = resolver.resolve_agent(did).await?;

// Get public keys
let all_keys = resolver.resolve_all_public_keys(did).await?;
let verified = resolver.resolve_verified_keys(did).await?;

// Filter by key type
use sage_crypto_core::crypto::KeyType;
let ed25519_keys = resolver
    .resolve_public_key_by_type(did, KeyType::Ed25519)
    .await?;

// Check activation
let is_active = resolver.is_agent_active(did).await?;

// Get owner
let owner = resolver.resolve_owner(did).await?;

// Batch resolve
let dids = vec!["did:sage:ethereum:0x111...", "did:sage:ethereum:0x222..."];
let results = resolver.batch_resolve(&dids).await;
```

---

## Examples

### Example 1: Basic Agent Query

```rust
use sage_crypto_core::blockchain::{EthereumClient, EthereumResolver};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = EthereumClient::new(
        "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY",
        "0x1234567890123456789012345678901234567890",
    ).await?;

    let resolver = EthereumResolver::new(client);

    let did = "did:sage:ethereum:0xabcd1234...";

    match resolver.resolve_agent(did).await {
        Ok(agent) => {
            println!("✅ Found agent: {}", agent.name);
            println!("   Active: {}", agent.is_active);
            println!("   Keys: {}", agent.public_keys.len());
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
        }
    }

    Ok(())
}
```

### Example 2: Key Type Filtering

```rust
use sage_crypto_core::crypto::KeyType;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = EthereumClient::new(rpc_url, registry_address).await?;
    let resolver = EthereumResolver::new(client);

    let did = "did:sage:ethereum:0xabcd...";

    // Get different key types
    let ed25519_keys = resolver
        .resolve_public_key_by_type(did, KeyType::Ed25519)
        .await?;

    let secp256k1_keys = resolver
        .resolve_public_key_by_type(did, KeyType::Secp256k1)
        .await?;

    println!("Ed25519 keys: {}", ed25519_keys.len());
    println!("Secp256k1 keys: {}", secp256k1_keys.len());

    Ok(())
}
```

### Example 3: Batch Resolution

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = EthereumClient::new(rpc_url, registry_address).await?;
    let resolver = EthereumResolver::new(client);

    let dids = vec![
        "did:sage:ethereum:0x1111...",
        "did:sage:ethereum:0x2222...",
        "did:sage:ethereum:0x3333...",
    ];

    let results = resolver.batch_resolve(&dids).await;

    for (did, result) in results {
        match result {
            Ok(agent) => println!("✅ {}: {}", did, agent.name),
            Err(e) => println!("❌ {}: {}", did, e),
        }
    }

    Ok(())
}
```

### Example 4: Caching Management

```rust
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = EthereumClient::new(rpc_url, registry_address).await?;

    // Create resolver with 10-minute cache
    let resolver = EthereumResolver::with_cache_ttl(
        client,
        Duration::from_secs(600),
    );

    // First call - fetches from blockchain
    let agent1 = resolver.resolve_agent(did).await?;
    println!("First call: {}", agent1.name);

    // Second call - uses cache (fast!)
    let agent2 = resolver.resolve_agent(did).await?;
    println!("Cached call: {}", agent2.name);

    // Check cache stats
    let (agents, keys) = resolver.cache_stats();
    println!("Cached agents: {}, keys: {}", agents, keys);

    // Clear cache if needed
    resolver.clear_cache();

    Ok(())
}
```

---

## Configuration

### RPC Endpoints

**Mainnet:**
```
https://eth-mainnet.g.alchemy.com/v2/YOUR-API-KEY
https://mainnet.infura.io/v3/YOUR-PROJECT-ID
```

**Sepolia Testnet:**
```
https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY
https://sepolia.infura.io/v3/YOUR-PROJECT-ID
```

### Registry Addresses

Check the latest deployed contract addresses in:
- Production: See deployment documentation
- Testnet: Contact SAGE team or check GitHub releases

---

## Troubleshooting

### "Invalid registry address"

**Problem:** RPC connection or address parsing failed

**Solution:**
```rust
// Ensure address is valid hex with 0x prefix
let address = "0x1234567890123456789012345678901234567890";
assert_eq!(address.len(), 42); // 0x + 40 hex chars
```

### "Agent not found"

**Problem:** DID doesn't exist in registry

**Solution:**
```rust
match resolver.resolve_agent(did).await {
    Ok(agent) => { /* use agent */ },
    Err(Error::NotFound(_)) => {
        println!("Agent not registered yet");
    },
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

### Network timeout

**Problem:** RPC endpoint slow or unreachable

**Solution:**
- Use reliable RPC provider (Alchemy, Infura)
- Check network connectivity
- Try different endpoint
- Implement retry logic

### Cache issues

**Problem:** Getting stale data

**Solution:**
```rust
// Disable caching for real-time data
let resolver = EthereumResolver::without_cache(client);

// Or clear cache periodically
resolver.clear_cache();

// Or use shorter TTL
let resolver = EthereumResolver::with_cache_ttl(
    client,
    Duration::from_secs(60), // 1 minute
);
```

---

## Architecture

### Contract Interface

The client uses Alloy's `sol!` macro to define type-safe contract bindings:

```rust
sol! {
    interface IAgentCardRegistry {
        struct AgentMetadata {
            string did;
            string name;
            string description;
            // ...
        }

        function getAgent(bytes32 agentId) external view
            returns (AgentMetadata memory);
        function getAgentByDID(string calldata did) external view
            returns (AgentMetadata memory);
    }
}
```

### Caching Layer

```
┌─────────────────┐
│  Application    │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Resolver       │ <-- Cache Layer (DashMap)
│  (with cache)   │     - Agent metadata cache
└────────┬────────┘     - Public keys cache
         │              - TTL-based expiration
         v
┌─────────────────┐
│  Client         │
│  (blockchain)   │ <-- Alloy Provider
└────────┬────────┘     - HTTP RPC calls
         │              - Contract calls
         v
┌─────────────────┐
│  Ethereum       │
│  (AgentCardRegistry)
└─────────────────┘
```

---

## Future Enhancements

### Planned for v0.4.0+

**Write Operations:**
- `commit_registration()` - Commit-reveal phase 1
- `register_agent()` - Full registration
- `add_key()` - Add new public key
- `rotate_key()` - Atomic key rotation
- `deactivate_agent()` - Deactivate agent

**Advanced Features:**
- Event listening and subscriptions
- Transaction signing with local wallet
- Multi-sig support
- Batch write operations

---

## Related Documentation

- [Blockchain Types](blockchain_integration.md)
- [Key Rotation Guide](KEY_ROTATION_GUIDE.md)
- [Ownership Verification](blockchain_integration.md#ownership-verification)
- [API Usage Guide](api_usage_guide.md)

---

## Support

- **GitHub Issues**: https://github.com/sage-x-project/sage/issues
- **Documentation**: https://github.com/sage-x-project/sage/tree/main/docs
- **Contract Source**: `sage/contracts/ethereum/contracts/AgentCardRegistry.sol`

---

**Version**: 0.3.0
**Last Updated**: 2025-10-27
**Status**: Production Ready (Read-only)
