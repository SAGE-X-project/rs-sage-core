# Blockchain Integration Guide

Complete guide for SAGE blockchain integration features (Phase 3).

## Overview

SAGE provides comprehensive blockchain integration for:
- **DID Management**: On-chain registration and resolution
- **Replay Protection**: Nonce tracking to prevent message replay attacks
- **Event Monitoring**: Automatic synchronization with blockchain state
- **Cache Management**: Efficient caching with automatic invalidation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  DID Resolver  │  Nonce Tracker  │  Synchronizer           │
├─────────────────────────────────────────────────────────────┤
│         DID Registry Contract Interface                     │
├─────────────────────────────────────────────────────────────┤
│              Blockchain Client (Ethers-rs)                  │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Blockchain Client

Connection and transaction management for Ethereum-compatible blockchains.

```rust
use sage_crypto_core::blockchain::{BlockchainClient, BlockchainConfig};

// Create configuration
let config = BlockchainConfig::new("http://localhost:8545")
    .with_private_key("0x...")?
    .with_gas_price(20_000_000_000u64)  // 20 Gwei
    .with_gas_limit(6_000_000u64);

// Connect to blockchain
let client = BlockchainClient::new(config).await?;
```

**Features**:
- Automatic nonce management
- Gas estimation and optimization
- Transaction retry logic
- Multiple network support (Mainnet, Sepolia, custom)

### 2. DID Registry

Smart contract interface for DID operations.

```rust
use sage_crypto_core::blockchain::DIDRegistry;
use sage_crypto_core::did::{DID, DIDDocument};

// Initialize registry
let registry = Arc::new(DIDRegistry::new(
    contract_address,
    client.middleware()
));

// Register DID
let did = DID::parse("did:chain:example")?;
let doc = DIDDocument::new(did.clone());
let tx_hash = registry.register_did(&did, &doc).await?;

// Resolve DID
let doc = registry.get_did_document(&did).await?;

// Update DID
let updated_doc = /* ... */;
registry.update_did_document(&did, &updated_doc).await?;

// Revoke DID
registry.revoke_did(&did).await?;
```

**Contract Methods**:
- `registerDID(did, document)`: Register new DID
- `getDIDDocument(did)`: Query DID document
- `updateDIDDocument(did, document)`: Update existing DID
- `revokeDID(did)`: Revoke DID
- `isDIDRegistered(did)`: Check registration status
- `useNonce(did, nonce)`: Mark nonce as used
- `isNonceUsed(did, nonce)`: Check nonce status

**Events**:
- `DIDRegistered(did, document)`
- `DIDUpdated(did, document)`
- `DIDRevoked(did)`

### 3. DID Resolver with Caching

Resolves DIDs with intelligent caching for performance.

```rust
use sage_crypto_core::did::resolver::BlockchainDIDResolver;
use std::time::Duration;

// Create resolver with caching
let resolver = Arc::new(BlockchainDIDResolver::with_cache_ttl(
    registry,
    Duration::from_secs(300)  // 5 minute cache
));

// Resolve DID (checks cache first)
let result = resolver.resolve(&did).await?;

// Clear cache manually if needed
resolver.clear_cache();
```

**Caching Strategy**:
- Time-based expiration (configurable TTL)
- Automatic invalidation on DID updates
- Thread-safe cache implementation
- Cache metrics available (`cache_len()`)

### 4. Nonce Tracker

Prevents replay attacks through nonce validation.

```rust
use sage_crypto_core::blockchain::NonceTracker;

// Create tracker with caching
let tracker = Arc::new(NonceTracker::new(registry));

// Check if nonce was used
let is_used = tracker.is_nonce_used(&did, "nonce-123").await?;

// Validate nonce (returns error if used)
tracker.validate_nonce(&did, "nonce-123").await?;

// Mark nonce as used
tracker.mark_nonce_used(&did, "nonce-123").await?;

// Atomic validate-and-mark
tracker.validate_and_mark_nonce(&did, "nonce-123").await?;

// Cache management
tracker.clear_cache();
let cache_size = tracker.cache_len();
```

**Two-Tier Strategy**:
1. **Local Cache**: Fast in-memory lookups
2. **Blockchain State**: Authoritative source of truth

**Cache Behavior**:
- Immediate local updates when marking nonces
- Query blockchain if not in cache
- Thread-safe concurrent access
- Optional cache-free mode

### 5. Event Listener

Monitors blockchain events for automatic updates.

```rust
use sage_crypto_core::blockchain::{
    EventListener,
    EventListenerConfig,
    EventCallbacks,
};
use std::time::Duration;

// Configure listener
let config = EventListenerConfig {
    poll_interval: Duration::from_secs(12),  // 1 block
    confirmations: 3,                         // Wait for 3 confirmations
    max_block_range: 1000,                    // Query max 1000 blocks
    process_history: false,                   // Skip historical events
    from_block: None,                         // Start from current
};

// Create listener
let listener = Arc::new(EventListener::with_config(
    registry,
    client.middleware(),
    config
));

// Add callbacks
listener.add_callback(EventCallbacks::logger()).await;

// Start listening
listener.start().await?;

// Process events in background
tokio::spawn(async move {
    listener.process_events_loop().await
});

// Manual sync to specific block
listener.sync_to_block(12345).await?;
```

**Event Types**:
```rust
pub enum RegistryEvent {
    DIDRegistered { did: String, document: Vec<u8>, block_number: u64 },
    DIDUpdated { did: String, document: Vec<u8>, block_number: u64 },
    DIDRevoked { did: String, block_number: u64 },
}
```

**Built-in Callbacks**:
- `EventCallbacks::logger()`: Console logging
- `EventCallbacks::cache_invalidator(resolver)`: DID cache invalidation

### 6. Synchronizer

Coordinates all components for automatic synchronization.

```rust
use sage_crypto_core::blockchain::{Synchronizer, SynchronizerBuilder};

// Build synchronizer with all components
let mut synchronizer = SynchronizerBuilder::new(registry, client)
    .with_resolver(resolver)
    .with_nonce_tracker(nonce_tracker)
    .add_callback(EventCallbacks::logger())
    .build()
    .await?;

// Start synchronization
synchronizer.start().await?;

// Check status
let is_running = synchronizer.is_running().await;
let last_block = synchronizer.last_processed_block().await;

// Manual sync
synchronizer.sync_to_block(12345).await?;

// Stop
synchronizer.stop().await?;
```

**What It Does**:
1. Monitors blockchain events continuously
2. Invalidates DID resolver cache on updates
3. Updates nonce tracker (when NonceUsed events available)
4. Runs callbacks for custom logic
5. Manages background task lifecycle

## Integration Patterns

### Pattern 1: Basic DID Registration

```rust
// 1. Connect to blockchain
let client = BlockchainClient::new(config).await?;

// 2. Initialize registry
let registry = Arc::new(DIDRegistry::new(contract_addr, client.middleware()));

// 3. Create DID and document
let keypair = KeyPair::generate(KeyType::Secp256k1)?;
let did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Chain)?;
let doc = DIDDocument::new(did.clone());

// 4. Register on-chain
let tx_hash = registry.register_did(&did, &doc).await?;

// 5. Wait for confirmation (15 seconds ~= 1 block on Ethereum)
tokio::time::sleep(Duration::from_secs(15)).await;
```

### Pattern 2: Message Verification with Nonce

```rust
// Setup
let registry = Arc::new(DIDRegistry::new(contract_addr, middleware));
let nonce_tracker = Arc::new(NonceTracker::new(registry));

// Verify message
async fn verify_message(
    message: &Message,
    nonce_tracker: &NonceTracker<M>,
) -> Result<()> {
    // 1. Extract DID and nonce
    let did = DID::parse(&message.agent_did)?;
    let nonce = &message.nonce;

    // 2. Validate nonce (checks local cache first, then blockchain)
    nonce_tracker.validate_nonce(&did, nonce).await?;

    // 3. Verify signature (from Phase 1)
    // ...

    // 4. Mark nonce as used if verification passes
    nonce_tracker.mark_nonce_used(&did, nonce).await?;

    Ok(())
}
```

### Pattern 3: Full Synchronization Setup

```rust
async fn setup_full_sync(
    registry: Arc<DIDRegistry<M>>,
    middleware: Arc<M>,
) -> Result<Synchronizer<M>> {
    // 1. Create resolver with caching
    let resolver = Arc::new(BlockchainDIDResolver::with_cache_ttl(
        registry.clone(),
        Duration::from_secs(300),
    ));

    // 2. Create nonce tracker
    let nonce_tracker = Arc::new(NonceTracker::new(registry.clone()));

    // 3. Build synchronizer
    let mut synchronizer = SynchronizerBuilder::new(registry, middleware)
        .with_resolver(resolver)
        .with_nonce_tracker(nonce_tracker)
        .add_callback(EventCallbacks::logger())
        .build()
        .await?;

    // 4. Start synchronization
    synchronizer.start().await?;

    Ok(synchronizer)
}
```

## Performance Considerations

### Caching

- **DID Resolver Cache**: 5-minute default TTL, reduces blockchain queries
- **Nonce Tracker Cache**: In-memory HashSet for O(1) lookups
- **Cache Invalidation**: Automatic via event listeners

### Gas Optimization

```rust
// Batch operations when possible
let mut txs = Vec::new();
for did in dids {
    txs.push(registry.register_did(&did, &doc));
}

// Execute in parallel (if independent)
let results = futures::future::join_all(txs).await;
```

### Event Processing

- **Poll Interval**: 12 seconds (≈1 block) default
- **Confirmations**: 3 blocks (≈36 seconds) for finality
- **Batch Queries**: Up to 1000 blocks per query

## Security Best Practices

1. **Private Key Management**:
   ```rust
   // Never hardcode private keys
   let private_key = env::var("PRIVATE_KEY")?;
   let config = BlockchainConfig::new(&rpc_url)
       .with_private_key(&private_key)?;
   ```

2. **Nonce Validation**:
   ```rust
   // Always validate before processing messages
   nonce_tracker.validate_nonce(&did, &nonce).await?;

   // Use atomic operation to prevent race conditions
   nonce_tracker.validate_and_mark_nonce(&did, &nonce).await?;
   ```

3. **Transaction Confirmation**:
   ```rust
   // Wait for sufficient confirmations
   let config = EventListenerConfig {
       confirmations: 3,  // Minimum for production
       ..Default::default()
   };
   ```

4. **Cache Invalidation**:
   ```rust
   // Ensure cache is invalidated on updates
   let synchronizer = SynchronizerBuilder::new(registry, middleware)
       .with_resolver(resolver)  // Automatic invalidation
       .build()
       .await?;
   ```

## Testing

### Unit Tests

```bash
# Run tests without blockchain feature
cargo test --lib

# Run tests with blockchain feature
cargo test --features blockchain --lib
```

### Integration Tests

```bash
# Requires deployed contract and running node
cargo test --features blockchain --test integration_tests -- --ignored
```

### Example

```bash
# Set environment variables
export BLOCKCHAIN_RPC_URL="http://localhost:8545"
export CONTRACT_ADDRESS="0x..."
export PRIVATE_KEY="0x..."

# Run example
cargo run --example blockchain_integration --features blockchain
```

## Deployment

### Smart Contract Deployment

1. Deploy DID Registry contract to target network
2. Note contract address
3. Configure application:
   ```rust
   let config = BlockchainConfig::new(rpc_url)
       .with_private_key(private_key)?;

   let contract_addr: Address = "0x...".parse()?;
   ```

### Production Configuration

```rust
let config = BlockchainConfig::mainnet()
    .with_private_key(&env::var("PRIVATE_KEY")?)?
    .with_gas_price(50_000_000_000u64)  // 50 Gwei for mainnet
    .with_gas_limit(6_000_000u64);

let event_config = EventListenerConfig {
    poll_interval: Duration::from_secs(12),
    confirmations: 12,  // Higher for mainnet
    max_block_range: 1000,
    process_history: false,
    from_block: None,
};
```

## Troubleshooting

### Common Issues

1. **Transaction Fails**:
   - Check gas price and limit
   - Verify private key has sufficient funds
   - Confirm contract address is correct

2. **Events Not Detected**:
   - Verify listener is started
   - Check poll interval configuration
   - Confirm contract emits events correctly

3. **Cache Stale**:
   - Reduce cache TTL
   - Ensure synchronizer is running
   - Check event callbacks are registered

4. **Nonce Already Used**:
   - This is expected behavior for replay protection
   - Generate new nonce for each message
   - Check cache is not corrupted

## Further Reading

- [Ethers-rs Documentation](https://docs.rs/ethers)
- [EIP-1056: Ethereum DID Registry](https://eips.ethereum.org/EIPS/eip-1056)
- [RFC 9421: HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421)
- [SAGE Core Documentation](../README.md)

## Support

For issues and questions:
- GitHub Issues: https://github.com/your-repo/sage/issues
- Documentation: https://sage-docs.example.com
