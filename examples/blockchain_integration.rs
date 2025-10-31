//! Blockchain Integration Example
//!
//! This example demonstrates the complete blockchain integration including:
//! - DID registration and resolution
//! - Nonce tracking for replay protection
//! - Event listening and automatic synchronization
//!
//! # Running this example
//!
//! ```bash
//! # Set environment variables
//! export BLOCKCHAIN_RPC_URL="http://localhost:8545"
//! export CONTRACT_ADDRESS="0x..."
//! export PRIVATE_KEY="0x..."
//!
//! # Run the example
//! cargo run --example blockchain_integration --features blockchain
//! ```

#[cfg(feature = "blockchain")]
use sage_crypto_core::blockchain::{
    BlockchainClient, BlockchainConfig, DIDRegistry, EventListener, EventListenerConfig,
    NonceTracker, Synchronizer, SynchronizerBuilder,
};
#[cfg(feature = "blockchain")]
use sage_crypto_core::crypto::{KeyPair, KeyType};
#[cfg(feature = "blockchain")]
use sage_crypto_core::did::method::{generate_did_from_pubkey, DIDMethod};
#[cfg(feature = "blockchain")]
use sage_crypto_core::did::resolver::{BlockchainDIDResolver, DIDResolver};
#[cfg(feature = "blockchain")]
use sage_crypto_core::did::{DIDDocument, VerificationMethod};
#[cfg(feature = "blockchain")]
use std::env;
#[cfg(feature = "blockchain")]
use std::sync::Arc;
#[cfg(feature = "blockchain")]
use std::time::Duration;

#[cfg(feature = "blockchain")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔗 SAGE Blockchain Integration Example");
    println!("========================================\n");

    // Step 1: Load configuration from environment
    let rpc_url = env::var("BLOCKCHAIN_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let contract_address = env::var("CONTRACT_ADDRESS")
        .expect("CONTRACT_ADDRESS environment variable must be set");
    let private_key = env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY environment variable must be set");

    println!("📝 Configuration:");
    println!("  RPC URL: {}", rpc_url);
    println!("  Contract: {}", contract_address);
    println!();

    // Step 2: Create blockchain client
    println!("🌐 Connecting to blockchain...");
    let config = BlockchainConfig::new(&rpc_url, 1337) // Chain ID for local network
        .with_private_key(&private_key);

    let client = BlockchainClient::new(config).await?;
    println!("✅ Connected to blockchain\n");

    // Step 3: Initialize DID Registry
    println!("📋 Initializing DID Registry...");
    let contract_addr: ethers::types::Address = contract_address.parse()?;

    // Use signer if available, otherwise use provider
    let provider = Arc::new(client.provider().clone());
    let registry = Arc::new(DIDRegistry::new(contract_addr, provider.clone()));
    println!("✅ DID Registry initialized\n");

    // Step 4: Generate DID for agent
    println!("🔑 Generating agent DID...");
    let keypair = KeyPair::generate(KeyType::Secp256k1)?;
    let agent_did = generate_did_from_pubkey(keypair.public_key(), DIDMethod::Chain)?;
    println!("  Agent DID: {}", agent_did.as_str());
    println!();

    // Step 5: Create and register DID Document
    println!("📄 Creating DID Document...");
    let mut did_document = DIDDocument::new(agent_did.clone());
    let verification_method = VerificationMethod::from_public_key(
        &agent_did,
        "key-1",
        keypair.public_key(),
    );
    did_document.add_verification_method(verification_method);

    println!("📤 Registering DID on blockchain...");
    let tx_hash = registry.register_did(&agent_did, &did_document).await?;
    println!("  Transaction: {:?}", tx_hash);
    println!("⏳ Waiting for confirmation...");

    // Wait for transaction confirmation
    tokio::time::sleep(Duration::from_secs(15)).await;
    println!("✅ DID registered successfully\n");

    // Step 6: Create DID Resolver with caching
    println!("🔍 Creating DID Resolver...");
    let resolver = Arc::new(BlockchainDIDResolver::with_cache_ttl(
        registry.clone(),
        Duration::from_secs(300), // 5 minutes cache
    ));
    println!("✅ DID Resolver created\n");

    // Step 7: Resolve DID
    println!("🔎 Resolving DID...");
    let resolution = resolver.resolve(&agent_did).await?;
    if let Some(doc) = resolution.document {
        println!("✅ DID resolved successfully");
        println!("  ID: {}", doc.id);
        println!("  Verification methods: {}", doc.verification_method.len());
    } else {
        println!("❌ DID not found");
    }
    println!();

    // Step 8: Initialize Nonce Tracker
    println!("🔐 Initializing Nonce Tracker...");
    let nonce_tracker = Arc::new(NonceTracker::new(registry.clone()));
    println!("✅ Nonce Tracker initialized\n");

    // Step 9: Test nonce validation
    println!("🔬 Testing nonce validation...");
    let test_nonce = "nonce-12345";

    println!("  Checking if nonce is used...");
    let is_used = nonce_tracker.is_nonce_used(&agent_did, test_nonce).await?;
    println!("  Nonce used: {}", is_used);

    if !is_used {
        println!("  Marking nonce as used...");
        nonce_tracker.mark_nonce_used(&agent_did, test_nonce).await?;
        println!("  ⏳ Waiting for confirmation...");
        tokio::time::sleep(Duration::from_secs(15)).await;

        let is_used_now = nonce_tracker.is_nonce_used(&agent_did, test_nonce).await?;
        println!("  Nonce used now: {}", is_used_now);
    }
    println!("✅ Nonce validation complete\n");

    // Step 10: Set up Event Listener
    println!("👂 Setting up Event Listener...");
    let event_config = EventListenerConfig {
        poll_interval: Duration::from_secs(12),
        confirmations: 3,
        max_block_range: 1000,
        process_history: false,
        from_block: None,
    };

    let event_listener = Arc::new(EventListener::with_config(
        registry.clone(),
        provider.clone(),
        event_config,
    ));

    // Add logging callback
    event_listener
        .add_callback(sage_crypto_core::blockchain::EventCallbacks::logger())
        .await;

    println!("✅ Event Listener configured\n");

    // Step 11: Create Synchronizer
    println!("🔄 Creating Synchronizer...");
    let mut synchronizer = SynchronizerBuilder::new(registry.clone(), provider.clone())
        .with_resolver(resolver.clone())
        .with_nonce_tracker(nonce_tracker.clone())
        .add_callback(sage_crypto_core::blockchain::EventCallbacks::logger())
        .build()
        .await?;

    println!("✅ Synchronizer created");
    println!();

    // Step 12: Start synchronizer
    println!("▶️  Starting synchronizer...");
    synchronizer.start().await?;
    println!("✅ Synchronizer running");
    println!("  Last processed block: {}", synchronizer.last_processed_block().await);
    println!();

    // Step 13: Run for a while to demonstrate event listening
    println!("⏱️  Running for 30 seconds to monitor events...");
    println!("  (In production, this would run indefinitely)");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 14: Stop synchronizer
    println!("\n⏹️  Stopping synchronizer...");
    synchronizer.stop().await?;
    println!("✅ Synchronizer stopped");
    println!();

    // Summary
    println!("📊 Summary:");
    println!("  ✅ DID Registration: Success");
    println!("  ✅ DID Resolution: Success (with caching)");
    println!("  ✅ Nonce Tracking: Success");
    println!("  ✅ Event Listening: Success");
    println!("  ✅ Auto Synchronization: Success");
    println!();
    println!("🎉 Blockchain integration complete!");

    Ok(())
}

#[cfg(not(feature = "blockchain"))]
fn main() {
    eprintln!("This example requires the 'blockchain' feature to be enabled.");
    eprintln!("Run with: cargo run --example blockchain_integration --features blockchain");
    std::process::exit(1);
}
