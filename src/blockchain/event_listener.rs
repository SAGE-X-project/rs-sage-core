//! Blockchain Event Listening and Synchronization
//!
//! Provides event monitoring for DID Registry smart contract and automatic
//! cache synchronization.

use crate::blockchain::DIDRegistry;
use crate::did::DID;
use crate::error::{Error, Result};
use ethers::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Event types from DID Registry contract
#[derive(Debug, Clone)]
pub enum RegistryEvent {
    /// DID was registered
    DIDRegistered {
        did: String,
        document: Vec<u8>,
        block_number: u64,
    },
    /// DID was updated
    DIDUpdated {
        did: String,
        document: Vec<u8>,
        block_number: u64,
    },
    /// DID was revoked
    DIDRevoked {
        did: String,
        block_number: u64,
    },
}

/// Event listener configuration
#[derive(Debug, Clone)]
pub struct EventListenerConfig {
    /// Poll interval for checking new blocks
    pub poll_interval: Duration,
    /// Number of confirmations required before processing event
    pub confirmations: u64,
    /// Maximum number of blocks to query at once
    pub max_block_range: u64,
    /// Whether to process historical events on startup
    pub process_history: bool,
    /// Starting block for historical event processing
    pub from_block: Option<u64>,
}

impl Default for EventListenerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(12), // ~1 block on Ethereum
            confirmations: 3,
            max_block_range: 1000,
            process_history: false,
            from_block: None,
        }
    }
}

/// Callback function type for event processing
pub type EventCallback = Arc<dyn Fn(RegistryEvent) -> Result<()> + Send + Sync>;

/// Event listener for DID Registry contract
pub struct EventListener<M: Middleware> {
    /// DID Registry contract
    registry: Arc<DIDRegistry<M>>,
    /// Middleware client for blockchain queries
    client: Arc<M>,
    /// Configuration
    config: EventListenerConfig,
    /// Last processed block number
    last_block: Arc<RwLock<u64>>,
    /// Event callbacks
    callbacks: Arc<RwLock<Vec<EventCallback>>>,
    /// Whether the listener is running
    running: Arc<RwLock<bool>>,
}

impl<M: Middleware + 'static> EventListener<M> {
    /// Creates a new event listener
    pub fn new(registry: Arc<DIDRegistry<M>>, client: Arc<M>) -> Self {
        Self::with_config(registry, client, EventListenerConfig::default())
    }

    /// Creates a new event listener with custom configuration
    pub fn with_config(
        registry: Arc<DIDRegistry<M>>,
        client: Arc<M>,
        config: EventListenerConfig,
    ) -> Self {
        Self {
            registry,
            client,
            config,
            last_block: Arc::new(RwLock::new(0)),
            callbacks: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Adds an event callback
    pub async fn add_callback(&self, callback: EventCallback) {
        let mut callbacks = self.callbacks.write().await;
        callbacks.push(callback);
    }

    /// Starts the event listener in the background
    pub async fn start(&self) -> Result<()> {
        // Check if already running
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(Error::Other("Event listener already running".to_string()));
            }
            *running = true;
        }

        // Get current block number
        let current_block = self
            .client
            .get_block_number()
            .await
            .map_err(|e| Error::Other(format!("Failed to get block number: {}", e)))?
            .as_u64();

        // Set starting block
        let mut last_block = self.last_block.write().await;
        *last_block = if self.config.process_history {
            self.config.from_block.unwrap_or(current_block)
        } else {
            current_block
        };
        drop(last_block);

        Ok(())
    }

    /// Stops the event listener
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Checks if the listener is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Processes events in a loop (should be run in a background task)
    pub async fn process_events_loop(&self) -> Result<()> {
        while self.is_running().await {
            if let Err(e) = self.process_pending_events().await {
                eprintln!("Error processing events: {}", e);
            }

            sleep(self.config.poll_interval).await;
        }

        Ok(())
    }

    /// Processes pending events from the last processed block
    async fn process_pending_events(&self) -> Result<()> {
        // Get current block number
        let current_block = self
            .client
            .get_block_number()
            .await
            .map_err(|e| Error::Other(format!("Failed to get block number: {}", e)))?
            .as_u64();

        // Calculate target block (with confirmations)
        let target_block = current_block.saturating_sub(self.config.confirmations);

        let last_block = *self.last_block.read().await;

        if target_block <= last_block {
            // No new blocks to process
            return Ok(());
        }

        // Calculate block range
        let from_block = last_block + 1;
        let to_block = std::cmp::min(target_block, from_block + self.config.max_block_range);

        // Query events
        let events = self.query_events(from_block, to_block).await?;

        // Process each event
        let callbacks = self.callbacks.read().await.clone();
        for event in events {
            for callback in &callbacks {
                if let Err(e) = callback(event.clone()) {
                    eprintln!("Error in event callback: {}", e);
                }
            }
        }

        // Update last processed block
        let mut last_block_write = self.last_block.write().await;
        *last_block_write = to_block;

        Ok(())
    }

    /// Queries events from the blockchain
    async fn query_events(&self, from_block: u64, to_block: u64) -> Result<Vec<RegistryEvent>> {
        let mut events = Vec::new();

        // Query DIDRegistered events
        let registered_filter = Filter::new()
            .address(self.registry.address())
            .event("DIDRegistered(string,bytes)")
            .from_block(BlockNumber::Number(from_block.into()))
            .to_block(BlockNumber::Number(to_block.into()));

        let registered_logs = self
            .client
            .get_logs(&registered_filter)
            .await
            .map_err(|e| Error::Other(format!("Failed to query DIDRegistered events: {}", e)))?;

        for log in registered_logs {
            if let Some(block_number) = log.block_number {
                // Parse event data
                // Note: In production, use proper ABI decoding
                if log.topics.len() >= 2 && !log.data.is_empty() {
                    let did = format!("{:?}", log.topics[1]); // Simplified
                    events.push(RegistryEvent::DIDRegistered {
                        did,
                        document: log.data.to_vec(),
                        block_number: block_number.as_u64(),
                    });
                }
            }
        }

        // Query DIDUpdated events
        let updated_filter = Filter::new()
            .address(self.registry.address())
            .event("DIDUpdated(string,bytes)")
            .from_block(BlockNumber::Number(from_block.into()))
            .to_block(BlockNumber::Number(to_block.into()));

        let updated_logs = self
            .client
            .get_logs(&updated_filter)
            .await
            .map_err(|e| Error::Other(format!("Failed to query DIDUpdated events: {}", e)))?;

        for log in updated_logs {
            if let Some(block_number) = log.block_number {
                if log.topics.len() >= 2 && !log.data.is_empty() {
                    let did = format!("{:?}", log.topics[1]);
                    events.push(RegistryEvent::DIDUpdated {
                        did,
                        document: log.data.to_vec(),
                        block_number: block_number.as_u64(),
                    });
                }
            }
        }

        // Query DIDRevoked events
        let revoked_filter = Filter::new()
            .address(self.registry.address())
            .event("DIDRevoked(string)")
            .from_block(BlockNumber::Number(from_block.into()))
            .to_block(BlockNumber::Number(to_block.into()));

        let revoked_logs = self
            .client
            .get_logs(&revoked_filter)
            .await
            .map_err(|e| Error::Other(format!("Failed to query DIDRevoked events: {}", e)))?;

        for log in revoked_logs {
            if let Some(block_number) = log.block_number {
                if log.topics.len() >= 2 {
                    let did = format!("{:?}", log.topics[1]);
                    events.push(RegistryEvent::DIDRevoked {
                        did,
                        block_number: block_number.as_u64(),
                    });
                }
            }
        }

        Ok(events)
    }

    /// Returns the last processed block number
    pub async fn last_processed_block(&self) -> u64 {
        *self.last_block.read().await
    }

    /// Manually processes events up to a specific block
    pub async fn sync_to_block(&self, target_block: u64) -> Result<()> {
        let last_block = *self.last_block.read().await;

        if target_block <= last_block {
            return Ok(());
        }

        let mut current_block = last_block + 1;

        while current_block <= target_block {
            let to_block = std::cmp::min(target_block, current_block + self.config.max_block_range);

            let events = self.query_events(current_block, to_block).await?;

            let callbacks = self.callbacks.read().await.clone();
            for event in events {
                for callback in &callbacks {
                    if let Err(e) = callback(event.clone()) {
                        eprintln!("Error in event callback: {}", e);
                    }
                }
            }

            current_block = to_block + 1;
        }

        let mut last_block_write = self.last_block.write().await;
        *last_block_write = target_block;

        Ok(())
    }
}

/// Helper for creating event callbacks
pub struct EventCallbacks;

impl EventCallbacks {
    /// Creates a callback that logs events to console
    pub fn logger() -> EventCallback {
        Arc::new(|event: RegistryEvent| {
            match event {
                RegistryEvent::DIDRegistered { did, block_number, .. } => {
                    println!("DID Registered: {} at block {}", did, block_number);
                }
                RegistryEvent::DIDUpdated { did, block_number, .. } => {
                    println!("DID Updated: {} at block {}", did, block_number);
                }
                RegistryEvent::DIDRevoked { did, block_number } => {
                    println!("DID Revoked: {} at block {}", did, block_number);
                }
            }
            Ok(())
        })
    }

    /// Creates a callback that invalidates DID resolver cache
    pub fn cache_invalidator<M: Middleware + 'static>(
        resolver: Arc<crate::did::resolver::BlockchainDIDResolver<M>>,
    ) -> EventCallback {
        Arc::new(move |event: RegistryEvent| {
            match event {
                RegistryEvent::DIDRegistered { did, .. }
                | RegistryEvent::DIDUpdated { did, .. }
                | RegistryEvent::DIDRevoked { did, .. } => {
                    // Parse DID and invalidate cache
                    if let Ok(parsed_did) = DID::parse(&did) {
                        resolver.clear_cache();
                    }
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_listener_config_default() {
        let config = EventListenerConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(12));
        assert_eq!(config.confirmations, 3);
        assert_eq!(config.max_block_range, 1000);
        assert!(!config.process_history);
    }

    #[test]
    fn test_registry_event_clone() {
        let event = RegistryEvent::DIDRegistered {
            did: "did:sage:test".to_string(),
            document: vec![1, 2, 3],
            block_number: 100,
        };

        let cloned = event.clone();

        match cloned {
            RegistryEvent::DIDRegistered { did, block_number, .. } => {
                assert_eq!(did, "did:sage:test");
                assert_eq!(block_number, 100);
            }
            _ => panic!("Wrong event type"),
        }
    }

    // Integration tests would require a deployed contract
    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_event_listener_start() {
        // This would test actual event listening with blockchain
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_event_processing() {
        // This would test event processing with blockchain
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_sync_to_block() {
        // This would test manual synchronization
        assert!(true);
    }
}
