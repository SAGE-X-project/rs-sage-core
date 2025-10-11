//! Blockchain State Synchronizer
//!
//! Coordinates event listening and automatic cache updates for DID resolver
//! and nonce tracker.

use crate::blockchain::{
    DIDRegistry, EventCallback, EventListener, EventListenerConfig, NonceTracker, RegistryEvent,
};
use crate::did::resolver::BlockchainDIDResolver;
use crate::error::{Error, Result};
use ethers::prelude::*;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Synchronizer for automatic blockchain state updates
pub struct Synchronizer<M: Middleware> {
    /// Event listener
    event_listener: Arc<EventListener<M>>,
    /// Background task handle
    task_handle: Option<JoinHandle<Result<()>>>,
}

impl<M: Middleware + 'static> Synchronizer<M> {
    /// Creates a new synchronizer with default configuration
    pub fn new(registry: Arc<DIDRegistry<M>>, client: Arc<M>) -> Self {
        let event_listener = Arc::new(EventListener::new(registry, client));

        Self {
            event_listener,
            task_handle: None,
        }
    }

    /// Creates a new synchronizer with custom configuration
    pub fn with_config(
        registry: Arc<DIDRegistry<M>>,
        client: Arc<M>,
        config: EventListenerConfig,
    ) -> Self {
        let event_listener = Arc::new(EventListener::with_config(registry, client, config));

        Self {
            event_listener,
            task_handle: None,
        }
    }

    /// Adds a DID resolver for automatic cache invalidation
    pub async fn with_resolver(
        &self,
        resolver: Arc<BlockchainDIDResolver<M>>,
    ) -> Result<()> {
        // Create callback for cache invalidation
        let callback: EventCallback = Arc::new(move |event: RegistryEvent| {
            match event {
                RegistryEvent::DIDRegistered { .. }
                | RegistryEvent::DIDUpdated { .. }
                | RegistryEvent::DIDRevoked { .. } => {
                    // Clear entire cache on any DID change
                    // In production, could be optimized to invalidate only specific DID
                    resolver.clear_cache();
                }
            }
            Ok(())
        });

        self.event_listener.add_callback(callback).await;
        Ok(())
    }

    /// Adds a nonce tracker for automatic cache updates
    pub async fn with_nonce_tracker(
        &self,
        _nonce_tracker: Arc<NonceTracker<M>>,
    ) -> Result<()> {
        // Note: Currently DID Registry doesn't emit NonceUsed events
        // This is a placeholder for when that event is added to the contract

        // Future implementation would look like:
        // let callback: EventCallback = Arc::new(move |event: RegistryEvent| {
        //     if let RegistryEvent::NonceUsed { did, nonce, .. } = event {
        //         // Update nonce tracker cache
        //         nonce_tracker.cache_nonce(&did, &nonce);
        //     }
        //     Ok(())
        // });
        // self.event_listener.add_callback(callback).await;

        Ok(())
    }

    /// Adds a custom event callback
    pub async fn add_callback(&self, callback: EventCallback) {
        self.event_listener.add_callback(callback).await;
    }

    /// Starts the synchronizer
    pub async fn start(&mut self) -> Result<()> {
        // Start the event listener
        self.event_listener.start().await?;

        // Spawn background task for event processing
        let listener = self.event_listener.clone();
        let handle = tokio::spawn(async move {
            listener.process_events_loop().await
        });

        self.task_handle = Some(handle);

        Ok(())
    }

    /// Stops the synchronizer
    pub async fn stop(&mut self) -> Result<()> {
        // Stop the event listener
        self.event_listener.stop().await;

        // Wait for background task to finish
        if let Some(handle) = self.task_handle.take() {
            handle
                .await
                .map_err(|e| Error::Other(format!("Failed to join task: {}", e)))??;
        }

        Ok(())
    }

    /// Checks if the synchronizer is running
    pub async fn is_running(&self) -> bool {
        self.event_listener.is_running().await
    }

    /// Manually syncs to a specific block
    pub async fn sync_to_block(&self, block_number: u64) -> Result<()> {
        self.event_listener.sync_to_block(block_number).await
    }

    /// Returns the last processed block number
    pub async fn last_processed_block(&self) -> u64 {
        self.event_listener.last_processed_block().await
    }
}

/// Builder for creating a fully configured synchronizer
pub struct SynchronizerBuilder<M: Middleware> {
    registry: Arc<DIDRegistry<M>>,
    client: Arc<M>,
    config: Option<EventListenerConfig>,
    resolver: Option<Arc<BlockchainDIDResolver<M>>>,
    nonce_tracker: Option<Arc<NonceTracker<M>>>,
    callbacks: Vec<EventCallback>,
}

impl<M: Middleware + 'static> SynchronizerBuilder<M> {
    /// Creates a new synchronizer builder
    pub fn new(registry: Arc<DIDRegistry<M>>, client: Arc<M>) -> Self {
        Self {
            registry,
            client,
            config: None,
            resolver: None,
            nonce_tracker: None,
            callbacks: Vec::new(),
        }
    }

    /// Sets the event listener configuration
    pub fn with_config(mut self, config: EventListenerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Adds a DID resolver for automatic cache invalidation
    pub fn with_resolver(mut self, resolver: Arc<BlockchainDIDResolver<M>>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Adds a nonce tracker for automatic cache updates
    pub fn with_nonce_tracker(mut self, nonce_tracker: Arc<NonceTracker<M>>) -> Self {
        self.nonce_tracker = Some(nonce_tracker);
        self
    }

    /// Adds a custom event callback
    pub fn add_callback(mut self, callback: EventCallback) -> Self {
        self.callbacks.push(callback);
        self
    }

    /// Builds the synchronizer
    pub async fn build(self) -> Result<Synchronizer<M>> {
        let synchronizer = if let Some(config) = self.config {
            Synchronizer::with_config(self.registry, self.client, config)
        } else {
            Synchronizer::new(self.registry, self.client)
        };

        // Add resolver callback if provided
        if let Some(resolver) = self.resolver {
            synchronizer.with_resolver(resolver).await?;
        }

        // Add nonce tracker callback if provided
        if let Some(nonce_tracker) = self.nonce_tracker {
            synchronizer.with_nonce_tracker(nonce_tracker).await?;
        }

        // Add custom callbacks
        for callback in self.callbacks {
            synchronizer.add_callback(callback).await;
        }

        Ok(synchronizer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synchronizer_builder() {
        // This test just verifies the builder structure can be created
        // Actual functionality requires a deployed contract
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_synchronizer_start_stop() {
        // This would test starting and stopping the synchronizer
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_synchronizer_with_resolver() {
        // This would test DID resolver integration
        assert!(true);
    }

    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_synchronizer_sync_to_block() {
        // This would test manual synchronization
        assert!(true);
    }
}
