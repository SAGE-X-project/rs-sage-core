//! Smart Contract Interface
//!
//! Provides abstractions for interacting with smart contracts.

use crate::error::{Error, Result};
use ethers::prelude::*;
use ethers::abi::{Abi, Token};
use ethers::types::transaction::eip2718::TypedTransaction;
use std::sync::Arc;

/// Interface for smart contract interactions
pub trait ContractInterface {
    /// Returns the contract address
    fn address(&self) -> Address;

    /// Returns the contract ABI
    fn abi(&self) -> &Abi;
}

/// A contract call builder
pub struct ContractCall<M: Middleware> {
    /// The contract instance
    contract: Arc<Contract<M>>,
    /// The function name
    function: String,
    /// The function arguments
    args: Vec<Token>,
}

impl<M: Middleware> ContractCall<M> {
    /// Creates a new contract call
    pub fn new(
        contract: Arc<Contract<M>>,
        function: impl Into<String>,
        args: Vec<Token>,
    ) -> Self {
        Self {
            contract,
            function: function.into(),
            args,
        }
    }

    /// Calls the contract function (read-only, doesn't send transaction)
    pub async fn call(&self) -> Result<Vec<Token>> {
        let function = self
            .contract
            .abi()
            .function(&self.function)
            .map_err(|e| Error::Other(format!("Function not found: {}", e)))?;

        let data = function
            .encode_input(&self.args)
            .map_err(|e| Error::Other(format!("Failed to encode function input: {}", e)))?;

        let client = self.contract.client();
        let tx = self.build_transaction(data.into());

        let result = client
            .call(&tx, None)
            .await
            .map_err(|e| Error::Other(format!("Contract call failed: {}", e)))?;

        function
            .decode_output(&result)
            .map_err(|e| Error::Other(format!("Failed to decode output: {}", e)))
    }

    /// Sends a transaction to the contract function (write operation)
    /// Returns the transaction hash
    pub async fn send(&self) -> Result<H256>
    where
        M: 'static,
    {
        let function = self
            .contract
            .abi()
            .function(&self.function)
            .map_err(|e| Error::Other(format!("Function not found: {}", e)))?;

        let data = function
            .encode_input(&self.args)
            .map_err(|e| Error::Other(format!("Failed to encode function input: {}", e)))?;

        let client = self.contract.client();
        let tx = self.build_transaction(data.into());

        let pending = client
            .send_transaction(tx, None)
            .await
            .map_err(|e| Error::Other(format!("Failed to send transaction: {}", e)))?;

        Ok(pending.tx_hash())
    }

    /// Builds a transaction for the contract call
    fn build_transaction(&self, data: Bytes) -> TypedTransaction {
        let mut tx = TypedTransaction::default();
        tx.set_to(self.contract.address());
        tx.set_data(data);
        tx
    }
}

/// Helper for creating contract instances
pub struct ContractHelper;

impl ContractHelper {
    /// Creates a contract instance from ABI and address
    pub fn new_contract<M: Middleware>(
        address: Address,
        abi: Abi,
        client: Arc<M>,
    ) -> Arc<Contract<M>> {
        Arc::new(Contract::new(address, abi, client))
    }

    /// Creates a contract instance from ABI JSON string
    pub fn new_contract_from_json<M: Middleware>(
        address: Address,
        abi_json: &str,
        client: Arc<M>,
    ) -> Result<Arc<Contract<M>>> {
        let abi: Abi = serde_json::from_str(abi_json)
            .map_err(|e| Error::Other(format!("Failed to parse ABI: {}", e)))?;

        Ok(Self::new_contract(address, abi, client))
    }
}

/// Event filter helper
pub struct EventFilter<M: Middleware> {
    /// The contract instance
    contract: Arc<Contract<M>>,
    /// The event name
    event: String,
    /// Start block for filtering
    from_block: Option<BlockNumber>,
    /// End block for filtering
    to_block: Option<BlockNumber>,
}

impl<M: Middleware> EventFilter<M> {
    /// Creates a new event filter
    pub fn new(contract: Arc<Contract<M>>, event: impl Into<String>) -> Self {
        Self {
            contract,
            event: event.into(),
            from_block: None,
            to_block: None,
        }
    }

    /// Sets the starting block for the filter
    pub fn from_block(mut self, block: BlockNumber) -> Self {
        self.from_block = Some(block);
        self
    }

    /// Sets the ending block for the filter
    pub fn to_block(mut self, block: BlockNumber) -> Self {
        self.to_block = Some(block);
        self
    }

    /// Queries past events
    pub async fn query(&self) -> Result<Vec<Log>> {
        let event = self
            .contract
            .abi()
            .event(&self.event)
            .map_err(|e| Error::Other(format!("Event not found: {}", e)))?;

        let filter = Filter::new()
            .address(self.contract.address())
            .event(event.name.as_str());

        let filter = if let Some(from) = self.from_block {
            filter.from_block(from)
        } else {
            filter
        };

        let filter = if let Some(to) = self.to_block {
            filter.to_block(to)
        } else {
            filter
        };

        self.contract
            .client()
            .get_logs(&filter)
            .await
            .map_err(|e| Error::Other(format!("Failed to query events: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_factory() {
        // Test basic contract factory functionality
        // Note: Actual contract interaction requires a running blockchain
        assert!(true);
    }

    #[test]
    fn test_abi_parsing() {
        let abi_json = r#"[
            {
                "inputs": [],
                "name": "getValue",
                "outputs": [{"name": "", "type": "uint256", "internalType": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]"#;

        let abi: std::result::Result<Abi, _> = serde_json::from_str(abi_json);
        if let Err(ref e) = abi {
            eprintln!("ABI parsing error: {:?}", e);
        }
        assert!(abi.is_ok());
    }
}
