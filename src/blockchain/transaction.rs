//! Transaction Signing and Submission
//!
//! Provides utilities for creating, signing, and sending blockchain transactions.

use crate::error::{Error, Result};
use ethers::prelude::*;
use ethers::providers::JsonRpcClient;
use ethers::types::transaction::eip2718::TypedTransaction;

/// Re-export ethers TransactionReceipt for convenience
pub use ethers::types::TransactionReceipt;

/// Transaction builder for creating and signing transactions
pub struct Transaction {
    /// Transaction type
    tx: TypedTransaction,
}

impl Transaction {
    /// Creates a new transaction to an address
    pub fn new(to: Address) -> Self {
        let mut tx = TypedTransaction::default();
        tx.set_to(to);
        Self { tx }
    }

    /// Creates a new contract deployment transaction
    pub fn deploy(bytecode: Bytes) -> Self {
        let mut tx = TypedTransaction::default();
        tx.set_data(bytecode);
        Self { tx }
    }

    /// Sets the transaction value (amount of ETH to send)
    pub fn value(mut self, value: U256) -> Self {
        self.tx.set_value(value);
        self
    }

    /// Sets the transaction data (contract call data)
    pub fn data(mut self, data: Bytes) -> Self {
        self.tx.set_data(data);
        self
    }

    /// Sets the gas limit
    pub fn gas(mut self, gas: U256) -> Self {
        self.tx.set_gas(gas);
        self
    }

    /// Sets the gas price
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.tx.set_gas_price(gas_price);
        self
    }

    /// Sets the nonce
    pub fn nonce(mut self, nonce: U256) -> Self {
        self.tx.set_nonce(nonce);
        self
    }

    /// Sets the chain ID
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.tx.set_chain_id(chain_id);
        self
    }

    /// Builds the transaction
    pub fn build(self) -> TypedTransaction {
        self.tx
    }

    /// Signs and sends the transaction using a signer
    /// Returns the transaction hash
    pub async fn send<M: Middleware>(
        self,
        signer: &SignerMiddleware<M, LocalWallet>,
    ) -> Result<H256> {
        let pending = signer
            .send_transaction(self.tx, None)
            .await
            .map_err(|e| Error::Other(format!("Failed to send transaction: {}", e)))?;
        Ok(pending.tx_hash())
    }

    /// Signs the transaction and returns the raw signed transaction bytes
    pub async fn sign(
        self,
        signer: &LocalWallet,
        _chain_id: u64,
    ) -> Result<Bytes> {
        let sig = signer
            .sign_transaction(&self.tx)
            .await
            .map_err(|e| Error::Other(format!("Failed to sign transaction: {}", e)))?;

        let rlp = self.tx.rlp_signed(&sig);
        Ok(rlp)
    }
}

/// Transaction helper functions
pub struct TransactionHelper;

impl TransactionHelper {
    /// Waits for a transaction to be mined and returns the receipt
    pub async fn wait_for_confirmation<P: JsonRpcClient>(
        pending: PendingTransaction<'_, P>,
        _confirmations: usize,
    ) -> Result<TransactionReceipt> {
        pending
            .await
            .map_err(|e| Error::Other(format!("Transaction failed: {}", e)))?
            .ok_or_else(|| Error::Other("Transaction receipt not found".to_string()))
    }

    /// Checks if a transaction was successful
    pub fn is_success(receipt: &TransactionReceipt) -> bool {
        receipt.status == Some(1.into())
    }

    /// Gets the contract address from a deployment transaction receipt
    pub fn get_contract_address(receipt: &TransactionReceipt) -> Option<Address> {
        receipt.contract_address
    }

    /// Gets the gas used from a transaction receipt
    pub fn get_gas_used(receipt: &TransactionReceipt) -> U256 {
        receipt.gas_used.unwrap_or_default()
    }

    /// Calculates the transaction cost (gas used * gas price)
    pub fn get_transaction_cost(receipt: &TransactionReceipt) -> U256 {
        let gas_used = receipt.gas_used.unwrap_or_default();
        let gas_price = receipt.effective_gas_price.unwrap_or_default();
        gas_used * gas_price
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_builder() {
        let to = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();

        let tx = Transaction::new(to)
            .value(U256::from(1000))
            .gas(U256::from(21000))
            .chain_id(1)
            .build();

        assert_eq!(tx.to(), Some(&NameOrAddress::Address(to)));
        assert_eq!(tx.value(), Some(&U256::from(1000)));
        assert_eq!(tx.gas(), Some(&U256::from(21000)));
    }

    #[test]
    fn test_deploy_transaction() {
        let bytecode = Bytes::from(vec![0x60, 0x80, 0x60, 0x40]);
        let tx = Transaction::deploy(bytecode.clone()).build();

        assert_eq!(tx.data(), Some(&bytecode));
        assert_eq!(tx.to(), None); // Deployment transactions have no 'to' address
    }

    #[test]
    fn test_transaction_helper_is_success() {
        let mut receipt = TransactionReceipt::default();
        receipt.status = Some(1.into());
        assert!(TransactionHelper::is_success(&receipt));

        receipt.status = Some(0.into());
        assert!(!TransactionHelper::is_success(&receipt));
    }

    #[test]
    fn test_transaction_helper_gas_used() {
        let mut receipt = TransactionReceipt::default();
        receipt.gas_used = Some(U256::from(50000));
        assert_eq!(TransactionHelper::get_gas_used(&receipt), U256::from(50000));
    }

    #[test]
    fn test_transaction_cost_calculation() {
        let mut receipt = TransactionReceipt::default();
        receipt.gas_used = Some(U256::from(50000));
        receipt.effective_gas_price = Some(U256::from(20_000_000_000u64)); // 20 gwei

        let cost = TransactionHelper::get_transaction_cost(&receipt);
        assert_eq!(cost, U256::from(50000u64) * U256::from(20_000_000_000u64));
    }
}
