//! DID Registry Smart Contract Interface
//!
//! Provides an interface to interact with the DID Registry smart contract.

use crate::blockchain::{ContractCall, ContractHelper};
use crate::did::{DIDDocument, DID};
use crate::error::{Error, Result};
use ethers::prelude::*;
use ethers::abi::{Abi, Token};
use std::sync::Arc;

/// DID Registry contract interface
pub struct DIDRegistry<M: Middleware> {
    /// The contract instance
    contract: Arc<Contract<M>>,
    /// The middleware client
    #[allow(dead_code)]
    client: Arc<M>,
}

impl<M: Middleware + 'static> DIDRegistry<M> {
    /// Creates a new DID Registry instance
    pub fn new(contract_address: Address, client: Arc<M>) -> Self {
        let abi = Self::abi();
        let contract = ContractHelper::new_contract(contract_address, abi, client.clone());

        Self { contract, client }
    }

    /// Returns the DID Registry ABI
    fn abi() -> Abi {
        // This is a simplified ABI for the DID Registry contract
        // In production, this would be generated using `abigen!` macro
        serde_json::from_str(
            r#"[
                {
                    "inputs": [
                        {"name": "did", "type": "string"},
                        {"name": "document", "type": "bytes"}
                    ],
                    "name": "registerDID",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "did", "type": "string"}],
                    "name": "getDIDDocument",
                    "outputs": [{"name": "", "type": "bytes"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "did", "type": "string"},
                        {"name": "document", "type": "bytes"}
                    ],
                    "name": "updateDIDDocument",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "did", "type": "string"}],
                    "name": "revokeDID",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "did", "type": "string"}],
                    "name": "isDIDRegistered",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "did", "type": "string"},
                        {"name": "nonce", "type": "string"}
                    ],
                    "name": "useNonce",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "did", "type": "string"},
                        {"name": "nonce", "type": "string"}
                    ],
                    "name": "isNonceUsed",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "anonymous": false,
                    "inputs": [
                        {"indexed": true, "name": "did", "type": "string"},
                        {"indexed": false, "name": "document", "type": "bytes"}
                    ],
                    "name": "DIDRegistered",
                    "type": "event"
                },
                {
                    "anonymous": false,
                    "inputs": [
                        {"indexed": true, "name": "did", "type": "string"},
                        {"indexed": false, "name": "document", "type": "bytes"}
                    ],
                    "name": "DIDUpdated",
                    "type": "event"
                },
                {
                    "anonymous": false,
                    "inputs": [
                        {"indexed": true, "name": "did", "type": "string"}
                    ],
                    "name": "DIDRevoked",
                    "type": "event"
                }
            ]"#,
        )
        .expect("Failed to parse DID Registry ABI")
    }

    /// Returns the contract address
    pub fn address(&self) -> Address {
        self.contract.address()
    }

    /// Registers a new DID on-chain
    pub async fn register_did(&self, did: &DID, document: &DIDDocument) -> Result<H256> {
        // Serialize DID Document to JSON bytes
        let doc_json = serde_json::to_vec(document)
            .map_err(|e| Error::Other(format!("Failed to serialize DID Document: {}", e)))?;

        let call = ContractCall::new(
            self.contract.clone(),
            "registerDID",
            vec![
                Token::String(did.to_string()),
                Token::Bytes(doc_json),
            ],
        );

        call.send().await
    }

    /// Gets a DID Document from the blockchain
    pub async fn get_did_document(&self, did: &DID) -> Result<Option<DIDDocument>> {
        let call = ContractCall::new(
            self.contract.clone(),
            "getDIDDocument",
            vec![Token::String(did.to_string())],
        );

        let result = call.call().await?;

        if result.is_empty() {
            return Ok(None);
        }

        let doc_bytes = result[0]
            .clone()
            .into_bytes()
            .ok_or_else(|| Error::Other("Invalid response from contract".to_string()))?;

        if doc_bytes.is_empty() {
            return Ok(None);
        }

        let document: DIDDocument = serde_json::from_slice(&doc_bytes)
            .map_err(|e| Error::Other(format!("Failed to deserialize DID Document: {}", e)))?;

        Ok(Some(document))
    }

    /// Updates an existing DID Document
    pub async fn update_did_document(&self, did: &DID, document: &DIDDocument) -> Result<H256> {
        let doc_json = serde_json::to_vec(document)
            .map_err(|e| Error::Other(format!("Failed to serialize DID Document: {}", e)))?;

        let call = ContractCall::new(
            self.contract.clone(),
            "updateDIDDocument",
            vec![
                Token::String(did.to_string()),
                Token::Bytes(doc_json),
            ],
        );

        call.send().await
    }

    /// Revokes a DID
    pub async fn revoke_did(&self, did: &DID) -> Result<H256> {
        let call = ContractCall::new(
            self.contract.clone(),
            "revokeDID",
            vec![Token::String(did.to_string())],
        );

        call.send().await
    }

    /// Checks if a DID is registered
    pub async fn is_did_registered(&self, did: &DID) -> Result<bool> {
        let call = ContractCall::new(
            self.contract.clone(),
            "isDIDRegistered",
            vec![Token::String(did.to_string())],
        );

        let result = call.call().await?;

        result[0]
            .clone()
            .into_bool()
            .ok_or_else(|| Error::Other("Invalid response from contract".to_string()))
    }

    /// Marks a nonce as used
    pub async fn use_nonce(&self, did: &DID, nonce: &str) -> Result<H256> {
        let call = ContractCall::new(
            self.contract.clone(),
            "useNonce",
            vec![
                Token::String(did.to_string()),
                Token::String(nonce.to_string()),
            ],
        );

        call.send().await
    }

    /// Checks if a nonce has been used
    pub async fn is_nonce_used(&self, did: &DID, nonce: &str) -> Result<bool> {
        let call = ContractCall::new(
            self.contract.clone(),
            "isNonceUsed",
            vec![
                Token::String(did.to_string()),
                Token::String(nonce.to_string()),
            ],
        );

        let result = call.call().await?;

        result[0]
            .clone()
            .into_bool()
            .ok_or_else(|| Error::Other("Invalid response from contract".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_registry_abi() {
        let abi = DIDRegistry::<Provider<Http>>::abi();
        assert!(!abi.functions.is_empty());
        assert!(abi.function("registerDID").is_ok());
        assert!(abi.function("getDIDDocument").is_ok());
        assert!(abi.event("DIDRegistered").is_ok());
    }

    // Integration tests require deployed contract
    #[tokio::test]
    #[ignore = "Requires deployed DID Registry contract"]
    async fn test_register_did() {
        // This test would require a deployed contract and a running blockchain
        assert!(true);
    }
}
