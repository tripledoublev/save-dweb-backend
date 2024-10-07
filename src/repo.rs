use crate::common::DHTEntity;
use anyhow::{anyhow, Result};
use async_stream::stream;
use bytes::{BufMut, Bytes, BytesMut};
use futures_core::stream::Stream;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{io::ErrorKind, path::PathBuf};
use tokio::sync::{broadcast, mpsc};
use veilid_core::{
    CryptoKey, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, ProtectedStore, RoutingContext,
    SharedSecret, Target, VeilidAPI, VeilidUpdate,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

pub const HASH_SUBKEY: u32 = 1;
pub const ROUTE_SUBKEY: u32 = 2;

#[derive(Clone)]
pub struct Repo {
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub secret_key: Option<CryptoTyped<CryptoKey>>,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
    pub iroh_blobs: VeilidIrohBlobs,
}

impl Repo {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        secret_key: Option<CryptoTyped<CryptoKey>>,
        routing_context: Arc<RoutingContext>,
        crypto_system: CryptoSystemVLD0,
        iroh_blobs: VeilidIrohBlobs,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            secret_key,
            routing_context,
            crypto_system,
            iroh_blobs,
        }
    }

    pub fn id(&self) -> CryptoKey {
        self.dht_record.key().value.clone()
    }

    pub fn can_write(&self) -> bool {
        self.secret_key.is_some()
    }

    pub async fn update_route_on_dht(&self) -> Result<()> {
        let route_id_blob = self.iroh_blobs.route_id_blob().await;

        // Set the root hash in the DHT record
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                ROUTE_SUBKEY,
                route_id_blob,
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to store route ID blob in DHT: {}", e))?;

        Ok(())
    }

    pub fn file_names(&self) -> Result<Vec<String>> {
        unimplemented!("WIP")
    }

    pub async fn has_file(&self, file_name: &str) -> Result<bool> {
        unimplemented!("WIP")
    }

    pub async fn has_hash(&self, hash: &Hash) -> Result<bool> {
        if self.can_write() {
            Ok(self.iroh_blobs.has_hash(hash).await)
        } else {
            let route_id = self.get_route_id_blob().await?;
            self.iroh_blobs.ask_hash(route_id, *hash).await
        }
    }

    pub async fn get_route_id_blob(&self) -> Result<Vec<u8>> {
        if self.can_write() {
            return Ok(self.iroh_blobs.route_id_blob().await);
        }

        let value = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), ROUTE_SUBKEY, false)
            .await?
            .ok_or_else(|| anyhow!("Unable to get DHT value for route id blob"))?;

        Ok(value.data().to_vec())
    }

    pub async fn get_file_stream(&self, file_name: &str) -> Result<impl Stream<Item = Vec<u8>>> {
        let s = stream! {
            let mut vec: Vec<u8> = Vec::new();
            yield vec;
        };

        Ok(s)
    }

    pub async fn download_all(&self) -> Result<()> {
        // Get hash from dht
        // Download collection
        // Iterate through hahses in collection
        // Download
        unimplemented!("WIP")
    }

    pub async fn update_hash_on_dht(&self, hash: &Hash) -> Result<()> {
        // Convert hash to hex for DHT storage
        let root_hash_hex = hash.to_hex();
        // Set the root hash in the DHT record
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                HASH_SUBKEY,
                root_hash_hex.clone().into(),
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to store collection blob in DHT: {}", e))?;

        Ok(())
    }

    pub async fn get_hash_from_dht(&self) -> Result<Hash> {
        let value = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), HASH_SUBKEY, false)
            .await?
            .ok_or_else(|| anyhow!("Unable to get DHT value for repo root hash"))?;
        let mut hash_raw: [u8; 32] = [0; 32];
        hash_raw.copy_from_slice(value.data());

        let hash = Hash::from_bytes(hash_raw);

        Ok(hash)
    }

    pub async fn upload_blob(&self, file_path: PathBuf) -> Result<Hash> {
        if !self.can_write() {
            return Err(anyhow!("Cannot upload blob, repo is not writable"));
        }
        // Use repo id as key for a collection
        // Upload the file and get the hash
        let hash = self.iroh_blobs.upload_from_path(file_path).await?;

        self.update_hash_on_dht(&hash).await?;
        Ok(hash)
    }

    // Method to get or create a collection associated with the repo
    pub async fn get_or_create_collection(&self) -> Result<Hash> {
        self.check_write_permissions()?;
        let collection_name = self.get_name().await?;

        match self.iroh_blobs.collection_hash(&collection_name).await {
            Ok(collection_hash) => Ok(collection_hash),
            Err(_) => self.iroh_blobs.create_collection(&collection_name).await,
        }
    }

    // Method to add a file to the collection identified by repo ID
    pub async fn set_file_in_repo_collection(&self, file_name: &str, file_hash: Hash) -> Result<Hash> {
        self.check_write_permissions()?;
        let collection_name = self.get_name().await?;

        self.iroh_blobs.set_file(&collection_name, file_name, &file_hash).await
    }

    // Method to retrieve a file's hash from the collection
    pub async fn get_file_hash(&self, file_name: &str) -> Result<Hash> {
        let collection_name = self.get_name().await?;

        self.iroh_blobs.get_file(&collection_name, file_name).await
    }

    // Method to list all files in the collection
    async fn list_files_in_repo_collection(&self) -> Result<Vec<String>> {
        let collection_name = self.get_name().await?;

        self.iroh_blobs.list_files(&collection_name).await
    }

    // Method to delete a file from the collection
    pub async fn delete_file_from_repo_collection(&self, file_name: &str) -> Result<Hash> {
        self.check_write_permissions()?;
        let collection_name = self.get_name().await?;

        self.iroh_blobs.delete_file(&collection_name, file_name).await
    }

    // Method to get the collection's hash
    pub async fn get_collection_hash(&self) -> Result<Hash> {
        let collection_name = self.get_name().await?;

        self.iroh_blobs.collection_hash(&collection_name).await
    }

    // Method to upload a file to the collection via a file stream
    pub async fn upload_to_collection(&self, file_name: &str, data_to_upload: Vec<u8>) -> Result<Hash> {
        self.check_write_permissions()?;
        let collection_name = self.get_name().await?;

        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(data_to_upload.clone()))).await.unwrap();
        drop(tx);

        self.iroh_blobs.upload_to(&collection_name, file_name, rx).await
    }

    // Helper method to check if the repo can write
    fn check_write_permissions(&self) -> Result<()> {
        if !self.can_write() {
            return Err(anyhow::Error::msg("Repo does not have write permissions"));
        }
        Ok(())
    }
}

impl DHTEntity for Repo {
    fn get_id(&self) -> CryptoKey {
        self.id().clone()
    }

    fn get_encryption_key(&self) -> SharedSecret {
        self.encryption_key.clone() 
    }

    fn get_routing_context(&self) -> Arc<RoutingContext> {
        self.routing_context.clone()
    }

    fn get_crypto_system(&self) -> CryptoSystemVLD0 {
        self.crypto_system.clone()
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        self.secret_key.clone().map(|key| key.value)
    }
}
