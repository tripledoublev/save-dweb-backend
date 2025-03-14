use crate::common::DHTEntity;
use anyhow::{anyhow, Result};
use async_stream::stream;
use bytes::{BufMut, Bytes, BytesMut};
use core::hash;
use futures_core::stream::Stream;
use hex::decode;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;
use std::collections::HashMap;
use std::sync::Arc;
use std::{io::ErrorKind, path::PathBuf};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
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
    pub routing_context: RoutingContext,
    pub veilid: VeilidAPI,
    pub iroh_blobs: VeilidIrohBlobs,
}

impl Repo {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        secret_key: Option<CryptoTyped<CryptoKey>>,
        routing_context: RoutingContext,
        veilid: VeilidAPI,
        iroh_blobs: VeilidIrohBlobs,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            secret_key,
            routing_context,
            veilid,
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
            .get_dht_value(self.dht_record.key().clone(), ROUTE_SUBKEY, true)
            .await?
            .ok_or_else(|| anyhow!("Unable to get DHT value for route id blob"))?
            .data()
            .to_vec();

        Ok(value)
    }

    pub async fn get_file_stream(
        &self,
        file_name: &str,
    ) -> Result<impl Stream<Item = std::io::Result<Bytes>>> {
        let hash = self.get_file_hash(file_name).await?;
        // download the blob
        let receiver = self.iroh_blobs.read_file(hash.clone()).await?;

        let stream = ReceiverStream::new(receiver);

        Ok(stream)
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
            .get_dht_value(self.dht_record.key().clone(), HASH_SUBKEY, true)
            .await?
            .ok_or_else(|| anyhow!("Unable to get DHT value for repo root hash"))?;

        let data = value.data();

        // Decode the hex string (64 bytes) into a 32-byte hash
        let decoded_hash = decode(data).expect("Failed to decode hex string");

        // Ensure the decoded hash is 32 bytes
        if decoded_hash.len() != 32 {
            panic!(
                "Expected a 32-byte hash after decoding, but got {} bytes",
                decoded_hash.len()
            );
        }
        let mut hash_raw: [u8; 32] = [0; 32];
        hash_raw.copy_from_slice(&decoded_hash);

        // Now create the Hash object
        let hash = Hash::from_bytes(hash_raw);

        Ok(hash)
    }

    pub async fn update_collection_on_dht(&self) -> Result<()> {
        let collection_hash = self.get_collection_hash().await?;
        self.update_hash_on_dht(&collection_hash).await
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
    async fn get_or_create_collection(&self) -> Result<Hash> {
        if !self.can_write() {
            // Try to get the collection hash from the DHT (remote or unwritable repos)
            if let Ok(collection_hash) = self.get_hash_from_dht().await {
                // The collection hash is found, return it directly (no need for a name)
                println!("Collection hash found in DHT: {:?}", collection_hash);
                return Ok(collection_hash);
            } else {
                // Error if we're trying to create a collection in a read-only repo
                return Err(anyhow::Error::msg(
                    "Collection not found and cannot create in read-only repo",
                ));
            }
        }
        // If the repo is writable, check if the collection exists
        let collection_name = self.get_name().await?;
        if let Ok(collection_hash) = self.iroh_blobs.collection_hash(&collection_name).await {
            // Collection exists, return the hash
            println!("Collection hash found in store: {:?}", collection_hash);
            Ok(collection_hash)
        } else {
            // Create a new collection
            println!("Creating new collection...");
            let new_hash = match self.iroh_blobs.create_collection(&collection_name).await {
                Ok(hash) => {
                    println!("New collection created with hash: {:?}", hash);
                    hash
                }
                Err(e) => {
                    eprintln!("Failed to create collection: {:?}", e);
                    return Err(e);
                }
            };

            // Update the DHT with the new collection hash
            if let Err(e) = self.update_collection_on_dht().await {
                eprintln!("Failed to update DHT: {:?}", e);
                return Err(e);
            }

            // Return the new collection hash
            Ok(new_hash)
        }
    }

    // Method to retrieve a file's hash from the collection
    pub async fn get_file_hash(&self, file_name: &str) -> Result<Hash> {
        // Ensure the collection exists before reading
        let collection_hash = self.get_or_create_collection().await?;

        self.iroh_blobs
            .get_file_from_collection_hash(&collection_hash, file_name)
            .await
    }

    pub async fn list_files(&self) -> Result<Vec<String>> {
        if self.can_write() {
            let hash = self.get_or_create_collection().await?;
            self.list_files_from_collection_hash(&hash).await
        } else {
            let got_hash = self.get_hash_from_dht().await;

            // Return empty list if we can't fetch from the DHT
            if got_hash.is_err() {
                Ok(Vec::new())
            } else {
                self.list_files_from_collection_hash(&got_hash.unwrap())
                    .await
            }
        }
    }

    pub async fn list_files_from_collection_hash(
        &self,
        collection_hash: &Hash,
    ) -> Result<Vec<String>> {
        let file_list = self
            .iroh_blobs
            .list_files_from_hash(collection_hash)
            .await?;

        Ok(file_list)
    }

    // Method to delete a file from the collection
    pub async fn delete_file(&self, file_name: &str) -> Result<Hash> {
        self.check_write_permissions()?;

        // Ensure the collection exists before deleting a file
        let collection_hash = self.get_or_create_collection().await?;

        // Delete the file from the collection and get the new collection hash
        let deleted_hash = self
            .iroh_blobs
            .delete_file_from_collection_hash(&collection_hash, file_name)
            .await?;

        // Persist the new collection hash with the name to the store
        let collection_name = self.get_name().await?;
        self.iroh_blobs
            .persist_collection_with_name(&collection_name, &deleted_hash)
            .await?;

        // Update the DHT with the new collection hash
        self.update_collection_on_dht().await?;

        Ok(deleted_hash)
    }

    // Method to get the collection's hash
    async fn get_collection_hash(&self) -> Result<Hash> {
        let collection_name = self.get_name().await?;

        self.iroh_blobs.collection_hash(&collection_name).await
    }

    pub async fn upload(&self, file_name: &str, data_to_upload: Vec<u8>) -> Result<Hash> {
        self.check_write_permissions()?;

        // Ensure the collection exists before uploading
        let collection_hash = self.get_or_create_collection().await?;

        // Use the repo name
        let collection_name = self.get_name().await?;
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(data_to_upload.clone())))
            .await
            .unwrap();
        drop(tx);

        let file_hash = self
            .iroh_blobs
            .upload_to(&collection_name, file_name, rx)
            .await?;

        // Persist the new collection hash with the name to the store
        self.iroh_blobs
            .persist_collection_with_name(&collection_name, &file_hash)
            .await?;

        // Update the collection hash on the DHT
        self.update_collection_on_dht().await?;

        Ok(file_hash)
    }

    pub async fn set_file_and_update_dht(
        &self,
        collection_name: &str,
        file_name: &str,
        file_hash: &Hash,
    ) -> Result<Hash> {
        // Step 1: Update the collection with the new file using `set_file`
        let updated_collection_hash = self
            .iroh_blobs
            .set_file(collection_name, file_name, file_hash)
            .await?;
        println!("Updated collection hash: {:?}", updated_collection_hash);

        // Step 2: Persist the new collection hash locally
        self.iroh_blobs
            .persist_collection_with_name(collection_name, &updated_collection_hash)
            .await?;
        println!(
            "Collection persisted with new hash: {:?}",
            updated_collection_hash
        );

        // Step 3: Update the DHT with the new collection hash
        self.update_collection_on_dht().await?;
        println!(
            "DHT updated with new collection hash: {:?}",
            updated_collection_hash
        );

        Ok(updated_collection_hash)
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

    fn get_routing_context(&self) -> RoutingContext {
        self.routing_context.clone()
    }

    fn get_veilid_api(&self) -> VeilidAPI {
        self.veilid.clone()
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        self.secret_key.clone().map(|key| key.value)
    }
}
