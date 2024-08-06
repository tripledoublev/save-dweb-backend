use std::sync::Arc;
use std::path::Path;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use tracing::info;
use eyre::{Result, WrapErr};
use async_stream::stream;
use futures_core::stream::Stream;
use veilid_core::{
    CryptoKey, DHTRecordDescriptor, SharedSecret, CryptoTyped, CryptoSystemVLD0, RoutingContext, OperationId, Target, CryptoSystem, PublicKey, TypedKey, CRYPTO_KIND_VLD0
};
use crate::common::DHTEntity;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
pub struct Repo {
    pub id: CryptoKey,
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub secret_key: Option<CryptoTyped<CryptoKey>>,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
    pub tunnels: Vec<PublicKey>, 
}

impl Repo {
    pub fn new(
        id: CryptoKey,
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        secret_key: Option<CryptoTyped<CryptoKey>>,
        routing_context: Arc<RoutingContext>,
        crypto_system: CryptoSystemVLD0,
    ) -> Self {
        Self {
            id,
            dht_record,
            encryption_key,
            secret_key,
            routing_context,
            crypto_system,
            tunnels: Vec::new(),
        }
    }

    pub async fn retrieve_tunnel(&self) -> Option<String> {
        info!("Attempting to retrieve existing tunnel ID from DHT");
        let key = self.get_dht_record().key().clone();
        if let Ok(Some(tunnel_id)) = self.routing_context.get_dht_value(key, 0, false).await {
            let tunnel_id_str = String::from_utf8(tunnel_id.data().to_vec()).ok()?;
            if !tunnel_id_str.trim().is_empty() {
                info!("Retrieved existing tunnel ID from DHT: {}", tunnel_id_str);
                return Some(tunnel_id_str);
            }
        }
        info!("No existing tunnel ID found in DHT");
        None
    }

    pub async fn establish_tunnel(&mut self) -> eyre::Result<String> {
        let schema = self.get_dht_record().schema().clone();
        let max_subkey = schema.max_subkey();

        info!("Max subkey: {}", max_subkey);

        let new_tunnel_id = self.generate_new_tunnel_id()?;
        let tunnel_id_base64 = BASE64_STANDARD.encode(&new_tunnel_id);

        info!("Establishing a new tunnel with ID: {}", tunnel_id_base64);

        let key = self.get_dht_record().key().clone();
        let encrypted_id = self.encrypt_aead(&new_tunnel_id, None)?;
        self.routing_context.set_dht_value(key.clone(), 0, encrypted_id, None).await.wrap_err("Failed to store tunnel ID in DHT")?;

        info!("New tunnel ID saved to DHT");

        // Store the new tunnel public key
        match PublicKey::try_from(new_tunnel_id.as_slice()) {
            Ok(public_key) => self.tunnels.push(public_key),
            Err(e) => return Err(eyre::eyre!("Failed to create public key from tunnel ID: {:?}", e)),
        }

        Ok(tunnel_id_base64)
    }

    fn generate_new_tunnel_id(&self) -> eyre::Result<Vec<u8>> {
        let identifier = self.crypto_system.generate_hash(b"tunnel_data");
        info!("Generated new tunnel ID");
        Ok(identifier.as_ref().to_vec())
    }

    pub async fn send_ping(&self, target: Target) -> eyre::Result<()> {
        let message = b"ping".to_vec();
        self.routing_context.app_call(target, message).await?;
        Ok(())
    }

    pub fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }

    pub fn file_names(&self) -> Result<Vec<String>> {
        unimplemented!("WIP")
    }

    pub async fn has_file(&self, file_name: &str) -> Result<bool> {
        unimplemented!("WIP")
    }

    pub async fn get_file_stream(&self, file_name: &str) -> Result<impl Stream<Item = Vec<u8>>> {
        let s = stream! {
            let mut vec: Vec<u8> = Vec::new();
            yield vec;
        };

        Ok(s)
    }

    pub async fn download_all(&self) -> Result<()> {
        unimplemented!("WIP")
    }

    // Get the list of active tunnel public keys
    pub fn get_tunnels(&self) -> Vec<PublicKey> {
        self.tunnels.clone()
    }

    // Remove a tunnel public key from the list before closing
    pub async fn remove_tunnel(&mut self, public_key: &PublicKey) -> eyre::Result<()> {
        if let Some(pos) = self.tunnels.iter().position(|x| x == public_key) {
            self.tunnels.remove(pos);
            let key = self.get_dht_record().key().clone();
            let typed_key = TypedKey::new(CRYPTO_KIND_VLD0, key.value.clone());
            self.routing_context.close_dht_record(typed_key).await.wrap_err("Failed to remove tunnel ID from DHT")?;
            info!("Removed tunnel ID from DHT");
        }
        Ok(())
    }
}

impl DHTEntity for Repo {
    fn get_id(&self) -> CryptoKey {
        self.id.clone()
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
