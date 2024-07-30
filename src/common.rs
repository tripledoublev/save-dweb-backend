#![allow(async_fn_in_trait)]
#![allow(clippy::async_yields_async)]

use serde::{Serialize, Deserialize};
use eyre::{Result, anyhow};
use std::sync::Arc;
use veilid_core::{
    CryptoKey, SharedSecret, CryptoTyped, DHTRecordDescriptor, RoutingContext, CryptoSystemVLD0,
    ProtectedStore, Nonce, CRYPTO_KIND_VLD0, CryptoSystem
};

#[derive(Serialize, Deserialize)]
pub struct CommonKeypair {
    pub public_key: CryptoKey,
    pub secret_key: Option<CryptoKey>,
    pub encryption_key: SharedSecret,
}

impl CommonKeypair {
    pub async fn store_keypair(&self, protected_store: &ProtectedStore, id: &CryptoKey) -> Result<()> {
        let keypair_data = serde_cbor::to_vec(&self).map_err(|e| anyhow!("Failed to serialize keypair: {}", e))?;
        protected_store.save_user_secret(id.to_string(), &keypair_data).await.map_err(|e| anyhow!("Unable to store keypair: {}", e))?;
        Ok(())
    }

    pub async fn load_keypair(protected_store: &ProtectedStore, id: &CryptoKey) -> Result<Self> {
        let keypair_data = protected_store.load_user_secret(id.to_string()).await.map_err(|_| anyhow!("Failed to load keypair"))?.ok_or_else(|| anyhow!("Keypair not found"))?;
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data).map_err(|_| anyhow!("Failed to deserialize keypair"))?;
        Ok(retrieved_keypair)
    }
}


pub trait DHTEntity {
    fn get_id(&self) -> CryptoKey;
    fn get_encryption_key(&self) -> SharedSecret;
    fn get_routing_context(&self) -> Arc<RoutingContext>;
    fn get_crypto_system(&self) -> CryptoSystemVLD0;
    fn get_dht_record(&self) -> DHTRecordDescriptor;
    fn get_secret_key(&self) -> Option<CryptoKey>;

    fn encrypt_aead(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce = self.get_crypto_system().random_nonce();
        let mut buffer = Vec::with_capacity(nonce.as_slice().len() + data.len());
        buffer.extend_from_slice(nonce.as_slice());
        buffer.extend_from_slice(
            &self
                .get_crypto_system()
                .encrypt_aead(data, &nonce, &self.get_encryption_key(), associated_data)
                .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?,
        );
        Ok(buffer)
    }

    fn decrypt_aead(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = data[..24].try_into().map_err(|_| anyhow!("Failed to convert nonce slice to array"))?;
        let nonce = Nonce::new(nonce);
        let encrypted_data = &data[24..];
        self.get_crypto_system()
            .decrypt_aead(encrypted_data, &nonce, &self.get_encryption_key(), associated_data)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))
    }

    async fn set_name(&self, name: &str) -> Result<()> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        let encrypted_name = self.encrypt_aead(name.as_bytes(), None)?;
        routing_context.set_dht_value(key, 0, encrypted_name, None).await?;
        Ok(())
    }

    async fn get_name(&self) -> Result<String> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        let value = routing_context.get_dht_value(key, 0, false).await?;
        match value {
            Some(value) => {
                let decrypted_name = self.decrypt_aead(value.data(), None)?;
                Ok(String::from_utf8(decrypted_name).map_err(|e| anyhow!("Failed to convert DHT value to string: {}", e))?)
            }
            None => Err(anyhow!("Value not found")),
        }
    }

    async fn close(&self) -> Result<()> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        routing_context.close_dht_record(key).await?;
        Ok(())
    }

    
    fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }

    async fn members(&self) -> Result<Vec<CryptoKey>> {
        unimplemented!("WIP")
    }

    async fn join(&self) -> Result<()> {
        unimplemented!("WIP")
    }

    async fn leave(&self) -> Result<()> {
        unimplemented!("WIP")
    }
}
