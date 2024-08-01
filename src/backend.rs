use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use tokio::fs;
use tracing::info;
use xdg::BaseDirectories;
use veilid_core::{VeilidAPI, CryptoKey, VeilidUpdate, VeilidConfigInner, api_startup_config, DHTSchema, CRYPTO_KIND_VLD0, vld0_generate_keypair, CryptoTyped, CryptoSystemVLD0, RoutingContext, KeyPair, ProtectedStore, SharedSecret, CryptoSystem};
use std::sync::Arc;
use crate::common::{CommonKeypair, DHTEntity};
use crate::group::Group;
use crate::repo::Repo;

pub struct Backend {
    path: PathBuf,
    port: u16,
    veilid_api: Option<Arc<VeilidAPI>>,
    groups: HashMap<CryptoKey, Box<Group>>,
    repos: HashMap<CryptoKey, Box<Repo>>,
    routing_context: Option<Arc<RoutingContext>>,
    crypto_system: Option<Arc<dyn CryptoSystem>>,
}

impl Backend {
    pub fn new(base_path: &Path, port: u16) -> Result<Self> {
        Ok(Backend {
            path: base_path.to_path_buf(),
            port,
            veilid_api: None,
            groups: HashMap::new(),
            repos: HashMap::new(),
            routing_context: None,
            crypto_system: None,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        println!("Starting on {} with port {}", self.path.display(), self.port);
        let base_dir = &self.path;
        fs::create_dir_all(base_dir).await.map_err(|e| anyhow!("Failed to create base directory {}: {}", base_dir.display(), e))?;

        let update_callback: Arc<dyn Fn(VeilidUpdate) + Send + Sync> = Arc::new(|update| {
            info!("Received update: {:?}", update);
        });

        let xdg_dirs = BaseDirectories::with_prefix("save-dweb-backend")?;
        let base_dir = xdg_dirs.get_data_home();

        let config_inner = VeilidConfigInner {
            program_name: "save-dweb-backend".to_string(),
            namespace: "openarchive".into(),
            capabilities: Default::default(),
            protected_store: veilid_core::VeilidConfigProtectedStore {
                allow_insecure_fallback: true,
                always_use_insecure_storage: true,
                directory: base_dir.join("protected_store").to_string_lossy().to_string(),
                delete: false,
                device_encryption_key_password: "".to_string(),
                new_device_encryption_key_password: None,
            },
            table_store: veilid_core::VeilidConfigTableStore {
                directory: base_dir.join("table_store").to_string_lossy().to_string(),
                delete: false,
            },
            block_store: veilid_core::VeilidConfigBlockStore {
                directory: base_dir.join("block_store").to_string_lossy().to_string(),
                delete: false,
            },
            network: Default::default(),
        };

        if self.veilid_api.is_none() {
            self.veilid_api = Some(Arc::new(api_startup_config(update_callback, config_inner).await.map_err(|e| anyhow!("Failed to initialize Veilid API: {}", e))?));
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        println!("Stopping Backend...");
        if let Some(veilid) = &self.veilid_api {
            if let Ok(veilid) = Arc::try_unwrap(Arc::clone(veilid)) {
                println!("Shutting down Veilid API");
                veilid.shutdown().await;
                println!("Veilid API shut down successfully");
            } else {
                println!("Failed to unwrap Arc. There are other references to VeilidAPI.");
            }
        }
        Ok(())
    }

    pub async fn create_group(&mut self) -> Result<Group> {
        let veilid = self.veilid_api.as_ref().ok_or_else(|| anyhow!("Veilid API is not initialized"))?;
        let routing_context = veilid.routing_context()?;
        let schema = DHTSchema::dflt(1)?;
        let kind = Some(CRYPTO_KIND_VLD0);

        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let keypair = vld0_generate_keypair();
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);

        let encryption_key = crypto_system.random_shared_secret();


        let group = Group::new(
            keypair.key.clone(),
            dht_record,
            encryption_key,
            Some(CryptoTyped::new(CRYPTO_KIND_VLD0, keypair.secret)),
            Arc::new(routing_context),
            crypto_system,
        );

        let protected_store = veilid.protected_store().unwrap();
        CommonKeypair {
            public_key: group.get_id(),
            secret_key: group.get_secret_key(),
            encryption_key: group.get_encryption_key(),
        }
        .store_keypair(&protected_store, &group.get_id())
        .await.map_err(|e| anyhow!(e))?;

        self.groups.insert(group.get_id(), Box::new(group.clone()));

        Ok(group)
    }

    pub async fn get_group(&self, key: CryptoKey) -> Result<Box<Group>> {
        if let Some(group) = self.groups.get(&key) {
            return Ok(group.clone());
        }

        let protected_store = self.veilid_api.as_ref().unwrap().protected_store().unwrap();
        let keypair_data = protected_store.load_user_secret(key.to_string()).await.map_err(|_| anyhow!("Failed to load keypair"))?.ok_or_else(|| anyhow!("Keypair not found"))?;
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data).map_err(|_| anyhow!("Failed to deserialize keypair"))?;

        let routing_context = self.veilid_api.as_ref().unwrap().routing_context()?;
        let dht_record = if let Some(secret_key) = retrieved_keypair.secret_key.clone() {
            routing_context.open_dht_record(CryptoTyped::new(CRYPTO_KIND_VLD0, retrieved_keypair.public_key.clone()), Some(KeyPair { key: retrieved_keypair.public_key.clone(), secret: secret_key })).await?
        } else {
            routing_context.open_dht_record(CryptoTyped::new(CRYPTO_KIND_VLD0, retrieved_keypair.public_key.clone()), None).await?
        };

        let crypto_system = CryptoSystemVLD0::new(self.veilid_api.as_ref().unwrap().crypto()?);

        let group = Group {
            id: retrieved_keypair.public_key.clone(),
            dht_record,
            encryption_key: retrieved_keypair.encryption_key.clone(),
            secret_key: retrieved_keypair.secret_key.map(|sk| CryptoTyped::new(CRYPTO_KIND_VLD0, sk)),
            routing_context: Arc::new(routing_context),
            crypto_system,
            repos: Vec::new(),
        };

        Ok(Box::new(group))
    }

    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        Ok(self.groups.values().cloned().collect())
    }

    pub async fn close_group(&mut self, key: CryptoKey) -> Result<()> {
        if let Some(group) = self.groups.remove(&key) {
            group.close().await.map_err(|e| anyhow!(e))?;
        } else {
            return Err(anyhow!("Group not found"));
        }
        Ok(())
    }

    pub fn get_protected_store(&self) -> Result<Arc<ProtectedStore>> {
        self.veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API not initialized"))
            .map(|api| Arc::new(api.protected_store().unwrap()))
    }

    pub async fn create_repo(&mut self) -> Result<Repo> {
        let veilid = self.veilid_api.as_ref().ok_or_else(|| anyhow!("Veilid API is not initialized"))?;
        let routing_context = veilid.routing_context()?;
        let schema = DHTSchema::dflt(1)?;
        let kind = Some(CRYPTO_KIND_VLD0);

        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let keypair = vld0_generate_keypair();
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);
        let encryption_key = crypto_system.random_shared_secret();


        let repo = Repo::new(
            keypair.key.clone(),
            dht_record,
            encryption_key,
            Some(CryptoTyped::new(CRYPTO_KIND_VLD0, keypair.secret)),
            Arc::new(routing_context),
            crypto_system,
        );

        self.repos.insert(repo.get_id(), Box::new(repo.clone()));

        Ok(repo)
    }

    pub async fn get_repo(&self, key: CryptoKey) -> Result<Box<Repo>> {
        if let Some(repo) = self.repos.get(&key) {
            return Ok(repo.clone());
        }

        let protected_store = self.veilid_api.as_ref().unwrap().protected_store().unwrap();
        let keypair_data = protected_store.load_user_secret(key.to_string()).await.map_err(|_| anyhow!("Failed to load keypair"))?.ok_or_else(|| anyhow!("Keypair not found"))?;
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data).map_err(|_| anyhow!("Failed to deserialize keypair"))?;

        let routing_context = self.veilid_api.as_ref().unwrap().routing_context()?;
        let dht_record = if let Some(secret_key) = retrieved_keypair.secret_key.clone() {
            routing_context.open_dht_record(CryptoTyped::new(CRYPTO_KIND_VLD0, retrieved_keypair.public_key.clone()), Some(KeyPair { key: retrieved_keypair.public_key.clone(), secret: secret_key })).await?
        } else {
            routing_context.open_dht_record(CryptoTyped::new(CRYPTO_KIND_VLD0, retrieved_keypair.public_key.clone()), None).await?
        };

        let crypto_system = CryptoSystemVLD0::new(self.veilid_api.as_ref().unwrap().crypto()?);

        let repo = Repo {
            id: retrieved_keypair.public_key.clone(),
            dht_record,
            encryption_key: SharedSecret::new([0; 32]),
            secret_key: retrieved_keypair.secret_key.map(|sk| CryptoTyped::new(CRYPTO_KIND_VLD0, sk)),
            routing_context: Arc::new(routing_context),
            crypto_system,
        };

        Ok(Box::new(repo))
    }
}
