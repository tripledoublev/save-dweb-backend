pub mod group;
pub mod repo;
pub mod backend;
pub mod common;
pub mod constants;

use crate::constants::{GROUP_NOT_FOUND, UNABLE_TO_SET_GROUP_NAME, UNABLE_TO_GET_GROUP_NAME, TEST_GROUP_NAME, UNABLE_TO_STORE_KEYPAIR, FAILED_TO_LOAD_KEYPAIR, KEYPAIR_NOT_FOUND, FAILED_TO_DESERIALIZE_KEYPAIR, TEST_REPO_NAME, UNABLE_TO_SET_REPO_NAME, UNABLE_TO_GET_REPO_NAME};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use veilid_core::{vld0_generate_keypair, PublicKey, Target, CryptoTyped, CRYPTO_KIND_VLD0};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use tmpdir::TmpDir;
    use std::path::PathBuf;

    #[tokio::test]
    async fn basic_test() {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();
        let tunnel_id_path = path.as_ref().join("tunnel_id.txt");
        let port = 8080;

        fs::create_dir_all(path.as_ref()).await.expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref(), port).expect("Unable to create Backend");

        backend.start().await.expect("Unable to start");
        let group = backend.create_group().await.expect("Unable to create group");

        let group_key = group.get_id();
        group.set_name(TEST_GROUP_NAME).await.expect(UNABLE_TO_SET_GROUP_NAME);
        let name = group.get_name().await.expect(UNABLE_TO_GET_GROUP_NAME);
        assert_eq!(name, TEST_GROUP_NAME);

        backend.stop().await.expect("Unable to stop");

        backend.start().await.expect("Unable to restart");
        let loaded_group = backend.get_group(group_key.clone()).await.expect(GROUP_NOT_FOUND);

        let protected_store = backend.get_protected_store().unwrap();
        let keypair_data = protected_store.load_user_secret(group.get_id().to_string()).await.expect(FAILED_TO_LOAD_KEYPAIR).expect(KEYPAIR_NOT_FOUND);
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data).expect(FAILED_TO_DESERIALIZE_KEYPAIR);

        assert_eq!(retrieved_keypair.public_key, group.get_id());
        assert_eq!(retrieved_keypair.secret_key, group.get_secret_key());
        assert_eq!(retrieved_keypair.encryption_key, group.get_encryption_key());

        let mut loaded_group = backend.get_group(group.get_id()).await.expect(GROUP_NOT_FOUND);

        // Check if we can get group name
        let group_name = loaded_group.get_name().await.expect(UNABLE_TO_GET_GROUP_NAME);
        assert_eq!(group_name, TEST_GROUP_NAME);

        assert_eq!(loaded_group.get_id(), retrieved_keypair.public_key);

        // Create a repo
        let repo = backend.create_repo().await.expect("Unable to create repo");
        let repo_key = repo.get_id();

        // Set and get repo name
        repo.set_name(TEST_REPO_NAME).await.expect(UNABLE_TO_SET_REPO_NAME);
        let name = repo.get_name().await.expect(UNABLE_TO_GET_REPO_NAME);
        assert_eq!(name, TEST_REPO_NAME);

        // Add repo to group
        loaded_group.add_repo(repo).await.expect("Unable to add repo to group");

        // List known repos
        let repos = loaded_group.list_repos().await;
        assert!(repos.contains(&repo_key));
  
        // Retrieve repo by key
        let mut loaded_repo = backend.get_repo(repo_key.clone()).await.expect("Repo not found");

        // Check if repo name is correctly retrieved
        let retrieved_name = loaded_repo.get_name().await.expect("Unable to get repo name after restart");
        assert_eq!(retrieved_name, TEST_REPO_NAME);

        // Retrieve tunnel ID
        let tunnel_id = match loaded_repo.retrieve_tunnel().await {
            Some(tunnel_id) => tunnel_id,
            None => loaded_repo.establish_tunnel().await.expect("Unable to establish tunnel"),
        };

        // Convert the tunnel ID to PublicKey
        let public_key = match PublicKey::try_from(BASE64_STANDARD.decode(&tunnel_id).unwrap().as_slice()) {
            Ok(public_key) => public_key,
            Err(e) => panic!("Failed to create public key from tunnel ID: {:?}", e),
        };

        // Create a TypedKey from the public_key
        let typed_key = CryptoTyped::new(CRYPTO_KIND_VLD0, public_key);

        // Create a target for the ping
        let target = Target::NodeId(typed_key);

        // Send a ping
        loaded_repo.send_ping(target).await.expect("Unable to send ping");

        // Remove the tunnel before closing
        loaded_repo.remove_tunnel(&public_key).await.expect("Unable to remove tunnel");

        backend.stop().await.expect("Unable to stop");
    }
      
}
