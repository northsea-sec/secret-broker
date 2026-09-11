use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sled::{self, Tree};
use tokio::task;

use super::quantum_resistant::{DilithiumKeyPair, KyberKeyPair};

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRecord {
    key_id: String,
    algorithm: String,
    ciphertext: String,
    nonce: String,
    created_at: DateTime<Utc>,
}

pub struct SealedKeyStore {
    _db: Arc<sled::Db>,
    kyber_tree: Arc<Tree>,
    dilithium_tree: Arc<Tree>,
    // New: generic key storage for non-PQC keys (RSA/ECDSA/symmetric)
    generic_tree: Arc<Tree>,
    master_key: Arc<[u8; 32]>,
}

impl SealedKeyStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sealed key store directory at {}",
                    parent.display()
                )
            })?;
        }

        let db = sled::open(path)
            .with_context(|| format!("failed to open sealed key store at {}", path.display()))?;
        let kyber_tree = db
            .open_tree("kyber_keys")
            .context("failed to open kyber key tree")?;
        let dilithium_tree = db
            .open_tree("dilithium_keys")
            .context("failed to open dilithium key tree")?;
        let generic_tree = db
            .open_tree("generic_keys")
            .context("failed to open generic key tree")?;

        let master_key = Arc::new(Self::load_or_create_master_key(path)?);

        Ok(Self {
            _db: Arc::new(db),
            kyber_tree: Arc::new(kyber_tree),
            dilithium_tree: Arc::new(dilithium_tree),
            generic_tree: Arc::new(generic_tree),
            master_key,
        })
    }

    fn load_or_create_master_key(db_path: &Path) -> Result<[u8; 32]> {
        let master_path = Self::master_key_path(db_path);
        if master_path.exists() {
            let bytes = fs::read(&master_path).with_context(|| {
                format!(
                    "failed to read sealed key store master key from {}",
                    master_path.display()
                )
            })?;
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "sealed key store master key at {} has invalid length",
                    master_path.display()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        } else {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            fs::write(&master_path, key).with_context(|| {
                format!(
                    "failed to write sealed key store master key to {}",
                    master_path.display()
                )
            })?;
            Ok(key)
        }
    }

    fn master_key_path(db_path: &Path) -> PathBuf {
        let mut path = db_path.to_path_buf();
        let file_name = path
            .file_name()
            .map(|name| format!("{}.master", name.to_string_lossy()))
            .unwrap_or_else(|| "sealed_keys.master".to_string());
        path.set_file_name(file_name);
        path
    }

    pub async fn store_kyber_keypair(&self, pair: &KyberKeyPair) -> Result<()> {
        self.store_keypair(
            self.kyber_tree.clone(),
            pair.key_id.clone(),
            pair.algorithm.clone(),
            pair.created_at,
            pair,
        )
        .await
    }

    pub async fn store_dilithium_keypair(&self, pair: &DilithiumKeyPair) -> Result<()> {
        self.store_keypair(
            self.dilithium_tree.clone(),
            pair.key_id.clone(),
            pair.algorithm.clone(),
            pair.created_at,
            pair,
        )
        .await
    }

    pub async fn load_kyber_keypair(&self, key_id: &str) -> Result<Option<KyberKeyPair>> {
        self.load_keypair(self.kyber_tree.clone(), key_id).await
    }

    pub async fn load_dilithium_keypair(&self, key_id: &str) -> Result<Option<DilithiumKeyPair>> {
        self.load_keypair(self.dilithium_tree.clone(), key_id).await
    }

    pub async fn kyber_key_count(&self) -> Result<u64> {
        self.count_entries(self.kyber_tree.clone()).await
    }

    pub async fn dilithium_key_count(&self) -> Result<u64> {
        self.count_entries(self.dilithium_tree.clone()).await
    }

    async fn store_keypair<T>(
        &self,
        tree: Arc<Tree>,
        key_id: String,
        algorithm: String,
        created_at: DateTime<Utc>,
        pair: &T,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let plaintext = serde_json::to_vec(pair).context("serializing key material")?;
        let (ciphertext, nonce) = self.encrypt(&plaintext)?;
        let record = EncryptedRecord {
            key_id,
            algorithm,
            ciphertext,
            nonce,
            created_at,
        };

        let data = serde_json::to_vec(&record).context("serializing encrypted record")?;

        task::spawn_blocking(move || -> Result<()> {
            tree.insert(record.key_id.as_bytes(), data)?;
            tree.flush()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    async fn load_keypair<T>(&self, tree: Arc<Tree>, key_id: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de> + Send + 'static,
    {
        let master_key = self.master_key.clone();
        let key = key_id.as_bytes().to_vec();
        task::spawn_blocking(move || -> Result<Option<T>> {
            let Some(value) = tree.get(&key)? else {
                return Ok(None);
            };
            let record: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted record")?;
            let plaintext = decrypt_record(&record, master_key.as_ref())?;
            let pair: T = serde_json::from_slice(&plaintext)
                .context("deserializing key pair from sealed store")?;
            Ok(Some(pair))
        })
        .await?
    }

    async fn count_entries(&self, tree: Arc<Tree>) -> Result<u64> {
        task::spawn_blocking(move || -> Result<u64> { Ok(tree.len() as u64) }).await?
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<(String, String)> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(self.master_key.as_ref());
        let cipher = Aes256Gcm::new(cipher_key);
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|err| anyhow!("failed to seal key material: {err}"))?;
        Ok((STANDARD.encode(ciphertext), STANDARD.encode(nonce_bytes)))
    }
}

fn decrypt_record(record: &EncryptedRecord, master_key: &[u8]) -> Result<Vec<u8>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce_bytes = STANDARD
        .decode(record.nonce.as_bytes())
        .context("failed to decode nonce from base64")?;
    let ciphertext = STANDARD
        .decode(record.ciphertext.as_bytes())
        .context("failed to decode ciphertext from base64")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|err| anyhow!("failed to unseal key material: {err}"))
}

// ============= New: Generic key APIs (RSA/ECDSA/symmetric/etc.) =============
impl SealedKeyStore {
    /// Store an arbitrary key by ID with algorithm label in the generic tree
    pub async fn store_generic_key(
        &self,
        key_id: &str,
        algorithm: &str,
        key_bytes: &[u8],
    ) -> Result<()> {
        let (ciphertext, nonce) = self.encrypt(key_bytes)?;
        let record = EncryptedRecord {
            key_id: key_id.to_string(),
            algorithm: algorithm.to_string(),
            ciphertext,
            nonce,
            created_at: Utc::now(),
        };

        let data = serde_json::to_vec(&record).context("serializing encrypted record")?;
        let tree = self.generic_tree.clone();

        task::spawn_blocking(move || -> Result<()> {
            tree.insert(record.key_id.as_bytes(), data)?;
            tree.flush()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    /// Load an arbitrary key by ID from the generic tree. Returns (algorithm, key_bytes)
    pub async fn load_generic_key(&self, key_id: &str) -> Result<Option<(String, Vec<u8>)>> {
        let master_key = self.master_key.clone();
        let tree = self.generic_tree.clone();
        let key = key_id.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<Option<(String, Vec<u8>)>> {
            let Some(value) = tree.get(&key)? else {
                return Ok(None);
            };
            let record: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted record")?;
            let plaintext = decrypt_record(&record, master_key.as_ref())?;
            Ok(Some((record.algorithm, plaintext)))
        })
        .await?
    }

    /// Delete a generic key by ID
    pub async fn delete_generic_key(&self, key_id: &str) -> Result<()> {
        let tree = self.generic_tree.clone();
        let key = key_id.as_bytes().to_vec();
        let _ = task::spawn_blocking(move || -> Result<()> {
            tree.remove(&key)?;
            tree.flush()?;
            Ok(())
        })
        .await?;
        Ok(())
    }
}
