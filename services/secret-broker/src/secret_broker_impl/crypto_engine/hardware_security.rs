//! Software-backed hardware-security interface.
//!
//! The broker currently implements a sealed software key store. Configuring any
//! other backend is rejected explicitly rather than silently changing execution
//! modes. Hardware backends belong here only after their complete key lifecycle
//! is implemented and verified against real hardware.

use anyhow::Context;
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::config::CryptoConfig;
use super::sealed_key_store::SealedKeyStore;

#[derive(Debug, Clone, PartialEq)]
pub enum HsmType {
    Software,
}

impl HsmType {
    fn from_config(value: &str) -> Result<Self, anyhow::Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "software" => Ok(Self::Software),
            other => Err(anyhow::anyhow!(
                "unsupported HSM type {other:?}; this build supports only the sealed software backend"
            )),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Software => "software",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HsmStatus {
    Healthy,
    Unhealthy,
}

#[derive(Clone)]
pub struct HardwareSecurityModule {
    config: CryptoConfig,
    hsm_type: HsmType,
    status: Arc<RwLock<HsmStatus>>,
    is_initialized: Arc<RwLock<bool>>,
    rng: Arc<RwLock<OsRng>>,
    key_store: Arc<SealedKeyStore>,
}

impl HardwareSecurityModule {
    pub async fn new(config: CryptoConfig) -> Result<Self, anyhow::Error> {
        if !config.hsm.enabled {
            return Err(anyhow::anyhow!(
                "HardwareSecurityModule cannot be constructed while HSM support is disabled"
            ));
        }

        let hsm_type = HsmType::from_config(&config.hsm.hsm_type)?;
        let sealed_store = SealedKeyStore::open(&config.quantum_crypto.sealed_store_path)
            .context("failed to initialise sealed key store for HSM")?;
        let hsm = Self {
            config,
            hsm_type,
            status: Arc::new(RwLock::new(HsmStatus::Unhealthy)),
            is_initialized: Arc::new(RwLock::new(false)),
            rng: Arc::new(RwLock::new(OsRng)),
            key_store: Arc::new(sealed_store),
        };
        hsm.initialize_hsm().await?;
        info!(
            backend = hsm.hsm_type.as_str(),
            "HardwareSecurityModule initialized"
        );
        Ok(hsm)
    }

    async fn initialize_hsm(&self) -> Result<(), anyhow::Error> {
        let mut initialized = self.is_initialized.write().await;
        *initialized = true;
        let mut status = self.status.write().await;
        *status = HsmStatus::Healthy;
        Ok(())
    }

    pub fn key_store_path(&self) -> String {
        self.config.quantum_crypto.sealed_store_path.clone()
    }

    pub async fn generate_random_bytes(&self, length: usize) -> Result<Vec<u8>, anyhow::Error> {
        self.check_hsm_health().await?;
        let mut bytes = vec![0u8; length];
        self.rng.write().await.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    pub async fn store_key(
        &self,
        key_id: &str,
        key_data: &[u8],
        key_type: &str,
    ) -> Result<(), anyhow::Error> {
        self.check_hsm_health().await?;
        self.key_store
            .store_generic_key(key_id, key_type, key_data)
            .await
            .context("failed to store key in sealed key store")
    }

    pub async fn retrieve_key(&self, key_id: &str) -> Result<Vec<u8>, anyhow::Error> {
        self.check_hsm_health().await?;
        match self.key_store.load_generic_key(key_id).await {
            Ok(Some((_algorithm, bytes))) => Ok(bytes),
            Ok(None) => Err(anyhow::anyhow!("key not found: {key_id}")),
            Err(error) => Err(anyhow::anyhow!("failed to load key {key_id}: {error}")),
        }
    }

    pub async fn delete_key(&self, key_id: &str) -> Result<(), anyhow::Error> {
        self.check_hsm_health().await?;
        self.key_store
            .delete_generic_key(key_id)
            .await
            .context("failed to delete key from sealed key store")
    }

    pub async fn health_check(&self) -> Result<HsmStatus, anyhow::Error> {
        if !*self.is_initialized.read().await {
            return Ok(HsmStatus::Unhealthy);
        }
        Ok(self.status.read().await.clone())
    }

    async fn check_hsm_health(&self) -> Result<(), anyhow::Error> {
        if !*self.is_initialized.read().await {
            *self.status.write().await = HsmStatus::Unhealthy;
            return Err(anyhow::anyhow!("HardwareSecurityModule is not initialized"));
        }
        *self.status.write().await = HsmStatus::Healthy;
        Ok(())
    }

    pub fn get_capabilities(&self) -> Vec<String> {
        vec!["random_generation".to_string(), "key_storage".to_string()]
    }

    pub async fn get_info(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, anyhow::Error> {
        let mut info = std::collections::HashMap::new();
        info.insert("type".to_string(), self.hsm_type.as_str().to_string());
        info.insert("enabled".to_string(), self.config.hsm.enabled.to_string());
        info.insert(
            "status".to_string(),
            format!("{:?}", self.health_check().await?),
        );
        info.insert(
            "capabilities".to_string(),
            self.get_capabilities().join(", "),
        );
        Ok(info)
    }
}
