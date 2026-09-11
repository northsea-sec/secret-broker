use std::sync::Arc;

use super::crypto_engine::CryptoEngineService;
use super::postgres::PostgresLeaseManager;
use anyhow::Result;
use chrono::Duration;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::warn;
use uuid::Uuid;

use super::sealed_store::SealedStore;
use super::transparency::{TransparencyEvent, TransparencyLogger};

type HmacSha256 = Hmac<Sha256>;

pub struct BrokerStateConfig {
    pub default_customer_id: String,
    pub max_handle_ttl: Duration,
    pub transparency: Option<TransparencyLogger>,
    pub postgres: Option<PostgresLeaseManager>,
    pub handle_hmac_key: Vec<u8>,
    pub redeem_token_ttl: Duration,
}

#[derive(Clone)]
pub struct BrokerState {
    crypto: Arc<CryptoEngineService>,
    sealed_store: Arc<SealedStore>,
    default_customer_id: String,
    max_handle_ttl: Duration,
    transparency: Option<Arc<TransparencyLogger>>,
    postgres: Option<Arc<PostgresLeaseManager>>,
    handle_hmac_key: Arc<Vec<u8>>,
    redeem_token_ttl: Duration,
    /// When true, MintDischarge requires attested broker transport lineage.
    require_attested_discharge_mint: bool,
    /// Optional allowlist for principals permitted to mint discharges.
    allowed_discharge_principal_ids: Arc<Vec<String>>,
}

impl BrokerState {
    pub fn new(
        crypto: CryptoEngineService,
        sealed_store: SealedStore,
        config: BrokerStateConfig,
    ) -> Self {
        Self {
            crypto: Arc::new(crypto),
            sealed_store: Arc::new(sealed_store),
            default_customer_id: config.default_customer_id,
            max_handle_ttl: config.max_handle_ttl,
            transparency: config.transparency.map(Arc::new),
            postgres: config.postgres.map(Arc::new),
            handle_hmac_key: Arc::new(config.handle_hmac_key),
            redeem_token_ttl: config.redeem_token_ttl,
            require_attested_discharge_mint: false,
            allowed_discharge_principal_ids: Arc::new(Vec::new()),
        }
    }

    pub fn crypto(&self) -> &CryptoEngineService {
        &self.crypto
    }

    pub fn sealed_store(&self) -> Arc<SealedStore> {
        Arc::clone(&self.sealed_store)
    }

    pub fn default_customer_id(&self) -> &str {
        &self.default_customer_id
    }

    pub fn max_handle_ttl(&self) -> Duration {
        self.max_handle_ttl
    }

    pub fn postgres(&self) -> Option<&PostgresLeaseManager> {
        self.postgres.as_deref()
    }

    pub fn handle_hmac_key(&self) -> &[u8] {
        &self.handle_hmac_key
    }

    pub fn redeem_token_ttl(&self) -> Duration {
        self.redeem_token_ttl
    }

    pub fn compute_redeem_token(
        &self,
        handle: &Uuid,
        binding_hash: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.handle_hmac_key)
            .map_err(|_| anyhow::anyhow!("invalid handle HMAC key length"))?;
        mac.update(handle.as_bytes());
        mac.update(binding_hash);
        mac.update(nonce);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Derive a deterministic macaroon root key for the given handle UUID.
    /// root_key = HMAC-SHA256(handle_hmac_key, "macaroon-root-v1:" || uuid_bytes)
    pub fn macaroon_root_key(&self, handle_id: &Uuid) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.handle_hmac_key)
            .expect("handle_hmac_key always valid length");
        mac.update(b"macaroon-root-v1:");
        mac.update(handle_id.as_bytes());
        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    pub async fn mark_redeem_token_used(&self, handle: &Uuid) -> Result<()> {
        self.sealed_store.mark_redeem_used(handle).await.map(|_| ())
    }

    pub fn require_attested_discharge_mint(&self) -> bool {
        self.require_attested_discharge_mint
    }

    pub fn allowed_discharge_principal_ids(&self) -> Vec<String> {
        (*self.allowed_discharge_principal_ids).clone()
    }

    pub fn configure_discharge_policy(
        &mut self,
        require_attested_discharge_mint: bool,
        allowed_discharge_principal_ids: Vec<String>,
    ) {
        self.require_attested_discharge_mint = require_attested_discharge_mint;
        self.allowed_discharge_principal_ids = Arc::new(
            allowed_discharge_principal_ids
                .into_iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect(),
        );
    }

    pub async fn record_transparency(&self, event: TransparencyEvent) {
        if let Some(logger) = &self.transparency {
            if let Err(err) = logger.record(event).await {
                warn!(?err, "failed to append transparency event");
            }
        }
    }
}
