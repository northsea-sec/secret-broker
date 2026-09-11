//! Private implementation backing the standalone secret-broker runtime.

pub mod crypto_engine;
pub mod handlers;
pub mod macaroon_caveats;
pub mod models;
pub mod postgres;
pub mod sealed_store;
pub mod state;
pub mod threshold;
pub mod transparency;

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::Duration;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::crypto_engine::CryptoEngineService;
use self::sealed_store::SealedStore;
use self::state::{BrokerState, BrokerStateConfig};
use self::transparency::TransparencyLogger;
type HmacSha256 = Hmac<Sha256>;

/// Per-request caller lineage derived from the live mTLS/RA-TLS connection.
///
/// Production construction carries the TLS exporter and authenticated identity
/// material proven by the certificate presented on that channel. Unit tests use
/// a separate unauthenticated constructor to exercise rejection paths.
#[derive(Clone, Debug)]
pub struct BrokerClientContext {
    exporter: Vec<u8>,
    session_id: Option<Uuid>,
    principal_id: Option<String>,
    authenticated_transport: bool,
    peer_cert_sha256: Option<Vec<u8>>,
    attestation_digest: Option<Vec<u8>>,
}

impl BrokerClientContext {
    #[cfg(test)]
    fn from_master_key(master_key: &[u8]) -> Result<Self> {
        let mut mac = HmacSha256::new_from_slice(master_key)
            .map_err(|_| anyhow::anyhow!("invalid master key length for HMAC"))?;
        mac.update(b"secret-broker-test-context-v1");
        let exporter = mac.finalize().into_bytes().to_vec();
        Ok(Self::synthetic_dev_context(exporter))
    }

    /// Test-only synthetic context for exercising cryptographic binding logic.
    #[cfg(test)]
    pub(crate) fn synthetic_dev_context(exporter: impl Into<Vec<u8>>) -> Self {
        Self {
            exporter: exporter.into(),
            session_id: None,
            principal_id: None,
            authenticated_transport: false,
            peer_cert_sha256: None,
            attestation_digest: None,
        }
    }

    pub fn from_tls_exporter(
        exporter: impl Into<Vec<u8>>,
        session_id: Option<Uuid>,
        principal_id: Option<String>,
        peer_cert_sha256: Option<Vec<u8>>,
        attestation_digest: Option<Vec<u8>>,
    ) -> Self {
        Self {
            exporter: exporter.into(),
            session_id,
            principal_id: principal_id
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            authenticated_transport: true,
            peer_cert_sha256: peer_cert_sha256.filter(|value| !value.is_empty()),
            attestation_digest,
        }
    }

    pub fn exporter(&self) -> &[u8] {
        &self.exporter
    }

    pub fn session_id(&self) -> Option<Uuid> {
        self.session_id
    }

    pub fn principal_id(&self) -> Option<&str> {
        self.principal_id.as_deref()
    }

    pub fn has_authenticated_transport(&self) -> bool {
        self.authenticated_transport
    }

    pub fn peer_cert_sha256(&self) -> Option<&[u8]> {
        self.peer_cert_sha256.as_deref()
    }

    pub fn attestation_digest(&self) -> Option<&[u8]> {
        self.attestation_digest.as_deref()
    }
}

/// Standalone broker state. Caller identity is supplied exclusively by the
/// authenticated TLS connection attached to each request.
pub(crate) struct SecretBrokerState {
    pub(crate) broker: BrokerState,
}

pub(crate) async fn broker_state_from_env(
    require_attested_discharge_mint: bool,
) -> Result<BrokerState> {
    let (broker, _master_key_bytes) = load_broker_from_env(require_attested_discharge_mint).await?;
    Ok(broker)
}

async fn load_broker_from_env(
    require_attested_discharge_mint: bool,
) -> Result<(BrokerState, Zeroizing<Vec<u8>>)> {
    let master_key_path = std::env::var("BROKER_MASTER_KEY_FILE")
        .context("BROKER_MASTER_KEY_FILE env var required for secret broker")?;

    let master_key_bytes = Zeroizing::new(
        fs::read(&master_key_path)
            .with_context(|| format!("failed to read master key from {}", master_key_path))?,
    );
    anyhow::ensure!(
        master_key_bytes.len() == 32,
        "master key must be exactly 32 bytes, got {}",
        master_key_bytes.len()
    );

    // File permissions hardening
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&master_key_path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            fs::set_permissions(&master_key_path, fs::Permissions::from_mode(0o600))?;
            info!(path = %master_key_path, "enforced 0600 on master key file");
        }
    }

    // mlock the master key page
    #[cfg(unix)]
    unsafe {
        libc::mlock(
            master_key_bytes.as_ptr() as *const libc::c_void,
            master_key_bytes.len(),
        );
    }

    let sled_path = std::env::var("BROKER_SLED_PATH")
        .unwrap_or_else(|_| "/var/lib/secret-broker/broker.sled".to_string());
    let transparency_path = std::env::var("BROKER_TRANSPARENCY_LOG")
        .unwrap_or_else(|_| "/var/log/secret-broker/broker-transparency.jsonl".to_string());

    // Ensure sled directory has restricted permissions
    let sled_dir = PathBuf::from(&sled_path);
    if let Some(parent) = sled_dir.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create sled directory {}", parent.display()))?;
    }

    let sealed_store = SealedStore::open(&sled_path).context("failed to open SealedStore")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if sled_dir.exists() {
            fs::set_permissions(&sled_dir, fs::Permissions::from_mode(0o700))?;
            info!(path = %sled_path, "enforced 0700 on sled directory");
        }
    }

    let transparency = TransparencyLogger::new(&transparency_path)
        .context("failed to initialise transparency logger")?;

    // HMAC key for redeem tokens - derived from master key
    let mut hmac_key_mac = HmacSha256::new_from_slice(&master_key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid master key for HMAC derivation"))?;
    hmac_key_mac.update(b"secret-broker-broker-handle-hmac-v1");
    let handle_hmac_key = hmac_key_mac.finalize().into_bytes().to_vec();

    let crypto_config = crypto_engine::CryptoConfig::from_env();
    crypto_config
        .validate()
        .context("crypto engine config validation failed")?;
    info!(
        default_algorithm = crypto_config.get_default_algorithm(),
        fips_required = crypto_config.is_fips_compliance_required(),
        rate_limiting = crypto_config.is_rate_limiting_enabled(),
        rate_limit_rpm = crypto_config.get_rate_limit_per_minute(),
        "crypto engine configuration validated"
    );
    let crypto_service = CryptoEngineService::new(crypto_config)
        .await
        .context("failed to initialise CryptoEngineService")?;

    // Run startup diagnostics - exercises all crypto subsystems and validates connectivity
    crypto_service
        .startup_diagnostics()
        .await
        .context("crypto engine startup diagnostics failed")?;

    let max_handle_ttl = Duration::hours(24 * 365);
    let postgres = postgres::PostgresLeaseManager::from_env(max_handle_ttl).await?;

    let mut broker = BrokerState::new(
        crypto_service,
        sealed_store,
        BrokerStateConfig {
            default_customer_id: "default".to_string(),
            max_handle_ttl,
            transparency: Some(transparency),
            postgres,
            handle_hmac_key,
            redeem_token_ttl: Duration::hours(24),
        },
    );

    let allowed_discharge_principals = env_csv("BROKER_DISCHARGE_PRINCIPAL_ALLOWLIST");
    broker.configure_discharge_policy(
        require_attested_discharge_mint,
        allowed_discharge_principals,
    );

    // Third-party caveats use per-record sealed secrets only.

    // Disable core dumps for this process
    #[cfg(unix)]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);
    }

    info!(
        "broker state initialised (sled={}, transparency={})",
        sled_path, transparency_path
    );

    Ok((broker, master_key_bytes))
}

fn env_flag_enabled(key: &str, default: bool) -> Result<bool> {
    let value = match std::env::var(key) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(default),
        Err(error) => return Err(error).with_context(|| format!("failed to read {key}")),
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("{key} must be one of true, false, 1, 0, yes, no, on, or off"),
    }
}

pub(crate) fn discharge_attestation_required_from_env() -> Result<bool> {
    env_flag_enabled("BROKER_REQUIRE_DISCHARGE_ATTESTATION", true)
}

fn env_csv(key: &str) -> Vec<String> {
    std::env::var(key)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::discharge_attestation_required_from_env;
    use crate::test_support::env_lock;

    #[test]
    fn discharge_attestation_defaults_to_enabled() {
        let _guard = env_lock();
        std::env::remove_var("BROKER_REQUIRE_DISCHARGE_ATTESTATION");
        assert!(discharge_attestation_required_from_env().unwrap());
    }

    #[test]
    fn discharge_attestation_accepts_explicit_boolean() {
        let _guard = env_lock();
        std::env::set_var("BROKER_REQUIRE_DISCHARGE_ATTESTATION", "0");
        assert!(!discharge_attestation_required_from_env().unwrap());
        std::env::set_var("BROKER_REQUIRE_DISCHARGE_ATTESTATION", "1");
        assert!(discharge_attestation_required_from_env().unwrap());
        std::env::remove_var("BROKER_REQUIRE_DISCHARGE_ATTESTATION");
    }

    #[test]
    fn discharge_attestation_rejects_invalid_boolean() {
        let _guard = env_lock();
        std::env::set_var("BROKER_REQUIRE_DISCHARGE_ATTESTATION", "sometimes");
        assert!(discharge_attestation_required_from_env().is_err());
        std::env::remove_var("BROKER_REQUIRE_DISCHARGE_ATTESTATION");
    }
}
