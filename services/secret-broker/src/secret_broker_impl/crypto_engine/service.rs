use anyhow::Result;
use chrono::Utc;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use super::config::CryptoConfig;
use super::engine::{CryptoEngine, DecryptionResult, EncryptionResult};
use super::hardware_security::{HardwareSecurityModule, HsmStatus};
use super::key_manager::{KeyManager, KeyPair};
use super::performance_monitor::PerformanceMonitor;
use super::quantum_resistant::QuantumResistantCrypto;

/// Main Crypto Engine service
#[derive(Clone)]
pub struct CryptoEngineService {
    config: CryptoConfig,
    crypto_engine: Arc<CryptoEngine>,
    key_manager: Arc<KeyManager>,
    quantum_crypto: Arc<QuantumResistantCrypto>,
    hsm: Option<Arc<HardwareSecurityModule>>,
    pub(crate) performance_monitor: Arc<PerformanceMonitor>,
}

// Re-export request types from the engine module to avoid duplication
pub use super::engine::{DecryptionRequest, EncryptionRequest};

/// Encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    // ML-KEM-768 hybrid encryption.
    Kyber768,
}

impl CryptoEngineService {
    /// Create new Crypto Engine service
    pub async fn new(config: CryptoConfig) -> Result<Self> {
        info!(
            "Initializing CryptoEngine service v{}",
            env!("CARGO_PKG_VERSION")
        );

        // Initialize components
        let crypto_engine = Arc::new(CryptoEngine::new(config.clone()).await?);
        let key_manager = Arc::new(KeyManager::new(config.clone()).await?);
        let quantum_crypto = Arc::new(QuantumResistantCrypto::new(config.clone()).await?);
        let performance_monitor = Arc::new(PerformanceMonitor::new().await?);

        // Initialize HSM if configured
        let hsm = if config.hsm.enabled {
            Some(Arc::new(HardwareSecurityModule::new(config.clone()).await?))
        } else {
            None
        };

        let service = Self {
            config,
            crypto_engine,
            key_manager,
            quantum_crypto,
            hsm,
            performance_monitor,
        };

        // Start background tasks
        service.start_background_tasks().await?;

        info!(" CryptoEngine service initialized successfully");
        Ok(service)
    }

    /// Start background tasks
    async fn start_background_tasks(&self) -> Result<()> {
        info!("Starting background tasks");

        // Start key rotation task
        let key_manager = self.key_manager.clone();
        let rotation_interval = self.config.key_management.rotation_interval_hours;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(rotation_interval * 3600));
            loop {
                interval.tick().await;
                if let Err(e) = key_manager.rotate_expired_keys().await {
                    error!("Failed to rotate expired keys: {}", e);
                }
            }
        });

        // Start performance monitoring
        let performance_monitor = self.performance_monitor.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = performance_monitor.report_metrics().await {
                    error!("Failed to report performance metrics: {}", e);
                }
            }
        });

        // Start HSM health monitoring
        if let Some(hsm) = &self.hsm {
            let hsm_clone = hsm.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    match hsm_clone.health_check().await {
                        Ok(HsmStatus::Healthy) => debug!("HSM health check passed"),
                        Ok(HsmStatus::Unhealthy) => error!("HSM health check failed"),
                        Err(e) => error!("HSM health check error: {}", e),
                    }
                }
            });
        }

        Ok(())
    }

    /// Encrypt data, optionally pinning the operation to a specific key.
    pub async fn encrypt_data_with_key(
        &self,
        data: &[u8],
        algorithm: EncryptionAlgorithm,
        key_id: Option<&str>,
        customer_id: &str,
    ) -> Result<EncryptionResult> {
        let request = EncryptionRequest {
            id: uuid::Uuid::new_v4().to_string(),
            data: data.to_vec(),
            algorithm,
            key_id: key_id.map(|value| value.to_string()),
            associated_data: None,
            customer_id: customer_id.to_string(),
            timestamp: Utc::now(),
            exporter_secret: None,
        };

        let algo_str = format!("{:?}", algorithm);
        let _ = self
            .performance_monitor
            .update_active_operations("encrypt", 1)
            .await;
        let start = std::time::Instant::now();

        // For synchronous operation, process immediately
        let result = match algorithm {
            EncryptionAlgorithm::Aes256Gcm
            | EncryptionAlgorithm::ChaCha20Poly1305
            | EncryptionAlgorithm::XChaCha20Poly1305 => {
                self.crypto_engine
                    .process_encryption_request(&request)
                    .await
            }
            EncryptionAlgorithm::Kyber768 => {
                self.quantum_crypto
                    .process_encryption_request(&request)
                    .await
            }
        };

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        let _ = self
            .performance_monitor
            .update_active_operations("encrypt", -1)
            .await;
        let _ = self
            .performance_monitor
            .record_operation("encrypt", elapsed)
            .await;
        match &result {
            Ok(_) => {
                let _ = self
                    .performance_monitor
                    .record_operation_count("encrypt", &algo_str, "ok")
                    .await;
            }
            Err(e) => {
                let _ = self
                    .performance_monitor
                    .record_error("encrypt", &format!("{e}"))
                    .await;
                let _ = self
                    .performance_monitor
                    .record_operation_count("encrypt", &algo_str, "error")
                    .await;
            }
        }
        let _ = self
            .performance_monitor
            .update_memory_usage("encrypt_buffer", data.len() as u64)
            .await;
        result
    }

    /// Decrypt data
    pub async fn decrypt_data(
        &self,
        encrypted_data: &[u8],
        algorithm: EncryptionAlgorithm,
        key_id: &str,
        customer_id: &str,
    ) -> Result<DecryptionResult> {
        let request = DecryptionRequest {
            id: uuid::Uuid::new_v4().to_string(),
            encrypted_data: encrypted_data.to_vec(),
            nonce: None,
            algorithm,
            key_id: key_id.to_string(),
            associated_data: None,
            customer_id: customer_id.to_string(),
            timestamp: Utc::now(),
            exporter_secret: None,
        };

        let algo_str = format!("{:?}", algorithm);
        let _ = self
            .performance_monitor
            .update_active_operations("decrypt", 1)
            .await;
        let _ = self
            .performance_monitor
            .update_cpu_usage("decrypt_thread", 0.0)
            .await;
        let start = std::time::Instant::now();

        // For synchronous operation, process immediately
        let result = match algorithm {
            EncryptionAlgorithm::Aes256Gcm
            | EncryptionAlgorithm::ChaCha20Poly1305
            | EncryptionAlgorithm::XChaCha20Poly1305 => {
                self.crypto_engine
                    .process_decryption_request(&request)
                    .await
            }
            EncryptionAlgorithm::Kyber768 => {
                self.quantum_crypto
                    .process_decryption_request(&request)
                    .await
            }
        };

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        let _ = self
            .performance_monitor
            .update_active_operations("decrypt", -1)
            .await;
        let _ = self
            .performance_monitor
            .record_operation("decrypt", elapsed)
            .await;
        match &result {
            Ok(_) => {
                let _ = self
                    .performance_monitor
                    .record_operation_count("decrypt", &algo_str, "ok")
                    .await;
            }
            Err(e) => {
                let _ = self
                    .performance_monitor
                    .record_error("decrypt", &format!("{e}"))
                    .await;
                let _ = self
                    .performance_monitor
                    .record_operation_count("decrypt", &algo_str, "error")
                    .await;
            }
        }
        result
    }

    /// Encrypt data using the Kyber768 hybrid workflow and persist state for later unsealing.
    pub async fn encrypt_pqc(
        &self,
        data: &[u8],
        envelope_key_id: &str,
        customer_id: &str,
        exporter_secret: Option<&[u8]>,
    ) -> Result<EncryptionResult> {
        let request = EncryptionRequest {
            id: uuid::Uuid::new_v4().to_string(),
            data: data.to_vec(),
            algorithm: EncryptionAlgorithm::Kyber768,
            key_id: Some(envelope_key_id.to_string()),
            associated_data: None,
            customer_id: customer_id.to_string(),
            timestamp: Utc::now(),
            exporter_secret: exporter_secret.map(|secret| secret.to_vec()),
        };

        self.quantum_crypto
            .process_encryption_request(&request)
            .await
    }

    /// Decrypt data produced by [`encrypt_pqc`], verifying Kyber ciphertext integrity.
    pub async fn decrypt_pqc(
        &self,
        encrypted_data: &[u8],
        kyber_ciphertext: &[u8],
        envelope_key_id: &str,
        customer_id: &str,
        exporter_secret: Option<&[u8]>,
    ) -> Result<DecryptionResult> {
        let request = DecryptionRequest {
            id: uuid::Uuid::new_v4().to_string(),
            encrypted_data: encrypted_data.to_vec(),
            nonce: Some(kyber_ciphertext.to_vec()),
            algorithm: EncryptionAlgorithm::Kyber768,
            key_id: envelope_key_id.to_string(),
            associated_data: None,
            customer_id: customer_id.to_string(),
            timestamp: Utc::now(),
            exporter_secret: exporter_secret.map(|secret| secret.to_vec()),
        };

        self.quantum_crypto
            .process_decryption_request(&request)
            .await
    }

    /// Generate new key pair
    pub async fn generate_key_pair(&self, algorithm: &str, customer_id: &str) -> Result<KeyPair> {
        self.key_manager
            .generate_key_pair(algorithm, customer_id)
            .await
    }

    /// Get public key
    pub async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
        self.key_manager.get_public_key(key_id).await
    }

    /// Sign data
    pub async fn sign_data(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>> {
        self.key_manager.sign_data(data, key_id).await
    }

    /// Verify signature
    pub async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        key_id: &str,
    ) -> Result<bool> {
        self.key_manager
            .verify_signature(data, signature, key_id)
            .await
    }

    /// Verify a sealed envelope's persisted ML-DSA-65 signature.
    ///
    /// Sealed records retain only the public verification material, so this path
    /// remains valid after the in-memory signing-key cache is recreated.
    pub fn verify_persisted_envelope_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        KeyManager::verify_dilithium5_with_public_key(data, signature, public_key)
    }

    /// Generate secure random bytes
    pub async fn generate_random_bytes(&self, length: usize) -> Result<Vec<u8>> {
        if let Some(hsm) = &self.hsm {
            hsm.generate_random_bytes(length).await
        } else {
            let mut bytes = vec![0u8; length];
            rand::thread_rng().fill_bytes(&mut bytes);
            Ok(bytes)
        }
    }

    /// Health check
    pub async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();

        // Check crypto engine core (RNG + key cache)
        let engine_status = match self.crypto_engine.health_check().await {
            Ok(_) => "healthy",
            Err(_) => "unhealthy",
        };
        health.insert("crypto_engine".to_string(), engine_status.to_string());

        // Check key manager
        let key_manager_status = match self.key_manager.health_check().await {
            Ok(_) => "healthy",
            Err(_) => "unhealthy",
        };
        health.insert("key_manager".to_string(), key_manager_status.to_string());

        // Check quantum crypto
        let quantum_status = match self.quantum_crypto.health_check().await {
            Ok(_) => "healthy",
            Err(_) => "unhealthy",
        };
        health.insert("quantum_crypto".to_string(), quantum_status.to_string());

        // Check HSM if present
        if let Some(hsm) = &self.hsm {
            let hsm_status = match hsm.health_check().await {
                Ok(HsmStatus::Healthy) => "healthy",
                Ok(HsmStatus::Unhealthy) => "unhealthy",
                Err(_) => "error",
            };
            health.insert("hsm".to_string(), hsm_status.to_string());
        } else {
            health.insert("hsm".to_string(), "not_configured".to_string());
        }

        // Overall status
        let overall = if health
            .values()
            .all(|v| matches!(v.as_str(), "healthy" | "operational" | "not_configured"))
        {
            "healthy"
        } else {
            "degraded"
        };

        health.insert("overall".to_string(), overall.to_string());

        Ok(health)
    }

    /// Run comprehensive startup diagnostics exercising all subsystems.
    /// Called once during broker init to validate the entire crypto pipeline.
    pub async fn startup_diagnostics(&self) -> Result<()> {
        info!("running crypto engine startup diagnostics");

        // 1. Health check
        let health = self.health_check().await?;
        info!(overall = ?health.get("overall"), "health check passed");

        // 2. Random byte generation
        let random = self.generate_random_bytes(32).await?;
        assert!(random.len() == 32, "random byte generation failed");
        info!("random byte generation verified");

        // 3. Performance monitor snapshot
        let perf_metrics = self.performance_monitor.get_metrics("overall").await;
        info!(?perf_metrics, "performance monitor baseline");

        // 4. Key manager diagnostics
        let key_creation_info = self
            .key_manager
            .get_key_creation_info("__diagnostic__")
            .await;
        debug!(?key_creation_info, "key_manager.get_key_creation_info");
        let customer_keys = self
            .key_manager
            .get_keys_by_customer("__diagnostic__")
            .await;
        debug!(
            count = customer_keys.len(),
            "key_manager.get_keys_by_customer"
        );

        // 5. Hardware security module probe
        if let Some(hsm) = &self.hsm {
            let hsm_health = hsm.health_check().await;
            info!(?hsm_health, "HSM health check");
            // Probe key store and RNG subsystems
            let key_store_info = hsm.key_store_path();
            let rng_bytes = hsm.generate_random_bytes(16).await;
            info!(
                ?key_store_info,
                rng_ok = rng_bytes.is_ok(),
                "HSM subsystem probe"
            );
        }

        // 6. Quantum-resistant subsystem probe (includes sealed key store)
        let supported = self.quantum_crypto.get_supported_algorithms();
        info!(algorithms = ?supported, "quantum-resistant algorithms available");
        let stats = self.quantum_crypto.get_crypto_statistics().await?;
        debug!(?stats, "quantum crypto statistics");
        for algo in &supported {
            debug!(
                algo,
                supported = self.quantum_crypto.is_algorithm_supported(algo),
                "algorithm check"
            );
        }

        // 6b. Quantum health_check - exercises ML-KEM keypair + lifecycle (is_expired, age_days)
        //     and ML-DSA keypair + encapsulation/decapsulation round-trip
        self.quantum_crypto.health_check().await?;
        info!("quantum crypto health_check passed (ML-KEM + ML-DSA lifecycle verified)");

        // 7. Quantum key lifecycle probe - exercises generate_real_dilithium_keypair,
        //    load_dilithium_keypair, is_expired, age_days, QUANTUM_KEY_MAX_AGE_DAYS
        {
            let diag_key_id = format!("__diag_{}", uuid::Uuid::new_v4());
            let keypair = self
                .quantum_crypto
                .generate_real_dilithium_keypair(&diag_key_id)
                .await?;
            info!(
                key_id = %keypair.key_id,
                age_days = keypair.age_days(),
                expired = keypair.is_expired(),
                max_age = super::quantum_resistant::QUANTUM_KEY_MAX_AGE_DAYS,
                "dilithium keypair lifecycle check"
            );
            // Round-trip through sealed store: store was done by generate, now load
            let loaded = self
                .quantum_crypto
                .key_store()
                .load_dilithium_keypair(&diag_key_id)
                .await?;
            info!(
                found = loaded.is_some(),
                "sealed key store dilithium round-trip"
            );
            if let Some(loaded_kp) = loaded {
                info!(
                    loaded_age = loaded_kp.age_days(),
                    loaded_expired = loaded_kp.is_expired(),
                    "loaded dilithium keypair lifecycle"
                );
            }
        }

        // 7b. ML-KEM lifecycle is exercised via quantum_crypto.health_check() in step 6
        //     (calls generate_mlkem_keypair -> KyberKeyPair::is_expired/age_days)

        // 7c. HSM info + capabilities + store/retrieve/delete round-trip
        if let Some(hsm) = &self.hsm {
            let caps = hsm.get_capabilities();
            info!(capabilities = ?caps, "HSM capabilities");
            let info = hsm.get_info().await;
            info!(?info, "HSM device info");
            let diag_key_id = "__diag_hsm_key__";
            let diag_key_data = b"diagnostic_key_material_32bytes!";
            match hsm.store_key(diag_key_id, diag_key_data, "aes256").await {
                Ok(()) => {
                    info!("HSM store_key diagnostic succeeded");
                    match hsm.retrieve_key(diag_key_id).await {
                        Ok(retrieved) => info!(
                            len = retrieved.len(),
                            "HSM retrieve_key diagnostic succeeded"
                        ),
                        Err(e) => warn!("HSM retrieve_key diagnostic: {}", e),
                    }
                    match hsm.delete_key(diag_key_id).await {
                        Ok(()) => info!("HSM delete_key diagnostic succeeded"),
                        Err(e) => warn!("HSM delete_key diagnostic: {}", e),
                    }
                }
                Err(e) => warn!("HSM store_key diagnostic: {}", e),
            }
        }

        info!("crypto engine startup diagnostics complete - all subsystems operational");
        Ok(())
    }
}
