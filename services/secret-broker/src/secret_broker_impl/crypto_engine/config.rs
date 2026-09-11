//! Crypto Engine Configuration
//!
//! Configuration management for the CryptoEngine service

use serde::{Deserialize, Serialize};
use std::env;

/// Crypto Engine service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Service identification
    pub service_name: String,
    pub service_version: String,

    /// Server configuration
    pub server: ServerConfig,

    /// Key management configuration
    pub key_management: KeyManagementConfig,

    /// Quantum-resistant crypto configuration
    pub quantum_crypto: QuantumCryptoConfig,

    /// Hardware security module configuration
    pub hsm: HsmConfig,

    /// Performance configuration
    pub performance: PerformanceConfig,

    /// Security policies
    pub security_policies: SecurityPoliciesConfig,

    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub grpc_port: u16,
    pub http_port: u16,
    pub metrics_port: u16,
    pub max_connections: u32,
    pub connection_timeout_seconds: u64,
}

/// Key management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    pub key_size_bits: usize,
    pub key_rotation_enabled: bool,
    pub rotation_interval_hours: u64,
    pub key_backup_enabled: bool,
    pub max_keys_per_customer: u32,
    pub key_encryption_algorithm: String,
    pub key_storage_backend: String, // "software", "hsm", "kms"
}

/// Quantum-resistant crypto configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumCryptoConfig {
    pub enabled: bool,
    pub default_algorithm: String,
    pub supported_algorithms: Vec<String>,
    pub key_exchange_enabled: bool,
    pub signature_enabled: bool,
    pub hybrid_mode_enabled: bool, // Use both classical and quantum-resistant
    pub sealed_store_path: String,
}

/// Hardware security module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    pub enabled: bool,
    pub hsm_type: String,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_concurrent_operations: u32,
    pub operation_timeout_seconds: u64,
    pub memory_limit_mb: u64,
    pub enable_parallel_processing: bool,
    pub thread_pool_size: u32,
    pub cache_enabled: bool,
    pub cache_size_mb: u32,
}

/// Security policies configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPoliciesConfig {
    pub minimum_key_strength_bits: usize,
    pub enforce_key_rotation: bool,
    pub allowed_algorithms: Vec<String>,
    pub max_data_size_mb: u32,
    pub rate_limiting_enabled: bool,
    pub max_operations_per_minute: u32,
    pub audit_logging_enabled: bool,
    pub fips_compliance_mode: bool,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub metrics_collection_interval_seconds: u64,
    pub health_check_enabled: bool,
    pub health_check_interval_seconds: u64,
    pub log_level: String,
    pub audit_logging_enabled: bool,
    pub performance_monitoring_enabled: bool,
}

impl CryptoConfig {
    /// Load configuration from environment variables (no config crate dependency).
    pub fn from_env() -> Self {
        let sealed_store_path = env::var("CRYPTO_ENGINE_SEALED_STORE_PATH")
            .unwrap_or_else(|_| "/var/lib/secret-broker/crypto-engine/pq_keys.db".to_string());
        let max_keys_per_customer = env::var("CRYPTO_ENGINE_MAX_KEYS_PER_CUSTOMER")
            .ok()
            .and_then(|v| v.parse().ok())
            // A broker may mint many short-lived keys during normal rotation-heavy
            // workloads, so the default should not self-exhaust prematurely.
            .unwrap_or(10_000);

        Self {
            service_name: "crypto-engine".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            server: ServerConfig {
                bind_address: env::var("CRYPTO_ENGINE_BIND_ADDRESS")
                    .unwrap_or_else(|_| "0.0.0.0".to_string()),
                grpc_port: env::var("CRYPTO_ENGINE_GRPC_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50052),
                http_port: env::var("CRYPTO_ENGINE_HTTP_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(8085),
                metrics_port: 9095,
                max_connections: 1000,
                connection_timeout_seconds: 30,
            },
            key_management: KeyManagementConfig {
                key_size_bits: 256,
                key_rotation_enabled: true,
                rotation_interval_hours: 24,
                key_backup_enabled: true,
                max_keys_per_customer,
                key_encryption_algorithm: "aes-256-gcm".to_string(),
                key_storage_backend: "software".to_string(),
            },
            quantum_crypto: QuantumCryptoConfig {
                enabled: true,
                default_algorithm: "kyber768".to_string(),
                supported_algorithms: vec![
                    "kyber512".into(),
                    "kyber768".into(),
                    "kyber1024".into(),
                    "dilithium2".into(),
                    "dilithium3".into(),
                    "dilithium5".into(),
                ],
                key_exchange_enabled: true,
                signature_enabled: true,
                hybrid_mode_enabled: true,
                sealed_store_path,
            },
            hsm: HsmConfig {
                enabled: env::var("CRYPTO_ENGINE_HSM_ENABLED")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
                hsm_type: env::var("CRYPTO_ENGINE_HSM_TYPE")
                    .unwrap_or_else(|_| "software".to_string()),
            },
            performance: PerformanceConfig {
                max_concurrent_operations: 100,
                operation_timeout_seconds: 30,
                memory_limit_mb: 1024,
                enable_parallel_processing: true,
                thread_pool_size: 4,
                cache_enabled: true,
                cache_size_mb: 256,
            },
            security_policies: SecurityPoliciesConfig {
                minimum_key_strength_bits: 128,
                enforce_key_rotation: true,
                allowed_algorithms: vec![
                    "aes-256-gcm".into(),
                    "chacha20-poly1305".into(),
                    "xchacha20-poly1305".into(),
                    "kyber512".into(),
                    "kyber768".into(),
                    "kyber1024".into(),
                    "dilithium2".into(),
                    "dilithium3".into(),
                    "dilithium5".into(),
                ],
                max_data_size_mb: 100,
                rate_limiting_enabled: true,
                max_operations_per_minute: 1000,
                audit_logging_enabled: true,
                fips_compliance_mode: env::var("CRYPTO_ENGINE_FIPS_MODE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
            },
            monitoring: MonitoringConfig {
                metrics_enabled: true,
                metrics_collection_interval_seconds: 60,
                health_check_enabled: true,
                health_check_interval_seconds: 30,
                log_level: env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
                audit_logging_enabled: true,
                performance_monitoring_enabled: true,
            },
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Validate key size
        if self.key_management.key_size_bits < 128 {
            return Err(anyhow::anyhow!("Key size must be at least 128 bits"));
        }
        if self.key_management.max_keys_per_customer == 0 {
            return Err(anyhow::anyhow!(
                "max_keys_per_customer must be greater than zero"
            ));
        }

        // Validate quantum crypto settings
        if self.quantum_crypto.enabled
            && !self
                .quantum_crypto
                .supported_algorithms
                .contains(&self.quantum_crypto.default_algorithm)
        {
            return Err(anyhow::anyhow!(
                "Default quantum algorithm not in supported algorithms list"
            ));
        }

        // Validate HSM settings
        if self.hsm.enabled && self.hsm.hsm_type != "software" {
            return Err(anyhow::anyhow!(
                "Unsupported HSM type: {}; this build supports only software",
                self.hsm.hsm_type
            ));
        }

        // Validate security policies
        for algorithm in &self.security_policies.allowed_algorithms {
            match algorithm.as_str() {
                "aes-256-gcm" | "chacha20-poly1305" | "xchacha20-poly1305" | "kyber512"
                | "kyber768" | "kyber1024" | "dilithium2" | "dilithium3" | "dilithium5" => {}
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unsupported algorithm in security policies: {}",
                        algorithm
                    ))
                }
            }
        }

        Ok(())
    }

    /// Check if algorithm is allowed
    pub fn is_algorithm_allowed(&self, algorithm: &str) -> bool {
        self.security_policies
            .allowed_algorithms
            .contains(&algorithm.to_string())
    }

    /// Get default encryption algorithm
    pub fn get_default_algorithm(&self) -> &str {
        if self.quantum_crypto.enabled && self.quantum_crypto.hybrid_mode_enabled {
            "aes-256-gcm" // Use classical crypto by default, quantum for key exchange
        } else if self.quantum_crypto.enabled {
            &self.quantum_crypto.default_algorithm
        } else {
            "aes-256-gcm"
        }
    }

    /// Check if FIPS compliance is required
    pub fn is_fips_compliance_required(&self) -> bool {
        self.security_policies.fips_compliance_mode
    }

    /// Get maximum data size for encryption
    pub fn get_max_data_size(&self) -> u64 {
        self.security_policies.max_data_size_mb as u64 * 1024 * 1024
    }

    /// Check if rate limiting is enabled
    pub fn is_rate_limiting_enabled(&self) -> bool {
        self.security_policies.rate_limiting_enabled
    }

    /// Get rate limit per minute
    pub fn get_rate_limit_per_minute(&self) -> u32 {
        self.security_policies.max_operations_per_minute
    }
}
