//! Core Crypto Engine Module
//!
//! Handles symmetric encryption/decryption operations with high performance
//! and security, supporting AES-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::RngCore;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::config::CryptoConfig;

/// Encryption result
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub associated_data: Option<Vec<u8>>,
    pub algorithm: String,
    pub key_id: Option<String>,
    pub exporter_binding: Option<Vec<u8>>,
}

/// Decryption result
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecryptionResult {
    pub plaintext: Vec<u8>,
    pub algorithm: String,
    pub verified: bool,
}

/// Encryption request from main service
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub id: String,
    pub data: Vec<u8>,
    pub algorithm: super::service::EncryptionAlgorithm,
    pub key_id: Option<String>,
    pub associated_data: Option<Vec<u8>>,
    pub customer_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub exporter_secret: Option<Vec<u8>>,
}

/// Decryption request from main service
#[derive(Debug, Clone)]
pub struct DecryptionRequest {
    pub id: String,
    pub encrypted_data: Vec<u8>,
    pub nonce: Option<Vec<u8>>, // CRITICAL: For post-quantum crypto, this contains KEM ciphertext (Kyber/HQC)
    pub algorithm: super::service::EncryptionAlgorithm,
    pub key_id: String,
    pub associated_data: Option<Vec<u8>>,
    pub customer_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub exporter_secret: Option<Vec<u8>>,
}

/// Key for encryption operations
#[derive(Clone)]
pub struct EncryptionKey {
    pub key_id: String,
    pub key_data: Vec<u8>,
    pub algorithm: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Main crypto engine
pub struct CryptoEngine {
    config: CryptoConfig,
    key_cache: Arc<RwLock<std::collections::HashMap<String, EncryptionKey>>>,
    rng: Arc<RwLock<rand::rngs::OsRng>>,
}

impl CryptoEngine {
    /// Create new crypto engine
    pub async fn new(config: CryptoConfig) -> Result<Self, anyhow::Error> {
        info!("Initializing CryptoEngine");

        let engine = Self {
            config,
            key_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            rng: Arc::new(RwLock::new(rand::rngs::OsRng)),
        };

        info!(" CryptoEngine initialized successfully");
        Ok(engine)
    }

    /// Process encryption request with comprehensive error handling
    pub async fn process_encryption_request(
        &self,
        request: &EncryptionRequest,
    ) -> Result<EncryptionResult, anyhow::Error> {
        debug!(
            id = %request.id,
            algorithm = ?request.algorithm,
            customer_id = %request.customer_id,
            timestamp = %request.timestamp,
            has_exporter = request.exporter_secret.is_some(),
            data_len = request.data.len(),
            "processing encryption request"
        );

        // Validate request first
        if request.data.is_empty() {
            warn!("Encryption request {} has empty data", request.id);
            return Err(anyhow::anyhow!("Encryption data cannot be empty"));
        }

        // Validate request
        self.validate_encryption_request(request).await?;

        // Get or generate key
        let key = self
            .get_or_generate_key(&request.key_id, &request.algorithm)
            .await?;

        // Encrypt data
        let mut result = match request.algorithm {
            super::service::EncryptionAlgorithm::Aes256Gcm => {
                self.encrypt_aes256_gcm(&request.data, &key, &request.associated_data)
                    .await?
            }
            super::service::EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.encrypt_chacha20_poly1305(&request.data, &key, &request.associated_data)
                    .await?
            }
            super::service::EncryptionAlgorithm::XChaCha20Poly1305 => {
                self.encrypt_xchacha20_poly1305(&request.data, &key, &request.associated_data)
                    .await?
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported algorithm for classical encryption"
                ))
            }
        };

        if result.exporter_binding.is_none() {
            result.exporter_binding = request.exporter_secret.clone();
        }

        debug!("Encryption completed for request: {}", request.id);
        Ok(result)
    }

    /// Process decryption request
    pub async fn process_decryption_request(
        &self,
        request: &DecryptionRequest,
    ) -> Result<DecryptionResult, anyhow::Error> {
        debug!(
            id = %request.id,
            algorithm = ?request.algorithm,
            customer_id = %request.customer_id,
            timestamp = %request.timestamp,
            has_exporter = request.exporter_secret.is_some(),
            ciphertext_len = request.encrypted_data.len(),
            "processing decryption request"
        );

        // Validate exporter binding if provided
        if let Some(ref secret) = request.exporter_secret {
            if secret.is_empty() {
                return Err(anyhow::anyhow!("exporter_secret provided but empty"));
            }
        }

        // Validate request
        self.validate_decryption_request(request).await?;

        // Get key
        let key = self
            .get_key(&request.key_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", request.key_id))?;

        // Reject expired keys
        if let Some(expires_at) = key.expires_at {
            if chrono::Utc::now() > expires_at {
                tracing::warn!(
                    key_id = %key.key_id,
                    expired_at = %expires_at,
                    algorithm = %key.algorithm,
                    created_at = %key.created_at,
                    "attempted use of expired encryption key"
                );
                return Err(anyhow::anyhow!(
                    "Key {} expired at {} (algorithm: {}, created: {})",
                    key.key_id,
                    expires_at,
                    key.algorithm,
                    key.created_at
                ));
            }
        }

        // Parse encrypted data (assuming format: nonce + ciphertext)
        if request.encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data format"));
        }

        let nonce = &request.encrypted_data[..12];
        let ciphertext = &request.encrypted_data[12..];

        // Decrypt data
        let result = match request.algorithm {
            super::service::EncryptionAlgorithm::Aes256Gcm => {
                self.decrypt_aes256_gcm(ciphertext, nonce, &key, &request.associated_data)
                    .await?
            }
            super::service::EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.decrypt_chacha20_poly1305(ciphertext, nonce, &key, &request.associated_data)
                    .await?
            }
            super::service::EncryptionAlgorithm::XChaCha20Poly1305 => {
                self.decrypt_xchacha20_poly1305(ciphertext, nonce, &key, &request.associated_data)
                    .await?
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported algorithm for classical decryption"
                ))
            }
        };

        debug!("Decryption completed for request: {}", request.id);
        Ok(result)
    }

    /// Encrypt data with AES-256-GCM
    async fn encrypt_aes256_gcm(
        &self,
        plaintext: &[u8],
        key: &EncryptionKey,
        associated_data: &Option<Vec<u8>>,
    ) -> Result<EncryptionResult, anyhow::Error> {
        if key.key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size for AES-256"));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(&key.key_data);
        let cipher = Aes256Gcm::new(cipher_key);

        let mut rng = self.rng.write().await;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = match associated_data {
            Some(aad) => cipher
                .encrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?,
            None => cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?,
        };

        let mut result_ciphertext = nonce_bytes.to_vec();
        result_ciphertext.extend_from_slice(&ciphertext);

        Ok(EncryptionResult {
            ciphertext: result_ciphertext,
            nonce: nonce_bytes.to_vec(),
            associated_data: associated_data.clone(),
            algorithm: "aes-256-gcm".to_string(),
            key_id: Some(key.key_id.clone()),
            exporter_binding: None,
        })
    }

    /// Decrypt data with AES-256-GCM
    async fn decrypt_aes256_gcm(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key: &EncryptionKey,
        associated_data: &Option<Vec<u8>>,
    ) -> Result<DecryptionResult, anyhow::Error> {
        if key.key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size for AES-256"));
        }

        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("Invalid nonce size for AES-256-GCM"));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(&key.key_data);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = match associated_data {
            Some(aad) => cipher
                .decrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?,
            None => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?,
        };

        Ok(DecryptionResult {
            plaintext,
            algorithm: "aes-256-gcm".to_string(),
            verified: true,
        })
    }

    /// Encrypt data with ChaCha20-Poly1305
    async fn encrypt_chacha20_poly1305(
        &self,
        plaintext: &[u8],
        key: &EncryptionKey,
        associated_data: &Option<Vec<u8>>,
    ) -> Result<EncryptionResult, anyhow::Error> {
        if key.key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size for ChaCha20-Poly1305"));
        }

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = ChaCha20Poly1305::new(cipher_key);

        let mut rng = self.rng.write().await;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        let ciphertext = match associated_data {
            Some(aad) => cipher
                .encrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))?,
            None => cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))?,
        };

        let mut result_ciphertext = nonce_bytes.to_vec();
        result_ciphertext.extend_from_slice(&ciphertext);

        Ok(EncryptionResult {
            ciphertext: result_ciphertext,
            nonce: nonce_bytes.to_vec(),
            associated_data: associated_data.clone(),
            algorithm: "chacha20-poly1305".to_string(),
            key_id: Some(key.key_id.clone()),
            exporter_binding: None,
        })
    }

    /// Decrypt data with ChaCha20-Poly1305
    async fn decrypt_chacha20_poly1305(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key: &EncryptionKey,
        associated_data: &Option<Vec<u8>>,
    ) -> Result<DecryptionResult, anyhow::Error> {
        if key.key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size for ChaCha20-Poly1305"));
        }

        if nonce.len() != 12 {
            return Err(anyhow::anyhow!("Invalid nonce size for ChaCha20-Poly1305"));
        }

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);

        let plaintext = match associated_data {
            Some(aad) => cipher
                .decrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))?,
            None => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))?,
        };

        Ok(DecryptionResult {
            plaintext,
            algorithm: "chacha20-poly1305".to_string(),
            verified: true,
        })
    }

    /// Encrypt data with XChaCha20-Poly1305
    async fn encrypt_xchacha20_poly1305(
        &self,
        plaintext: &[u8],
        key: &EncryptionKey,
        associated_data: &Option<Vec<u8>>,
    ) -> Result<EncryptionResult, anyhow::Error> {
        if key.key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size for XChaCha20-Poly1305"));
        }

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = XChaCha20Poly1305::new(cipher_key);

        let mut rng = self.rng.write().await;
        let mut nonce_bytes = [0u8; 24];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

        let ciphertext = match associated_data {
            Some(aad) => cipher
                .encrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 encryption failed: {}", e))?,
            None => cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 encryption failed: {}", e))?,
        };

        let mut result_ciphertext = nonce_bytes.to_vec();
        result_ciphertext.extend_from_slice(&ciphertext);

        Ok(EncryptionResult {
            ciphertext: result_ciphertext,
            nonce: nonce_bytes.to_vec(),
            associated_data: associated_data.clone(),
            algorithm: "xchacha20-poly1305".to_string(),
            key_id: Some(key.key_id.clone()),
            exporter_binding: None,
        })
    }

    /// Decrypt data with XChaCha20-Poly1305
    async fn decrypt_xchacha20_poly1305(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key: &EncryptionKey,
        associated_data: &Option<Vec<u8>>,
    ) -> Result<DecryptionResult, anyhow::Error> {
        if key.key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size for XChaCha20-Poly1305"));
        }

        if nonce.len() != 24 {
            return Err(anyhow::anyhow!("Invalid nonce size for XChaCha20-Poly1305"));
        }

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = XChaCha20Poly1305::new(cipher_key);
        let nonce = chacha20poly1305::XNonce::from_slice(nonce);

        let plaintext = match associated_data {
            Some(aad) => cipher
                .decrypt(
                    nonce,
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 decryption failed: {}", e))?,
            None => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 decryption failed: {}", e))?,
        };

        Ok(DecryptionResult {
            plaintext,
            algorithm: "xchacha20-poly1305".to_string(),
            verified: true,
        })
    }

    /// Validate encryption request
    async fn validate_encryption_request(
        &self,
        request: &EncryptionRequest,
    ) -> Result<(), anyhow::Error> {
        // Check data size
        if request.data.len() > self.config.get_max_data_size() as usize {
            return Err(anyhow::anyhow!("Data size exceeds maximum allowed size"));
        }

        // Check algorithm is allowed
        let algorithm_str = match request.algorithm {
            super::service::EncryptionAlgorithm::Aes256Gcm => "aes-256-gcm",
            super::service::EncryptionAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            super::service::EncryptionAlgorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };

        if !self.config.is_algorithm_allowed(algorithm_str) {
            return Err(anyhow::anyhow!("Algorithm not allowed: {}", algorithm_str));
        }

        Ok(())
    }

    /// Validate decryption request
    async fn validate_decryption_request(
        &self,
        request: &DecryptionRequest,
    ) -> Result<(), anyhow::Error> {
        // Check data size
        if request.encrypted_data.len() > self.config.get_max_data_size() as usize {
            return Err(anyhow::anyhow!(
                "Encrypted data size exceeds maximum allowed size"
            ));
        }

        // Check algorithm is allowed
        let algorithm_str = match request.algorithm {
            super::service::EncryptionAlgorithm::Aes256Gcm => "aes-256-gcm",
            super::service::EncryptionAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            super::service::EncryptionAlgorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };

        if !self.config.is_algorithm_allowed(algorithm_str) {
            return Err(anyhow::anyhow!("Algorithm not allowed: {}", algorithm_str));
        }

        Ok(())
    }

    /// Get or generate encryption key
    async fn get_or_generate_key(
        &self,
        key_id: &Option<String>,
        algorithm: &super::service::EncryptionAlgorithm,
    ) -> Result<EncryptionKey, anyhow::Error> {
        if let Some(key_id) = key_id {
            if let Some(key) = self.get_key(key_id).await? {
                return Ok(key);
            }
        }

        // Generate new key
        self.generate_key(algorithm).await
    }

    /// Get encryption key by ID
    async fn get_key(&self, key_id: &str) -> Result<Option<EncryptionKey>, anyhow::Error> {
        let cache = self.key_cache.read().await;
        Ok(cache.get(key_id).cloned())
    }

    /// Generate new encryption key
    async fn generate_key(
        &self,
        algorithm: &super::service::EncryptionAlgorithm,
    ) -> Result<EncryptionKey, anyhow::Error> {
        let key_size = match algorithm {
            super::service::EncryptionAlgorithm::Aes256Gcm
            | super::service::EncryptionAlgorithm::ChaCha20Poly1305
            | super::service::EncryptionAlgorithm::XChaCha20Poly1305 => 32,
            _ => return Err(anyhow::anyhow!("Unsupported algorithm for key generation")),
        };

        let mut rng = self.rng.write().await;
        let mut key_data = vec![0u8; key_size];
        rng.fill_bytes(&mut key_data);

        let key_id = format!("key_{}", uuid::Uuid::new_v4());
        let algorithm_name = match algorithm {
            super::service::EncryptionAlgorithm::Aes256Gcm => "aes-256-gcm",
            super::service::EncryptionAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            super::service::EncryptionAlgorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
            _ => "unknown",
        };

        let key = EncryptionKey {
            key_id: key_id.clone(),
            key_data,
            algorithm: algorithm_name.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        // Cache the key
        let mut cache = self.key_cache.write().await;
        cache.insert(key_id, key.clone());

        Ok(key)
    }

    /// Generate random bytes
    pub async fn generate_random_bytes(&self, length: usize) -> Result<Vec<u8>, anyhow::Error> {
        let mut rng = self.rng.write().await;
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    /// Health check
    pub async fn health_check(&self) -> Result<(), anyhow::Error> {
        // Test random number generation
        let _ = self.generate_random_bytes(32).await?;

        // Check key cache
        let cache_size = self.key_cache.read().await.len();
        debug!("Key cache size: {}", cache_size);

        Ok(())
    }
}
