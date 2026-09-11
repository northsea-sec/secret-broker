//! Key Manager Module
//!
//! Manages cryptographic keys including generation, storage, rotation,
//! and secure key lifecycle management

// Post-quantum cryptography imports - used in key generation functions
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::config::CryptoConfig;

/// Key pair for asymmetric cryptography
///
/// Note: The `created_at`, `expires_at`, and `metadata` fields ARE used in:
/// - `is_key_expired()` - expiration checking
/// - `sign_data()` / `verify_signature()` - error messages with timestamps
/// - `get_key_creation_info()` / `get_keys_by_customer()` - audit trail
///
/// Lint warning is false positive from Zeroize macro expansion.
#[allow(unused_assignments)]
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // Encrypted in storage
    pub algorithm: String,
    #[zeroize(skip)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[zeroize(skip)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[zeroize(skip)]
    pub metadata: HashMap<String, String>,
}

/// Key metadata for tracking
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub algorithm: String,
    pub key_size_bits: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub customer_id: String,
    pub usage_count: u64,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: KeyStatus,
    pub metadata: HashMap<String, String>,
}

/// Key status
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum KeyStatus {
    Active,
    Rotating,
    Rotated,
    Expired,
    Revoked,
    Compromised,
}

/// Main key manager
pub struct KeyManager {
    config: CryptoConfig,
    key_pairs: Arc<RwLock<HashMap<String, KeyPair>>>,
    key_metadata: Arc<RwLock<HashMap<String, KeyMetadata>>>,
    master_key: Arc<RwLock<Option<Vec<u8>>>>,
    rng: Arc<RwLock<rand::rngs::OsRng>>,
}

impl KeyManager {
    /// Create new key manager
    pub async fn new(config: CryptoConfig) -> Result<Self, anyhow::Error> {
        info!("Initializing KeyManager");

        let manager = Self {
            config,
            key_pairs: Arc::new(RwLock::new(HashMap::new())),
            key_metadata: Arc::new(RwLock::new(HashMap::new())),
            master_key: Arc::new(RwLock::new(None)),
            rng: Arc::new(RwLock::new(rand::rngs::OsRng)),
        };

        // Initialize master key
        manager.initialize_master_key().await?;

        info!(" KeyManager initialized successfully");
        Ok(manager)
    }

    /// Initialize master key for encrypting other keys
    async fn initialize_master_key(&self) -> Result<(), anyhow::Error> {
        let mut master_key = self.master_key.write().await;

        if master_key.is_none() {
            let mut rng = self.rng.write().await;
            let mut key = vec![0u8; 32];
            rng.fill_bytes(&mut key);

            *master_key = Some(key);
            info!("Master key initialized");
        }

        Ok(())
    }

    /// Generate new post-quantum key pair (Kyber for encryption, Dilithium for signatures)
    pub async fn generate_key_pair(
        &self,
        algorithm: &str,
        customer_id: &str,
    ) -> Result<KeyPair, anyhow::Error> {
        debug!(
            " Generating POST-QUANTUM key pair for algorithm: {}, customer: {}",
            algorithm, customer_id
        );

        // Only post-quantum algorithms allowed
        self.validate_post_quantum_algorithm(algorithm)?;

        // Check key limits
        self.check_key_limits(customer_id).await?;

        // Generate keys based on algorithm
        let (public_key, private_key) = match algorithm {
            "kyber768" => self.generate_kyber_keys().await?,
            "dilithium5" => self.generate_dilithium_keys().await?,
            "kyber-dilithium" => self.generate_hybrid_pq_keys().await?,
            _ => {
                return Err(anyhow::anyhow!(
                    " Unsupported post-quantum algorithm: {}",
                    algorithm
                ))
            }
        };

        let key_id = format!("keypair_{}", uuid::Uuid::new_v4());

        // Encrypt private key
        let encrypted_private_key = self.encrypt_private_key(&private_key).await?;

        let key_pair = KeyPair {
            key_id: key_id.clone(),
            public_key,
            private_key: encrypted_private_key,
            algorithm: algorithm.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: self.calculate_expiry(),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("customer_id".to_string(), customer_id.to_string());
                meta.insert("generator".to_string(), "software".to_string());
                meta
            },
        };

        // Create metadata
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            algorithm: algorithm.to_string(),
            key_size_bits: self.get_key_size(algorithm),
            created_at: key_pair.created_at,
            expires_at: key_pair.expires_at,
            customer_id: customer_id.to_string(),
            usage_count: 0,
            last_used_at: None,
            status: KeyStatus::Active,
            metadata: HashMap::new(),
        };

        // Store key pair and metadata
        let mut key_pairs = self.key_pairs.write().await;
        let mut key_metadata = self.key_metadata.write().await;

        key_pairs.insert(key_id.clone(), key_pair.clone());
        key_metadata.insert(key_id.clone(), metadata);

        info!(
            key_id = %key_id,
            customer_id = %customer_id,
            algorithm = %key_pair.algorithm,
            created_at = ?key_pair.created_at,
            expires_at = ?key_pair.expires_at,
            metadata_keys = ?key_pair.metadata.keys().collect::<Vec<_>>(),
            "generated post-quantum key pair"
        );
        Ok(key_pair)
    }

    /// Get public key
    pub async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, anyhow::Error> {
        let key_pairs = self.key_pairs.read().await;

        if let Some(key_pair) = key_pairs.get(key_id) {
            self.update_key_usage(key_id).await?;
            Ok(key_pair.public_key.clone())
        } else {
            Err(anyhow::anyhow!("Key pair not found: {}", key_id))
        }
    }

    /// Check if a key is expired
    fn is_key_expired(key_pair: &KeyPair) -> bool {
        if let Some(expires_at) = key_pair.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Get key creation info for audit trail
    pub async fn get_key_creation_info(
        &self,
        key_id: &str,
    ) -> Option<(chrono::DateTime<chrono::Utc>, HashMap<String, String>)> {
        let key_pairs = self.key_pairs.read().await;
        key_pairs
            .get(key_id)
            .map(|kp| (kp.created_at, kp.metadata.clone()))
    }

    /// Get all keys created by a specific customer
    pub async fn get_keys_by_customer(&self, customer_id: &str) -> Vec<String> {
        let key_pairs = self.key_pairs.read().await;
        key_pairs
            .iter()
            .filter(|(_, kp)| {
                kp.metadata
                    .get("customer_id")
                    .map(|c| c == customer_id)
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Sign data
    pub async fn sign_data(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>, anyhow::Error> {
        let key_pairs = self.key_pairs.read().await;

        if let Some(key_pair) = key_pairs.get(key_id) {
            // Check key expiration before use
            if Self::is_key_expired(key_pair) {
                return Err(anyhow::anyhow!(
                    "Key '{}' has expired (expired at: {:?}, created at: {:?})",
                    key_id,
                    key_pair.expires_at,
                    key_pair.created_at
                ));
            }

            // Decrypt private key
            let private_key = self.decrypt_private_key(&key_pair.private_key).await?;

            let signature = match key_pair.algorithm.as_str() {
                "dilithium5" => self.sign_dilithium5(data, &private_key).await?,
                "kyber-dilithium" => self.sign_hybrid_pq(data, &private_key).await?,
                "rsa" | "ecdsa" | "ed25519" => {
                    error!(
                        " REJECTED: Classical signature algorithm '{}' deprecated",
                        key_pair.algorithm
                    );
                    return Err(anyhow::anyhow!(
                        " Classical algorithm '{}' rejected - migrate to Dilithium5",
                        key_pair.algorithm
                    ));
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        " Unsupported post-quantum algorithm for signing: {}",
                        key_pair.algorithm
                    ))
                }
            };

            self.update_key_usage(key_id).await?;
            Ok(signature)
        } else {
            Err(anyhow::anyhow!("Key pair not found: {}", key_id))
        }
    }

    /// Verify post-quantum signature (Dilithium only)
    pub async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        key_id: &str,
    ) -> Result<bool, anyhow::Error> {
        let key_pairs = self.key_pairs.read().await;

        if let Some(key_pair) = key_pairs.get(key_id) {
            // Check key expiration before use
            if Self::is_key_expired(key_pair) {
                return Err(anyhow::anyhow!(
                    "Key '{}' has expired (expired at: {:?}, created at: {:?})",
                    key_id,
                    key_pair.expires_at,
                    key_pair.created_at
                ));
            }

            let result = match key_pair.algorithm.as_str() {
                "dilithium5" => {
                    Self::verify_dilithium5_with_public_key(data, signature, &key_pair.public_key)
                }
                "kyber-dilithium" => {
                    self.verify_hybrid_pq(data, signature, &key_pair.public_key)
                        .await
                }
                "rsa" | "ecdsa" | "ed25519" => {
                    error!(
                        " REJECTED: Classical verification algorithm '{}' deprecated",
                        key_pair.algorithm
                    );
                    return Err(anyhow::anyhow!(
                        " Classical algorithm '{}' rejected - migrate to Dilithium5",
                        key_pair.algorithm
                    ));
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        " Unsupported post-quantum algorithm for verification: {}",
                        key_pair.algorithm
                    ))
                }
            };

            match result {
                Ok(valid) => {
                    if valid {
                        self.update_key_usage(key_id).await?;
                        debug!(
                            " Post-quantum signature verified with {}",
                            key_pair.algorithm
                        );
                    }
                    Ok(valid)
                }
                Err(e) => Err(e),
            }
        } else {
            Err(anyhow::anyhow!("Key pair not found: {}", key_id))
        }
    }

    /// Sign data with ML-DSA-65 (POST-QUANTUM - FIPS 204)
    async fn sign_dilithium5(
        &self,
        data: &[u8],
        private_key_bytes: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        use ml_dsa::signature::Signer;
        use ml_dsa::{MlDsa65, Seed, SigningKey};

        debug!(" Signing with ML-DSA-65 (FIPS 204) post-quantum signature");

        let seed: Seed = private_key_bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid ML-DSA-65 seed size (expected 32 bytes, got {})",
                private_key_bytes.len()
            )
        })?;

        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);

        let signature = signing_key
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {:?}", e))?;

        let sig_encoded = signature.encode();
        debug!(
            " ML-DSA-65 signature generated ({} bytes)",
            sig_encoded.len()
        );
        Ok(sig_encoded.as_slice().to_vec())
    }

    /// Verify an ML-DSA-65 signature with durable public verification material.
    ///
    /// This accepts the public key stored beside a sealed envelope, allowing the
    /// broker to verify an envelope after a process restart without recovering a
    /// private signing key into memory.
    pub(crate) fn verify_dilithium5_with_public_key(
        data: &[u8],
        signature: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<bool, anyhow::Error> {
        use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature, VerifyingKey};

        debug!(" Verifying with ML-DSA-65 (FIPS 204) post-quantum signature");

        let vk_encoded: EncodedVerifyingKey<MlDsa65> =
            public_key_bytes.try_into().map_err(|_| {
                anyhow::anyhow!("Invalid ML-DSA-65 public key size (expected 1952 bytes)")
            })?;

        let verifying_key = VerifyingKey::<MlDsa65>::decode(&vk_encoded);

        let sig = MlDsaSignature::<MlDsa65>::try_from(signature)
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 signature format"))?;

        match ml_dsa::signature::Verifier::verify(&verifying_key, data, &sig) {
            Ok(()) => {
                debug!(" ML-DSA-65 signature verification: VALID");
                Ok(true)
            }
            Err(_) => {
                debug!(" ML-DSA-65 signature verification: INVALID");
                Ok(false)
            }
        }
    }

    /// Generate ML-KEM-768 key pair (POST-QUANTUM KEM - FIPS 203)
    async fn generate_kyber_keys(&self) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
        use fips203::ml_kem_768;
        use fips203::traits::{KeyGen, SerDes};

        info!(" Generating ML-KEM-768 (FIPS 203) post-quantum key pair");

        let mut rng = rand::rngs::OsRng;
        let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut rng)
            .map_err(|e| anyhow::anyhow!("ML-KEM-768 keygen failed: {:?}", e))?;

        let public_key = ek.into_bytes().to_vec();
        let secret_key = dk.into_bytes().to_vec();

        debug!(
            " ML-KEM-768 key pair generated (pub: {} bytes, sec: {} bytes)",
            public_key.len(),
            secret_key.len()
        );

        Ok((public_key, secret_key))
    }

    /// Generate ML-DSA-65 key pair (POST-QUANTUM SIGNATURES - FIPS 204)
    async fn generate_dilithium_keys(&self) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
        use ml_dsa::{MlDsa65, SigningKey};
        use rand::RngCore;

        info!(" Generating ML-DSA-65 (FIPS 204) post-quantum key pair");

        // Generate a random 32-byte seed and use seed-based key generation
        // to avoid rand_core version mismatch between ml-dsa (0.10) and project (0.6)
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);

        let signing_key = SigningKey::<MlDsa65>::from_seed((&seed).into());
        let verifying_key = signing_key.verifying_key();

        let public_key = verifying_key.encode().as_slice().to_vec();
        // Store 32-byte seed (not 4032-byte expanded) per ml-dsa non-deprecated API
        let secret_key = seed.to_vec();

        debug!(
            " ML-DSA-65 key pair generated (pub: {} bytes, sec: {} bytes)",
            public_key.len(),
            secret_key.len()
        );

        Ok((public_key, secret_key))
    }

    /// Generate hybrid Kyber+Dilithium key pair (COMPLETE POST-QUANTUM)
    async fn generate_hybrid_pq_keys(&self) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
        info!(" Generating hybrid Kyber768+Dilithium5 post-quantum key pair");

        let (kyber_pub, kyber_sec) = self.generate_kyber_keys().await?;
        let (dilithium_pub, dilithium_sec) = self.generate_dilithium_keys().await?;

        // Combine public keys
        let mut combined_public = Vec::new();
        combined_public.extend_from_slice(&kyber_pub);
        combined_public.extend_from_slice(&dilithium_pub);

        // Combine private keys
        let mut combined_private = Vec::new();
        combined_private.extend_from_slice(&kyber_sec);
        combined_private.extend_from_slice(&dilithium_sec);

        debug!(
            " Hybrid post-quantum key pair generated (total pub: {} bytes, sec: {} bytes)",
            combined_public.len(),
            combined_private.len()
        );

        Ok((combined_public, combined_private))
    }

    /// Sign with hybrid post-quantum (uses Dilithium part)
    async fn sign_hybrid_pq(
        &self,
        data: &[u8],
        combined_private_key: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        // Extract Dilithium part (second half)
        let kyber_sec_len = 2400; // Kyber768 secret key length
        if combined_private_key.len() < kyber_sec_len {
            return Err(anyhow::anyhow!("Invalid hybrid private key length"));
        }

        let dilithium_private = &combined_private_key[kyber_sec_len..];
        self.sign_dilithium5(data, dilithium_private).await
    }

    /// Verify with hybrid post-quantum (uses Dilithium part)
    async fn verify_hybrid_pq(
        &self,
        data: &[u8],
        signature: &[u8],
        combined_public_key: &[u8],
    ) -> Result<bool, anyhow::Error> {
        // Extract Dilithium part (second half)
        let kyber_pub_len = 1184; // Kyber768 public key length
        if combined_public_key.len() < kyber_pub_len {
            return Err(anyhow::anyhow!("Invalid hybrid public key length"));
        }

        let dilithium_public = &combined_public_key[kyber_pub_len..];
        Self::verify_dilithium5_with_public_key(data, signature, dilithium_public)
    }

    /// Encrypt private key for storage
    async fn encrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let master_key_guard = self.master_key.read().await;
        let master_key = master_key_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Master key not initialized"))?;

        let cipher_key = Key::from_slice(master_key);
        let cipher = ChaCha20Poly1305::new(cipher_key);

        let mut rng = self.rng.write().await;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, private_key)
            .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt private key from storage
    async fn decrypt_private_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if encrypted_key.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted key format"));
        }

        let master_key_guard = self.master_key.read().await;
        let master_key = master_key_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Master key not initialized"))?;

        let cipher_key = Key::from_slice(master_key);
        let cipher = ChaCha20Poly1305::new(cipher_key);

        let nonce = Nonce::from_slice(&encrypted_key[..12]);
        let ciphertext = &encrypted_key[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Rotate expired keys
    pub async fn rotate_expired_keys(&self) -> Result<(), anyhow::Error> {
        info!("Starting key rotation");

        let mut rotated_count = 0;
        let now = chrono::Utc::now();

        let key_metadata = self.key_metadata.read().await;
        let expired_keys: Vec<String> = key_metadata
            .iter()
            .filter(|(_, metadata)| {
                metadata.status == KeyStatus::Active
                    && metadata.expires_at.is_some_and(|expiry| expiry < now)
            })
            .map(|(key_id, _)| key_id.clone())
            .collect();

        drop(key_metadata);

        for key_id in expired_keys {
            if let Err(e) = self.rotate_key(&key_id).await {
                error!("Failed to rotate key {}: {}", key_id, e);
            } else {
                rotated_count += 1;
            }
        }

        if rotated_count > 0 {
            info!("Rotated {} expired keys", rotated_count);
        }

        Ok(())
    }

    /// Rotate a specific key
    async fn rotate_key(&self, key_id: &str) -> Result<(), anyhow::Error> {
        debug!("Rotating key: {}", key_id);

        let key_pairs = self.key_pairs.read().await;
        let key_metadata = self.key_metadata.read().await;

        if let (Some(key_pair), Some(metadata)) = (key_pairs.get(key_id), key_metadata.get(key_id))
        {
            // Generate new key pair with same algorithm
            let new_key_pair = self
                .generate_key_pair(&key_pair.algorithm, &metadata.customer_id)
                .await?;

            // Update old key status
            let mut key_metadata_write = self.key_metadata.write().await;
            if let Some(metadata) = key_metadata_write.get_mut(key_id) {
                metadata.status = KeyStatus::Rotated;
            }

            // Add rotation metadata to new key
            let new_key_metadata = key_metadata_write.get_mut(&new_key_pair.key_id).unwrap();
            new_key_metadata
                .metadata
                .insert("rotated_from".to_string(), key_id.to_string());
        }

        Ok(())
    }

    /// Validate post-quantum algorithm support only
    fn validate_post_quantum_algorithm(&self, algorithm: &str) -> Result<(), anyhow::Error> {
        if !self.config.is_algorithm_allowed(algorithm) {
            return Err(anyhow::anyhow!("Algorithm not allowed: {}", algorithm));
        }

        match algorithm {
            "kyber768" | "dilithium5" | "kyber-dilithium" => Ok(()),
            "rsa" | "ecdsa" | "ed25519" => {
                warn!(
                    " DEPRECATED: Classical algorithm '{}' rejected - use post-quantum only",
                    algorithm
                );
                Err(anyhow::anyhow!(" Classical algorithm '{}' deprecated. Use 'kyber768', 'dilithium5', or 'kyber-dilithium'", algorithm))
            }
            _ => Err(anyhow::anyhow!(
                " Unsupported algorithm: {}. Supported: kyber768, dilithium5, kyber-dilithium",
                algorithm
            )),
        }
    }

    /// Check key limits for customer
    async fn check_key_limits(&self, customer_id: &str) -> Result<(), anyhow::Error> {
        let key_metadata = self.key_metadata.read().await;

        let customer_key_count = key_metadata
            .values()
            .filter(|metadata| {
                metadata.customer_id == customer_id
                    && matches!(metadata.status, KeyStatus::Active | KeyStatus::Rotating)
            })
            .count();

        if customer_key_count >= self.config.key_management.max_keys_per_customer as usize {
            return Err(anyhow::anyhow!(
                "Maximum key limit reached for customer: {}",
                customer_id
            ));
        }

        Ok(())
    }

    /// Get key size for algorithm
    fn get_key_size(&self, algorithm: &str) -> usize {
        match algorithm {
            "rsa" => self.config.key_management.key_size_bits,
            "ecdsa" | "ed25519" => 256,
            _ => 256,
        }
    }

    /// Calculate key expiry
    fn calculate_expiry(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        if self.config.key_management.key_rotation_enabled {
            let rotation_hours = self.config.key_management.rotation_interval_hours;
            Some(chrono::Utc::now() + chrono::Duration::hours(rotation_hours as i64))
        } else {
            None
        }
    }

    /// Health check
    pub async fn health_check(&self) -> Result<(), anyhow::Error> {
        let key_pairs_count = self.key_pairs.read().await.len();
        let metadata_count = self.key_metadata.read().await.len();

        debug!(
            "Key manager health - Key pairs: {}, Metadata: {}",
            key_pairs_count, metadata_count
        );

        if key_pairs_count != metadata_count {
            warn!("Key pairs and metadata count mismatch");
        }

        Ok(())
    }

    /// Update key usage statistics
    pub async fn update_key_usage(&self, key_id: &str) -> Result<(), anyhow::Error> {
        let mut metadata = self.key_metadata.write().await;
        if let Some(meta) = metadata.get_mut(key_id) {
            meta.usage_count += 1;
            meta.last_used_at = Some(chrono::Utc::now());
            debug!(
                "Updated usage statistics for key: {} (usage count: {})",
                key_id, meta.usage_count
            );
        }
        Ok(())
    }
}
