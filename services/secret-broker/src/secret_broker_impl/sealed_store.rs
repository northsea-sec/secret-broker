use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sled::Tree;
use tokio::task;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEnvelope {
    pub envelope_key_id: String,
    pub algorithm: String,
    pub ciphertext: String,
    pub kyber_ciphertext: String,
    pub customer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exporter_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

/// Lifecycle class for a sealed secret. Determines how the secret can be
/// accessed and whether it supports renewal, rotation, or revocation.
///
/// - `SingleUseUnwrap`: one wrap, one unwrap, then inert. The default for all
///   existing broker handles and the only class the current MaxUses caveat
///   supports.
/// - `RenewableLease`: the secret can be unwrapped repeatedly as long as the
///   lease is active (not expired, not revoked). Each unwrap extends the lease.
///   Used for long-lived infrastructure secrets (TLS private keys, DB creds).
/// - `ServiceBootstrap`: the secret is unwrapped once at service startup and
///   held in memory. Functionally similar to SingleUseUnwrap but with distinct
///   audit semantics (logged as bootstrap, not as operational access).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SecretLifecycle {
    #[default]
    SingleUseUnwrap,
    RenewableLease,
    ServiceBootstrap,
}

impl SecretLifecycle {
    /// Parse from proto enum value.
    pub fn from_proto_i32(v: i32) -> Self {
        match v {
            1 => SecretLifecycle::RenewableLease,
            2 => SecretLifecycle::ServiceBootstrap,
            _ => SecretLifecycle::SingleUseUnwrap,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEnvelopeRecord {
    pub envelope: SecretEnvelope,
    pub signature: String,
    pub signing_key_id: String,
    pub signing_public_key: String,
    /// Rotation expiry of the signing key that sealed this record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_accessed: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unwrap_principal_id: Option<String>,
    #[serde(default)]
    pub issued_with_authenticated_transport: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by_principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by_peer_cert_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by_attestation_digest: Option<String>,
    /// Per-handle third-party caveat discharge secrets keyed by opaque IDs.
    /// Sealed per-caveat secrets keep predicates out of bearer handles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub third_party_caveat_keys: Option<Vec<ThirdPartyCaveatKey>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub redeem_used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_commitments: Option<Vec<String>>,
    /// Explicit lifecycle class for this secret.
    pub lifecycle: SecretLifecycle,
    /// For RenewableLease: when the current lease period expires.
    /// Distinct from `expires_at` which is the hard secret TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// For RenewableLease: how many times the lease has been renewed.
    #[serde(default)]
    pub lease_renewal_count: u32,
    /// Whether this secret has been explicitly revoked.
    #[serde(default)]
    pub revoked: bool,
    /// When this secret was revoked, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason for revocation, if provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    /// Custodian-to-index assignments for broker-held shares.
    /// Each entry maps a custodian_id to the share index (1-based) assigned to them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_assignments: Option<Vec<ShareAssignment>>,
    /// Broker-held threshold share material (y-values, base64-encoded).
    /// Only present when custodian_ids were specified at mint time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_shares: Option<Vec<HeldShare>>,
}

/// A custodian->share mapping stored in the sealed record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareAssignment {
    pub custodian_id: String,
    pub share_index: u8,
    #[serde(default)]
    pub claimed: bool,
}

/// A broker-held share (y-value stored as base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldShare {
    pub x: u8,
    pub y_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyCaveatKey {
    pub location: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub secret_b64: String,
    pub created_at: DateTime<Utc>,
}

/// Result from claiming a custodian share.
pub struct ClaimResult {
    pub x: u8,
    pub y: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
    pub previously_claimed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRecord {
    nonce: String,
    ciphertext: String,
}

impl StoredEnvelopeRecord {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.map(|expiry| now > expiry).unwrap_or(false)
    }

    pub fn envelope_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.envelope).context("serializing envelope for verification")
    }

    pub fn ciphertext_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.envelope.ciphertext.as_bytes())
            .context("failed to decode ciphertext from base64")
    }

    pub fn kem_ciphertext_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.envelope.kyber_ciphertext.as_bytes())
            .context("failed to decode Kyber ciphertext from base64")
    }

    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.signature.as_bytes())
            .context("failed to decode signature from base64")
    }

    pub fn exporter_binding_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.envelope.exporter_binding {
            Some(binding) => {
                Ok(Some(STANDARD.decode(binding.as_bytes()).context(
                    "failed to decode exporter binding from base64",
                )?))
            }
            None => Ok(None),
        }
    }
}

#[derive(Clone)]
pub struct SealedStore {
    tree: Arc<Tree>,
    cipher: Arc<Aes256Gcm>,
}

impl SealedStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sealed store directory at {}",
                    parent.display()
                )
            })?;
        }

        let db = sled::open(path)
            .with_context(|| format!("failed to open sealed store at {}", path.display()))?;
        let tree = db
            .open_tree("sealed_envelopes")
            .context("failed to open sealed_envelopes tree")?;

        let master_key = Zeroizing::new(load_or_create_master_key(path)?);
        let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
            .map_err(|err| anyhow!("failed to initialize sealed store cipher: {err}"))?;

        Ok(Self {
            tree: Arc::new(tree),
            cipher: Arc::new(cipher),
        })
    }

    pub async fn insert_with_id(&self, handle: Uuid, record: StoredEnvelopeRecord) -> Result<Uuid> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();
        let plaintext = serde_json::to_vec(&record).context("serializing sealed envelope")?;

        task::spawn_blocking(move || -> Result<()> {
            let (nonce, ciphertext) = encrypt_payload(&cipher, &plaintext)?;
            let disk_record = EncryptedRecord {
                nonce: STANDARD.encode(&nonce),
                ciphertext: STANDARD.encode(&ciphertext),
            };
            let data =
                serde_json::to_vec(&disk_record).context("serializing encrypted envelope")?;
            tree.insert(key, data)?;
            tree.flush()?;
            Ok(())
        })
        .await??;

        Ok(handle)
    }

    pub async fn load(&self, handle: &Uuid) -> Result<Option<StoredEnvelopeRecord>> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();
        let accessed_at = Utc::now();

        task::spawn_blocking(move || -> Result<Option<StoredEnvelopeRecord>> {
            let Some(value) = tree.get(&key)? else {
                return Ok(None);
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            record.last_accessed = Some(accessed_at);
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(Some(record))
        })
        .await?
    }

    pub async fn delete(&self, handle: &Uuid) -> Result<bool> {
        let tree = self.tree.clone();
        let key = handle.as_bytes().to_vec();

        let removed = task::spawn_blocking(move || -> Result<bool> {
            let existed = tree.remove(&key)?.is_some();
            tree.flush()?;
            Ok(existed)
        })
        .await??;

        Ok(removed)
    }

    pub async fn update_threshold_config(
        &self,
        handle: &Uuid,
        threshold: u8,
        commitments: Vec<String>,
    ) -> Result<()> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<()> {
            let Some(value) = tree.get(&key)? else {
                return Err(anyhow!("sealed secret handle not found"));
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            record.threshold = Some(threshold);
            record.threshold_commitments = Some(commitments);
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    pub async fn append_third_party_caveat_key(
        &self,
        handle: &Uuid,
        entry: ThirdPartyCaveatKey,
    ) -> Result<()> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<()> {
            let Some(value) = tree.get(&key)? else {
                return Err(anyhow!("sealed secret handle not found"));
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            let entries = record.third_party_caveat_keys.get_or_insert_with(Vec::new);
            if !entries
                .iter()
                .any(|existing| existing.key_id == entry.key_id)
            {
                entries.push(entry);
            }
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    /// Store custodian-to-index assignments and broker-held shares.
    pub async fn update_share_assignments(
        &self,
        handle: &Uuid,
        assignments: Vec<ShareAssignment>,
        held_shares: Vec<HeldShare>,
    ) -> Result<()> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<()> {
            let Some(value) = tree.get(&key)? else {
                return Err(anyhow!("sealed secret handle not found"));
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            record.share_assignments = Some(assignments);
            record.held_shares = Some(held_shares);
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    /// Mark a custodian's share as claimed and return it.
    pub async fn claim_custodian_share(
        &self,
        handle: &Uuid,
        custodian_id: &str,
    ) -> Result<ClaimResult> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();
        let cid = custodian_id.to_string();

        task::spawn_blocking(move || -> Result<ClaimResult> {
            let Some(value) = tree.get(&key)? else {
                return Err(anyhow!("sealed secret handle not found"));
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;

            let assignments = record
                .share_assignments
                .as_mut()
                .ok_or_else(|| anyhow!("no share assignments for this handle"))?;
            let held = record
                .held_shares
                .as_ref()
                .ok_or_else(|| anyhow!("no held shares for this handle"))?;
            let commitments = record
                .threshold_commitments
                .as_ref()
                .ok_or_else(|| anyhow!("no threshold commitments for this handle"))?;

            let assignment = assignments
                .iter_mut()
                .find(|a| a.custodian_id == cid)
                .ok_or_else(|| anyhow!("custodian_id '{}' not assigned to this handle", cid))?;

            let share = held
                .iter()
                .find(|h| h.x == assignment.share_index)
                .ok_or_else(|| {
                    anyhow!(
                        "share index {} not found in held shares",
                        assignment.share_index
                    )
                })?;

            let y = STANDARD
                .decode(&share.y_b64)
                .context("decoding held share y-value")?;
            let previously_claimed = assignment.claimed;
            assignment.claimed = true;

            let commitment_bytes: Vec<Vec<u8>> = commitments
                .iter()
                .map(|c| STANDARD.decode(c).unwrap_or_default())
                .collect();

            // Persist the claimed flag
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;

            Ok(ClaimResult {
                x: share.x,
                y,
                commitments: commitment_bytes,
                previously_claimed,
            })
        })
        .await?
    }

    pub async fn mark_redeem_used(&self, handle: &Uuid) -> Result<()> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<()> {
            let Some(value) = tree.get(&key)? else {
                return Err(anyhow!("sealed secret handle not found"));
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            record.redeem_used = true;
            record.redeem_nonce = None;
            record.redeem_binding = None;
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    /// Renew the lease on a RenewableLease secret, extending lease_expires_at
    /// and incrementing the renewal counter.
    pub async fn renew_lease(
        &self,
        handle: &Uuid,
        new_lease_expires_at: DateTime<Utc>,
    ) -> Result<StoredEnvelopeRecord> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<StoredEnvelopeRecord> {
            let Some(value) = tree.get(&key)? else {
                return Err(anyhow!("sealed secret handle not found"));
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            record.lease_expires_at = Some(new_lease_expires_at);
            record.lease_renewal_count = record.lease_renewal_count.saturating_add(1);
            record.last_accessed = Some(Utc::now());
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(record)
        })
        .await?
    }

    /// Revoke a secret, marking it permanently inert.
    pub async fn revoke(&self, handle: &Uuid, reason: Option<String>) -> Result<bool> {
        let tree = self.tree.clone();
        let cipher = self.cipher.clone();
        let key = handle.as_bytes().to_vec();

        task::spawn_blocking(move || -> Result<bool> {
            let Some(value) = tree.get(&key)? else {
                return Ok(false);
            };
            let encrypted: EncryptedRecord =
                serde_json::from_slice(&value).context("deserializing encrypted envelope")?;
            let nonce = STANDARD
                .decode(encrypted.nonce.as_bytes())
                .context("decoding envelope nonce")?;
            let ciphertext = STANDARD
                .decode(encrypted.ciphertext.as_bytes())
                .context("decoding envelope ciphertext")?;
            let plaintext = decrypt_payload(&cipher, &nonce, &ciphertext)?;
            let mut record: StoredEnvelopeRecord =
                serde_json::from_slice(&plaintext).context("deserializing sealed envelope")?;
            record.revoked = true;
            record.revoked_at = Some(Utc::now());
            record.revocation_reason = reason;
            // Also consume redeem token so it cannot be used after revocation.
            record.redeem_used = true;
            record.redeem_nonce = None;
            record.redeem_binding = None;
            let updated_plaintext =
                serde_json::to_vec(&record).context("serializing updated sealed envelope")?;
            let (new_nonce, new_ciphertext) = encrypt_payload(&cipher, &updated_plaintext)?;
            let updated_record = EncryptedRecord {
                nonce: STANDARD.encode(&new_nonce),
                ciphertext: STANDARD.encode(&new_ciphertext),
            };
            tree.insert(
                key,
                serde_json::to_vec(&updated_record)
                    .context("serializing updated encrypted envelope")?,
            )?;
            tree.flush()?;
            Ok(true)
        })
        .await?
    }
}

fn encrypt_payload(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("failed to encrypt sealed envelope payload"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

fn decrypt_payload(cipher: &Aes256Gcm, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("failed to decrypt sealed envelope payload"))
}

fn load_or_create_master_key(db_path: &Path) -> Result<[u8; 32]> {
    let master_path = master_key_path(db_path);
    if master_path.exists() {
        let bytes = fs::read(&master_path).with_context(|| {
            format!(
                "failed to read sealed store master key from {}",
                master_path.display()
            )
        })?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "sealed store master key at {} has invalid length",
                master_path.display()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    let mut key = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut key[..]);
    match write_master_key(&master_path, key.as_ref()) {
        Ok(()) => {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(key.as_ref());
            Ok(raw)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            drop(key);
            load_or_create_master_key(db_path)
        }
        Err(err) => Err(anyhow!(
            "failed to write sealed store master key to {}: {}",
            master_path.display(),
            err
        )),
    }
}

fn master_key_path(db_path: &Path) -> PathBuf {
    let mut path = db_path.to_path_buf();
    let file_name = path
        .file_name()
        .map(|name| format!("{}.master", name.to_string_lossy()))
        .unwrap_or_else(|| "sealed_envelopes.master".to_string());
    path.set_file_name(file_name);
    path
}

fn write_master_key(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::Value;
    use tempfile::{tempdir, TempDir};

    fn sample_record() -> StoredEnvelopeRecord {
        StoredEnvelopeRecord {
            envelope: SecretEnvelope {
                envelope_key_id: "key-123".into(),
                algorithm: "kyber768-hybrid".into(),
                ciphertext: B64.encode(b"cipher-bytes"),
                kyber_ciphertext: B64.encode(b"kem-bytes"),
                customer_id: "example-customer".into(),
                exporter_binding: Some(B64.encode(b"exporter")),
                metadata: Some(Value::String("metadata".into())),
                created_at: Utc::now(),
            },
            signature: B64.encode(b"signature"),
            signing_key_id: "signing-key".into(),
            signing_public_key: B64.encode(b"public-key"),
            signing_key_expires_at: None,
            expires_at: None,
            last_accessed: None,
            redeem_nonce: None,
            redeem_binding: None,
            unwrap_principal_id: None,
            issued_with_authenticated_transport: false,
            issued_by_principal_id: None,
            issued_by_peer_cert_sha256: None,
            issued_by_attestation_digest: None,
            third_party_caveat_keys: None,
            redeem_expires_at: None,
            redeem_used: false,
            threshold: None,
            threshold_commitments: None,
            lifecycle: SecretLifecycle::SingleUseUnwrap,
            lease_expires_at: None,
            lease_renewal_count: 0,
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            share_assignments: None,
            held_shares: None,
        }
    }

    fn open_test_store() -> (TempDir, SealedStore) {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("sealed.db");
        let store = SealedStore::open(&db_path).expect("sealed store open");
        (dir, store)
    }

    fn read_record_without_touching(store: &SealedStore, handle: &Uuid) -> StoredEnvelopeRecord {
        let raw_value = store
            .tree
            .get(handle.as_bytes())
            .expect("read stored value")
            .expect("value present");
        let encrypted: EncryptedRecord =
            serde_json::from_slice(&raw_value).expect("deserialize encrypted record");
        let nonce = B64
            .decode(encrypted.nonce.as_bytes())
            .expect("decode nonce");
        let ciphertext = B64
            .decode(encrypted.ciphertext.as_bytes())
            .expect("decode ciphertext");
        let plaintext =
            decrypt_payload(store.cipher.as_ref(), &nonce, &ciphertext).expect("decrypt record");
        serde_json::from_slice(&plaintext).expect("deserialize stored record")
    }

    #[tokio::test]
    async fn encrypted_payload_is_not_plaintext() {
        let (dir, store) = open_test_store();
        let db_path = dir.path().join("sealed.db");

        let record = sample_record();
        let plaintext_bytes = serde_json::to_vec(&record).expect("serialize record");

        let handle = store
            .insert_with_id(uuid::Uuid::new_v4(), record.clone())
            .await
            .expect("insert sealed record");

        // Verify round-trip through the store API first (while store is still open).
        let loaded = store
            .load(&handle)
            .await
            .expect("load stored record")
            .expect("record present");
        assert_eq!(
            loaded.envelope.envelope_key_id,
            record.envelope.envelope_key_id
        );
        assert!(
            loaded.last_accessed.is_some(),
            "last_accessed should be set"
        );

        // Drop the SealedStore to release the sled file lock, then re-open raw
        // to verify that the on-disk payload is encrypted (not plaintext).
        drop(store);

        let disk = sled::open(&db_path)
            .expect("open sled")
            .open_tree("sealed_envelopes")
            .expect("open tree");
        let raw_value = disk
            .get(handle.as_bytes())
            .expect("read stored value")
            .expect("value present");

        assert_ne!(raw_value.as_ref(), plaintext_bytes.as_slice());
        let stored_json: EncryptedRecord =
            serde_json::from_slice(&raw_value).expect("encrypted json");
        assert!(!stored_json.ciphertext.is_empty());
        assert!(!stored_json.nonce.is_empty());
        let raw_string = String::from_utf8(raw_value.to_vec()).expect("utf8");
        assert!(!raw_string.contains("\"customer_id\":"));
    }

    #[tokio::test]
    async fn sealed_store_update_threshold_config_persists_and_loads_back() {
        let (_dir, store) = open_test_store();
        let handle = store
            .insert_with_id(Uuid::new_v4(), sample_record())
            .await
            .expect("insert sealed record");
        let commitments = vec![B64.encode(b"commitment-1"), B64.encode(b"commitment-2")];

        store
            .update_threshold_config(&handle, 2, commitments.clone())
            .await
            .expect("update threshold config");

        let stored = read_record_without_touching(&store, &handle);
        assert_eq!(stored.threshold, Some(2));
        assert_eq!(stored.threshold_commitments, Some(commitments.clone()));

        let loaded = store
            .load(&handle)
            .await
            .expect("load stored record")
            .expect("record present");
        assert_eq!(loaded.threshold, Some(2));
        assert_eq!(loaded.threshold_commitments, Some(commitments));
    }

    #[tokio::test]
    async fn sealed_store_share_assignments_and_claim_state_persist_across_claims() {
        let (_dir, store) = open_test_store();
        let handle = store
            .insert_with_id(Uuid::new_v4(), sample_record())
            .await
            .expect("insert sealed record");
        let commitments = vec![B64.encode(b"commitment-a"), B64.encode(b"commitment-b")];
        store
            .update_threshold_config(&handle, 2, commitments.clone())
            .await
            .expect("update threshold config");

        let assignments = vec![
            ShareAssignment {
                custodian_id: "custodian-a".into(),
                share_index: 2,
                claimed: false,
            },
            ShareAssignment {
                custodian_id: "custodian-b".into(),
                share_index: 1,
                claimed: false,
            },
        ];
        let held_shares = vec![
            HeldShare {
                x: 1,
                y_b64: B64.encode(b"share-one"),
            },
            HeldShare {
                x: 2,
                y_b64: B64.encode(b"share-two"),
            },
        ];

        store
            .update_share_assignments(&handle, assignments.clone(), held_shares.clone())
            .await
            .expect("update share assignments");

        let stored_before_claim = read_record_without_touching(&store, &handle);
        let stored_assignments: Vec<(String, u8, bool)> = stored_before_claim
            .share_assignments
            .expect("share assignments present")
            .into_iter()
            .map(|assignment| {
                (
                    assignment.custodian_id,
                    assignment.share_index,
                    assignment.claimed,
                )
            })
            .collect();
        let expected_assignments: Vec<(String, u8, bool)> = assignments
            .into_iter()
            .map(|assignment| {
                (
                    assignment.custodian_id,
                    assignment.share_index,
                    assignment.claimed,
                )
            })
            .collect();
        assert_eq!(stored_assignments, expected_assignments);

        let stored_shares: Vec<(u8, String)> = stored_before_claim
            .held_shares
            .expect("held shares present")
            .into_iter()
            .map(|share| (share.x, share.y_b64))
            .collect();
        let expected_shares: Vec<(u8, String)> = held_shares
            .into_iter()
            .map(|share| (share.x, share.y_b64))
            .collect();
        assert_eq!(stored_shares, expected_shares);

        let first_claim = store
            .claim_custodian_share(&handle, "custodian-a")
            .await
            .expect("first claim succeeds");
        assert_eq!(first_claim.x, 2);
        assert_eq!(first_claim.y, b"share-two".to_vec());
        assert_eq!(
            first_claim.commitments,
            vec![b"commitment-a".to_vec(), b"commitment-b".to_vec()]
        );
        assert!(
            !first_claim.previously_claimed,
            "first claim should not report prior claim"
        );

        let stored_after_first_claim = read_record_without_touching(&store, &handle);
        let claimed_assignment = stored_after_first_claim
            .share_assignments
            .expect("share assignments present")
            .into_iter()
            .find(|assignment| assignment.custodian_id == "custodian-a")
            .expect("custodian-a assignment");
        assert!(claimed_assignment.claimed, "claim should persist");

        let second_claim = store
            .claim_custodian_share(&handle, "custodian-a")
            .await
            .expect("repeat claim succeeds");
        assert_eq!(second_claim.x, 2);
        assert_eq!(second_claim.y, b"share-two".to_vec());
        assert_eq!(
            second_claim.commitments,
            vec![b"commitment-a".to_vec(), b"commitment-b".to_vec()]
        );
        assert!(
            second_claim.previously_claimed,
            "repeat claim should report prior claim"
        );

        let stored_after_second_claim = read_record_without_touching(&store, &handle);
        let repeated_claim_assignment = stored_after_second_claim
            .share_assignments
            .expect("share assignments present")
            .into_iter()
            .find(|assignment| assignment.custodian_id == "custodian-a")
            .expect("custodian-a assignment");
        assert!(
            repeated_claim_assignment.claimed,
            "claimed flag should remain persisted"
        );
    }

    #[tokio::test]
    async fn sealed_store_renew_lease_updates_and_persists_lease_fields() {
        let (_dir, store) = open_test_store();
        let mut record = sample_record();
        record.lifecycle = SecretLifecycle::RenewableLease;
        record.lease_renewal_count = 2;

        let handle = store
            .insert_with_id(Uuid::new_v4(), record)
            .await
            .expect("insert sealed record");
        let new_lease_expires_at = Utc::now() + chrono::Duration::minutes(30);
        let renew_started_at = Utc::now();

        let renewed = store
            .renew_lease(&handle, new_lease_expires_at)
            .await
            .expect("renew lease");
        let renew_finished_at = Utc::now();

        assert_eq!(renewed.lease_expires_at, Some(new_lease_expires_at));
        assert_eq!(renewed.lease_renewal_count, 3);
        let renewed_last_accessed = renewed.last_accessed.expect("last_accessed set");
        assert!(
            renewed_last_accessed >= renew_started_at && renewed_last_accessed <= renew_finished_at,
            "renewal should stamp last_accessed during renew"
        );

        let stored = read_record_without_touching(&store, &handle);
        assert_eq!(stored.lease_expires_at, Some(new_lease_expires_at));
        assert_eq!(stored.lease_renewal_count, 3);
        assert_eq!(stored.last_accessed, Some(renewed_last_accessed));
    }

    #[tokio::test]
    async fn sealed_store_revoke_marks_record_revoked_and_missing_handle_returns_false() {
        let (_dir, store) = open_test_store();
        let mut record = sample_record();
        record.redeem_nonce = Some("redeem-nonce".into());
        record.redeem_binding = Some("redeem-binding".into());

        let handle = store
            .insert_with_id(Uuid::new_v4(), record)
            .await
            .expect("insert sealed record");
        let revoke_reason = "ids-burn".to_string();

        let revoked = store
            .revoke(&handle, Some(revoke_reason.clone()))
            .await
            .expect("revoke succeeds");
        assert!(revoked, "existing handle should be revoked");

        let stored = read_record_without_touching(&store, &handle);
        assert!(stored.revoked, "record should be marked revoked");
        assert!(
            stored.revoked_at.is_some(),
            "revocation time should be recorded"
        );
        assert_eq!(stored.revocation_reason, Some(revoke_reason));
        assert!(
            stored.redeem_used,
            "revocation should consume redeem material"
        );
        assert!(
            stored.redeem_nonce.is_none(),
            "revocation should clear redeem nonce"
        );
        assert!(
            stored.redeem_binding.is_none(),
            "revocation should clear redeem binding"
        );

        let missing = store
            .revoke(&Uuid::new_v4(), Some("missing".into()))
            .await
            .expect("missing handle returns false");
        assert!(!missing, "missing handle should not report revocation");
    }
}
