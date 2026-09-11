use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task;

#[derive(Clone)]
pub struct TransparencyLogger {
    path: Arc<PathBuf>,
    sequence: Arc<AtomicU64>,
    prev_hash: Arc<Mutex<String>>,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Result of a transparency log chain verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Number of entries verified.
    pub entries: u64,
    /// SHA-256 hash of the final entry (chain head). Matches the in-memory
    /// `prev_hash` that the next appended entry would reference.
    pub head_hash: String,
}

impl TransparencyLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| {
                format!(
                    "failed to create transparency log directory at {}",
                    dir.display()
                )
            })?;
        }

        // Lazily create the file so we can append later without blocking.
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| {
                format!(
                    "failed to initialise transparency log at {}",
                    path.display()
                )
            })?;

        // Recover sequence + prev_hash from existing log entries.
        let (seq, hash) = Self::recover_chain_state(path)?;

        Ok(Self {
            path: Arc::new(path.to_path_buf()),
            sequence: Arc::new(AtomicU64::new(seq)),
            prev_hash: Arc::new(Mutex::new(hash)),
        })
    }

    fn recover_chain_state(path: &Path) -> Result<(u64, String)> {
        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok((0, GENESIS_HASH.to_string())),
        };
        let reader = BufReader::new(file);
        let mut last_seq: u64 = 0;
        let mut last_line: Option<String> = None;
        for line in reader.lines() {
            let line = line.context("reading transparency log line")?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(seq) = value.get("sequence").and_then(|v| v.as_u64()) {
                    last_seq = seq;
                }
            }
            last_line = Some(line);
        }
        let hash = match last_line {
            Some(ref line) => hex::encode(Sha256::digest(line.as_bytes())),
            None => GENESIS_HASH.to_string(),
        };
        let next_seq = if last_seq > 0 || last_line.is_some() {
            last_seq + 1
        } else {
            0
        };
        Ok((next_seq, hash))
    }

    /// Walk the entire log and verify every hash-chain link.
    ///
    /// Returns `Ok(VerifyResult)` with the number of entries checked and the
    /// final entry hash. Returns an error if any link is broken (i.e. the
    /// SHA-256 of line N does not match line N+1's `prev_hash` field).
    pub fn verify_chain(path: impl AsRef<Path>) -> Result<VerifyResult> {
        let file = fs::File::open(path.as_ref())
            .with_context(|| format!("opening transparency log at {}", path.as_ref().display()))?;
        let reader = BufReader::new(file);

        let mut expected_prev = GENESIS_HASH.to_string();
        let mut count: u64 = 0;
        let mut last_hash = GENESIS_HASH.to_string();

        for (lineno, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("reading line {lineno}"))?;
            if line.trim().is_empty() {
                continue;
            }

            let value: serde_json::Value = serde_json::from_str(&line)
                .with_context(|| format!("parsing JSON at line {lineno}"))?;

            let prev = value
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("line {lineno}: missing prev_hash field"))?;

            if prev != expected_prev {
                return Err(anyhow::anyhow!(
                    "chain broken at line {lineno} (sequence {}): expected prev_hash {expected_prev}, got {prev}",
                    value.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0)
                ));
            }

            last_hash = hex::encode(Sha256::digest(line.as_bytes()));
            expected_prev = last_hash.clone();
            count += 1;
        }

        Ok(VerifyResult {
            entries: count,
            head_hash: last_hash,
        })
    }

    pub async fn record(&self, mut entry: TransparencyEvent) -> Result<()> {
        let path = Arc::clone(&self.path);
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let prev = {
            let guard = self.prev_hash.lock().expect("prev_hash lock poisoned");
            guard.clone()
        };

        entry.sequence = seq;
        entry.prev_hash = prev;

        let line = serde_json::to_string(&entry).context("serializing transparency event")?;
        let new_hash = hex::encode(Sha256::digest(line.as_bytes()));

        {
            let mut guard = self.prev_hash.lock().expect("prev_hash lock poisoned");
            *guard = new_hash;
        }

        task::spawn_blocking(move || -> Result<()> {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&*path)
                .with_context(|| {
                    format!("failed to open transparency log at {}", path.display())
                })?;

            file.write_all(line.as_bytes())
                .context("writing transparency event")?;
            file.write_all(b"\n")
                .context("writing transparency newline")?;
            file.sync_all()
                .context("syncing transparency log to disk")?;
            Ok(())
        })
        .await??;

        Ok(())
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct TransparencyEvent {
    pub sequence: u64,
    pub prev_hash: String,
    pub event: &'static str,
    pub handle: Option<String>,
    pub envelope_key_id: Option<String>,
    pub customer_id: Option<String>,
    pub status: &'static str,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Phase 8: Authenticated caller identity (SPIFFE ID, admin key fingerprint, or session label).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_identity: Option<String>,
    /// Phase 8: Parent handle for attenuation lineage tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_handle: Option<String>,
    /// Phase 8: Lease sequence number for renewal audit trail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_sequence: Option<u32>,
    /// Phase 8: Previous lease expiry for renewal audit trail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_expires_at: Option<DateTime<Utc>>,
}

impl TransparencyEvent {
    /// Set caller identity for governance audit (Phase 8).
    pub fn with_caller(mut self, caller: impl Into<String>) -> Self {
        self.caller_identity = Some(caller.into());
        self
    }

    /// Set parent handle for attenuation lineage (Phase 8).
    pub fn with_parent_handle(mut self, parent: impl Into<String>) -> Self {
        self.parent_handle = Some(parent.into());
        self
    }

    /// Set lease renewal metadata (Phase 8).
    pub fn with_lease_renewal(mut self, sequence: u32, previous_expires: DateTime<Utc>) -> Self {
        self.lease_sequence = Some(sequence);
        self.previous_expires_at = Some(previous_expires);
        self
    }

    fn base() -> Self {
        Self {
            sequence: 0,
            prev_hash: String::new(),
            event: "wrap",
            handle: None,
            envelope_key_id: None,
            customer_id: None,
            status: "issued",
            timestamp: Utc::now(),
            metadata: None,
            caller_identity: None,
            parent_handle: None,
            lease_sequence: None,
            previous_expires_at: None,
        }
    }

    pub fn wrap(handle: &str, envelope: &str, customer_id: &str, metadata: Option<Value>) -> Self {
        Self {
            event: "wrap",
            handle: Some(handle.to_string()),
            envelope_key_id: Some(envelope.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "issued",
            metadata,
            ..Self::base()
        }
    }

    pub fn unwrap(
        handle: &str,
        envelope: Option<&str>,
        customer_id: &str,
        metadata: Option<Value>,
    ) -> Self {
        Self {
            event: "unwrap",
            handle: Some(handle.to_string()),
            envelope_key_id: envelope.map(|value| value.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "unwrapped",
            metadata,
            ..Self::base()
        }
    }

    pub fn mint_aead(
        handle: &str,
        envelope: &str,
        customer_id: &str,
        metadata: Option<Value>,
    ) -> Self {
        Self {
            event: "mint_aead",
            handle: Some(handle.to_string()),
            envelope_key_id: Some(envelope.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "issued",
            metadata,
            ..Self::base()
        }
    }

    pub fn delete(handle: &str, found: bool, metadata: Option<Value>) -> Self {
        Self {
            event: "delete",
            handle: Some(handle.to_string()),
            status: if found { "removed" } else { "not_found" },
            metadata,
            ..Self::base()
        }
    }

    pub fn revoke(handle: &str, customer_id: &str, metadata: Option<Value>) -> Self {
        Self {
            event: "revoke",
            handle: Some(handle.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "revoked",
            metadata,
            ..Self::base()
        }
    }

    pub fn renew_lease(handle: &str, customer_id: &str, metadata: Option<Value>) -> Self {
        Self {
            event: "renew_lease",
            handle: Some(handle.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "renewed",
            metadata,
            ..Self::base()
        }
    }

    pub fn attenuate(handle: &str, customer_id: &str, metadata: Option<Value>) -> Self {
        Self {
            event: "attenuate",
            handle: Some(handle.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "attenuated",
            metadata,
            ..Self::base()
        }
    }

    pub fn rotate(
        old_handle: &str,
        new_handle: &str,
        envelope_key_id: &str,
        customer_id: &str,
        metadata: Option<Value>,
    ) -> Self {
        let mut meta = metadata
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        meta.insert("old_handle".into(), Value::String(old_handle.to_string()));
        meta.insert("new_handle".into(), Value::String(new_handle.to_string()));
        Self {
            event: "rotate",
            handle: Some(new_handle.to_string()),
            envelope_key_id: Some(envelope_key_id.to_string()),
            customer_id: Some(customer_id.to_string()),
            status: "rotated",
            metadata: Some(Value::Object(meta)),
            ..Self::base()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use uuid::Uuid;

    #[derive(Debug, serde::Deserialize)]
    struct TransparencyEventOwned {
        pub sequence: u64,
        pub prev_hash: String,
        pub event: String,
        pub handle: Option<String>,
        pub envelope_key_id: Option<String>,
        pub customer_id: Option<String>,
        pub status: String,
        pub timestamp: DateTime<Utc>,
        pub metadata: Option<Value>,
        pub caller_identity: Option<String>,
        pub parent_handle: Option<String>,
        pub lease_sequence: Option<u32>,
        pub previous_expires_at: Option<DateTime<Utc>>,
    }

    #[tokio::test]
    async fn logger_appends_events() {
        let path = std::env::temp_dir().join(format!("transparency-{}.log", Uuid::new_v4()));
        let logger = TransparencyLogger::new(&path).expect("initialise logger");

        logger
            .record(TransparencyEvent::wrap(
                "handle-1",
                "envelope-1",
                "cust-a",
                Some(json!({"ttl": 60})),
            ))
            .await
            .expect("record entry");

        logger
            .record(TransparencyEvent::delete("handle-1", true, None))
            .await
            .expect("record second entry");

        let contents = fs::read_to_string(&path).expect("read log");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: TransparencyEventOwned = serde_json::from_str(lines[0]).expect("parse first");
        assert_eq!(first.event, "wrap");
        assert_eq!(first.status, "issued");
        assert_eq!(first.sequence, 0);
        assert_eq!(first.prev_hash, GENESIS_HASH);
        assert_eq!(first.handle.as_deref(), Some("handle-1"));
        assert_eq!(first.envelope_key_id.as_deref(), Some("envelope-1"));
        assert_eq!(first.customer_id.as_deref(), Some("cust-a"));
        assert!(
            first.timestamp <= Utc::now(),
            "timestamp should not be in the future"
        );
        assert_eq!(first.metadata, Some(json!({"ttl": 60})));

        let second: TransparencyEventOwned = serde_json::from_str(lines[1]).expect("parse second");
        assert_eq!(second.event, "delete");
        assert_eq!(second.status, "removed");
        assert_eq!(second.sequence, 1);
        // second.prev_hash should be SHA-256 of the first line
        let expected_hash = hex::encode(Sha256::digest(lines[0].as_bytes()));
        assert_eq!(second.prev_hash, expected_hash);
        assert_eq!(second.handle.as_deref(), Some("handle-1"));
        assert_eq!(second.envelope_key_id, None);
        assert_eq!(second.customer_id, None);
        assert!(
            second.timestamp <= Utc::now(),
            "timestamp should not be in the future"
        );
        assert_eq!(second.metadata, None);
    }

    #[tokio::test]
    async fn logger_recovers_chain_state() {
        let path =
            std::env::temp_dir().join(format!("transparency-recover-{}.log", Uuid::new_v4()));
        let logger1 = TransparencyLogger::new(&path).expect("initialise logger");
        for _ in 0..3 {
            logger1
                .record(TransparencyEvent::wrap("h", "e", "c", None))
                .await
                .expect("record");
        }

        // Create a second logger on the same file -- it should recover
        let logger2 = TransparencyLogger::new(&path).expect("recover logger");
        logger2
            .record(TransparencyEvent::delete("h", true, None))
            .await
            .expect("record after recover");

        let contents = fs::read_to_string(&path).expect("read log");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 4);

        let fourth: TransparencyEventOwned = serde_json::from_str(lines[3]).expect("parse fourth");
        assert_eq!(fourth.sequence, 3);
        let expected_hash = hex::encode(Sha256::digest(lines[2].as_bytes()));
        assert_eq!(fourth.prev_hash, expected_hash);
    }

    #[tokio::test]
    async fn logger_preserves_lineage_fields_and_verifies_chain() {
        let path =
            std::env::temp_dir().join(format!("transparency-lineage-{}.log", Uuid::new_v4()));
        let logger = TransparencyLogger::new(&path).expect("initialise logger");
        let previous_expires_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .expect("parse previous expiry")
            .with_timezone(&Utc);

        logger
            .record(
                TransparencyEvent::attenuate(
                    "child-handle",
                    "cust-a",
                    Some(json!({"scope": "read"})),
                )
                .with_caller("spiffe://cluster/ns/default/sa/attenuator")
                .with_parent_handle("parent-handle"),
            )
            .await
            .expect("record attenuation entry");

        logger
            .record(
                TransparencyEvent::renew_lease(
                    "child-handle",
                    "cust-a",
                    Some(json!({"reason": "scheduled_renewal", "ttl_seconds": 600})),
                )
                .with_caller("spiffe://cluster/ns/default/sa/renewer")
                .with_parent_handle("parent-handle")
                .with_lease_renewal(7, previous_expires_at),
            )
            .await
            .expect("record renewal entry");

        let contents = fs::read_to_string(&path).expect("read log");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let attenuation: TransparencyEventOwned =
            serde_json::from_str(lines[0]).expect("parse attenuation entry");
        assert_eq!(attenuation.event, "attenuate");
        assert_eq!(attenuation.handle.as_deref(), Some("child-handle"));
        assert_eq!(attenuation.customer_id.as_deref(), Some("cust-a"));
        assert_eq!(
            attenuation.caller_identity.as_deref(),
            Some("spiffe://cluster/ns/default/sa/attenuator")
        );
        assert_eq!(attenuation.parent_handle.as_deref(), Some("parent-handle"));
        assert_eq!(attenuation.metadata, Some(json!({"scope": "read"})));
        assert_eq!(attenuation.lease_sequence, None);
        assert_eq!(attenuation.previous_expires_at, None);

        let renewal: TransparencyEventOwned =
            serde_json::from_str(lines[1]).expect("parse renewal entry");
        assert_eq!(renewal.event, "renew_lease");
        assert_eq!(renewal.status, "renewed");
        assert_eq!(renewal.handle.as_deref(), Some("child-handle"));
        assert_eq!(renewal.customer_id.as_deref(), Some("cust-a"));
        assert_eq!(
            renewal.caller_identity.as_deref(),
            Some("spiffe://cluster/ns/default/sa/renewer")
        );
        assert_eq!(renewal.parent_handle.as_deref(), Some("parent-handle"));
        assert_eq!(renewal.lease_sequence, Some(7));
        assert_eq!(renewal.previous_expires_at, Some(previous_expires_at));
        assert_eq!(
            renewal.metadata,
            Some(json!({"reason": "scheduled_renewal", "ttl_seconds": 600}))
        );

        let expected_prev_hash = hex::encode(Sha256::digest(lines[0].as_bytes()));
        assert_eq!(renewal.prev_hash, expected_prev_hash);

        let result = TransparencyLogger::verify_chain(&path).expect("verify should pass");
        assert_eq!(result.entries, 2);
        assert_eq!(
            result.head_hash,
            hex::encode(Sha256::digest(lines[1].as_bytes()))
        );
    }

    #[test]
    fn rotate_injects_handle_metadata_and_preserves_lineage_fields() {
        let event = TransparencyEvent::rotate(
            "old-handle",
            "new-handle",
            "envelope-1",
            "cust-a",
            Some(json!({"reason": "scheduled_rotation"})),
        )
        .with_caller("spiffe://cluster/ns/default/sa/rotator")
        .with_parent_handle("parent-handle");

        assert_eq!(event.event, "rotate");
        assert_eq!(event.status, "rotated");
        assert_eq!(event.handle.as_deref(), Some("new-handle"));
        assert_eq!(event.envelope_key_id.as_deref(), Some("envelope-1"));
        assert_eq!(event.customer_id.as_deref(), Some("cust-a"));
        assert_eq!(
            event.caller_identity.as_deref(),
            Some("spiffe://cluster/ns/default/sa/rotator")
        );
        assert_eq!(event.parent_handle.as_deref(), Some("parent-handle"));
        assert_eq!(
            event.metadata,
            Some(json!({
                "reason": "scheduled_rotation",
                "old_handle": "old-handle",
                "new_handle": "new-handle"
            }))
        );
    }

    #[test]
    fn revoke_preserves_status_metadata_and_lineage_fields() {
        let event = TransparencyEvent::revoke(
            "new-handle",
            "cust-a",
            Some(json!({"reason": "operator_burn", "source": "ids"})),
        )
        .with_caller("spiffe://cluster/ns/default/sa/revoker")
        .with_parent_handle("old-handle");

        assert_eq!(event.event, "revoke");
        assert_eq!(event.status, "revoked");
        assert_eq!(event.handle.as_deref(), Some("new-handle"));
        assert_eq!(event.customer_id.as_deref(), Some("cust-a"));
        assert_eq!(
            event.caller_identity.as_deref(),
            Some("spiffe://cluster/ns/default/sa/revoker")
        );
        assert_eq!(event.parent_handle.as_deref(), Some("old-handle"));
        assert_eq!(
            event.metadata,
            Some(json!({"reason": "operator_burn", "source": "ids"}))
        );
    }

    #[test]
    fn rotate_discards_non_object_metadata_and_keeps_handle_fields() {
        let event = TransparencyEvent::rotate(
            "old-handle",
            "new-handle",
            "envelope-1",
            "cust-a",
            Some(json!("not-an-object")),
        );

        assert_eq!(event.event, "rotate");
        assert_eq!(
            event.metadata,
            Some(json!({
                "old_handle": "old-handle",
                "new_handle": "new-handle"
            }))
        );
    }

    #[tokio::test]
    async fn logger_records_wrap_rotate_revoke_chain_and_verifies_metadata() {
        let path =
            std::env::temp_dir().join(format!("transparency-rotate-revoke-{}.log", Uuid::new_v4()));
        let logger = TransparencyLogger::new(&path).expect("initialise logger");

        logger
            .record(TransparencyEvent::wrap(
                "old-handle",
                "envelope-1",
                "cust-a",
                Some(json!({"ttl": 60})),
            ))
            .await
            .expect("record wrap entry");

        logger
            .record(
                TransparencyEvent::rotate(
                    "old-handle",
                    "new-handle",
                    "envelope-2",
                    "cust-a",
                    Some(json!({"reason": "scheduled_rotation"})),
                )
                .with_caller("spiffe://cluster/ns/default/sa/rotator")
                .with_parent_handle("old-handle"),
            )
            .await
            .expect("record rotate entry");

        logger
            .record(
                TransparencyEvent::revoke(
                    "new-handle",
                    "cust-a",
                    Some(json!({"reason": "operator_burn", "source": "ids"})),
                )
                .with_caller("spiffe://cluster/ns/default/sa/revoker")
                .with_parent_handle("old-handle"),
            )
            .await
            .expect("record revoke entry");

        let contents = fs::read_to_string(&path).expect("read log");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 3);

        let wrap: TransparencyEventOwned = serde_json::from_str(lines[0]).expect("parse wrap");
        assert_eq!(wrap.event, "wrap");
        assert_eq!(wrap.status, "issued");
        assert_eq!(wrap.handle.as_deref(), Some("old-handle"));
        assert_eq!(wrap.metadata, Some(json!({"ttl": 60})));

        let rotate: TransparencyEventOwned = serde_json::from_str(lines[1]).expect("parse rotate");
        assert_eq!(rotate.event, "rotate");
        assert_eq!(rotate.status, "rotated");
        assert_eq!(rotate.handle.as_deref(), Some("new-handle"));
        assert_eq!(rotate.envelope_key_id.as_deref(), Some("envelope-2"));
        assert_eq!(rotate.customer_id.as_deref(), Some("cust-a"));
        assert_eq!(
            rotate.caller_identity.as_deref(),
            Some("spiffe://cluster/ns/default/sa/rotator")
        );
        assert_eq!(rotate.parent_handle.as_deref(), Some("old-handle"));
        assert_eq!(
            rotate.metadata,
            Some(json!({
                "reason": "scheduled_rotation",
                "old_handle": "old-handle",
                "new_handle": "new-handle"
            }))
        );
        assert_eq!(
            rotate.prev_hash,
            hex::encode(Sha256::digest(lines[0].as_bytes()))
        );

        let revoke: TransparencyEventOwned = serde_json::from_str(lines[2]).expect("parse revoke");
        assert_eq!(revoke.event, "revoke");
        assert_eq!(revoke.status, "revoked");
        assert_eq!(revoke.handle.as_deref(), Some("new-handle"));
        assert_eq!(revoke.customer_id.as_deref(), Some("cust-a"));
        assert_eq!(
            revoke.caller_identity.as_deref(),
            Some("spiffe://cluster/ns/default/sa/revoker")
        );
        assert_eq!(revoke.parent_handle.as_deref(), Some("old-handle"));
        assert_eq!(
            revoke.metadata,
            Some(json!({"reason": "operator_burn", "source": "ids"}))
        );
        assert_eq!(
            revoke.prev_hash,
            hex::encode(Sha256::digest(lines[1].as_bytes()))
        );

        let result = TransparencyLogger::verify_chain(&path).expect("verify should pass");
        assert_eq!(result.entries, 3);
        assert_eq!(
            result.head_hash,
            hex::encode(Sha256::digest(lines[2].as_bytes()))
        );
    }

    #[tokio::test]
    async fn verify_chain_passes_on_valid_log() {
        let path = std::env::temp_dir().join(format!("transparency-verify-{}.log", Uuid::new_v4()));
        let logger = TransparencyLogger::new(&path).expect("initialise logger");

        for i in 0..5 {
            logger
                .record(TransparencyEvent::wrap(
                    &format!("h-{i}"),
                    "env-key",
                    "cust-1",
                    None,
                ))
                .await
                .expect("record");
        }

        let result = TransparencyLogger::verify_chain(&path).expect("verify should pass");
        assert_eq!(result.entries, 5);
        // head_hash should match SHA-256 of the last line
        let contents = fs::read_to_string(&path).expect("read log");
        let last_line = contents.lines().last().unwrap();
        let expected = hex::encode(Sha256::digest(last_line.as_bytes()));
        assert_eq!(result.head_hash, expected);
    }

    #[tokio::test]
    async fn verify_chain_detects_tampered_line() {
        let path = std::env::temp_dir().join(format!("transparency-tamper-{}.log", Uuid::new_v4()));
        let logger = TransparencyLogger::new(&path).expect("initialise logger");

        for _ in 0..3 {
            logger
                .record(TransparencyEvent::wrap("h", "e", "c", None))
                .await
                .expect("record");
        }

        // Tamper with the second line (change the event field)
        let contents = fs::read_to_string(&path).expect("read");
        let mut lines: Vec<String> = contents.lines().map(String::from).collect();
        lines[1] = lines[1].replace(r#""event":"wrap"#, r#""event":"TAMPERED"#);
        fs::write(&path, lines.join("\n") + "\n").expect("write tampered");

        let err = TransparencyLogger::verify_chain(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("chain broken"),
            "expected chain-broken error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn verify_chain_empty_log() {
        let path = std::env::temp_dir().join(format!("transparency-empty-{}.log", Uuid::new_v4()));
        let _logger = TransparencyLogger::new(&path).expect("initialise logger");

        let result = TransparencyLogger::verify_chain(&path).expect("verify empty");
        assert_eq!(result.entries, 0);
        assert_eq!(result.head_hash, GENESIS_HASH);
    }
}
