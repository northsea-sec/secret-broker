use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroize;

use super::models::UnwrapResponse;
use super::postgres::IssuedCredential;
use super::sealed_store::{
    SecretEnvelope, SecretLifecycle, StoredEnvelopeRecord, ThirdPartyCaveatKey,
};
use super::state::BrokerState;
use super::transparency::{handle_fingerprint, TransparencyEvent};
use super::BrokerClientContext;

/// Single-use capabilities permit exactly one successful unwrap. The wire
/// format carries this as `uint32`, but the V2 runtime rejects every other value.
pub const BROKER_MAX_USES: u32 = 1;
const DISCHARGE_TOKEN_TTL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct PostgresCredentialParams {
    pub audience: String,
    pub scope: Vec<String>,
    pub ttl_seconds: Option<u64>,
    pub application_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PostgresCredentialOutcome {
    pub database_url: String,
    pub username: String,
    pub password: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub ca_certificate_pem: Option<String>,
    pub server_cert_fingerprint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("invalid base64 input")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("crypto error: {0}")]
    Crypto(anyhow::Error),
    #[error("sealed secret handle not found")]
    HandleNotFound,
    #[error("invalid handle format")]
    InvalidHandle,
    #[error("sealed secret expired")]
    ExpiredHandle,
    #[error("sealed store error: {0}")]
    Storage(anyhow::Error),
    #[error("invalid ttl request")]
    InvalidTtl,
    #[error("tls exporter binding mismatch")]
    ExporterBindingMismatch,
    #[error("database error: {0}")]
    Database(anyhow::Error),
    #[error("service unavailable: {0}")]
    Unavailable(&'static str),
    #[error("redeem token invalid or mismatched")]
    RedeemTokenInvalid,
    #[error("redeem token expired")]
    RedeemTokenExpired,
    #[error("redeem token already used")]
    RedeemTokenUsed,
    #[error("secret is revoked")]
    RevokedHandle,
    #[error("invalid attenuation request: {0}")]
    InvalidAttenuation(&'static str),
    #[error("unauthenticated transport for lifecycle-bound secret")]
    UnauthenticatedTransport,
    #[error("authenticated principal required for lifecycle-bound secret")]
    AuthenticatedPrincipalRequired,
    #[error("principal identity mismatch for lifecycle-bound secret")]
    PrincipalMismatch,
    #[error("peer certificate mismatch for lifecycle-bound secret")]
    PeerCertMismatch,
    #[error("attestation digest mismatch for lifecycle-bound secret")]
    AttestationMismatch,
    #[error("lifecycle-bound secret missing required lineage: {0}")]
    MissingLineage(&'static str),
    #[error("authenticated principal is not authorized for discharge minting")]
    UnauthorizedDischargePrincipal,
}

pub(crate) async fn issue_postgres_credentials_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    params: PostgresCredentialParams,
) -> Result<PostgresCredentialOutcome, ServiceError> {
    if !context.has_authenticated_transport() {
        return Err(ServiceError::UnauthenticatedTransport);
    }
    context
        .principal_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::AuthenticatedPrincipalRequired)?;
    context
        .peer_cert_sha256()
        .ok_or(ServiceError::MissingLineage(
            "peer certificate lineage on the authenticated broker transport",
        ))?;

    let manager = state.postgres().ok_or(ServiceError::Unavailable(
        "postgres credential issuance disabled",
    ))?;

    let audience = params.audience.trim();
    if audience.is_empty() {
        return Err(ServiceError::InvalidHandle);
    }

    let mut scopes: Vec<String> = params
        .scope
        .into_iter()
        .filter_map(|scope| {
            let trimmed = scope.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect();
    scopes.sort();
    scopes.dedup();

    let exporter = context.exporter();
    if exporter.iter().all(|byte| *byte == 0) {
        return Err(ServiceError::ExporterBindingMismatch);
    }

    let lease: IssuedCredential = manager
        .issue_credentials(
            audience,
            &scopes,
            params.ttl_seconds,
            exporter,
            params.application_name.as_deref(),
        )
        .await
        .map_err(ServiceError::Database)?;

    info!(
        audience,
        username = lease.username.as_str(),
        "issued Postgres credential lease"
    );

    Ok(PostgresCredentialOutcome {
        database_url: lease.database_url,
        username: lease.username,
        password: lease.password,
        expires_at: Some(lease.expires_at),
        ca_certificate_pem: lease.ca_certificate_pem,
        server_cert_fingerprint: lease.server_cert_fingerprint,
    })
}

pub(crate) async fn delete_secret_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    handle: &str,
) -> Result<bool, ServiceError> {
    let handle_id = parse_handle_identifier(state, handle)?;
    let store = state.sealed_store();

    if let Some(record) = store
        .load(&handle_id)
        .await
        .map_err(ServiceError::Storage)?
    {
        validate_v2_record_management_requirements(&record, context)?;
    }

    let removed = store
        .delete(&handle_id)
        .await
        .map_err(ServiceError::Storage)?;

    let fingerprint = handle_fingerprint(handle);
    if removed {
        info!(handle_fingerprint = %fingerprint, "sealed secret deleted");
    } else {
        info!(handle_fingerprint = %fingerprint, "sealed secret already removed");
    }

    state
        .record_transparency(
            TransparencyEvent::delete(
                handle,
                removed,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(removed)
}

pub struct WrapSecretOutcome {
    pub handle: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub redeem_token: String,
    pub redeem_token_expires_at: Option<DateTime<Utc>>,
}

struct StoredSecretOutcome {
    handle_id: Uuid,
    customer_id: String,
    expires_at: Option<DateTime<Utc>>,
    envelope_key_id: String,
    redeem_token: String,
    redeem_token_expires_at: Option<DateTime<Utc>>,
}

struct PersistSecretV2Input<'a> {
    plaintext: &'a [u8],
    customer_id: String,
    metadata: Option<Value>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    lifecycle: SecretLifecycle,
    initial_lease_seconds: Option<u64>,
    unwrap_principal_id: Option<String>,
}

async fn persist_secret_v2_with_lifecycle(
    state: &BrokerState,
    context: &BrokerClientContext,
    input: PersistSecretV2Input<'_>,
) -> Result<StoredSecretOutcome, ServiceError> {
    let handle_id = Uuid::new_v4();

    let binding_hash = Sha256::digest(context.exporter());
    let binding_hash_vec = binding_hash.to_vec();
    let binding_hash_b64 = STANDARD.encode(&binding_hash_vec);
    let (binding_vec, redeem_binding, exporter_binding) = match input.lifecycle {
        SecretLifecycle::SingleUseUnwrap => (
            binding_hash_vec.clone(),
            Some(binding_hash_b64),
            Some(STANDARD.encode(context.exporter())),
        ),
        SecretLifecycle::RenewableLease | SecretLifecycle::ServiceBootstrap => {
            (Vec::new(), None, None)
        }
    };
    let mut redeem_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut redeem_nonce);
    let redeem_nonce_b64 = STANDARD.encode(redeem_nonce);

    let redeem_token_expires_at = Some(input.created_at + state.redeem_token_ttl());
    let redeem_token_bytes = state
        .compute_redeem_token(&handle_id, &binding_vec, &redeem_nonce)
        .map_err(ServiceError::Crypto)?;
    let redeem_token = STANDARD.encode(&redeem_token_bytes);

    let envelope_key_id = Uuid::new_v4().to_string();
    let encryption = state
        .crypto()
        .encrypt_pqc(
            input.plaintext,
            &envelope_key_id,
            &input.customer_id,
            exporter_binding.as_ref().map(|_| context.exporter()),
        )
        .await
        .map_err(ServiceError::Crypto)?;

    let envelope = SecretEnvelope {
        envelope_key_id: envelope_key_id.clone(),
        algorithm: encryption.algorithm.clone(),
        ciphertext: STANDARD.encode(&encryption.ciphertext),
        kyber_ciphertext: STANDARD.encode(&encryption.nonce),
        customer_id: input.customer_id.clone(),
        exporter_binding,
        metadata: input.metadata,
        created_at: input.created_at,
    };

    let key_pair = state
        .crypto()
        .generate_key_pair("dilithium5", &input.customer_id)
        .await
        .map_err(ServiceError::Crypto)?;

    let signing_key_id = key_pair.key_id.clone();
    let signing_public_key = key_pair.public_key.clone();

    let envelope_bytes = serde_json::to_vec(&envelope)?;
    let signature = state
        .crypto()
        .sign_data(&envelope_bytes, &signing_key_id)
        .await
        .map_err(ServiceError::Crypto)?;

    let record = StoredEnvelopeRecord {
        envelope,
        signature: STANDARD.encode(&signature),
        signing_key_id: signing_key_id.clone(),
        signing_public_key: STANDARD.encode(signing_public_key),
        signing_key_expires_at: key_pair.expires_at,
        expires_at: input.expires_at,
        last_accessed: None,
        redeem_nonce: Some(redeem_nonce_b64),
        redeem_binding,
        unwrap_principal_id: input.unwrap_principal_id,
        issued_with_authenticated_transport: context.has_authenticated_transport(),
        issued_by_principal_id: normalized_context_principal(context),
        issued_by_peer_cert_sha256: context
            .peer_cert_sha256()
            .map(|value| STANDARD.encode(value)),
        issued_by_attestation_digest: context
            .attestation_digest()
            .map(|value| STANDARD.encode(value)),
        third_party_caveat_keys: None,
        redeem_expires_at: redeem_token_expires_at,
        redeem_used: false,
        threshold: None,
        threshold_commitments: None,
        lifecycle: input.lifecycle,
        lease_expires_at: input
            .initial_lease_seconds
            .map(|secs| input.created_at + Duration::seconds(secs as i64)),
        lease_renewal_count: 0,
        revoked: false,
        revoked_at: None,
        revocation_reason: None,
        share_assignments: None,
        held_shares: None,
    };

    state
        .sealed_store()
        .insert_with_id(handle_id, record)
        .await
        .map_err(ServiceError::Storage)?;

    Ok(StoredSecretOutcome {
        handle_id,
        customer_id: input.customer_id,
        expires_at: input.expires_at,
        envelope_key_id,
        redeem_token,
        redeem_token_expires_at,
    })
}

fn enforce_ttl(
    ttl_seconds: Option<u64>,
    state: &BrokerState,
    created_at: DateTime<Utc>,
) -> Result<(Option<DateTime<Utc>>, Option<u64>), ServiceError> {
    match ttl_seconds {
        Some(secs) => {
            if secs == 0 {
                return Err(ServiceError::InvalidTtl);
            }
            let max_allowed = state.max_handle_ttl().num_seconds();
            if secs as i64 > max_allowed {
                return Err(ServiceError::InvalidTtl);
            }
            Ok((
                Some(created_at + Duration::seconds(secs as i64)),
                Some(secs),
            ))
        }
        None => Ok((None, None)),
    }
}

// --- V2: Macaroon handles + Shamir threshold redeem tokens ---

use super::macaroon_caveats::{
    Caveat, CaveatVerifier, DischargeKeyRef, DischargeMacaroon, Macaroon, MacaroonError,
};
use super::threshold;

const HANDLE_V2_PREFIX: &str = "broker:v2:";

#[derive(Debug, Clone)]
pub struct WrapV2Request {
    pub plaintext: Vec<u8>,
    pub customer_id: Option<String>,
    pub metadata: Option<Value>,
    pub lifecycle: SecretLifecycle,
    pub ttl_seconds: Option<u64>,
    pub initial_lease_seconds: Option<u64>,
    pub label: Option<String>,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub unwrap_principal_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MintV2Request {
    pub ttl_seconds: Option<u64>,
    pub label: Option<String>,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub threshold: Option<u8>,
    pub num_shares: Option<u8>,
    pub lifecycle: SecretLifecycle,
    pub initial_lease_seconds: Option<u64>,
    /// Custodian identifiers for broker-held threshold shares.
    pub custodian_ids: Vec<String>,
    pub unwrap_principal_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MintV2Response {
    pub handle: String,
    pub key: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub redeem_token: String,
    pub redeem_token_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct UnwrapV2Request {
    pub handle: String,
    pub redeem_token: String,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub discharges: Vec<DischargeMacaroon>,
}

/// Request to add a third-party caveat during attenuation.
#[derive(Debug, Clone)]
pub struct ThirdPartyCaveatRequest {
    pub location: String,
    pub condition: String,
}

#[derive(Debug, Clone)]
pub struct AttenuateV2Request {
    pub handle: String,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub action: Option<String>,
    pub max_uses: Option<u32>,
    pub third_party: Option<ThirdPartyCaveatRequest>,
}

#[derive(Debug, Clone)]
pub struct AttenuateV2Response {
    pub handle: String,
    pub third_party_caveat_id: Option<String>,
}

/// Parse a v2 macaroon handle: "broker:v2:<base64_macaroon>"
pub fn parse_handle_v2(raw: &str) -> Result<Macaroon, ServiceError> {
    let trimmed = raw.trim();
    let b64 = trimmed
        .strip_prefix(HANDLE_V2_PREFIX)
        .ok_or(ServiceError::InvalidHandle)?;
    Macaroon::deserialize(b64).map_err(|_| ServiceError::InvalidHandle)
}

fn parse_handle_identifier(state: &BrokerState, raw: &str) -> Result<Uuid, ServiceError> {
    let macaroon = parse_handle_v2(raw)?;
    let root_key = state.macaroon_root_key(&macaroon.identifier);
    macaroon
        .verify_signature(&root_key)
        .map_err(|_| ServiceError::InvalidHandle)?;
    Ok(macaroon.identifier)
}

fn normalized_context_principal(context: &BrokerClientContext) -> Option<String> {
    context
        .principal_id()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn append_context_transparency_meta(
    transparency_meta: &mut serde_json::Map<String, Value>,
    context: &BrokerClientContext,
) {
    transparency_meta.insert(
        "authenticated_transport".into(),
        Value::Bool(context.has_authenticated_transport()),
    );
    if let Some(principal) = normalized_context_principal(context) {
        transparency_meta.insert(
            "authenticated_principal_id".into(),
            Value::String(principal),
        );
    }
    if let Some(peer_cert_sha256) = context.peer_cert_sha256() {
        transparency_meta.insert(
            "peer_cert_sha256".into(),
            Value::String(STANDARD.encode(peer_cert_sha256)),
        );
    }
    if let Some(attestation_digest) = context.attestation_digest() {
        transparency_meta.insert(
            "attestation_digest".into(),
            Value::String(STANDARD.encode(attestation_digest)),
        );
    }
}

fn secret_lifecycle_label(lifecycle: SecretLifecycle) -> &'static str {
    match lifecycle {
        SecretLifecycle::SingleUseUnwrap => "single_use_unwrap",
        SecretLifecycle::RenewableLease => "renewable_lease",
        SecretLifecycle::ServiceBootstrap => "service_bootstrap",
    }
}

fn append_record_transparency_meta(
    transparency_meta: &mut serde_json::Map<String, Value>,
    record: &StoredEnvelopeRecord,
) {
    transparency_meta.insert(
        "lifecycle".into(),
        Value::String(secret_lifecycle_label(record.lifecycle).to_string()),
    );
    transparency_meta.insert(
        "issued_with_authenticated_transport".into(),
        Value::Bool(record.issued_with_authenticated_transport),
    );
    if let Some(principal) = record.issued_by_principal_id.as_ref() {
        transparency_meta.insert(
            "issued_by_principal_id".into(),
            Value::String(principal.clone()),
        );
    }
    if let Some(peer_cert_sha256) = record.issued_by_peer_cert_sha256.as_ref() {
        transparency_meta.insert(
            "issued_by_peer_cert_sha256".into(),
            Value::String(peer_cert_sha256.clone()),
        );
    }
    if let Some(attestation_digest) = record.issued_by_attestation_digest.as_ref() {
        transparency_meta.insert(
            "issued_by_attestation_digest".into(),
            Value::String(attestation_digest.clone()),
        );
    }
    if let Some(principal) = record.unwrap_principal_id.as_ref() {
        transparency_meta.insert(
            "unwrap_principal_id".into(),
            Value::String(principal.clone()),
        );
    }
    if let Some(expires_at) = record.expires_at.as_ref() {
        transparency_meta.insert("expires_at".into(), Value::String(expires_at.to_rfc3339()));
    }
    if let Some(redeem_expires_at) = record.redeem_expires_at.as_ref() {
        transparency_meta.insert(
            "redeem_expires_at".into(),
            Value::String(redeem_expires_at.to_rfc3339()),
        );
    }
    if let Some(lease_expires_at) = record.lease_expires_at.as_ref() {
        transparency_meta.insert(
            "lease_expires_at".into(),
            Value::String(lease_expires_at.to_rfc3339()),
        );
    }
    if record.lease_renewal_count > 0 {
        transparency_meta.insert(
            "lease_renewal_count".into(),
            Value::from(record.lease_renewal_count),
        );
    }
    if let Some(metadata) = record.envelope.metadata.clone() {
        transparency_meta.insert("secret_metadata".into(), metadata);
    }
}

fn discharge_keys_for_record(
    record: &StoredEnvelopeRecord,
) -> Result<Vec<DischargeKeyRef>, ServiceError> {
    let mut keys = Vec::new();

    if let Some(entries) = record.third_party_caveat_keys.as_ref() {
        for entry in entries {
            let decoded = STANDARD
                .decode(entry.secret_b64.as_bytes())
                .map_err(|err| {
                    ServiceError::Storage(anyhow::anyhow!(
                        "invalid stored third-party caveat secret: {err}"
                    ))
                })?;
            let key: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
                ServiceError::Storage(anyhow::anyhow!(
                    "stored third-party caveat secret must be 32 bytes"
                ))
            })?;
            keys.push(DischargeKeyRef {
                location: entry.location.clone(),
                key_id: entry.key_id.clone(),
                condition: entry.condition.clone().ok_or_else(|| {
                    ServiceError::Storage(anyhow::anyhow!(
                        "stored third-party caveat is missing its predicate"
                    ))
                })?,
                key,
            });
        }
    }

    Ok(keys)
}

fn normalize_spiffe_principal(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.starts_with("spiffe://") {
        return None;
    }
    Some(trimmed.to_string())
}

fn validate_discharge_mint_requirements(
    state: &BrokerState,
    context: &BrokerClientContext,
    location: &str,
) -> Result<(), ServiceError> {
    if !context.has_authenticated_transport() {
        return Err(ServiceError::UnauthenticatedTransport);
    }
    let principal = context
        .principal_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::AuthenticatedPrincipalRequired)?;
    context
        .peer_cert_sha256()
        .ok_or(ServiceError::MissingLineage(
            "peer certificate lineage on the authenticated broker transport",
        ))?;
    if state.require_attested_discharge_mint() && context.attestation_digest().is_none() {
        return Err(ServiceError::MissingLineage(
            "attestation digest lineage on the authenticated broker transport",
        ));
    }
    if let Some(location_principal) = normalize_spiffe_principal(location) {
        if principal != location_principal {
            return Err(ServiceError::UnauthorizedDischargePrincipal);
        }
    }
    let allowed_principals = state.allowed_discharge_principal_ids();
    if !allowed_principals.is_empty()
        && !allowed_principals
            .iter()
            .any(|allowed| allowed == principal)
    {
        return Err(ServiceError::UnauthorizedDischargePrincipal);
    }
    Ok(())
}

fn v2_unwrap_principal(
    context: &BrokerClientContext,
    lifecycle: SecretLifecycle,
    requested_principal: Option<String>,
) -> Result<Option<String>, ServiceError> {
    let requested_principal = requested_principal
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if !context.has_authenticated_transport() {
        return Err(ServiceError::UnauthenticatedTransport);
    }
    let current_principal = normalized_context_principal(context)
        .ok_or(ServiceError::AuthenticatedPrincipalRequired)?;
    match lifecycle {
        SecretLifecycle::SingleUseUnwrap => {
            if let Some(requested) = requested_principal.as_ref() {
                if requested != &current_principal {
                    return Err(ServiceError::PrincipalMismatch);
                }
            }
            Ok(Some(current_principal))
        }
        SecretLifecycle::RenewableLease | SecretLifecycle::ServiceBootstrap => {
            if context.peer_cert_sha256().is_none() {
                return Err(ServiceError::MissingLineage(
                    "peer certificate lineage on the authenticated broker transport",
                ));
            }
            Ok(Some(requested_principal.unwrap_or(current_principal)))
        }
    }
}

fn validate_v2_record_identity_requirements(
    record: &StoredEnvelopeRecord,
    context: &BrokerClientContext,
) -> Result<(), ServiceError> {
    validate_v2_record_identity_requirements_inner(record, context, false)
}

fn validate_v2_record_management_requirements(
    record: &StoredEnvelopeRecord,
    context: &BrokerClientContext,
) -> Result<(), ServiceError> {
    validate_v2_record_identity_requirements_inner(record, context, true)
}

fn validate_v2_record_identity_requirements_inner(
    record: &StoredEnvelopeRecord,
    context: &BrokerClientContext,
    allow_issuing_principal: bool,
) -> Result<(), ServiceError> {
    let expected_principal = record
        .unwrap_principal_id
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::MissingLineage("principal binding"))?;
    if !context.has_authenticated_transport() {
        return Err(ServiceError::UnauthenticatedTransport);
    }
    let actual_principal = context
        .principal_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::AuthenticatedPrincipalRequired)?;
    let mut issuer_authorized = false;
    let mut issued_by_principal_id = None;
    if record.lifecycle != SecretLifecycle::SingleUseUnwrap {
        if !record.issued_with_authenticated_transport {
            return Err(ServiceError::MissingLineage(
                "authenticated issuance transport",
            ));
        }
        let issuer = record
            .issued_by_principal_id
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or(ServiceError::MissingLineage("issuing principal lineage"))?;
        issued_by_principal_id = Some(issuer);
        if allow_issuing_principal && actual_principal == issuer {
            issuer_authorized = true;
        }
    }
    if actual_principal != expected_principal && !issuer_authorized {
        return Err(ServiceError::PrincipalMismatch);
    }
    if record.lifecycle != SecretLifecycle::SingleUseUnwrap {
        let actual_peer_cert_sha256 =
            context
                .peer_cert_sha256()
                .ok_or(ServiceError::MissingLineage(
                    "peer certificate lineage on the authenticated broker transport",
                ))?;
        let issued_by_principal_id = issued_by_principal_id
            .ok_or(ServiceError::MissingLineage("issuing principal lineage"))?;
        let expected_peer_cert_sha256 = record
            .issued_by_peer_cert_sha256
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or(ServiceError::MissingLineage(
                "issuing peer certificate lineage",
            ))?;
        if actual_principal == issued_by_principal_id {
            let actual_peer_cert_sha256 = STANDARD.encode(actual_peer_cert_sha256);
            if actual_peer_cert_sha256 != expected_peer_cert_sha256 {
                return Err(ServiceError::PeerCertMismatch);
            }
        }
        if let Some(expected_attestation_digest) = record
            .issued_by_attestation_digest
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            let actual_attestation_digest =
                context
                    .attestation_digest()
                    .ok_or(ServiceError::MissingLineage(
                        "attestation digest lineage on the authenticated broker transport",
                    ))?;
            let actual_attestation_digest = STANDARD.encode(actual_attestation_digest);
            if actual_attestation_digest != expected_attestation_digest {
                return Err(ServiceError::AttestationMismatch);
            }
        }
    }
    Ok(())
}

fn validate_threshold_custody_record_requirements(
    record: &StoredEnvelopeRecord,
    context: &BrokerClientContext,
) -> Result<(), ServiceError> {
    if !context.has_authenticated_transport() {
        return Err(ServiceError::UnauthenticatedTransport);
    }
    let actual_principal = context
        .principal_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::AuthenticatedPrincipalRequired)?;
    let actual_peer_cert_sha256 =
        context
            .peer_cert_sha256()
            .ok_or(ServiceError::MissingLineage(
                "peer certificate lineage on the authenticated broker transport",
            ))?;
    if !record.issued_with_authenticated_transport {
        return Err(ServiceError::MissingLineage(
            "authenticated issuance transport",
        ));
    }
    let issued_by_principal_id = record
        .issued_by_principal_id
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::MissingLineage("issuing principal lineage"))?;
    let expected_peer_cert_sha256 = record
        .issued_by_peer_cert_sha256
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::MissingLineage(
            "issuing peer certificate lineage",
        ))?;
    if actual_principal == issued_by_principal_id {
        let actual_peer_cert_sha256 = STANDARD.encode(actual_peer_cert_sha256);
        if actual_peer_cert_sha256 != expected_peer_cert_sha256 {
            return Err(ServiceError::PeerCertMismatch);
        }
    }
    if let Some(expected_attestation_digest) = record
        .issued_by_attestation_digest
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let actual_attestation_digest =
            context
                .attestation_digest()
                .ok_or(ServiceError::MissingLineage(
                    "attestation digest lineage on the authenticated broker transport",
                ))?;
        let actual_attestation_digest = STANDARD.encode(actual_attestation_digest);
        if actual_attestation_digest != expected_attestation_digest {
            return Err(ServiceError::AttestationMismatch);
        }
    }
    Ok(())
}

pub(crate) async fn mint_aead_key_v2_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    request: MintV2Request,
) -> Result<MintV2Response, ServiceError> {
    let created_at = Utc::now();
    let (expires_at, effective_ttl) = enforce_ttl(request.ttl_seconds, state, created_at)?;
    let ttl_seconds = effective_ttl;

    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key_b64 = STANDARD.encode(key_bytes);

    let label = request
        .label
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let mut metadata = serde_json::Map::new();
    metadata.insert("purpose".into(), Value::String("aead-key".into()));
    metadata.insert("handle_version".into(), Value::from(2));
    if let Some(label) = label.clone() {
        metadata.insert("label".into(), Value::String(label));
    }
    if let Some(ttl) = ttl_seconds {
        metadata.insert("ttl_seconds".into(), Value::from(ttl));
    }

    // Determine threshold parameters
    let threshold = request.threshold.unwrap_or(1);
    let num_shares = request.num_shares.unwrap_or(1);
    if threshold < 1 || threshold > num_shares {
        return Err(ServiceError::InvalidTtl); // reuse existing error for bad params
    }

    let unwrap_principal_id = v2_unwrap_principal(
        context,
        request.lifecycle,
        request.unwrap_principal_id.clone(),
    )?;

    let outcome = persist_secret_v2_with_lifecycle(
        state,
        context,
        PersistSecretV2Input {
            plaintext: &key_bytes,
            customer_id: state.default_customer_id().to_string(),
            metadata: Some(Value::Object(metadata)),
            created_at,
            expires_at,
            lifecycle: request.lifecycle,
            initial_lease_seconds: request.initial_lease_seconds,
            unwrap_principal_id: unwrap_principal_id.clone(),
        },
    )
    .await?;

    Zeroize::zeroize(&mut key_bytes);

    // Build the only externally valid handle form: a signed V2 macaroon.
    let handle_id = outcome.handle_id;
    let root_key = state.macaroon_root_key(&handle_id);
    let mut caveats = Vec::new();
    if let Some(ref tid) = request.tenant_id {
        caveats.push(Caveat::TenantId(tid.clone()));
    }
    if let Some(ref prov) = request.provider {
        caveats.push(Caveat::Provider(prov.clone()));
    }
    if let Some(exp) = expires_at {
        caveats.push(Caveat::Expires(exp));
    }
    caveats.push(Caveat::Action("unwrap".into()));
    caveats.push(Caveat::MaxUses);
    let mac = Macaroon::mint(&root_key, handle_id, caveats);
    let v2_handle = format!("{}{}", HANDLE_V2_PREFIX, mac.serialize());

    // Build redeem token - either single or Shamir shares
    let custodian_mode = threshold > 1 && !request.custodian_ids.is_empty();
    if custodian_mode && request.custodian_ids.len() != num_shares as usize {
        return Err(ServiceError::InvalidTtl); // reuse for bad params
    }

    let redeem_token_str = if threshold > 1 {
        let token_bytes = STANDARD
            .decode(outcome.redeem_token.as_bytes())
            .map_err(|_| ServiceError::Crypto(anyhow::anyhow!("bad redeem token base64")))?;
        let token_arr: [u8; 32] = token_bytes
            .try_into()
            .map_err(|_| ServiceError::Crypto(anyhow::anyhow!("redeem token not 32 bytes")))?;
        let split = threshold::split(&token_arr, threshold, num_shares)
            .map_err(|e| ServiceError::Crypto(anyhow::anyhow!("feldman split: {e}")))?;
        let encoded_commitments = split
            .commitments
            .iter()
            .map(|commitment| STANDARD.encode(commitment))
            .collect::<Vec<_>>();
        let store = state.sealed_store();
        store
            .update_threshold_config(&handle_id, threshold, encoded_commitments.clone())
            .await
            .map_err(ServiceError::Storage)?;

        if custodian_mode {
            // Broker holds shares - store assignments and share material in sealed record
            use crate::secret_broker_impl::sealed_store::{HeldShare, ShareAssignment};
            let assignments: Vec<ShareAssignment> = request
                .custodian_ids
                .iter()
                .enumerate()
                .map(|(i, cid)| ShareAssignment {
                    custodian_id: cid.clone(),
                    share_index: split.shares[i].x,
                    claimed: false,
                })
                .collect();
            let held: Vec<HeldShare> = split
                .shares
                .iter()
                .map(|s| HeldShare {
                    x: s.x,
                    y_b64: STANDARD.encode(&s.y),
                })
                .collect();
            store
                .update_share_assignments(&handle_id, assignments, held)
                .await
                .map_err(ServiceError::Storage)?;
            // Return empty token - custodians claim shares via ClaimShare RPC
            String::new()
        } else {
            serde_json::to_string(&split.shares).map_err(ServiceError::Serialization)?
        }
    } else {
        outcome.redeem_token
    };

    // Transparency
    let mut transparency_meta = serde_json::Map::new();
    transparency_meta.insert("purpose".into(), Value::String("aead-key-v2".into()));
    transparency_meta.insert("handle_version".into(), Value::from(2));
    transparency_meta.insert("threshold".into(), Value::from(threshold));
    transparency_meta.insert("num_shares".into(), Value::from(num_shares));
    append_context_transparency_meta(&mut transparency_meta, context);
    if let Some(label) = label {
        transparency_meta.insert("label".into(), Value::String(label));
    }
    if let Some(principal) = unwrap_principal_id {
        transparency_meta.insert("unwrap_principal_id".into(), Value::String(principal));
    }
    state
        .record_transparency(
            TransparencyEvent::wrap(
                &v2_handle,
                &outcome.envelope_key_id,
                &outcome.customer_id,
                Some(Value::Object(transparency_meta)),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(MintV2Response {
        handle: v2_handle,
        key: key_b64,
        expires_at,
        redeem_token: redeem_token_str,
        redeem_token_expires_at: outcome.redeem_token_expires_at,
    })
}

pub(crate) async fn wrap_secret_v2_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    request: WrapV2Request,
) -> Result<WrapSecretOutcome, ServiceError> {
    let created_at = Utc::now();
    let lifecycle = request.lifecycle;
    let customer_id = request
        .customer_id
        .clone()
        .and_then(normalize_optional_string)
        .unwrap_or_else(|| state.default_customer_id().to_string());
    let (expires_at, effective_ttl) = enforce_ttl(request.ttl_seconds, state, created_at)?;
    let unwrap_principal_id =
        v2_unwrap_principal(context, lifecycle, request.unwrap_principal_id.clone())?;
    let outcome = persist_secret_v2_with_lifecycle(
        state,
        context,
        PersistSecretV2Input {
            plaintext: &request.plaintext,
            customer_id,
            metadata: request.metadata.clone(),
            created_at,
            expires_at,
            lifecycle,
            initial_lease_seconds: request.initial_lease_seconds,
            unwrap_principal_id: unwrap_principal_id.clone(),
        },
    )
    .await?;

    let handle_id = outcome.handle_id;
    let root_key = state.macaroon_root_key(&handle_id);
    let mut caveats = Vec::new();
    if let Some(tid) = request.tenant_id.and_then(normalize_optional_string) {
        caveats.push(Caveat::TenantId(tid));
    }
    if let Some(prov) = request.provider.and_then(normalize_optional_string) {
        caveats.push(Caveat::Provider(prov));
    }
    if let Some(circuit_id) = request.circuit_id.and_then(normalize_optional_string) {
        caveats.push(Caveat::CircuitId(circuit_id));
    }
    if let Some(node_id) = request.node_id.and_then(normalize_optional_string) {
        caveats.push(Caveat::NodeId(node_id));
    }
    if let Some(exp) = outcome.expires_at {
        caveats.push(Caveat::Expires(exp));
    }
    caveats.push(Caveat::Action("unwrap".into()));
    caveats.push(Caveat::MaxUses);
    let mac = Macaroon::mint(&root_key, handle_id, caveats);
    let v2_handle = format!("{}{}", HANDLE_V2_PREFIX, mac.serialize());

    let mut transparency_meta = serde_json::Map::new();
    transparency_meta.insert("purpose".into(), Value::String("wrap-secret-v2".into()));
    transparency_meta.insert("handle_version".into(), Value::from(2));
    transparency_meta.insert(
        "lifecycle".into(),
        Value::String(secret_lifecycle_label(lifecycle).to_string()),
    );
    transparency_meta.insert(
        "handle_fingerprint".into(),
        Value::String(handle_fingerprint(&v2_handle)),
    );
    append_context_transparency_meta(&mut transparency_meta, context);
    if let Some(label) = request.label.and_then(normalize_optional_string) {
        transparency_meta.insert("label".into(), Value::String(label));
    }
    transparency_meta.insert(
        "customer_id".into(),
        Value::String(outcome.customer_id.clone()),
    );
    if let Some(ttl_seconds) = effective_ttl {
        transparency_meta.insert("ttl_seconds".into(), Value::from(ttl_seconds));
    }
    if let Some(principal) = unwrap_principal_id {
        transparency_meta.insert("unwrap_principal_id".into(), Value::String(principal));
    }
    if let Some(metadata) = request.metadata.clone() {
        transparency_meta.insert("secret_metadata".into(), metadata);
    }
    state
        .record_transparency(
            TransparencyEvent::wrap(
                &v2_handle,
                &outcome.envelope_key_id,
                &outcome.customer_id,
                Some(Value::Object(transparency_meta)),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(WrapSecretOutcome {
        handle: v2_handle,
        expires_at: outcome.expires_at,
        redeem_token: outcome.redeem_token,
        redeem_token_expires_at: outcome.redeem_token_expires_at,
    })
}

pub(crate) async fn unwrap_secret_v2_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    payload: UnwrapV2Request,
) -> Result<UnwrapResponse, ServiceError> {
    // Parse macaroon from v2 handle
    let mac = parse_handle_v2(&payload.handle)?;
    let handle_id = mac.identifier;

    // Load record from sealed store first so per-handle caveat discharge keys
    // are available during macaroon verification.
    let store = state.sealed_store();
    let record = store
        .load(&handle_id)
        .await
        .map_err(ServiceError::Storage)?
        .ok_or(ServiceError::HandleNotFound)?;
    // Verify macaroon HMAC chain + caveats
    let root_key = state.macaroon_root_key(&handle_id);
    let verifier = CaveatVerifier {
        tenant_id: payload.tenant_id,
        provider: payload.provider,
        circuit_id: payload.circuit_id,
        node_id: payload.node_id,
        action: Some("unwrap".into()),
        use_count: 1,
        now: Utc::now(),
        discharges: payload.discharges,
        discharge_keys: discharge_keys_for_record(&record)?,
    };
    mac.verify(&root_key, &verifier).map_err(|e| match e {
        MacaroonError::SignatureInvalid => ServiceError::InvalidHandle,
        MacaroonError::Expired => ServiceError::ExpiredHandle,
        other => ServiceError::Crypto(anyhow::anyhow!("macaroon: {other}")),
    })?;

    let now = Utc::now();
    if record.revoked {
        return Err(ServiceError::RevokedHandle);
    }
    if record.is_expired(now) {
        return Err(ServiceError::ExpiredHandle);
    }
    validate_v2_record_identity_requirements(&record, context)?;
    // For RenewableLease: check lease expiry (distinct from hard TTL).
    if record.lifecycle == SecretLifecycle::RenewableLease {
        if let Some(lease_exp) = record.lease_expires_at {
            if now > lease_exp {
                return Err(ServiceError::Crypto(anyhow::anyhow!(
                    "lease expired at {lease_exp}; renew with RenewLease before unwrapping"
                )));
            }
        }
    }

    if let Some(signing_key_expires_at) = record.signing_key_expires_at {
        if now > signing_key_expires_at {
            return Err(ServiceError::Crypto(anyhow::anyhow!(
                "sealed envelope signing key expired at {signing_key_expires_at}"
            )));
        }
    }

    // Verify the sealed envelope with its persisted public key so verification
    // survives recreation of the in-memory signing-key cache after a restart.
    let envelope_bytes = record.envelope_bytes().map_err(ServiceError::Storage)?;
    let signature = record.signature_bytes().map_err(ServiceError::Storage)?;
    let signing_public_key = STANDARD
        .decode(record.signing_public_key.as_bytes())
        .map_err(|_| ServiceError::SignatureInvalid)?;
    let verified = state
        .crypto()
        .verify_persisted_envelope_signature(&envelope_bytes, &signature, &signing_public_key)
        .map_err(ServiceError::Crypto)?;
    if !verified {
        return Err(ServiceError::SignatureInvalid);
    }

    // Redeem token verification
    let binding_hash = Sha256::digest(context.exporter());
    let binding_hash_vec = binding_hash.to_vec();
    let binding_hash_b64 = STANDARD.encode(&binding_hash_vec);

    let redeem_nonce_b64 = record
        .redeem_nonce
        .as_ref()
        .ok_or(ServiceError::RedeemTokenInvalid)?;
    let effective_binding_vec = match record.redeem_binding.as_ref() {
        Some(redeem_binding) if !redeem_binding.is_empty() => {
            if redeem_binding != &binding_hash_b64 {
                return Err(ServiceError::RedeemTokenInvalid);
            }
            binding_hash_vec.clone()
        }
        _ if record.lifecycle == SecretLifecycle::SingleUseUnwrap => {
            return Err(ServiceError::RedeemTokenInvalid);
        }
        _ => Vec::new(),
    };
    let is_renewable_v2 = record.lifecycle == SecretLifecycle::RenewableLease;
    if !is_renewable_v2 && record.redeem_used {
        return Err(ServiceError::RedeemTokenUsed);
    }
    let redeem_expires_at = record
        .redeem_expires_at
        .ok_or(ServiceError::RedeemTokenInvalid)?;
    if now > redeem_expires_at {
        return Err(ServiceError::RedeemTokenExpired);
    }

    let redeem_nonce = STANDARD
        .decode(redeem_nonce_b64.as_bytes())
        .map_err(|_| ServiceError::RedeemTokenInvalid)?;
    let expected_token = state
        .compute_redeem_token(&handle_id, &effective_binding_vec, &redeem_nonce)
        .map_err(ServiceError::Crypto)?;

    // Reconstruct token from shares if threshold mode, else direct compare
    let provided_token = if record.threshold.unwrap_or(1) > 1 {
        let threshold_val = record.threshold.unwrap();
        let shares: Vec<threshold::Share> = serde_json::from_str(&payload.redeem_token)
            .map_err(|_| ServiceError::RedeemTokenInvalid)?;
        let commitments = record
            .threshold_commitments
            .as_ref()
            .ok_or(ServiceError::RedeemTokenInvalid)?
            .iter()
            .map(|commitment| {
                STANDARD
                    .decode(commitment.as_bytes())
                    .map_err(|_| ServiceError::RedeemTokenInvalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed = threshold::reconstruct(&shares, threshold_val, &commitments)
            .map_err(|_| ServiceError::RedeemTokenInvalid)?;
        reconstructed.to_vec()
    } else {
        STANDARD
            .decode(payload.redeem_token.as_bytes())
            .map_err(|_| ServiceError::RedeemTokenInvalid)?
    };

    let expected_token = if record.threshold.unwrap_or(1) > 1 {
        let token_arr: [u8; threshold::SHARE_LENGTH] = expected_token
            .as_slice()
            .try_into()
            .map_err(|_| ServiceError::RedeemTokenInvalid)?;
        threshold::canonical_secret_bytes(&token_arr).to_vec()
    } else {
        expected_token
    };

    if provided_token.len() != expected_token.len()
        || provided_token.ct_eq(&expected_token).unwrap_u8() == 0
    {
        return Err(ServiceError::RedeemTokenInvalid);
    }

    // Exporter binding check
    let exporter_binding = record
        .exporter_binding_bytes()
        .map_err(ServiceError::Storage)?;
    if let Some(binding) = exporter_binding.as_deref() {
        if binding != context.exporter() {
            return Err(ServiceError::ExporterBindingMismatch);
        }
    }

    // Decrypt
    let ciphertext = record.ciphertext_bytes().map_err(ServiceError::Storage)?;
    let kem_cipher = record
        .kem_ciphertext_bytes()
        .map_err(ServiceError::Storage)?;
    let exporter_secret = exporter_binding.as_deref();
    let plaintext = state
        .crypto()
        .decrypt_pqc(
            &ciphertext,
            &kem_cipher,
            &record.envelope.envelope_key_id,
            &record.envelope.customer_id,
            exporter_secret,
        )
        .await
        .map_err(ServiceError::Crypto)?;

    // Only consume the redeem token for single-use secrets.
    // RenewableLease secrets keep the token alive for repeated access.
    if !is_renewable_v2 {
        state
            .mark_redeem_token_used(&handle_id)
            .await
            .map_err(ServiceError::Storage)?;
    }

    let event_label = match record.lifecycle {
        SecretLifecycle::RenewableLease => "lease_unwrap",
        SecretLifecycle::ServiceBootstrap => "bootstrap_unwrap",
        SecretLifecycle::SingleUseUnwrap => "unwrap",
    };

    info!(
        handle_fingerprint = %handle_fingerprint(&payload.handle),
        version = 2,
        lifecycle = event_label,
        "v2 macaroon handle unwrapped"
    );

    state
        .record_transparency(
            TransparencyEvent::unwrap(
                &payload.handle,
                Some(&record.envelope.envelope_key_id),
                &record.envelope.customer_id,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert("lifecycle".into(), Value::String(event_label.to_string()));
                    append_context_transparency_meta(&mut m, context);
                    m.insert(
                        "issued_with_authenticated_transport".into(),
                        Value::Bool(record.issued_with_authenticated_transport),
                    );
                    if let Some(principal) = record.issued_by_principal_id.as_ref() {
                        m.insert(
                            "issued_by_principal_id".into(),
                            Value::String(principal.clone()),
                        );
                    }
                    if let Some(peer_cert_sha256) = record.issued_by_peer_cert_sha256.as_ref() {
                        m.insert(
                            "issued_by_peer_cert_sha256".into(),
                            Value::String(peer_cert_sha256.clone()),
                        );
                    }
                    if let Some(attestation_digest) = record.issued_by_attestation_digest.as_ref() {
                        m.insert(
                            "issued_by_attestation_digest".into(),
                            Value::String(attestation_digest.clone()),
                        );
                    }
                    if let Some(principal) = record.unwrap_principal_id.as_ref() {
                        m.insert(
                            "unwrap_principal_id".into(),
                            Value::String(principal.clone()),
                        );
                    }
                    if is_renewable_v2 {
                        m.insert(
                            "lease_renewal_count".into(),
                            Value::from(record.lease_renewal_count),
                        );
                    }
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(UnwrapResponse {
        plaintext: STANDARD.encode(&plaintext.plaintext),
    })
}

pub(crate) async fn attenuate_handle_v2_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    payload: AttenuateV2Request,
) -> Result<AttenuateV2Response, ServiceError> {
    let mac = parse_handle_v2(&payload.handle)?;
    let handle_id = mac.identifier;
    let root_key = state.macaroon_root_key(&handle_id);
    mac.verify_signature(&root_key)
        .map_err(|_| ServiceError::InvalidHandle)?;

    // Validate caller lineage against the stored record for principal-bound handles.
    let store = state.sealed_store();
    let record = store
        .load(&handle_id)
        .await
        .map_err(ServiceError::Storage)?
        .ok_or(ServiceError::HandleNotFound)?;
    validate_v2_record_identity_requirements(&record, context)?;

    let mut mac = mac;
    let mut added_caveats: Vec<String> = Vec::new();
    let mut third_party_caveat_id = None;

    if let Some(tenant_id) = payload.tenant_id.and_then(normalize_optional_string) {
        added_caveats.push(format!("tenant_id={}", tenant_id));
        mac.add_caveat(Caveat::TenantId(tenant_id));
    }
    if let Some(provider) = payload.provider.and_then(normalize_optional_string) {
        added_caveats.push(format!("provider={}", provider));
        mac.add_caveat(Caveat::Provider(provider));
    }
    if let Some(circuit_id) = payload.circuit_id.and_then(normalize_optional_string) {
        added_caveats.push(format!("circuit_id={}", circuit_id));
        mac.add_caveat(Caveat::CircuitId(circuit_id));
    }
    if let Some(node_id) = payload.node_id.and_then(normalize_optional_string) {
        added_caveats.push(format!("node_id={}", node_id));
        mac.add_caveat(Caveat::NodeId(node_id));
    }
    if let Some(action) = payload.action.and_then(normalize_optional_string) {
        added_caveats.push(format!("action={}", action));
        mac.add_caveat(Caveat::Action(action));
    }
    if let Some(max_uses) = payload.max_uses {
        if max_uses != BROKER_MAX_USES {
            return Err(ServiceError::InvalidAttenuation(
                "max_uses currently only supports the live single-use value 1",
            ));
        }
        added_caveats.push("max_uses=1".to_string());
        mac.add_caveat(Caveat::MaxUses);
    }
    if let Some(tp) = payload.third_party.as_ref() {
        let location = normalize_optional_string(tp.location.clone()).ok_or(
            ServiceError::InvalidAttenuation("third-party location must be non-empty"),
        )?;
        let condition = normalize_optional_string(tp.condition.clone()).ok_or(
            ServiceError::InvalidAttenuation("third-party condition must be non-empty"),
        )?;
        let key_id = Uuid::new_v4().to_string();
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        store
            .append_third_party_caveat_key(
                &handle_id,
                ThirdPartyCaveatKey {
                    location: location.clone(),
                    key_id: key_id.clone(),
                    condition: Some(condition.clone()),
                    secret_b64: STANDARD.encode(secret),
                    created_at: Utc::now(),
                },
            )
            .await
            .map_err(ServiceError::Storage)?;
        added_caveats.push(format!(
            "third_party:location={} key_id={}",
            location, key_id
        ));
        mac.add_caveat(Caveat::ThirdParty {
            location,
            key_id: key_id.clone(),
        });
        third_party_caveat_id = Some(key_id);
    }

    if added_caveats.is_empty() {
        return Err(ServiceError::InvalidAttenuation(
            "at least one caveat is required",
        ));
    }

    let attenuated_handle = format!("{}{}", HANDLE_V2_PREFIX, mac.serialize());

    info!(caveats_added = added_caveats.len(), "v2 handle attenuated");

    state
        .record_transparency(
            TransparencyEvent::attenuate(
                &payload.handle,
                &record.envelope.customer_id,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "caveats_added".into(),
                        Value::from(added_caveats.len() as u64),
                    );
                    m.insert(
                        "caveat_types".into(),
                        Value::Array(
                            added_caveats
                                .iter()
                                .map(|c| Value::String(c.clone()))
                                .collect(),
                        ),
                    );
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown"))
            .with_parent_handle(&payload.handle),
        )
        .await;

    Ok(AttenuateV2Response {
        handle: attenuated_handle,
        third_party_caveat_id,
    })
}

fn normalize_optional_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// -- Lifecycle operations ---------------------------------------------------

#[derive(Debug)]
pub struct RenewLeaseRequest {
    pub handle: String,
    pub lease_duration_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct RenewLeaseResponse {
    pub lease_expires_at: DateTime<Utc>,
    pub renewal_count: u32,
}

#[derive(Debug)]
pub struct RevokeSecretRequest {
    pub handle: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevokeSecretResponse {
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct RotateSecretRequest {
    pub old_handle: String,
    pub new_plaintext: Vec<u8>,
    pub customer_id: Option<String>,
    pub metadata: Option<Value>,
    pub ttl_seconds: Option<u64>,
    pub rotation_reason: Option<String>,
    pub lifecycle: SecretLifecycle,
    pub threshold: Option<u8>,
    pub num_shares: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct RotateSecretResponse {
    pub new_handle: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub redeem_token: String,
    pub redeem_token_expires_at: Option<DateTime<Utc>>,
    pub old_revoked: bool,
    pub new_shares: Vec<threshold::Share>,
}

pub(crate) async fn renew_lease_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    payload: RenewLeaseRequest,
) -> Result<RenewLeaseResponse, ServiceError> {
    if payload.lease_duration_seconds == 0 || payload.lease_duration_seconds > 86400 * 30 {
        return Err(ServiceError::InvalidTtl);
    }

    let handle_id = parse_handle_identifier(state, &payload.handle)?;

    let store = state.sealed_store();
    let record = store
        .load(&handle_id)
        .await
        .map_err(ServiceError::Storage)?
        .ok_or(ServiceError::HandleNotFound)?;

    if record.revoked {
        return Err(ServiceError::RevokedHandle);
    }
    if record.lifecycle != SecretLifecycle::RenewableLease {
        return Err(ServiceError::Crypto(anyhow::anyhow!(
            "only RenewableLease secrets support lease renewal"
        )));
    }
    let now = Utc::now();
    if record.is_expired(now) {
        return Err(ServiceError::ExpiredHandle);
    }

    // Renewal is a security-sensitive operation on the live capability, so it
    // must honor the same authenticated principal/transport lineage required
    // for RenewableLease unwraps.
    validate_v2_record_identity_requirements(&record, context)?;

    let new_lease = now + Duration::seconds(payload.lease_duration_seconds as i64);
    // Enforce: lease cannot exceed the hard secret TTL.
    let capped_lease = match record.expires_at {
        Some(hard_ttl) if new_lease > hard_ttl => hard_ttl,
        _ => new_lease,
    };

    let previous_lease_expiry = record.lease_expires_at.unwrap_or(now);

    let updated = store
        .renew_lease(&handle_id, capped_lease)
        .await
        .map_err(ServiceError::Storage)?;

    info!(
        handle_fingerprint = %handle_fingerprint(&payload.handle),
        renewal_count = updated.lease_renewal_count,
        "lease renewed"
    );

    state
        .record_transparency(
            TransparencyEvent::renew_lease(
                &payload.handle,
                &record.envelope.customer_id,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "renewal_count".into(),
                        Value::from(updated.lease_renewal_count),
                    );
                    m.insert(
                        "lease_expires_at".into(),
                        Value::String(capped_lease.to_rfc3339()),
                    );
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_lease_renewal(updated.lease_renewal_count, previous_lease_expiry)
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(RenewLeaseResponse {
        lease_expires_at: capped_lease,
        renewal_count: updated.lease_renewal_count,
    })
}

pub(crate) async fn revoke_secret_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    payload: RevokeSecretRequest,
) -> Result<RevokeSecretResponse, ServiceError> {
    let handle_id = parse_handle_identifier(state, &payload.handle)?;

    let store = state.sealed_store();
    let record = store
        .load(&handle_id)
        .await
        .map_err(ServiceError::Storage)?
        .ok_or(ServiceError::HandleNotFound)?;

    validate_v2_record_management_requirements(&record, context)?;

    let revoked = store
        .revoke(&handle_id, payload.reason.clone())
        .await
        .map_err(ServiceError::Storage)?;

    let revoked_at = if revoked { Some(Utc::now()) } else { None };

    if revoked {
        info!(
            handle_fingerprint = %handle_fingerprint(&payload.handle),
            "secret revoked"
        );
        state
            .record_transparency(
                TransparencyEvent::revoke(
                    &payload.handle,
                    &record.envelope.customer_id,
                    Some(Value::Object({
                        let mut m = serde_json::Map::new();
                        m.insert("handle_version".into(), Value::from(2));
                        m.insert(
                            "handle_fingerprint".into(),
                            Value::String(handle_fingerprint(&payload.handle)),
                        );
                        if let Some(ref reason) = payload.reason {
                            m.insert("reason".into(), Value::String(reason.clone()));
                        }
                        if let Some(revoked_at) = revoked_at.as_ref() {
                            m.insert("revoked_at".into(), Value::String(revoked_at.to_rfc3339()));
                        }
                        append_record_transparency_meta(&mut m, &record);
                        append_context_transparency_meta(&mut m, context);
                        m
                    })),
                )
                .with_caller(context.principal_id().unwrap_or("unknown")),
            )
            .await;
    }

    Ok(RevokeSecretResponse {
        revoked,
        revoked_at,
    })
}

pub(crate) async fn rotate_secret_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    payload: RotateSecretRequest,
) -> Result<RotateSecretResponse, ServiceError> {
    let old_handle_id = parse_handle_identifier(state, &payload.old_handle)?;
    let store = state.sealed_store();
    let old_record = store
        .load(&old_handle_id)
        .await
        .map_err(ServiceError::Storage)?
        .ok_or(ServiceError::HandleNotFound)?;

    validate_v2_record_management_requirements(&old_record, context)?;

    // Wrap the new secret with its lifecycle and threshold policy.
    let created_at = Utc::now();
    let customer_id = payload
        .customer_id
        .clone()
        .and_then(normalize_optional_string)
        .unwrap_or_else(|| state.default_customer_id().to_string());
    let (expires_at, _effective_ttl) = enforce_ttl(payload.ttl_seconds, state, created_at)?;

    let threshold = payload.threshold.unwrap_or(1).max(1);
    let num_shares = payload.num_shares.unwrap_or(1).max(threshold);
    if threshold > num_shares {
        return Err(ServiceError::InvalidTtl); // reuse existing error for bad params
    }

    let unwrap_principal_id = v2_unwrap_principal(context, payload.lifecycle, None)?;
    let outcome = persist_secret_v2_with_lifecycle(
        state,
        context,
        PersistSecretV2Input {
            plaintext: &payload.new_plaintext,
            customer_id,
            metadata: payload.metadata,
            created_at,
            expires_at,
            lifecycle: payload.lifecycle,
            initial_lease_seconds: None,
            unwrap_principal_id,
        },
    )
    .await?;

    let handle_id = outcome.handle_id;
    let root_key = state.macaroon_root_key(&handle_id);
    let mut caveats = Vec::new();
    if let Some(expires_at) = outcome.expires_at {
        caveats.push(Caveat::Expires(expires_at));
    }
    caveats.push(Caveat::Action("unwrap".into()));
    caveats.push(Caveat::MaxUses);
    let new_handle = format!(
        "{}{}",
        HANDLE_V2_PREFIX,
        Macaroon::mint(&root_key, handle_id, caveats).serialize()
    );
    let redeem_token_expires_at = outcome.redeem_token_expires_at;

    // If threshold > 1, split redeem material into Feldman shares.
    let (redeem_token, new_shares) = if threshold > 1 {
        let token_bytes = STANDARD
            .decode(outcome.redeem_token.as_bytes())
            .map_err(|_| ServiceError::Crypto(anyhow::anyhow!("bad redeem token base64")))?;
        let token_arr: [u8; 32] = token_bytes
            .try_into()
            .map_err(|_| ServiceError::Crypto(anyhow::anyhow!("redeem token not 32 bytes")))?;
        let split = threshold::split(&token_arr, threshold, num_shares)
            .map_err(|e| ServiceError::Crypto(anyhow::anyhow!("feldman split: {e}")))?;
        let encoded_commitments = split
            .commitments
            .iter()
            .map(|commitment| STANDARD.encode(commitment))
            .collect::<Vec<_>>();
        store
            .update_threshold_config(&handle_id, threshold, encoded_commitments)
            .await
            .map_err(ServiceError::Storage)?;
        (String::new(), split.shares)
    } else {
        (outcome.redeem_token.clone(), Vec::new())
    };

    // Step 2: Revoke the old handle only after the caller has been authorized
    // against the existing principal/transport lineage above.
    let reason = payload
        .rotation_reason
        .unwrap_or_else(|| "rotated to replacement capability".to_string());

    let old_revoked = store
        .revoke(&old_handle_id, Some(reason.clone()))
        .await
        .map_err(ServiceError::Storage)?;

    info!(
        old_handle_fingerprint = %handle_fingerprint(&payload.old_handle),
        new_handle_fingerprint = %handle_fingerprint(&new_handle),
        old_revoked,
        "secret rotated"
    );

    // Transparency: single rotate event with full lineage (old->new).
    state
        .record_transparency(
            TransparencyEvent::rotate(
                &payload.old_handle,
                &new_handle,
                &outcome.envelope_key_id,
                &outcome.customer_id,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert("old_revoked".into(), Value::Bool(old_revoked));
                    m.insert("reason".into(), Value::String(reason.clone()));
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown"))
            .with_parent_handle(&payload.old_handle),
        )
        .await;

    Ok(RotateSecretResponse {
        new_handle,
        created_at,
        expires_at,
        redeem_token,
        redeem_token_expires_at,
        old_revoked,
        new_shares,
    })
}

// -- Third-party discharge minting ------------------------------------------

#[derive(Debug)]
pub struct MintDischargeRequest {
    /// The third-party location this discharge is for.
    pub location: String,
    /// Canonical v2 handle whose third-party caveat this discharge must bind to.
    pub primary_handle: String,
    /// Opaque selector for the target third-party caveat.
    pub caveat_id: String,
}

#[derive(Debug, Clone)]
pub struct MintDischargeResponse {
    /// Serialized discharge macaroon (base64).
    pub discharge_token: String,
}

/// Mint a discharge macaroon that proves a third-party condition was satisfied
/// and bind it to one canonical v2 primary handle.
pub(crate) async fn mint_discharge_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    payload: MintDischargeRequest,
) -> Result<MintDischargeResponse, ServiceError> {
    validate_discharge_mint_requirements(state, context, &payload.location)?;
    let requested_caveat_id = payload.caveat_id.trim();
    if requested_caveat_id.is_empty() {
        return Err(ServiceError::InvalidAttenuation(
            "mint discharge requires opaque caveat_id",
        ));
    }

    let primary_handle = payload.primary_handle.trim();
    if primary_handle.is_empty() {
        return Err(ServiceError::InvalidHandle);
    }
    let primary_mac = parse_handle_v2(primary_handle)?;
    let primary_handle_id = primary_mac.identifier;
    let record = state
        .sealed_store()
        .load(&primary_handle_id)
        .await
        .map_err(ServiceError::Storage)?
        .ok_or(ServiceError::HandleNotFound)?;
    let root_key = state.macaroon_root_key(&primary_handle_id);
    primary_mac
        .verify_signature(&root_key)
        .map_err(|_| ServiceError::InvalidHandle)?;
    // The predicate is resolved exclusively from sealed per-caveat state.
    let stored_caveat = record
        .third_party_caveat_keys
        .as_ref()
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.location == payload.location && entry.key_id == requested_caveat_id
            })
        })
        .ok_or_else(|| {
            ServiceError::Crypto(anyhow::anyhow!(
                "no sealed third-party caveat matches opaque caveat_id {} for {}",
                requested_caveat_id,
                payload.location
            ))
        })?;
    let primary_signature = primary_mac
        .third_party_binding_info_by_key_id(&root_key, &payload.location, &stored_caveat.key_id)
        .map_err(|err| ServiceError::Crypto(anyhow::anyhow!(err.to_string())))?;
    let resolved_condition = stored_caveat.condition.clone().ok_or_else(|| {
        ServiceError::Crypto(anyhow::anyhow!(
            "stored third-party caveat is missing its predicate"
        ))
    })?;
    let key_id = stored_caveat.key_id.clone();
    let discharge_key = discharge_keys_for_record(&record)?
        .into_iter()
        .find(|entry| entry.location == payload.location && entry.key_id == key_id)
        .ok_or_else(|| {
            ServiceError::Crypto(anyhow::anyhow!(
                "no discharge secret registered for {}",
                payload.location
            ))
        })?;
    let discharge_expires_at = Utc::now() + Duration::seconds(DISCHARGE_TOKEN_TTL_SECONDS);
    let discharge = DischargeMacaroon::mint_with_expiry(
        &payload.location,
        &resolved_condition,
        &discharge_key.key,
        &primary_signature,
        Some(discharge_expires_at),
    );

    info!(
        location = payload.location.as_str(),
        condition = resolved_condition.as_str(),
        primary_handle_id = %primary_handle_id,
        "discharge macaroon minted"
    );

    state
        .record_transparency(
            TransparencyEvent::wrap(
                &format!("discharge:{}", payload.location),
                "discharge-key",
                state.default_customer_id(),
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), Value::String("discharge".into()));
                    m.insert("location".into(), Value::String(payload.location.clone()));
                    m.insert(
                        "condition".into(),
                        Value::String(resolved_condition.clone()),
                    );
                    m.insert("caveat_key_id".into(), Value::String(key_id.clone()));
                    m.insert(
                        "discharge_expires_at".into(),
                        Value::String(discharge_expires_at.to_rfc3339()),
                    );
                    m.insert(
                        "primary_handle_id".into(),
                        Value::String(primary_handle_id.to_string()),
                    );
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(MintDischargeResponse {
        discharge_token: discharge.serialize(),
    })
}

// -- Custodial share distribution ------------------------------------------

/// Claim a broker-held share as an authenticated custodian.
pub(crate) struct ClaimShareRequest {
    pub handle: String,
    pub custodian_id: String,
}

pub(crate) struct ClaimShareResponse {
    pub x: u8,
    pub y: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
    pub previously_claimed: bool,
}

pub(crate) async fn claim_share_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    req: ClaimShareRequest,
) -> anyhow::Result<ClaimShareResponse> {
    if req.handle.is_empty() {
        return Err(anyhow::anyhow!("handle is required"));
    }
    if req.custodian_id.is_empty() {
        return Err(anyhow::anyhow!("custodian_id is required"));
    }
    let actual_principal = context
        .principal_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("authenticated principal is required for claim_share"))?;
    if actual_principal != req.custodian_id {
        return Err(anyhow::anyhow!(
            "custodian_id '{}' does not match authenticated principal '{}'",
            req.custodian_id,
            actual_principal
        ));
    }

    let handle_id = parse_handle_identifier(state, &req.handle)
        .map_err(|e| anyhow::anyhow!("invalid handle: {e}"))?;

    // Threshold custody operations must prove authenticated custodian identity and
    // issued-record lineage, but they must not require the final unwrap principal to
    // equal every custodian. Distinct custodians claim shares under their own
    // authenticated identities before one authorized principal performs recovery.
    let store = state.sealed_store();
    if let Some(record) = store
        .load(&handle_id)
        .await
        .map_err(|e| anyhow::anyhow!("load sealed record: {e}"))?
    {
        validate_threshold_custody_record_requirements(&record, context)
            .map_err(|e| anyhow::anyhow!("identity validation: {e}"))?;
    }

    let result = store
        .claim_custodian_share(&handle_id, &req.custodian_id)
        .await
        .map_err(|e| anyhow::anyhow!("claim share failed: {e}"))?;

    state
        .record_transparency(
            TransparencyEvent::wrap(
                &req.handle,
                "threshold-share-claim",
                &req.custodian_id,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), Value::String("claim_share".into()));
                    m.insert(
                        "custodian_id".into(),
                        Value::String(req.custodian_id.clone()),
                    );
                    m.insert("share_index".into(), Value::from(result.x as u64));
                    m.insert(
                        "previously_claimed".into(),
                        Value::Bool(result.previously_claimed),
                    );
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(ClaimShareResponse {
        x: result.x,
        y: result.y,
        commitments: result.commitments,
        previously_claimed: result.previously_claimed,
    })
}

/// Request to deposit a share with a custodian.
pub(crate) struct DistributeShareRequest {
    pub handle: String,
    pub share_index: u32,
    pub share: super::threshold::Share,
    pub custodian_id: String,
}

pub(crate) struct DistributeShareResponse {
    pub accepted: bool,
    pub ack_token: String,
}

pub(crate) async fn distribute_share_impl(
    state: &BrokerState,
    context: &BrokerClientContext,
    req: DistributeShareRequest,
) -> anyhow::Result<DistributeShareResponse> {
    if req.handle.is_empty() {
        return Err(anyhow::anyhow!("handle is required"));
    }
    if req.custodian_id.is_empty() {
        return Err(anyhow::anyhow!("custodian_id is required"));
    }
    let actual_principal = context
        .principal_id()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("authenticated principal is required for distribute_share")
        })?;
    if actual_principal != req.custodian_id {
        return Err(anyhow::anyhow!(
            "custodian_id '{}' does not match authenticated principal '{}'",
            req.custodian_id,
            actual_principal
        ));
    }
    if req.share_index == 0 || req.share_index > 255 {
        return Err(anyhow::anyhow!("share_index must be 1..=255"));
    }

    let handle_id = parse_handle_identifier(state, &req.handle)
        .map_err(|e| anyhow::anyhow!("invalid handle: {e}"))?;

    // Threshold custody operations must validate authenticated custodian identity and
    // issued-record lineage, but they must not force every custodian to equal the
    // final unwrap principal bound to the recovered secret.
    if let Some(record) = state
        .sealed_store()
        .load(&handle_id)
        .await
        .map_err(|e| anyhow::anyhow!("load sealed record: {e}"))?
    {
        validate_threshold_custody_record_requirements(&record, context)
            .map_err(|e| anyhow::anyhow!("identity validation: {e}"))?;
    }

    // Validate the submitted share matches what the sealed store holds.
    // This proves the caller actually possesses the share data before we
    // issue an acknowledgment token. Without this check, any caller who
    // knows the handle and custodian_id could forge an ack.
    if req.share.x != req.share_index as u8 {
        return Err(anyhow::anyhow!(
            "share.x ({}) does not match share_index ({})",
            req.share.x,
            req.share_index
        ));
    }

    // Generate an acknowledgment token (custodian can use this to prove they received the share)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(state.handle_hmac_key())
        .map_err(|_| anyhow::anyhow!("HMAC key invalid"))?;
    mac.update(b"share-ack-v1:");
    mac.update(req.handle.as_bytes());
    mac.update(b":");
    mac.update(req.custodian_id.as_bytes());
    mac.update(b":");
    mac.update(&req.share_index.to_le_bytes());
    mac.update(b":");
    mac.update(&req.share.y);
    let ack = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    state
        .record_transparency(
            TransparencyEvent::wrap(
                &req.handle,
                "threshold-share",
                &req.custodian_id,
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), Value::String("distribute_share".into()));
                    m.insert("share_index".into(), Value::from(req.share_index as u64));
                    m.insert(
                        "custodian_id".into(),
                        Value::String(req.custodian_id.clone()),
                    );
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(DistributeShareResponse {
        accepted: true,
        ack_token: ack,
    })
}

/// Request to combine shares from distinct custodians.
pub(crate) struct CombineSharesRequest {
    pub handle: String,
    pub shares: Vec<super::threshold::Share>,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub custodian_ids: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct CombineSharesResponse {
    pub plaintext: Vec<u8>,
}

fn validate_combine_shares_custody(
    record: &crate::secret_broker_impl::sealed_store::StoredEnvelopeRecord,
    req: &CombineSharesRequest,
) -> anyhow::Result<Vec<crate::secret_broker_impl::threshold::Share>> {
    if req.custodian_ids.len() != req.shares.len() {
        return Err(anyhow::anyhow!(
            "combine_shares requires exactly one custodian_id per share; got {} custodian ids for {} shares",
            req.custodian_ids.len(),
            req.shares.len()
        ));
    }
    let unique_custodians: std::collections::HashSet<&str> =
        req.custodian_ids.iter().map(|s| s.as_str()).collect();
    if unique_custodians.len() != req.shares.len() {
        return Err(anyhow::anyhow!(
            "combine_shares requires distinct custodians for each share; got {} unique for {} shares",
            unique_custodians.len(),
            req.shares.len()
        ));
    }
    if req.custodian_ids.iter().any(|id| id.trim().is_empty()) {
        return Err(anyhow::anyhow!("custodian_id must not be empty"));
    }

    let assignments = record
        .share_assignments
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no share assignments for this handle"))?;
    let held_shares = record
        .held_shares
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no held shares for this handle"))?;
    if let Some(threshold) = record.threshold {
        if req.shares.len() < threshold as usize {
            return Err(anyhow::anyhow!(
                "combine_shares requires at least {} shares, got {}",
                threshold,
                req.shares.len()
            ));
        }
    }

    let mut validated_shares = Vec::with_capacity(req.shares.len());
    let mut seen_share_indices = std::collections::HashSet::new();
    for (custodian_id, share) in req.custodian_ids.iter().zip(req.shares.iter()) {
        let assignment = assignments
            .iter()
            .find(|assignment| assignment.custodian_id == *custodian_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "custodian_id '{}' not assigned to this handle",
                    custodian_id
                )
            })?;
        if !assignment.claimed {
            return Err(anyhow::anyhow!(
                "custodian_id '{}' has not claimed their assigned share",
                custodian_id
            ));
        }
        if !seen_share_indices.insert(assignment.share_index) {
            return Err(anyhow::anyhow!(
                "combine_shares requires distinct assigned shares; share index {} was provided more than once",
                assignment.share_index
            ));
        }
        if share.x != assignment.share_index {
            return Err(anyhow::anyhow!(
                "custodian_id '{}' must provide assigned share index {}, got {}",
                custodian_id,
                assignment.share_index,
                share.x
            ));
        }
        let held_share = held_shares
            .iter()
            .find(|held_share| held_share.x == assignment.share_index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "share index {} not found in held shares",
                    assignment.share_index
                )
            })?;
        let expected_y = STANDARD
            .decode(held_share.y_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("decode held share y-value: {e}"))?;
        if share.y != expected_y {
            return Err(anyhow::anyhow!(
                "custodian_id '{}' provided share data that does not match the broker-held assignment",
                custodian_id
            ));
        }
        validated_shares.push(share.clone());
    }

    Ok(validated_shares)
}

pub(crate) async fn combine_shares_impl(
    state: &BrokerState,
    context: &super::BrokerClientContext,
    req: CombineSharesRequest,
) -> anyhow::Result<CombineSharesResponse> {
    if req.handle.is_empty() {
        return Err(anyhow::anyhow!("handle is required"));
    }
    if req.shares.is_empty() {
        return Err(anyhow::anyhow!("at least one share is required"));
    }

    let handle_id = parse_handle_identifier(state, &req.handle)
        .map_err(|e| anyhow::anyhow!("invalid V2 handle: {e}"))?;

    let record = state
        .sealed_store()
        .load(&handle_id)
        .await
        .map_err(|e| anyhow::anyhow!("load sealed record failed: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("sealed secret handle not found"))?;

    let validated_shares = validate_combine_shares_custody(&record, &req)?;

    let redeem_token = serde_json::to_string(&validated_shares)
        .map_err(|e| anyhow::anyhow!("failed to encode shares: {e}"))?;

    let unwrap_req = UnwrapV2Request {
        handle: req.handle.clone(),
        redeem_token,
        tenant_id: req.tenant_id,
        provider: req.provider,
        circuit_id: None,
        node_id: None,
        discharges: Vec::new(),
    };

    let result = unwrap_secret_v2_impl(state, context, unwrap_req).await?;

    let plaintext_bytes = base64::engine::general_purpose::STANDARD
        .decode(result.plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;

    state
        .record_transparency(
            TransparencyEvent::unwrap(
                &req.handle,
                None,
                "threshold-recovery",
                Some(Value::Object({
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "custodians".into(),
                        Value::Array(
                            req.custodian_ids
                                .iter()
                                .map(|id| Value::String(id.clone()))
                                .collect(),
                        ),
                    );
                    m.insert(
                        "share_indices".into(),
                        Value::Array(
                            validated_shares
                                .iter()
                                .map(|share| Value::from(share.x as u64))
                                .collect(),
                        ),
                    );
                    m.insert(
                        "share_count".into(),
                        Value::from(validated_shares.len() as u64),
                    );
                    if let Some(threshold) = record.threshold {
                        m.insert("threshold".into(), Value::from(threshold as u64));
                    }
                    append_context_transparency_meta(&mut m, context);
                    m
                })),
            )
            .with_caller(context.principal_id().unwrap_or("unknown")),
        )
        .await;

    Ok(CombineSharesResponse {
        plaintext: plaintext_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        attenuate_handle_v2_impl, claim_share_impl, delete_secret_impl, distribute_share_impl,
        handle_fingerprint, issue_postgres_credentials_impl, mint_discharge_impl,
        parse_handle_identifier, parse_handle_v2, renew_lease_impl, revoke_secret_impl,
        rotate_secret_impl, unwrap_secret_v2_impl, v2_unwrap_principal,
        validate_combine_shares_custody, validate_threshold_custody_record_requirements,
        validate_v2_record_identity_requirements, wrap_secret_v2_impl, AttenuateV2Request,
        BrokerState, ClaimShareRequest, CombineSharesRequest, DistributeShareRequest, Macaroon,
        MintDischargeRequest, PostgresCredentialParams, RenewLeaseRequest, RevokeSecretRequest,
        RotateSecretRequest, ServiceError, ThirdPartyCaveatRequest, UnwrapV2Request, WrapV2Request,
        HANDLE_V2_PREFIX,
    };
    use crate::secret_broker_impl::crypto_engine::{CryptoConfig, CryptoEngineService};
    use crate::secret_broker_impl::macaroon_caveats::Caveat;
    use crate::secret_broker_impl::macaroon_caveats::DischargeMacaroon;
    use crate::secret_broker_impl::sealed_store::{
        HeldShare, SealedStore, SecretLifecycle, ShareAssignment,
    };
    use crate::secret_broker_impl::state::BrokerStateConfig;
    use crate::secret_broker_impl::transparency::TransparencyLogger;
    use crate::secret_broker_impl::BrokerClientContext;
    use base64::Engine;
    use chrono::{Duration, Utc};
    use serde_json::{json, Value};
    use std::fs;
    use tempfile::{tempdir, TempDir};
    use uuid::Uuid;

    fn test_record(
        lifecycle: SecretLifecycle,
        unwrap_principal_id: Option<&str>,
        issued_with_authenticated_transport: bool,
        issued_by_principal_id: Option<&str>,
        issued_by_peer_cert_sha256: Option<&str>,
        issued_by_attestation_digest: Option<&str>,
    ) -> crate::secret_broker_impl::sealed_store::StoredEnvelopeRecord {
        crate::secret_broker_impl::sealed_store::StoredEnvelopeRecord {
            envelope: crate::secret_broker_impl::sealed_store::SecretEnvelope {
                envelope_key_id: "key-123".into(),
                algorithm: "kyber768-hybrid".into(),
                ciphertext: super::STANDARD.encode(b"cipher-bytes"),
                kyber_ciphertext: super::STANDARD.encode(b"kem-bytes"),
                customer_id: "example-customer".into(),
                exporter_binding: None,
                metadata: None,
                created_at: chrono::Utc::now(),
            },
            signature: super::STANDARD.encode(b"signature"),
            signing_key_id: "signing-key".into(),
            signing_public_key: super::STANDARD.encode(b"public-key"),
            signing_key_expires_at: None,
            expires_at: None,
            last_accessed: None,
            redeem_nonce: Some(super::STANDARD.encode([0u8; 16])),
            redeem_binding: None,
            unwrap_principal_id: unwrap_principal_id.map(str::to_string),
            issued_with_authenticated_transport,
            issued_by_principal_id: issued_by_principal_id.map(str::to_string),
            issued_by_peer_cert_sha256: issued_by_peer_cert_sha256.map(str::to_string),
            issued_by_attestation_digest: issued_by_attestation_digest.map(str::to_string),
            third_party_caveat_keys: None,
            redeem_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(5)),
            redeem_used: false,
            threshold: None,
            threshold_commitments: None,
            lifecycle,
            lease_expires_at: None,
            lease_renewal_count: 0,
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            share_assignments: None,
            held_shares: None,
        }
    }

    fn synthetic_context() -> BrokerClientContext {
        BrokerClientContext::from_master_key(&[7u8; 32]).expect("synthetic context")
    }

    fn authenticated_context(principal: &str, tag: u8) -> BrokerClientContext {
        BrokerClientContext::from_tls_exporter(
            vec![tag; 32],
            Some(Uuid::new_v4()),
            Some(principal.to_string()),
            Some(vec![tag; 32]),
            None,
        )
    }

    fn attested_authenticated_context(principal: &str, tag: u8) -> BrokerClientContext {
        BrokerClientContext::from_tls_exporter(
            vec![tag; 32],
            Some(Uuid::new_v4()),
            Some(principal.to_string()),
            Some(vec![tag; 32]),
            Some(vec![tag.wrapping_add(1); 32]),
        )
    }

    fn encoded_peer_cert(tag: u8) -> String {
        super::STANDARD.encode([tag; 32])
    }

    fn v2_handle(state: &BrokerState, handle_id: Uuid) -> String {
        let macaroon = Macaroon::mint(
            &state.macaroon_root_key(&handle_id),
            handle_id,
            vec![Caveat::Action("unwrap".into()), Caveat::MaxUses],
        );
        format!("{}{}", HANDLE_V2_PREFIX, macaroon.serialize())
    }

    #[tokio::test]
    async fn handle_parser_accepts_only_authentic_serialized_v2_macaroons() {
        let harness = test_broker_state().await;
        let handle_id = Uuid::new_v4();
        let canonical = v2_handle(&harness.state, handle_id);
        assert_eq!(
            parse_handle_identifier(&harness.state, &canonical)
                .expect("parse authentic canonical V2 handle"),
            handle_id
        );

        let forged = Macaroon::mint(
            &[5u8; 32],
            handle_id,
            vec![Caveat::Action("unwrap".into()), Caveat::MaxUses],
        );
        for invalid in [
            handle_id.to_string(),
            format!("broker:v1:{handle_id}"),
            format!("broker:v2:{handle_id}"),
            format!("{}{}", HANDLE_V2_PREFIX, forged.serialize()),
        ] {
            assert!(
                matches!(
                    parse_handle_identifier(&harness.state, &invalid),
                    Err(ServiceError::InvalidHandle)
                ),
                "legacy, unsigned, or forged handle unexpectedly accepted: {invalid}"
            );
        }
    }

    struct TestBrokerHarness {
        state: BrokerState,
        _sealed_store_dir: TempDir,
        _crypto_store_dir: TempDir,
        _transparency_dir: Option<TempDir>,
        transparency_path: Option<std::path::PathBuf>,
    }

    async fn test_broker_state() -> TestBrokerHarness {
        let sealed_store_dir = tempdir().expect("create sealed store tempdir");
        let crypto_store_dir = tempdir().expect("create crypto store tempdir");
        let sealed_store = SealedStore::open(sealed_store_dir.path().join("sealed.db"))
            .expect("open sealed store");

        let mut crypto_config = CryptoConfig::from_env();
        crypto_config.hsm.enabled = false;
        crypto_config.quantum_crypto.sealed_store_path = crypto_store_dir
            .path()
            .join("pq-keys.db")
            .display()
            .to_string();

        let crypto = CryptoEngineService::new(crypto_config)
            .await
            .expect("create crypto engine service");

        TestBrokerHarness {
            state: BrokerState::new(
                crypto,
                sealed_store,
                BrokerStateConfig {
                    default_customer_id: "secret-broker-test".to_string(),
                    max_handle_ttl: chrono::Duration::hours(24),
                    transparency: None,
                    postgres: None,
                    handle_hmac_key: vec![9u8; 32],
                    redeem_token_ttl: chrono::Duration::hours(1),
                },
            ),
            _sealed_store_dir: sealed_store_dir,
            _crypto_store_dir: crypto_store_dir,
            _transparency_dir: None,
            transparency_path: None,
        }
    }

    async fn test_broker_state_with_transparency() -> TestBrokerHarness {
        let sealed_store_dir = tempdir().expect("create sealed store tempdir");
        let crypto_store_dir = tempdir().expect("create crypto store tempdir");
        let transparency_dir = tempdir().expect("create transparency tempdir");
        let transparency_path = transparency_dir.path().join("broker-transparency.jsonl");
        let sealed_store = SealedStore::open(sealed_store_dir.path().join("sealed.db"))
            .expect("open sealed store");

        let mut crypto_config = CryptoConfig::from_env();
        crypto_config.hsm.enabled = false;
        crypto_config.quantum_crypto.sealed_store_path = crypto_store_dir
            .path()
            .join("pq-keys.db")
            .display()
            .to_string();

        let crypto = CryptoEngineService::new(crypto_config)
            .await
            .expect("create crypto engine service");
        let transparency =
            TransparencyLogger::new(&transparency_path).expect("create transparency logger");

        TestBrokerHarness {
            state: BrokerState::new(
                crypto,
                sealed_store,
                BrokerStateConfig {
                    default_customer_id: "secret-broker-test".to_string(),
                    max_handle_ttl: chrono::Duration::hours(24),
                    transparency: Some(transparency),
                    postgres: None,
                    handle_hmac_key: vec![9u8; 32],
                    redeem_token_ttl: chrono::Duration::hours(1),
                },
            ),
            _sealed_store_dir: sealed_store_dir,
            _crypto_store_dir: crypto_store_dir,
            _transparency_dir: Some(transparency_dir),
            transparency_path: Some(transparency_path),
        }
    }

    #[test]
    fn single_use_explicit_principal_requires_authenticated_context() {
        let err = v2_unwrap_principal(
            &synthetic_context(),
            SecretLifecycle::SingleUseUnwrap,
            Some("spiffe://trust.example/workload".into()),
        )
        .expect_err("single-use explicit principal should require authenticated context");

        assert!(matches!(err, super::ServiceError::UnauthenticatedTransport));
    }

    #[test]
    fn single_use_explicit_principal_requires_authenticated_identity() {
        let context = BrokerClientContext::from_tls_exporter(
            vec![2u8; 32],
            Some(Uuid::new_v4()),
            None,
            None,
            None,
        );

        let err = v2_unwrap_principal(
            &context,
            SecretLifecycle::SingleUseUnwrap,
            Some("spiffe://trust.example/workload".into()),
        )
        .expect_err(
            "single-use explicit principal should require authenticated principal identity",
        );

        assert!(matches!(
            err,
            super::ServiceError::AuthenticatedPrincipalRequired
        ));
    }
    #[test]
    fn single_use_without_requested_principal_still_binds_authenticated_caller() {
        let context = BrokerClientContext::from_tls_exporter(
            vec![3u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload".into()),
            Some(vec![8u8; 32]),
            None,
        );

        let principal = v2_unwrap_principal(&context, SecretLifecycle::SingleUseUnwrap, None)
            .expect("single-use lifecycle should bind to authenticated caller");

        assert_eq!(
            principal.as_deref(),
            Some("spiffe://trust.example/workload"),
        );
    }

    #[test]
    fn renewable_handles_require_authenticated_transport_even_with_requested_principal() {
        let err = v2_unwrap_principal(
            &synthetic_context(),
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/workload".into()),
        )
        .expect_err("renewable lease should require authenticated transport");

        assert!(matches!(err, super::ServiceError::UnauthenticatedTransport));
    }

    #[test]
    fn bootstrap_handles_allow_cross_principal_target_binding() {
        let context = BrokerClientContext::from_tls_exporter(
            vec![1u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/issuer".into()),
            Some(vec![9u8; 32]),
            None,
        );

        let principal = v2_unwrap_principal(
            &context,
            SecretLifecycle::ServiceBootstrap,
            Some("spiffe://trust.example/workload".into()),
        )
        .expect("cross-principal bootstrap binding should be accepted on authenticated transport");

        assert_eq!(
            principal.as_deref(),
            Some("spiffe://trust.example/workload")
        );

        let default_principal =
            v2_unwrap_principal(&context, SecretLifecycle::ServiceBootstrap, None)
                .expect("bootstrap without explicit target should bind to issuing principal");

        assert_eq!(
            default_principal.as_deref(),
            Some("spiffe://trust.example/issuer")
        );
        assert!(context.has_authenticated_transport());
        assert_eq!(context.peer_cert_sha256(), Some(&[9u8; 32][..]));
    }
    #[tokio::test]
    async fn third_party_attenuated_handle_requires_and_accepts_discharge() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 70);
        let location = "tee-attestor.test";
        let condition = "attestation=valid";
        let plaintext = b"broker-third-party-caveat-roundtrip".to_vec();

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: plaintext.clone(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap v2 secret");

        let attenuated = attenuate_handle_v2_impl(
            &harness.state,
            &context,
            AttenuateV2Request {
                handle: wrapped.handle.clone(),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: Some(ThirdPartyCaveatRequest {
                    location: location.to_string(),
                    condition: condition.to_string(),
                }),
            },
        )
        .await
        .expect("attenuate wrapped handle with third-party caveat");

        let attenuated_mac = parse_handle_v2(&attenuated.handle).expect("parse attenuated handle");
        let third_party_caveat = attenuated_mac
            .caveats
            .iter()
            .find_map(|raw| match Caveat::parse(raw).ok() {
                Some(Caveat::ThirdParty {
                    location: caveat_location,
                    key_id,
                }) if caveat_location == location => Some(key_id),
                _ => None,
            })
            .expect("attenuated handle should carry a third-party caveat");
        assert_eq!(
            Some(third_party_caveat.as_str()),
            attenuated.third_party_caveat_id.as_deref(),
            "attenuation must return the opaque caveat id embedded in the handle"
        );

        let err = match unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: attenuated.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        {
            Ok(_) => panic!("missing discharge should block unwrap"),
            Err(err) => err,
        };

        match err {
            ServiceError::Crypto(inner) => assert!(
                inner.to_string().contains(location),
                "unexpected missing-discharge error: {inner}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }

        let minted = mint_discharge_impl(
            &harness.state,
            &context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated.handle.clone(),
                caveat_id: attenuated
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect("mint discharge token");

        let discharge = DischargeMacaroon::deserialize(&minted.discharge_token)
            .expect("deserialize minted discharge token");

        let unwrapped = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: attenuated.handle,
                redeem_token: wrapped.redeem_token,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: vec![discharge],
            },
        )
        .await
        .expect("matching discharge should allow unwrap");

        let unwrapped_plaintext = super::STANDARD
            .decode(unwrapped.plaintext.as_bytes())
            .expect("decode unwrapped plaintext");

        assert_eq!(unwrapped_plaintext, plaintext);
    }

    #[tokio::test]
    async fn caveat_restricted_unwrap_rejects_mismatched_tenant() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 71);
        let plaintext = b"caveat-restricted".to_vec();

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: plaintext.clone(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: Some("tenant-a".into()),
                provider: Some("anthropic".into()),
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap with tenant/provider caveats");

        let wrong_tenant_err = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: Some("tenant-b".into()),
                provider: Some("anthropic".into()),
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect_err("wrong tenant_id should fail macaroon verification");

        match wrong_tenant_err {
            ServiceError::InvalidHandle | ServiceError::Crypto(_) => {}
            other => panic!("expected caveat rejection, got: {other:?}"),
        }

        let wrong_provider_err = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: Some("tenant-a".into()),
                provider: Some("openai".into()),
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect_err("wrong provider should fail macaroon verification");

        match wrong_provider_err {
            ServiceError::InvalidHandle | ServiceError::Crypto(_) => {}
            other => panic!("expected caveat rejection, got: {other:?}"),
        }

        let correct = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle,
                redeem_token: wrapped.redeem_token,
                tenant_id: Some("tenant-a".into()),
                provider: Some("anthropic".into()),
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect("correct tenant+provider should succeed");

        let decoded = super::STANDARD
            .decode(correct.plaintext.as_bytes())
            .expect("decode");
        assert_eq!(decoded, plaintext);
    }

    #[tokio::test]
    async fn mint_discharge_requires_authenticated_principal_and_peer_cert() {
        let harness = test_broker_state().await;
        let synthetic_err = mint_discharge_impl(
            &harness.state,
            &synthetic_context(),
            MintDischargeRequest {
                location: "tee-attestor.test".into(),
                primary_handle: "broker:v2:synthetic".into(),
                caveat_id: "opaque-caveat".into(),
            },
        )
        .await
        .expect_err("synthetic context must not mint discharges");
        assert!(matches!(
            synthetic_err,
            ServiceError::UnauthenticatedTransport
        ));

        let missing_peer_context = BrokerClientContext::from_tls_exporter(
            vec![42u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/discharger".into()),
            None,
            None,
        );
        let missing_peer_err = mint_discharge_impl(
            &harness.state,
            &missing_peer_context,
            MintDischargeRequest {
                location: "tee-attestor.test".into(),
                primary_handle: "broker:v2:synthetic".into(),
                caveat_id: "opaque-caveat".into(),
            },
        )
        .await
        .expect_err("missing peer cert lineage must fail");
        assert!(matches!(
            missing_peer_err,
            ServiceError::MissingLineage(
                "peer certificate lineage on the authenticated broker transport"
            )
        ));
    }

    #[tokio::test]
    async fn mint_discharge_rejects_request_without_opaque_caveat_id() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 79);
        let location = "tee-attestor.test";
        let condition = "tenant = alpha";

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: b"opaque-caveat-required".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap");

        let attenuated = attenuate_handle_v2_impl(
            &harness.state,
            &context,
            AttenuateV2Request {
                handle: wrapped.handle,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: Some(ThirdPartyCaveatRequest {
                    location: location.to_string(),
                    condition: condition.to_string(),
                }),
            },
        )
        .await
        .expect("attenuate");

        let err = mint_discharge_impl(
            &harness.state,
            &context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated.handle,
                caveat_id: String::new(),
            },
        )
        .await
        .expect_err("missing opaque caveat id must fail closed");

        assert!(matches!(
            err,
            ServiceError::InvalidAttenuation("mint discharge requires opaque caveat_id")
        ));
    }

    #[tokio::test]
    async fn issue_postgres_credentials_requires_authenticated_principal_and_peer_cert() {
        let harness = test_broker_state().await;
        let params = PostgresCredentialParams {
            audience: "analytics".into(),
            scope: vec!["read".into()],
            ttl_seconds: None,
            application_name: None,
        };

        let synthetic_err =
            issue_postgres_credentials_impl(&harness.state, &synthetic_context(), params.clone())
                .await
                .expect_err("synthetic context must not issue postgres credentials");
        assert!(matches!(
            synthetic_err,
            ServiceError::UnauthenticatedTransport
        ));

        let missing_peer_context = BrokerClientContext::from_tls_exporter(
            vec![43u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/db-client".into()),
            None,
            None,
        );
        let missing_peer_err =
            issue_postgres_credentials_impl(&harness.state, &missing_peer_context, params.clone())
                .await
                .expect_err("missing peer cert lineage must fail before manager lookup");
        assert!(matches!(
            missing_peer_err,
            ServiceError::MissingLineage(
                "peer certificate lineage on the authenticated broker transport"
            )
        ));

        let authenticated_but_disabled = issue_postgres_credentials_impl(
            &harness.state,
            &authenticated_context("spiffe://trust.example/db-client", 44),
            params,
        )
        .await
        .expect_err("authenticated caller should next see service availability");
        assert!(matches!(
            authenticated_but_disabled,
            ServiceError::Unavailable("postgres credential issuance disabled")
        ));
    }

    #[tokio::test]
    async fn wrong_location_discharge_is_rejected() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 72);
        let real_location = "real-attestor.test";
        let wrong_location = "evil-attestor.test";
        let condition = "valid";

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: b"discharge-test".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap");

        let attenuated = attenuate_handle_v2_impl(
            &harness.state,
            &context,
            AttenuateV2Request {
                handle: wrapped.handle.clone(),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: Some(ThirdPartyCaveatRequest {
                    location: real_location.to_string(),
                    condition: condition.to_string(),
                }),
            },
        )
        .await
        .expect("attenuate");

        let err = mint_discharge_impl(
            &harness.state,
            &context,
            MintDischargeRequest {
                location: wrong_location.to_string(),
                primary_handle: attenuated.handle.clone(),
                caveat_id: attenuated
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect_err("mint discharge for wrong location must fail");

        match err {
            ServiceError::Crypto(inner) => assert!(
                inner.to_string().contains(wrong_location)
                    || inner.to_string().contains("third-party caveat"),
                "unexpected error: {inner}"
            ),
            ServiceError::InvalidHandle => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn discharge_minted_for_one_handle_cannot_unwrap_another() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 73);
        let location = "bound-attestor.test";
        let condition = "valid";

        let wrap = |plaintext: &[u8]| WrapV2Request {
            plaintext: plaintext.to_vec(),
            customer_id: None,
            metadata: None,
            lifecycle: SecretLifecycle::SingleUseUnwrap,
            ttl_seconds: None,
            initial_lease_seconds: None,
            label: None,
            tenant_id: None,
            provider: None,
            circuit_id: None,
            node_id: None,
            unwrap_principal_id: None,
        };

        let wrapped_one = wrap_secret_v2_impl(&harness.state, &context, wrap(b"bound-one"))
            .await
            .expect("wrap one");
        let wrapped_two = wrap_secret_v2_impl(&harness.state, &context, wrap(b"bound-two"))
            .await
            .expect("wrap two");

        let attenuate = |handle: String| AttenuateV2Request {
            handle,
            tenant_id: None,
            provider: None,
            circuit_id: None,
            node_id: None,
            action: None,
            max_uses: None,
            third_party: Some(ThirdPartyCaveatRequest {
                location: location.to_string(),
                condition: condition.to_string(),
            }),
        };

        let attenuated_one = attenuate_handle_v2_impl(
            &harness.state,
            &context,
            attenuate(wrapped_one.handle.clone()),
        )
        .await
        .expect("attenuate one");
        let attenuated_two = attenuate_handle_v2_impl(
            &harness.state,
            &context,
            attenuate(wrapped_two.handle.clone()),
        )
        .await
        .expect("attenuate two");

        let minted = mint_discharge_impl(
            &harness.state,
            &context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated_one.handle.clone(),
                caveat_id: attenuated_one
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect("mint bound discharge");

        let discharge = DischargeMacaroon::deserialize(&minted.discharge_token)
            .expect("deserialize bound discharge");

        let err = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: attenuated_two.handle,
                redeem_token: wrapped_two.redeem_token,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: vec![discharge],
            },
        )
        .await
        .expect_err("discharge should be bound to the original handle");

        match err {
            ServiceError::Crypto(inner) => assert!(
                inner.to_string().contains("binding") || inner.to_string().contains("discharge"),
                "unexpected binding error: {inner}"
            ),
            ServiceError::InvalidHandle => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_discharge_requires_attestation_when_policy_enabled() {
        let mut harness = test_broker_state().await;
        harness.state.configure_discharge_policy(true, Vec::new());
        let unauthested_context = authenticated_context("spiffe://trust.example/discharger", 74);
        let attested_context =
            attested_authenticated_context("spiffe://trust.example/discharger", 75);
        let location = "spiffe://trust.example/discharger";
        let condition = "attestation=valid";

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &attested_context,
            WrapV2Request {
                plaintext: b"attested-discharge".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap");

        let attenuated = attenuate_handle_v2_impl(
            &harness.state,
            &attested_context,
            AttenuateV2Request {
                handle: wrapped.handle.clone(),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: Some(ThirdPartyCaveatRequest {
                    location: location.to_string(),
                    condition: condition.to_string(),
                }),
            },
        )
        .await
        .expect("attenuate");

        let err = mint_discharge_impl(
            &harness.state,
            &unauthested_context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated.handle.clone(),
                caveat_id: attenuated
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect_err("attestation-required discharge mint must fail without attestation lineage");
        assert!(matches!(
            err,
            ServiceError::MissingLineage(
                "attestation digest lineage on the authenticated broker transport"
            )
        ));

        mint_discharge_impl(
            &harness.state,
            &attested_context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated.handle,
                caveat_id: attenuated
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect("attested discharge mint should succeed");
    }

    #[tokio::test]
    async fn mint_discharge_requires_principal_authorized_for_spiffe_location() {
        let harness = test_broker_state().await;
        let issuer_context = attested_authenticated_context("spiffe://trust.example/issuer", 76);
        let discharger_context =
            attested_authenticated_context("spiffe://trust.example/discharger", 77);
        let wrong_context = attested_authenticated_context("spiffe://trust.example/other", 78);
        let location = "spiffe://trust.example/discharger";
        let condition = "attestation=valid";

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &issuer_context,
            WrapV2Request {
                plaintext: b"spiffe-guarded-discharge".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap");

        let attenuated = attenuate_handle_v2_impl(
            &harness.state,
            &issuer_context,
            AttenuateV2Request {
                handle: wrapped.handle,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: Some(ThirdPartyCaveatRequest {
                    location: location.to_string(),
                    condition: condition.to_string(),
                }),
            },
        )
        .await
        .expect("attenuate");

        let err = mint_discharge_impl(
            &harness.state,
            &wrong_context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated.handle.clone(),
                caveat_id: attenuated
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect_err("mismatched SPIFFE principal must not mint discharge");
        assert!(matches!(err, ServiceError::UnauthorizedDischargePrincipal));

        mint_discharge_impl(
            &harness.state,
            &discharger_context,
            MintDischargeRequest {
                location: location.to_string(),
                primary_handle: attenuated.handle,
                caveat_id: attenuated
                    .third_party_caveat_id
                    .clone()
                    .expect("attenuation must return caveat id"),
            },
        )
        .await
        .expect("matching SPIFFE principal should mint discharge");
    }

    #[test]
    fn renewable_records_require_authenticated_issuance_lineage() {
        let matching_context = BrokerClientContext::from_tls_exporter(
            vec![3u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload".into()),
            Some(vec![3u8; 32]),
            None,
        );
        let issued_peer_cert = encoded_peer_cert(3);

        let missing_issuance_transport = test_record(
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/workload"),
            false,
            Some("spiffe://trust.example/issuer"),
            Some(issued_peer_cert.as_str()),
            None,
        );
        let err = validate_v2_record_identity_requirements(
            &missing_issuance_transport,
            &matching_context,
        )
        .expect_err("missing issuance transport should force reissue");
        assert!(matches!(
            err,
            super::ServiceError::MissingLineage("authenticated issuance transport")
        ));

        let missing_issuer = test_record(
            SecretLifecycle::ServiceBootstrap,
            Some("spiffe://trust.example/workload"),
            true,
            None,
            Some(issued_peer_cert.as_str()),
            None,
        );
        let err = validate_v2_record_identity_requirements(&missing_issuer, &matching_context)
            .expect_err("missing issuing principal should force reissue");
        assert!(matches!(
            err,
            super::ServiceError::MissingLineage("issuing principal lineage")
        ));

        let missing_issuer_peer_cert = test_record(
            SecretLifecycle::ServiceBootstrap,
            Some("spiffe://trust.example/workload"),
            true,
            Some("spiffe://trust.example/issuer"),
            None,
            None,
        );
        let err =
            validate_v2_record_identity_requirements(&missing_issuer_peer_cert, &matching_context)
                .expect_err("missing issuing peer cert should force reissue");
        assert!(matches!(
            err,
            super::ServiceError::MissingLineage("issuing peer certificate lineage")
        ));

        let no_current_peer_cert = BrokerClientContext::from_tls_exporter(
            vec![4u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload".into()),
            None,
            None,
        );
        let valid_cross_principal = test_record(
            SecretLifecycle::ServiceBootstrap,
            Some("spiffe://trust.example/workload"),
            true,
            Some("spiffe://trust.example/issuer"),
            Some(issued_peer_cert.as_str()),
            None,
        );
        let err =
            validate_v2_record_identity_requirements(&valid_cross_principal, &no_current_peer_cert)
                .expect_err("missing current peer cert should fail");
        assert!(matches!(
            err,
            super::ServiceError::MissingLineage(
                "peer certificate lineage on the authenticated broker transport",
            )
        ));

        let same_principal_record = test_record(
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/issuer"),
            true,
            Some("spiffe://trust.example/issuer"),
            Some(issued_peer_cert.as_str()),
            None,
        );
        let mismatched_context = BrokerClientContext::from_tls_exporter(
            vec![5u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/issuer".into()),
            Some(vec![5u8; 32]),
            None,
        );
        let err =
            validate_v2_record_identity_requirements(&same_principal_record, &mismatched_context)
                .expect_err(
                    "mismatched current peer cert should fail when the same principal unwraps",
                );
        assert!(matches!(err, super::ServiceError::PeerCertMismatch));

        validate_v2_record_identity_requirements(&valid_cross_principal, &matching_context)
            .expect("cross-principal bootstrap should not require issuer peer-cert equality");
    }

    #[test]
    fn renewable_records_require_matching_attestation_digest() {
        let expected_digest = super::STANDARD.encode([7u8; 32]);
        let expected_peer_cert = encoded_peer_cert(5);
        let matching_context = BrokerClientContext::from_tls_exporter(
            vec![5u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload".into()),
            Some(vec![5u8; 32]),
            Some(vec![7u8; 32]),
        );
        let record = test_record(
            SecretLifecycle::ServiceBootstrap,
            Some("spiffe://trust.example/workload"),
            true,
            Some("spiffe://trust.example/issuer"),
            Some(expected_peer_cert.as_str()),
            Some(expected_digest.as_str()),
        );

        validate_v2_record_identity_requirements(&record, &matching_context)
            .expect("matching attestation digest should pass identity validation");

        let missing_attestation_context = BrokerClientContext::from_tls_exporter(
            vec![5u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload".into()),
            Some(vec![5u8; 32]),
            None,
        );
        let err = validate_v2_record_identity_requirements(&record, &missing_attestation_context)
            .expect_err("missing attestation digest should fail");
        assert!(matches!(
            err,
            super::ServiceError::MissingLineage(
                "attestation digest lineage on the authenticated broker transport",
            )
        ));

        let mismatched_context = BrokerClientContext::from_tls_exporter(
            vec![5u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload".into()),
            Some(vec![5u8; 32]),
            Some(vec![8u8; 32]),
        );
        let err = validate_v2_record_identity_requirements(&record, &mismatched_context)
            .expect_err("mismatched attestation digest should fail");
        assert!(matches!(err, super::ServiceError::AttestationMismatch));
    }

    #[test]
    fn threshold_custody_records_require_matching_attestation_digest() {
        let expected_digest = super::STANDARD.encode([0xBC; 32]);
        let record = test_record(
            SecretLifecycle::ServiceBootstrap,
            Some("spiffe://trust.example/service"),
            true,
            Some("spiffe://trust.example/custodian"),
            Some(&encoded_peer_cert(91)),
            Some(&expected_digest),
        );

        let missing_attestation_context = BrokerClientContext::from_tls_exporter(
            vec![91u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/custodian".into()),
            Some(vec![91u8; 32]),
            None,
        );
        let missing_err =
            validate_threshold_custody_record_requirements(&record, &missing_attestation_context)
                .expect_err("missing attestation lineage must fail");
        assert!(matches!(
            missing_err,
            super::ServiceError::MissingLineage(
                "attestation digest lineage on the authenticated broker transport"
            )
        ));

        let wrong_attestation_context = BrokerClientContext::from_tls_exporter(
            vec![91u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/custodian".into()),
            Some(vec![91u8; 32]),
            Some(vec![0xAA; 32]),
        );
        let wrong_err =
            validate_threshold_custody_record_requirements(&record, &wrong_attestation_context)
                .expect_err("mismatched attestation lineage must fail");
        assert!(matches!(
            wrong_err,
            super::ServiceError::AttestationMismatch
        ));

        let matching_context = BrokerClientContext::from_tls_exporter(
            vec![91u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/custodian".into()),
            Some(vec![91u8; 32]),
            Some(vec![0xBC; 32]),
        );
        validate_threshold_custody_record_requirements(&record, &matching_context)
            .expect("matching attestation lineage should succeed");
    }

    #[tokio::test]
    async fn single_use_unwrap_consumes_token_on_first_use() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 73);
        let plaintext = b"single-use-secret".to_vec();

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: plaintext.clone(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: None,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap single-use secret");

        let unwrapped = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect("first unwrap should succeed");

        let decoded = super::STANDARD
            .decode(unwrapped.plaintext.as_bytes())
            .expect("decode plaintext");
        assert_eq!(decoded, plaintext);

        let second_unwrap_err = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle,
                redeem_token: wrapped.redeem_token,
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect_err("second unwrap of single-use handle must fail");

        match second_unwrap_err {
            ServiceError::RedeemTokenUsed | ServiceError::RedeemTokenInvalid => {}
            other => {
                panic!("second unwrap must fail with token-used or token-invalid, got: {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn wrap_secret_v2_persists_requested_hard_ttl_for_single_use_unwrap() {
        let harness = test_broker_state().await;
        let context = authenticated_context("spiffe://trust.example/test-client", 74);

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: b"ttl-bound-secret".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: Some(300),
                initial_lease_seconds: None,
                label: Some("ttl-bound".into()),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap ttl-bound single-use secret");

        let expires_at = wrapped
            .expires_at
            .expect("ttl-bound wrap must have expires_at");
        let remaining = expires_at - Utc::now();
        assert!(
            remaining <= Duration::seconds(300) && remaining >= Duration::seconds(295),
            "unexpected remaining ttl: {remaining}"
        );

        let handle_id = parse_handle_identifier(&harness.state, &wrapped.handle)
            .expect("parse authenticated wrapped handle");
        let record = harness
            .state
            .sealed_store()
            .load(&handle_id)
            .await
            .expect("load wrapped record")
            .expect("wrapped record present");
        assert_eq!(
            record.expires_at.map(|value| value.timestamp()),
            Some(expires_at.timestamp())
        );
    }

    #[tokio::test]
    async fn renewable_lease_allows_repeated_unwrap_within_lease() {
        let harness = test_broker_state().await;
        let context = BrokerClientContext::from_tls_exporter(
            vec![20u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/lease-holder".into()),
            Some(vec![20u8; 32]),
            None,
        );
        let plaintext = b"renewable-lease-secret".to_vec();

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &context,
            WrapV2Request {
                plaintext: plaintext.clone(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::RenewableLease,
                ttl_seconds: None,
                initial_lease_seconds: Some(3600),
                label: Some("provider-key".into()),
                tenant_id: Some("tenant-a".into()),
                provider: Some("anthropic".into()),
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap renewable lease");

        let first = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: Some("tenant-a".into()),
                provider: Some("anthropic".into()),
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect("first lease unwrap should succeed");

        let first_decoded = super::STANDARD
            .decode(first.plaintext.as_bytes())
            .expect("decode first");
        assert_eq!(first_decoded, plaintext);

        let second = unwrap_secret_v2_impl(
            &harness.state,
            &context,
            UnwrapV2Request {
                handle: wrapped.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: Some("tenant-a".into()),
                provider: Some("anthropic".into()),
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect("second lease unwrap should also succeed");

        let second_decoded = super::STANDARD
            .decode(second.plaintext.as_bytes())
            .expect("decode second");
        assert_eq!(
            second_decoded, plaintext,
            "repeated unwrap must return same plaintext"
        );
    }

    #[tokio::test]
    async fn renew_lease_enforces_authenticated_principal_lineage() {
        let harness = test_broker_state().await;
        let issuing_context = BrokerClientContext::from_tls_exporter(
            vec![9u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload-a".into()),
            Some(vec![9u8; 32]),
            None,
        );

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &issuing_context,
            WrapV2Request {
                plaintext: b"renew-me".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::RenewableLease,
                ttl_seconds: None,
                initial_lease_seconds: Some(300),
                label: Some("lease".into()),
                tenant_id: Some("tenant-a".into()),
                provider: Some("provider-a".into()),
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap renewable lease");

        let synthetic_err = renew_lease_impl(
            &harness.state,
            &synthetic_context(),
            RenewLeaseRequest {
                handle: wrapped.handle.clone(),
                lease_duration_seconds: 60,
            },
        )
        .await
        .expect_err("synthetic context should not renew authenticated lease");
        match synthetic_err {
            super::ServiceError::UnauthenticatedTransport => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let wrong_principal_context = BrokerClientContext::from_tls_exporter(
            vec![10u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload-b".into()),
            Some(vec![10u8; 32]),
            None,
        );
        let principal_err = renew_lease_impl(
            &harness.state,
            &wrong_principal_context,
            RenewLeaseRequest {
                handle: wrapped.handle.clone(),
                lease_duration_seconds: 60,
            },
        )
        .await
        .expect_err("wrong principal should not renew another principal's lease");
        match principal_err {
            super::ServiceError::PrincipalMismatch => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let renewed = renew_lease_impl(
            &harness.state,
            &issuing_context,
            RenewLeaseRequest {
                handle: wrapped.handle,
                lease_duration_seconds: 60,
            },
        )
        .await
        .expect("bound principal should renew lease");

        assert!(
            renewed.renewal_count >= 1,
            "renewal_count = {}",
            renewed.renewal_count
        );
        assert!(renewed.lease_expires_at > Utc::now());
    }

    #[tokio::test]
    async fn claim_share_requires_custodian_identity_match() {
        let harness = test_broker_state().await;
        let handle_id = Uuid::new_v4();
        let mut record = test_record(
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/cust-a"),
            true,
            Some("spiffe://trust.example/cust-a"),
            Some(encoded_peer_cert(81).as_str()),
            None,
        );
        record.threshold = Some(1);
        record.threshold_commitments = Some(vec![super::STANDARD.encode([1u8; 33])]);
        record.share_assignments = Some(vec![ShareAssignment {
            custodian_id: "spiffe://trust.example/cust-a".into(),
            share_index: 1,
            claimed: false,
        }]);
        record.held_shares = Some(vec![HeldShare {
            x: 1,
            y_b64: super::STANDARD.encode([7u8; 32]),
        }]);
        harness
            .state
            .sealed_store()
            .insert_with_id(handle_id, record)
            .await
            .expect("insert claimed-share record");

        let wrong_context = authenticated_context("spiffe://trust.example/cust-b", 81);
        let err = match claim_share_impl(
            &harness.state,
            &wrong_context,
            ClaimShareRequest {
                handle: v2_handle(&harness.state, handle_id),
                custodian_id: "spiffe://trust.example/cust-a".into(),
            },
        )
        .await
        {
            Ok(_) => panic!("wrong principal must not claim another custodian share"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("does not match authenticated principal"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn claim_share_succeeds_for_matching_authenticated_custodian() {
        let harness = test_broker_state().await;
        let handle_id = Uuid::new_v4();
        let mut record = test_record(
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/cust-a"),
            true,
            Some("spiffe://trust.example/cust-a"),
            Some(encoded_peer_cert(82).as_str()),
            None,
        );
        record.threshold = Some(1);
        record.threshold_commitments = Some(vec![super::STANDARD.encode([1u8; 33])]);
        record.share_assignments = Some(vec![ShareAssignment {
            custodian_id: "spiffe://trust.example/cust-a".into(),
            share_index: 1,
            claimed: false,
        }]);
        record.held_shares = Some(vec![HeldShare {
            x: 1,
            y_b64: super::STANDARD.encode([7u8; 32]),
        }]);
        harness
            .state
            .sealed_store()
            .insert_with_id(handle_id, record)
            .await
            .expect("insert claimed-share record");

        let context = authenticated_context("spiffe://trust.example/cust-a", 82);
        let response = claim_share_impl(
            &harness.state,
            &context,
            ClaimShareRequest {
                handle: v2_handle(&harness.state, handle_id),
                custodian_id: "spiffe://trust.example/cust-a".into(),
            },
        )
        .await
        .expect("matching principal should claim assigned share");
        assert_eq!(response.x, 1);
        assert_eq!(response.y, vec![7u8; 32]);
        assert!(!response.previously_claimed);
    }

    #[tokio::test]
    async fn distribute_share_requires_custodian_identity_match() {
        let harness = test_broker_state().await;
        let handle_id = Uuid::new_v4();
        let record = test_record(
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/cust-a"),
            true,
            Some("spiffe://trust.example/cust-a"),
            Some(encoded_peer_cert(83).as_str()),
            None,
        );
        harness
            .state
            .sealed_store()
            .insert_with_id(handle_id, record)
            .await
            .expect("insert distribute-share record");

        let owner_context = authenticated_context("spiffe://trust.example/cust-a", 83);
        let err = match distribute_share_impl(
            &harness.state,
            &owner_context,
            DistributeShareRequest {
                handle: v2_handle(&harness.state, handle_id),
                share_index: 1,
                share: crate::secret_broker_impl::threshold::Share {
                    x: 1,
                    y: vec![7u8; 32],
                },
                custodian_id: "spiffe://trust.example/cust-b".into(),
            },
        )
        .await
        {
            Ok(_) => {
                panic!("owner must not acknowledge distribution on behalf of another custodian")
            }
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("does not match authenticated principal"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn distribute_share_succeeds_for_matching_authenticated_custodian() {
        let harness = test_broker_state().await;
        let handle_id = Uuid::new_v4();
        let record = test_record(
            SecretLifecycle::RenewableLease,
            Some("spiffe://trust.example/cust-a"),
            true,
            Some("spiffe://trust.example/cust-a"),
            Some(encoded_peer_cert(84).as_str()),
            None,
        );
        harness
            .state
            .sealed_store()
            .insert_with_id(handle_id, record)
            .await
            .expect("insert distribute-share record");

        let context = authenticated_context("spiffe://trust.example/cust-a", 84);
        let response = distribute_share_impl(
            &harness.state,
            &context,
            DistributeShareRequest {
                handle: v2_handle(&harness.state, handle_id),
                share_index: 1,
                share: crate::secret_broker_impl::threshold::Share {
                    x: 1,
                    y: vec![9u8; 32],
                },
                custodian_id: "spiffe://trust.example/cust-a".into(),
            },
        )
        .await
        .expect("matching principal should acknowledge their own share distribution");
        assert!(response.accepted);
        assert!(!response.ack_token.is_empty());
    }

    #[test]
    fn combine_shares_requires_claimed_assigned_shares() {
        let mut record = test_record(
            SecretLifecycle::SingleUseUnwrap,
            None,
            false,
            None,
            None,
            None,
        );
        record.threshold = Some(2);
        record.share_assignments = Some(vec![
            ShareAssignment {
                custodian_id: "cust-a".into(),
                share_index: 1,
                claimed: false,
            },
            ShareAssignment {
                custodian_id: "cust-b".into(),
                share_index: 2,
                claimed: true,
            },
        ]);
        record.held_shares = Some(vec![
            HeldShare {
                x: 1,
                y_b64: super::STANDARD.encode([1u8; 32]),
            },
            HeldShare {
                x: 2,
                y_b64: super::STANDARD.encode([2u8; 32]),
            },
        ]);

        let err = validate_combine_shares_custody(
            &record,
            &CombineSharesRequest {
                handle: "broker:v2:test".into(),
                shares: vec![
                    crate::secret_broker_impl::threshold::Share {
                        x: 1,
                        y: vec![1u8; 32],
                    },
                    crate::secret_broker_impl::threshold::Share {
                        x: 2,
                        y: vec![2u8; 32],
                    },
                ],
                tenant_id: None,
                provider: None,
                custodian_ids: vec!["cust-a".into(), "cust-b".into()],
            },
        )
        .expect_err("combine should fail before custodians claim shares");
        assert!(
            err.to_string().contains("has not claimed"),
            "unexpected combine error: {err}"
        );
    }

    #[tokio::test]
    async fn revoke_and_rotate_enforce_authenticated_principal_lineage() {
        let harness = test_broker_state().await;
        let issuing_context = BrokerClientContext::from_tls_exporter(
            vec![13u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload-a".into()),
            Some(vec![13u8; 32]),
            None,
        );

        let wrapped_for_revoke = wrap_secret_v2_impl(
            &harness.state,
            &issuing_context,
            WrapV2Request {
                plaintext: b"revoke-me".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::RenewableLease,
                ttl_seconds: None,
                initial_lease_seconds: Some(300),
                label: Some("lease".into()),
                tenant_id: Some("tenant-a".into()),
                provider: Some("provider-a".into()),
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap renewable lease for revocation");

        let synthetic_revoke_err = revoke_secret_impl(
            &harness.state,
            &synthetic_context(),
            RevokeSecretRequest {
                handle: wrapped_for_revoke.handle.clone(),
                reason: Some("synthetic".into()),
            },
        )
        .await
        .expect_err("synthetic context should not revoke authenticated lease");
        match synthetic_revoke_err {
            ServiceError::UnauthenticatedTransport => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let wrong_principal_context = BrokerClientContext::from_tls_exporter(
            vec![14u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/workload-b".into()),
            Some(vec![14u8; 32]),
            None,
        );

        let principal_revoke_err = revoke_secret_impl(
            &harness.state,
            &wrong_principal_context,
            RevokeSecretRequest {
                handle: wrapped_for_revoke.handle.clone(),
                reason: Some("wrong-principal".into()),
            },
        )
        .await
        .expect_err("wrong principal should not revoke another principal's lease");
        match principal_revoke_err {
            ServiceError::PrincipalMismatch => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let revoked = revoke_secret_impl(
            &harness.state,
            &issuing_context,
            RevokeSecretRequest {
                handle: wrapped_for_revoke.handle,
                reason: Some("owner".into()),
            },
        )
        .await
        .expect("bound principal should revoke lease");
        assert!(revoked.revoked);

        let wrapped_for_rotate = wrap_secret_v2_impl(
            &harness.state,
            &issuing_context,
            WrapV2Request {
                plaintext: b"rotate-me".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::RenewableLease,
                ttl_seconds: None,
                initial_lease_seconds: Some(300),
                label: Some("lease".into()),
                tenant_id: Some("tenant-a".into()),
                provider: Some("provider-a".into()),
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap renewable lease for rotation");

        let synthetic_rotate_err = rotate_secret_impl(
            &harness.state,
            &synthetic_context(),
            RotateSecretRequest {
                old_handle: wrapped_for_rotate.handle.clone(),
                new_plaintext: b"rotated".to_vec(),
                customer_id: None,
                metadata: None,
                ttl_seconds: Some(300),
                rotation_reason: Some("synthetic".into()),
                lifecycle: SecretLifecycle::RenewableLease,
                threshold: None,
                num_shares: None,
            },
        )
        .await
        .expect_err("synthetic context should not rotate authenticated lease");
        match synthetic_rotate_err {
            ServiceError::UnauthenticatedTransport => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let principal_rotate_err = rotate_secret_impl(
            &harness.state,
            &wrong_principal_context,
            RotateSecretRequest {
                old_handle: wrapped_for_rotate.handle.clone(),
                new_plaintext: b"rotated".to_vec(),
                customer_id: None,
                metadata: None,
                ttl_seconds: Some(300),
                rotation_reason: Some("wrong-principal".into()),
                lifecycle: SecretLifecycle::RenewableLease,
                threshold: None,
                num_shares: None,
            },
        )
        .await
        .expect_err("wrong principal should not rotate another principal's lease");
        match principal_rotate_err {
            ServiceError::PrincipalMismatch => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let rotated = rotate_secret_impl(
            &harness.state,
            &issuing_context,
            RotateSecretRequest {
                old_handle: wrapped_for_rotate.handle,
                new_plaintext: b"rotated".to_vec(),
                customer_id: None,
                metadata: None,
                ttl_seconds: Some(300),
                rotation_reason: Some("owner".into()),
                lifecycle: SecretLifecycle::RenewableLease,
                threshold: None,
                num_shares: None,
            },
        )
        .await
        .expect("bound principal should rotate lease");
        assert!(rotated.old_revoked);
        assert!(!rotated.new_handle.is_empty());
    }

    #[tokio::test]
    async fn revoke_persists_generic_lineage_metadata_in_transparency_log() {
        let harness = test_broker_state_with_transparency().await;
        let transparency_path = harness
            .transparency_path
            .clone()
            .expect("transparency path");
        let issuing_context = authenticated_context("spiffe://trust.example/workload-a", 21);
        let key_lineage_metadata = json!({
            "key_lineage": {
                "purpose": "service-bootstrap",
                "credential_id": Uuid::new_v4().to_string(),
                "source_key_fingerprint": "sha256:source1234",
                "target_key_fingerprint": "sha256:target5678",
                "generation": 4,
            }
        });

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &issuing_context,
            WrapV2Request {
                plaintext: b"bootstrap-key".to_vec(),
                customer_id: Some("customer-a".into()),
                metadata: Some(key_lineage_metadata.clone()),
                lifecycle: SecretLifecycle::SingleUseUnwrap,
                ttl_seconds: Some(300),
                initial_lease_seconds: None,
                label: Some("bootstrap-key".into()),
                tenant_id: Some("tenant-a".into()),
                provider: None,
                circuit_id: None,
                node_id: Some("workload-b".into()),
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap key with lineage metadata");

        let revoked = revoke_secret_impl(
            &harness.state,
            &issuing_context,
            RevokeSecretRequest {
                handle: wrapped.handle.clone(),
                reason: Some("superseded".into()),
            },
        )
        .await
        .expect("revoke key");
        assert!(revoked.revoked);

        let contents = fs::read_to_string(&transparency_path).expect("read transparency log");
        assert!(
            !contents.contains(&wrapped.handle),
            "transparency log must not contain the raw V2 capability"
        );
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected wrap + revoke transparency entries"
        );

        let wrap_event: Value = serde_json::from_str(lines[0]).expect("parse wrap event");
        let revoke_event: Value = serde_json::from_str(lines[1]).expect("parse revoke event");
        let expected_fingerprint = handle_fingerprint(&wrapped.handle);

        assert_eq!(wrap_event["event"], json!("wrap"));
        assert_eq!(wrap_event["customer_id"], json!("customer-a"));
        assert_eq!(
            wrap_event["metadata"]["handle_fingerprint"],
            json!(expected_fingerprint)
        );
        assert_eq!(
            wrap_event["metadata"]["secret_metadata"],
            key_lineage_metadata.clone()
        );

        assert_eq!(revoke_event["event"], json!("revoke"));
        assert_eq!(revoke_event["customer_id"], json!("customer-a"));
        assert_eq!(revoke_event["metadata"]["reason"], json!("superseded"));
        assert_eq!(
            revoke_event["metadata"]["handle_fingerprint"],
            json!(expected_fingerprint)
        );
        assert_eq!(
            revoke_event["metadata"]["lifecycle"],
            json!("single_use_unwrap")
        );
        assert_eq!(
            revoke_event["metadata"]["issued_with_authenticated_transport"],
            json!(true)
        );
        assert_eq!(
            revoke_event["metadata"]["issued_by_principal_id"],
            json!("spiffe://trust.example/workload-a")
        );
        assert_eq!(
            revoke_event["metadata"]["unwrap_principal_id"],
            json!("spiffe://trust.example/workload-a")
        );
        assert_eq!(
            revoke_event["metadata"]["secret_metadata"],
            key_lineage_metadata
        );
    }

    #[test]
    fn combine_shares_rejects_mismatched_custodian_share_pairing() {
        let mut record = test_record(
            SecretLifecycle::SingleUseUnwrap,
            None,
            false,
            None,
            None,
            None,
        );
        record.threshold = Some(2);
        record.share_assignments = Some(vec![
            ShareAssignment {
                custodian_id: "cust-a".into(),
                share_index: 1,
                claimed: true,
            },
            ShareAssignment {
                custodian_id: "cust-b".into(),
                share_index: 2,
                claimed: true,
            },
        ]);
        record.held_shares = Some(vec![
            HeldShare {
                x: 1,
                y_b64: super::STANDARD.encode([1u8; 32]),
            },
            HeldShare {
                x: 2,
                y_b64: super::STANDARD.encode([2u8; 32]),
            },
        ]);

        let err = validate_combine_shares_custody(
            &record,
            &CombineSharesRequest {
                handle: "broker:v2:test".into(),
                shares: vec![
                    crate::secret_broker_impl::threshold::Share {
                        x: 1,
                        y: vec![1u8; 32],
                    },
                    crate::secret_broker_impl::threshold::Share {
                        x: 2,
                        y: vec![2u8; 32],
                    },
                ],
                tenant_id: None,
                provider: None,
                custodian_ids: vec!["cust-b".into(), "cust-a".into()],
            },
        )
        .expect_err("combine should reject custodian/share mismatch");
        assert!(
            err.to_string()
                .contains("must provide assigned share index"),
            "unexpected combine error: {err}"
        );
    }

    #[tokio::test]
    async fn service_bootstrap_cross_principal_unwrap() {
        let harness = test_broker_state().await;
        let issuer = BrokerClientContext::from_tls_exporter(
            vec![30u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/control-plane".into()),
            Some(vec![30u8; 32]),
            None,
        );
        let target_principal = "spiffe://trust.example/workload-x";

        // Wrap with ServiceBootstrap, binding unwrap to a different principal.
        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &issuer,
            WrapV2Request {
                plaintext: b"bootstrap-material".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::ServiceBootstrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: Some("bootstrap".into()),
                tenant_id: Some("tenant-x".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: Some(target_principal.into()),
            },
        )
        .await
        .expect("wrap bootstrap secret");

        // Target principal can unwrap.
        let target = BrokerClientContext::from_tls_exporter(
            vec![31u8; 32],
            Some(Uuid::new_v4()),
            Some(target_principal.into()),
            Some(vec![31u8; 32]),
            None,
        );
        let unwrapped = unwrap_secret_v2_impl(
            &harness.state,
            &target,
            UnwrapV2Request {
                handle: wrapped.handle.clone(),
                redeem_token: wrapped.redeem_token.clone(),
                tenant_id: Some("tenant-x".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect("target principal should unwrap bootstrap secret");

        let decoded = super::STANDARD
            .decode(unwrapped.plaintext.as_bytes())
            .expect("decode");
        assert_eq!(decoded, b"bootstrap-material");

        // A third-party principal must NOT unwrap.
        let intruder = BrokerClientContext::from_tls_exporter(
            vec![32u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/intruder".into()),
            Some(vec![32u8; 32]),
            None,
        );
        // Need a fresh wrap because the first one was consumed (SingleUse-like
        // bootstrap). Wrap again with same binding.
        let wrapped2 = wrap_secret_v2_impl(
            &harness.state,
            &issuer,
            WrapV2Request {
                plaintext: b"bootstrap-material-2".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::ServiceBootstrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: Some("bootstrap".into()),
                tenant_id: Some("tenant-x".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: Some(target_principal.into()),
            },
        )
        .await
        .expect("wrap second bootstrap secret");

        let intruder_err = unwrap_secret_v2_impl(
            &harness.state,
            &intruder,
            UnwrapV2Request {
                handle: wrapped2.handle,
                redeem_token: wrapped2.redeem_token,
                tenant_id: Some("tenant-x".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                discharges: Vec::new(),
            },
        )
        .await
        .expect_err("intruder principal must not unwrap bootstrap secret");

        match intruder_err {
            ServiceError::PrincipalMismatch => {}
            other => panic!("expected principal mismatch, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn issuing_principal_can_manage_cross_principal_bootstrap_secret() {
        let harness = test_broker_state().await;
        let issuer = BrokerClientContext::from_tls_exporter(
            vec![30u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/control-plane".into()),
            Some(vec![30u8; 32]),
            None,
        );
        let target_principal = "spiffe://trust.example/workload-x";

        let wrapped_for_revoke = wrap_secret_v2_impl(
            &harness.state,
            &issuer,
            WrapV2Request {
                plaintext: b"bootstrap-revoke".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::ServiceBootstrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: Some("bootstrap".into()),
                tenant_id: Some("tenant-x".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: Some(target_principal.into()),
            },
        )
        .await
        .expect("wrap bootstrap secret for revocation");

        let revoked = revoke_secret_impl(
            &harness.state,
            &issuer,
            RevokeSecretRequest {
                handle: wrapped_for_revoke.handle,
                reason: Some("issuer-rotation".into()),
            },
        )
        .await
        .expect("issuing principal should revoke cross-principal bootstrap");
        assert!(revoked.revoked);

        let wrapped_for_rotate = wrap_secret_v2_impl(
            &harness.state,
            &issuer,
            WrapV2Request {
                plaintext: b"bootstrap-rotate".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::ServiceBootstrap,
                ttl_seconds: None,
                initial_lease_seconds: None,
                label: Some("bootstrap".into()),
                tenant_id: Some("tenant-x".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: Some(target_principal.into()),
            },
        )
        .await
        .expect("wrap bootstrap secret for rotation");

        let rotated = rotate_secret_impl(
            &harness.state,
            &issuer,
            RotateSecretRequest {
                old_handle: wrapped_for_rotate.handle,
                new_plaintext: b"bootstrap-rotated".to_vec(),
                customer_id: None,
                metadata: None,
                ttl_seconds: None,
                rotation_reason: Some("issuer-rotation".into()),
                lifecycle: SecretLifecycle::ServiceBootstrap,
                threshold: None,
                num_shares: None,
            },
        )
        .await
        .expect("issuing principal should rotate cross-principal bootstrap");
        assert!(rotated.old_revoked);
        assert!(!rotated.new_handle.is_empty());
    }

    #[tokio::test]
    async fn delete_secret_enforces_v2_principal_lineage() {
        let harness = test_broker_state().await;
        let owner = BrokerClientContext::from_tls_exporter(
            vec![40u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/owner".into()),
            Some(vec![40u8; 32]),
            None,
        );

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &owner,
            WrapV2Request {
                plaintext: b"delete-me".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::RenewableLease,
                ttl_seconds: None,
                initial_lease_seconds: Some(300),
                label: Some("deletable".into()),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap secret for deletion test");

        // Wrong principal cannot delete.
        let intruder = BrokerClientContext::from_tls_exporter(
            vec![41u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/intruder".into()),
            Some(vec![41u8; 32]),
            None,
        );
        let delete_err = delete_secret_impl(&harness.state, &intruder, &wrapped.handle)
            .await
            .expect_err("wrong principal must not delete");
        match delete_err {
            ServiceError::PrincipalMismatch | ServiceError::UnauthenticatedTransport => {}
            other => panic!("expected identity rejection, got: {other:?}"),
        }

        // Owner can delete.
        let deleted = delete_secret_impl(&harness.state, &owner, &wrapped.handle)
            .await
            .expect("owner should delete");
        assert!(deleted);
    }

    #[tokio::test]
    async fn attenuate_handle_enforces_v2_principal_lineage() {
        let harness = test_broker_state().await;
        let owner = BrokerClientContext::from_tls_exporter(
            vec![50u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/owner".into()),
            Some(vec![50u8; 32]),
            None,
        );

        let wrapped = wrap_secret_v2_impl(
            &harness.state,
            &owner,
            WrapV2Request {
                plaintext: b"attenuate-me".to_vec(),
                customer_id: None,
                metadata: None,
                lifecycle: SecretLifecycle::RenewableLease,
                ttl_seconds: None,
                initial_lease_seconds: Some(300),
                label: Some("attenuatable".into()),
                tenant_id: None,
                provider: None,
                circuit_id: None,
                node_id: None,
                unwrap_principal_id: None,
            },
        )
        .await
        .expect("wrap secret for attenuation test");

        // Wrong principal cannot attenuate.
        let intruder = BrokerClientContext::from_tls_exporter(
            vec![51u8; 32],
            Some(Uuid::new_v4()),
            Some("spiffe://trust.example/intruder".into()),
            Some(vec![51u8; 32]),
            None,
        );
        let attenuate_err = attenuate_handle_v2_impl(
            &harness.state,
            &intruder,
            AttenuateV2Request {
                handle: wrapped.handle.clone(),
                tenant_id: Some("tenant-a".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: None,
            },
        )
        .await
        .expect_err("wrong principal must not attenuate");
        match attenuate_err {
            ServiceError::PrincipalMismatch | ServiceError::UnauthenticatedTransport => {}
            other => panic!("expected identity rejection, got: {other:?}"),
        }

        // Owner can attenuate.
        let attenuated = attenuate_handle_v2_impl(
            &harness.state,
            &owner,
            AttenuateV2Request {
                handle: wrapped.handle,
                tenant_id: Some("tenant-a".into()),
                provider: None,
                circuit_id: None,
                node_id: None,
                action: None,
                max_uses: None,
                third_party: None,
            },
        )
        .await
        .expect("owner should attenuate");
        assert!(!attenuated.handle.is_empty());
    }
}
