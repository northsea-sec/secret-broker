//! Authenticated typed gRPC client and protocol types for the Secret Broker.
//!
//! `SecretBrokerClient::connect` is the sole public transport constructor. It
//! requires explicit client mTLS identity, trust roots, server name, and either
//! verified RA-TLS or loopback-only local mTLS. The protocol adapter remains
//! crate-private so consumers cannot construct an unauthenticated channel.

mod client;
mod ra_tls;

pub use client::{
    AttestationMode, ClientIdentity, ClientPolicy, MeasurementPolicy, SecretBrokerClient,
    SecretBrokerClientConfig,
};

/// Expected length of a threshold share y-coordinate (32 bytes / 256 bits).
pub const SHARE_Y_LEN: usize = 32;

mod broker_proto {
    tonic::include_proto!("secretbroker.v1");
}

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use prost_types::{value::Kind as ProstKind, ListValue, Struct, Timestamp, Value as ProstValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};
use tonic::{transport::Channel, Status};
use url::Url;
use zeroize::Zeroizing;

use broker_proto::{
    secret_broker_service_client::SecretBrokerServiceClient,
    AttenuateHandleV2Request as GrpcAttenuateHandleV2Request,
    ClaimShareRequest as GrpcClaimShareRequest, CryptoDecryptRequest as GrpcCryptoDecryptRequest,
    CryptoEncryptRequest as GrpcCryptoEncryptRequest,
    CryptoKeygenRequest as GrpcCryptoKeygenRequest, CryptoPubkeyRequest as GrpcCryptoPubkeyRequest,
    CryptoRandomRequest as GrpcCryptoRandomRequest, CryptoSignRequest as GrpcCryptoSignRequest,
    CryptoVerifyRequest as GrpcCryptoVerifyRequest, DeleteSecretRequest,
    DescribeChannelRequest as GrpcDescribeChannelRequest,
    DescribeChannelResponse as GrpcDescribeChannelResponse, DischargeToken as GrpcDischargeToken,
    IssuePostgresCredentialsRequest, MintAeadKeyV2Request as GrpcMintAeadKeyV2Request,
    MintDischargeRequest as GrpcMintDischargeRequest, RenewLeaseRequest as GrpcRenewLeaseRequest,
    RevokeSecretRequest as GrpcRevokeSecretRequest, RotateSecretRequest as GrpcRotateSecretRequest,
    SecretLifecycle as GrpcSecretLifecycle, ThirdPartyCaveat as GrpcThirdPartyCaveat,
    ThresholdShare as GrpcThresholdShare, UnwrapSecretV2Request as GrpcUnwrapSecretV2Request,
    WrapSecretV2Request as GrpcWrapSecretV2Request,
};

/// Lifecycle policy for a brokered V2 capability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecretLifecycle {
    #[default]
    SingleUseUnwrap,
    RenewableLease,
    ServiceBootstrap,
}

impl SecretLifecycle {
    fn into_proto(self) -> GrpcSecretLifecycle {
        match self {
            Self::SingleUseUnwrap => GrpcSecretLifecycle::SingleUseUnwrap,
            Self::RenewableLease => GrpcSecretLifecycle::RenewableLease,
            Self::ServiceBootstrap => GrpcSecretLifecycle::ServiceBootstrap,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapResponse {
    pub handle: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub redeem_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem_token_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct WrapV2Params {
    pub metadata: Option<Value>,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub ttl_seconds: Option<u64>,
    pub lifecycle: Option<SecretLifecycle>,
    pub initial_lease_seconds: Option<u64>,
    pub label: Option<String>,
    pub unwrap_principal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdShareMaterial {
    pub x: u8,
    pub y: Vec<u8>,
}

impl Drop for ThresholdShareMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.y.zeroize();
    }
}

#[derive(Clone)]
pub(crate) struct SecretBrokerGrpcAdapterConfig {
    endpoint: Url,
    channel: Channel,
    client_principal_id: Option<String>,
}

impl SecretBrokerGrpcAdapterConfig {
    pub(crate) fn new(endpoint: Url, channel: Channel) -> Self {
        Self {
            endpoint,
            channel,
            client_principal_id: None,
        }
    }

    #[cfg(test)]
    fn client_principal_id(mut self, value: Option<String>) -> Self {
        self.client_principal_id = value
            .map(|principal| principal.trim().to_string())
            .filter(|principal| !principal.is_empty());
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct MintAeadKeyV2Params {
    pub ttl_seconds: Option<u64>,
    pub label: Option<String>,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub threshold: Option<u8>,
    pub num_shares: Option<u8>,
    pub lifecycle: Option<SecretLifecycle>,
    pub initial_lease_seconds: Option<u64>,
    pub unwrap_principal_id: Option<String>,
    /// Custodian identifiers for broker-held threshold-share distribution.
    /// When set with threshold > 1, shares are not returned in the response.
    pub custodian_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct MintAeadKeyV2Lease {
    pub key: Vec<u8>,
    pub handle: String,
    pub redeem_token: Option<String>,
    pub redeem_shares: Vec<ThresholdShareMaterial>,
    pub redeem_token_expires_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub threshold: u8,
    pub num_shares: u8,
}

#[derive(Debug, Clone, Default)]
pub struct UnwrapSecretV2Params {
    pub handle: String,
    pub redeem_token: Option<String>,
    pub redeem_shares: Vec<ThresholdShareMaterial>,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub discharges: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ThirdPartyCaveatParams {
    pub location: String,
    pub condition: String,
}

#[derive(Debug, Clone, Default)]
pub struct AttenuateHandleV2Params {
    pub handle: String,
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub action: Option<String>,
    pub max_uses: Option<u32>,
    pub third_party: Option<ThirdPartyCaveatParams>,
}

/// Result of adding caveats to a v2 handle.
#[derive(Debug, Clone)]
pub struct AttenuateHandleV2Result {
    pub handle: String,
    /// Broker-issued opaque ID for a requested third-party caveat.
    /// Pass it unchanged to [`SecretBrokerClient::mint_discharge`].
    pub third_party_caveat_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MintDischargeParams {
    pub primary_handle: String,
    pub location: String,
    pub caveat_id: String,
}

#[derive(Debug, Clone)]
pub struct PostgresCredentialParams {
    pub audience: String,
    pub scope: Vec<String>,
    pub ttl_seconds: Option<u64>,
    pub application_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PostgresCredentialLease {
    pub database_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ca_certificate_pem: Option<String>,
    pub server_cert_fingerprint: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CryptoEncryptParams {
    pub key_id: Option<String>,
    pub plaintext: Vec<u8>,
    pub algorithm: Option<String>,
    pub customer_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CryptoEncryptResult {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CryptoDecryptParams {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
    pub algorithm: Option<String>,
    pub customer_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CryptoDecryptResult {
    pub plaintext: Vec<u8>,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct CryptoSignParams {
    pub key_id: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CryptoVerifyParams {
    pub key_id: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CryptoKeygenParams {
    pub algorithm: String,
    pub customer_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CryptoKeyPairResult {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub algorithm: String,
}

#[derive(Debug, Clone)]
pub struct RenewLeaseResult {
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub renewal_count: u32,
}

#[derive(Debug, Clone)]
pub struct RevokeResult {
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone)]
pub struct RotateParams {
    pub customer_id: Option<String>,
    pub metadata: Option<Value>,
    pub ttl_seconds: Option<u64>,
    pub lifecycle: Option<SecretLifecycle>,
    pub rotation_reason: Option<String>,
    pub threshold: Option<u8>,
    pub num_shares: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct RotateResult {
    pub new_handle: String,
    pub created_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub redeem_token: String,
    pub redeem_token_expires_at: Option<DateTime<Utc>>,
    pub old_revoked: bool,
    pub new_shares: Vec<ThresholdShareMaterial>,
}

/// Result of an authenticated custodian share claim.
#[derive(Debug, Clone)]
pub struct ClaimShareResult {
    pub share: ThresholdShareMaterial,
    /// Feldman commitment set (serialized compressed P-256 points).
    pub commitments: Vec<Vec<u8>>,
    /// Whether this share was previously claimed by this custodian.
    pub previously_claimed: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SecretBrokerGrpcAdapter {
    channel: Channel,
    endpoint: Url,
    client_principal_id: Option<String>,
    redeem_cache: Arc<DashMap<String, RedeemCacheEntry>>,
}

impl SecretBrokerGrpcAdapter {
    pub(crate) fn new(config: SecretBrokerGrpcAdapterConfig) -> Self {
        Self {
            channel: config.channel,
            endpoint: config.endpoint,
            client_principal_id: config.client_principal_id,
            redeem_cache: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub async fn describe_channel(&self) -> Result<GrpcDescribeChannelResponse> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let response = client
            .describe_channel(GrpcDescribeChannelRequest {})
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(response)
    }

    fn resolve_v2_unwrap_principal(
        &self,
        lifecycle: GrpcSecretLifecycle,
        requested_principal: Option<String>,
        channel: &GrpcDescribeChannelResponse,
    ) -> Result<String> {
        let requested_principal = requested_principal
            .map(|principal| principal.trim().to_string())
            .filter(|principal| !principal.is_empty());
        let needs_authenticated_principal = requested_principal.is_some()
            || matches!(
                lifecycle,
                GrpcSecretLifecycle::RenewableLease | GrpcSecretLifecycle::ServiceBootstrap
            );
        if !needs_authenticated_principal {
            return Ok(String::new());
        }
        let channel_principal = self.require_authenticated_channel_principal(
            &format!("{:?}", lifecycle),
            channel,
            matches!(
                lifecycle,
                GrpcSecretLifecycle::RenewableLease | GrpcSecretLifecycle::ServiceBootstrap
            ),
        )?;
        match lifecycle {
            GrpcSecretLifecycle::SingleUseUnwrap => {
                if let Some(requested_principal) = requested_principal {
                    if requested_principal != channel_principal {
                        return Err(anyhow!(
                            "single-use explicit unwrap principal {} does not match broker channel principal {}",
                            requested_principal,
                            channel_principal
                        ));
                    }
                    Ok(requested_principal)
                } else {
                    Ok(String::new())
                }
            }
            GrpcSecretLifecycle::RenewableLease | GrpcSecretLifecycle::ServiceBootstrap => {
                Ok(requested_principal.unwrap_or_else(|| channel_principal.to_string()))
            }
        }
    }

    fn require_authenticated_channel_principal(
        &self,
        operation: &str,
        channel: &GrpcDescribeChannelResponse,
        require_peer_cert: bool,
    ) -> Result<String> {
        let channel_principal = channel.principal_id.trim();
        if !channel.authenticated_transport {
            return Err(anyhow!(
                "broker DescribeChannel reports unauthenticated transport for {}",
                operation
            ));
        }
        if channel_principal.is_empty() {
            return Err(anyhow!(
                "broker DescribeChannel reports no authenticated principal for {}",
                operation
            ));
        }
        if require_peer_cert && channel.peer_cert_sha256.is_empty() {
            return Err(anyhow!(
                "broker DescribeChannel reports no peer certificate lineage for {}",
                operation
            ));
        }
        if let Some(client_principal) = self.client_principal_id.as_deref() {
            let client_principal = client_principal.trim();
            if !client_principal.is_empty() && client_principal != channel_principal {
                return Err(anyhow!(
                    "broker channel principal mismatch: client={} broker={}",
                    client_principal,
                    channel_principal
                ));
            }
        }
        Ok(channel_principal.to_string())
    }

    pub async fn wrap_bytes_v2(
        &self,
        plaintext: &[u8],
        params: WrapV2Params,
    ) -> Result<WrapResponse> {
        self.purge_expired(Utc::now());
        let metadata_struct = option_json_to_struct(params.metadata)?;
        let lifecycle = params.lifecycle.unwrap_or_default().into_proto();
        let requested_principal = params
            .unwrap_principal_id
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let resolved_principal = if requested_principal.is_some()
            || matches!(
                lifecycle,
                GrpcSecretLifecycle::RenewableLease | GrpcSecretLifecycle::ServiceBootstrap
            ) {
            let channel = self.describe_channel().await?;
            self.resolve_v2_unwrap_principal(lifecycle, requested_principal, &channel)?
        } else {
            String::new()
        };

        let request = GrpcWrapSecretV2Request {
            plaintext: plaintext.to_vec(),
            customer_id: String::new(),
            metadata: metadata_struct,
            lifecycle: lifecycle as i32,
            initial_lease_seconds: params.initial_lease_seconds.unwrap_or_default(),
            label: params.label.unwrap_or_default(),
            tenant_id: params.tenant_id.unwrap_or_default(),
            provider: params.provider.unwrap_or_default(),
            circuit_id: params.circuit_id.unwrap_or_default(),
            node_id: params.node_id.unwrap_or_default(),
            unwrap_principal_id: resolved_principal,
            ttl_seconds: params.ttl_seconds.unwrap_or_default(),
        };

        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let response = client
            .wrap_secret_v2(request)
            .await
            .map_err(map_status)?
            .into_inner();

        let created_at = required_timestamp(response.created_at, "created_at")?;
        let expires_at = optional_timestamp(response.expires_at)?;
        let redeem_token = BASE64.encode(&response.redeem_token);
        let redeem_token_expires_at = optional_timestamp(response.redeem_token_expires_at)?;

        let wrap_response = WrapResponse {
            handle: response.handle,
            created_at,
            expires_at,
            redeem_token: redeem_token.clone(),
            redeem_token_expires_at,
        };

        self.remember_redeem_token(
            &wrap_response.handle,
            redeem_token,
            wrap_response.redeem_token_expires_at,
        )?;

        Ok(wrap_response)
    }

    pub async fn wrap_json_v2<T>(&self, payload: &T, params: WrapV2Params) -> Result<WrapResponse>
    where
        T: Serialize + ?Sized,
    {
        let plaintext = serde_json::to_vec(payload).context("serialising secret payload")?;
        self.wrap_bytes_v2(&plaintext, params).await
    }

    pub fn preload_redeem_token(
        &self,
        handle: impl Into<String>,
        token: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.purge_expired(Utc::now());
        let handle_clean = handle.into().trim().to_string();
        let token_clean = token.into();
        self.remember_redeem_token(&handle_clean, token_clean, expires_at)
    }

    pub fn preload_redeem_shares(
        &self,
        handle: impl Into<String>,
        shares: Vec<ThresholdShareMaterial>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.purge_expired(Utc::now());
        let handle_clean = handle.into().trim().to_string();
        self.remember_redeem_shares(&handle_clean, shares, expires_at)
    }

    pub async fn mint_aead_key_v2(
        &self,
        params: MintAeadKeyV2Params,
    ) -> Result<MintAeadKeyV2Lease> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let lifecycle = params.lifecycle.unwrap_or_default().into_proto();
        let requested_principal = params
            .unwrap_principal_id
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let resolved_principal = if requested_principal.is_some()
            || matches!(
                lifecycle,
                GrpcSecretLifecycle::RenewableLease | GrpcSecretLifecycle::ServiceBootstrap
            ) {
            let channel = self.describe_channel().await?;
            self.resolve_v2_unwrap_principal(lifecycle, requested_principal, &channel)?
        } else {
            String::new()
        };
        let request = GrpcMintAeadKeyV2Request {
            ttl_seconds: params.ttl_seconds.unwrap_or_default(),
            label: params.label.unwrap_or_default(),
            tenant_id: params.tenant_id.unwrap_or_default(),
            provider: params.provider.unwrap_or_default(),
            threshold: params.threshold.unwrap_or(0) as u32,
            num_shares: params.num_shares.unwrap_or(0) as u32,
            lifecycle: lifecycle as i32,
            initial_lease_seconds: params.initial_lease_seconds.unwrap_or_default(),
            custodian_ids: params.custodian_ids.clone().unwrap_or_default(),
            unwrap_principal_id: resolved_principal,
        };

        let response = client
            .mint_aead_key_v2(request)
            .await
            .map_err(map_status)?
            .into_inner();

        let threshold = if response.threshold == 0 {
            1
        } else if response.threshold <= u8::MAX as u32 {
            response.threshold as u8
        } else {
            return Err(anyhow!("response threshold exceeds u8"));
        };
        let num_shares = if response.num_shares == 0 {
            threshold
        } else if response.num_shares <= u8::MAX as u32 {
            response.num_shares as u8
        } else {
            return Err(anyhow!("response num_shares exceeds u8"));
        };

        let expires_at = optional_timestamp(response.expires_at)?;
        let redeem_expires_at = optional_timestamp(response.redeem_token_expires_at)?;
        let redeem_shares = proto_shares_to_material(response.redeem_shares)?;
        let redeem_token = if response.redeem_token.is_empty() {
            None
        } else {
            Some(BASE64.encode(&response.redeem_token))
        };

        if threshold > 1 {
            if redeem_shares.is_empty() {
                return Err(anyhow!(
                    "mint_aead_key_v2 response missing threshold shares"
                ));
            }
            self.remember_redeem_shares(
                &response.handle,
                redeem_shares.clone(),
                redeem_expires_at,
            )?;
        } else {
            let token = redeem_token
                .clone()
                .ok_or_else(|| anyhow!("mint_aead_key_v2 response missing redeem token"))?;
            self.remember_redeem_token(&response.handle, token, redeem_expires_at)?;
        }

        Ok(MintAeadKeyV2Lease {
            key: response.key,
            handle: response.handle,
            redeem_token,
            redeem_shares,
            redeem_token_expires_at: redeem_expires_at,
            expires_at,
            threshold,
            num_shares,
        })
    }

    pub async fn unwrap_secret_v2(&self, params: UnwrapSecretV2Params) -> Result<Vec<u8>> {
        let now = Utc::now();
        self.purge_expired(now);

        if params.redeem_token.is_some() && !params.redeem_shares.is_empty() {
            return Err(anyhow!(
                "unwrap_secret_v2 requires either redeem_token or redeem_shares, not both"
            ));
        }

        let handle = params.handle.trim().to_string();
        let (redeem_token, redeem_shares) = if let Some(token) = params.redeem_token {
            let token_bytes = BASE64
                .decode(token.trim().as_bytes())
                .context("redeem token is not valid base64")?;
            (token_bytes, Vec::new())
        } else if !params.redeem_shares.is_empty() {
            (Vec::new(), material_to_proto_shares(&params.redeem_shares)?)
        } else {
            match self.take_redeem_material(&handle, now)? {
                RedeemCapability::Token { token, expires_at } => {
                    validate_expiry(expires_at)?;
                    let token_bytes = BASE64
                        .decode(token.as_bytes())
                        .context("cached redeem token is not valid base64")?;
                    (token_bytes, Vec::new())
                }
                RedeemCapability::Shares { shares, expires_at } => {
                    validate_expiry(expires_at)?;
                    (Vec::new(), material_to_proto_shares(&shares)?)
                }
            }
        };

        let request = GrpcUnwrapSecretV2Request {
            handle,
            redeem_token,
            redeem_shares,
            tenant_id: params.tenant_id.unwrap_or_default(),
            provider: params.provider.unwrap_or_default(),
            circuit_id: params.circuit_id.unwrap_or_default(),
            node_id: params.node_id.unwrap_or_default(),
            discharges: params
                .discharges
                .into_iter()
                .map(|token| GrpcDischargeToken { token })
                .collect(),
        };

        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let response = client
            .unwrap_secret_v2(request)
            .await
            .map_err(map_status)?
            .into_inner();

        Ok(response.plaintext)
    }

    pub async fn attenuate_handle_v2(
        &self,
        params: AttenuateHandleV2Params,
    ) -> Result<AttenuateHandleV2Result> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let requested_third_party_caveat = params.third_party.is_some();
        let request = GrpcAttenuateHandleV2Request {
            handle: params.handle.trim().to_string(),
            tenant_id: params.tenant_id.unwrap_or_default(),
            provider: params.provider.unwrap_or_default(),
            circuit_id: params.circuit_id.unwrap_or_default(),
            node_id: params.node_id.unwrap_or_default(),
            action: params.action.unwrap_or_default(),
            max_uses: params.max_uses.unwrap_or_default(),
            third_party: params.third_party.map(|caveat| GrpcThirdPartyCaveat {
                location: caveat.location,
                condition: caveat.condition,
            }),
        };

        let response = client
            .attenuate_handle_v2(request)
            .await
            .map_err(map_status)?
            .into_inner();

        let handle = response.handle.trim().to_string();
        if handle.is_empty() {
            return Err(anyhow!("attenuate_handle_v2 response missing handle"));
        }
        let third_party_caveat_id = empty_to_none(response.third_party_caveat_id);
        if requested_third_party_caveat && third_party_caveat_id.is_none() {
            return Err(anyhow!(
                "attenuate_handle_v2 response missing third-party caveat ID"
            ));
        }
        Ok(AttenuateHandleV2Result {
            handle,
            third_party_caveat_id,
        })
    }

    pub async fn mint_discharge(&self, params: MintDischargeParams) -> Result<String> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let primary_handle = params.primary_handle.trim().to_string();
        if primary_handle.is_empty() {
            return Err(anyhow!("mint_discharge requires primary_handle"));
        }
        let location = params.location.trim().to_string();
        if location.is_empty() {
            return Err(anyhow!("mint_discharge requires location"));
        }
        let caveat_id = params.caveat_id.trim().to_string();
        if caveat_id.is_empty() {
            return Err(anyhow!("mint_discharge requires opaque caveat_id"));
        }
        let channel = self.describe_channel().await?;
        self.require_authenticated_channel_principal("MintDischarge", &channel, true)?;
        let request = GrpcMintDischargeRequest {
            location,
            primary_handle,
            caveat_id,
        };

        let response = client
            .mint_discharge(request)
            .await
            .map_err(map_status)?
            .into_inner();

        let discharge_token = response.discharge_token.trim().to_string();
        if discharge_token.is_empty() {
            return Err(anyhow!("mint_discharge response missing discharge_token"));
        }
        Ok(discharge_token)
    }

    pub async fn issue_postgres_credentials(
        &self,
        params: PostgresCredentialParams,
    ) -> Result<PostgresCredentialLease> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = IssuePostgresCredentialsRequest {
            audience: params.audience.trim().to_string(),
            scope: params.scope,
            ttl_seconds: params.ttl_seconds.unwrap_or_default(),
            application_name: params.application_name.unwrap_or_default(),
        };

        let response = client
            .issue_postgres_credentials(request)
            .await
            .map_err(map_status)?
            .into_inner();

        Ok(PostgresCredentialLease {
            database_url: response.database_url,
            username: empty_to_none(response.username),
            password: empty_to_none(response.password),
            ca_certificate_pem: empty_to_none(response.ca_certificate_pem),
            server_cert_fingerprint: empty_to_none(response.server_cert_fingerprint),
            expires_at: optional_timestamp(response.expires_at)?,
        })
    }

    pub async fn crypto_encrypt(&self, params: CryptoEncryptParams) -> Result<CryptoEncryptResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcCryptoEncryptRequest {
            key_id: params.key_id.unwrap_or_default(),
            plaintext: params.plaintext,
            algorithm: params.algorithm.unwrap_or_default(),
            customer_id: params.customer_id.unwrap_or_default(),
        };
        let response = client
            .crypto_encrypt(request)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(CryptoEncryptResult {
            ciphertext: response.ciphertext,
            key_id: response.key_id,
            nonce: response.nonce,
        })
    }

    pub async fn crypto_decrypt(&self, params: CryptoDecryptParams) -> Result<CryptoDecryptResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcCryptoDecryptRequest {
            key_id: params.key_id,
            ciphertext: params.ciphertext,
            algorithm: params.algorithm.unwrap_or_default(),
            customer_id: params.customer_id.unwrap_or_default(),
        };
        let response = client
            .crypto_decrypt(request)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(CryptoDecryptResult {
            plaintext: response.plaintext,
            verified: response.verified,
        })
    }

    pub async fn crypto_sign(&self, params: CryptoSignParams) -> Result<Vec<u8>> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcCryptoSignRequest {
            key_id: params.key_id,
            data: params.data,
        };
        let response = client
            .crypto_sign(request)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(response.signature)
    }

    pub async fn crypto_verify(&self, params: CryptoVerifyParams) -> Result<bool> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcCryptoVerifyRequest {
            key_id: params.key_id,
            data: params.data,
            signature: params.signature,
        };
        let response = client
            .crypto_verify(request)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(response.valid)
    }

    pub async fn crypto_keygen(&self, params: CryptoKeygenParams) -> Result<CryptoKeyPairResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcCryptoKeygenRequest {
            algorithm: params.algorithm,
            customer_id: params.customer_id.unwrap_or_default(),
        };
        let response = client
            .crypto_keygen(request)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(CryptoKeyPairResult {
            key_id: response.key_id,
            public_key: response.public_key,
            algorithm: response.algorithm,
        })
    }

    pub async fn crypto_random(&self, length: u32) -> Result<Vec<u8>> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let response = client
            .crypto_random(GrpcCryptoRandomRequest { length })
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(response.random)
    }

    pub async fn crypto_pubkey(&self, key_id: &str) -> Result<Vec<u8>> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let response = client
            .crypto_pubkey(GrpcCryptoPubkeyRequest {
                key_id: key_id.trim().to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(response.public_key)
    }

    pub async fn delete_secret(&self, handle: &str) -> Result<()> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = DeleteSecretRequest {
            handle: handle.to_string(),
        };

        client.delete_secret(request).await.map_err(map_status)?;
        self.redeem_cache.remove(handle);
        Ok(())
    }

    /// Renew the lease on a RenewableLease secret.
    pub async fn renew_lease(
        &self,
        handle: &str,
        lease_duration_seconds: u64,
    ) -> Result<RenewLeaseResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcRenewLeaseRequest {
            handle: handle.trim().to_string(),
            lease_duration_seconds,
        };
        let response = client
            .renew_lease(request)
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(RenewLeaseResult {
            lease_expires_at: optional_timestamp(response.lease_expires_at)?,
            renewal_count: response.renewal_count,
        })
    }

    /// Explicitly revoke a secret, making it permanently inaccessible.
    pub async fn revoke_secret(&self, handle: &str, reason: Option<&str>) -> Result<RevokeResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcRevokeSecretRequest {
            handle: handle.trim().to_string(),
            reason: reason.unwrap_or("").to_string(),
        };
        let response = client
            .revoke_secret(request)
            .await
            .map_err(map_status)?
            .into_inner();
        self.redeem_cache.remove(handle.trim());
        Ok(RevokeResult {
            revoked: response.revoked,
            revoked_at: optional_timestamp(response.revoked_at)?,
        })
    }

    /// Atomically wrap a new secret and revoke an old one (key rotation).
    pub async fn rotate_secret(
        &self,
        old_handle: &str,
        new_plaintext: &[u8],
        params: RotateParams,
    ) -> Result<RotateResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let metadata_struct = option_json_to_struct(params.metadata)?;
        let request = GrpcRotateSecretRequest {
            old_handle: old_handle.trim().to_string(),
            new_plaintext: new_plaintext.to_vec(),
            customer_id: params.customer_id.unwrap_or_default(),
            metadata: metadata_struct,
            ttl_seconds: params.ttl_seconds.unwrap_or(0),
            lifecycle: params
                .lifecycle
                .map(SecretLifecycle::into_proto)
                .map(|lifecycle| lifecycle as i32)
                .unwrap_or_default(),
            rotation_reason: params.rotation_reason.unwrap_or_default(),
            threshold: params.threshold.unwrap_or(0) as u32,
            num_shares: params.num_shares.unwrap_or(0) as u32,
        };
        let response = client
            .rotate_secret(request)
            .await
            .map_err(map_status)?
            .into_inner();
        let new_handle = response.new_handle.trim().to_string();
        let redeem_token = String::from_utf8(response.redeem_token).unwrap_or_default();
        let redeem_token_expires_at = optional_timestamp(response.redeem_token_expires_at)?;
        if !redeem_token.is_empty() {
            let _ = self.remember_redeem_token(
                &new_handle,
                redeem_token.clone(),
                redeem_token_expires_at,
            );
        }
        self.redeem_cache.remove(old_handle.trim());
        let new_shares = if response.new_shares.is_empty() {
            Vec::new()
        } else {
            proto_shares_to_material(response.new_shares)?
        };
        Ok(RotateResult {
            new_handle,
            created_at: optional_timestamp(response.created_at)?,
            expires_at: optional_timestamp(response.expires_at)?,
            redeem_token,
            redeem_token_expires_at,
            old_revoked: response.old_revoked,
            new_shares,
        })
    }

    /// Claim an assigned threshold share as an authenticated custodian.
    pub async fn claim_share(&self, handle: &str, custodian_id: &str) -> Result<ClaimShareResult> {
        let mut client = SecretBrokerServiceClient::new(self.channel.clone());
        let request = GrpcClaimShareRequest {
            handle: handle.trim().to_string(),
            custodian_id: custodian_id.trim().to_string(),
        };
        let response = client
            .claim_share(request)
            .await
            .map_err(map_status)?
            .into_inner();
        let share = response
            .share
            .ok_or_else(|| anyhow!("ClaimShare response missing share"))?;
        if share.x == 0 || share.x > u8::MAX as u32 {
            return Err(anyhow!("claimed share x must be in 1..=255"));
        }
        Ok(ClaimShareResult {
            share: ThresholdShareMaterial {
                x: share.x as u8,
                y: share.y,
            },
            commitments: response.commitments,
            previously_claimed: response.previously_claimed,
        })
    }

    fn purge_expired(&self, _now: DateTime<Utc>) {
        self.redeem_cache.retain(|_, entry| !entry.is_expired());
    }

    fn remember_redeem_token(
        &self,
        handle: &str,
        token: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let trimmed = token.trim();
        BASE64
            .decode(trimmed.as_bytes())
            .with_context(|| format!("invalid redeem token received for handle {handle}"))?;

        self.redeem_cache.insert(
            handle.trim().to_string(),
            RedeemCacheEntry {
                material: RedeemMaterial::Token(Zeroizing::new(trimmed.to_string())),
                expires_at,
            },
        );
        Ok(())
    }

    fn remember_redeem_shares(
        &self,
        handle: &str,
        shares: Vec<ThresholdShareMaterial>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        validate_threshold_shares(&shares)?;
        self.redeem_cache.insert(
            handle.trim().to_string(),
            RedeemCacheEntry {
                material: RedeemMaterial::Shares(shares),
                expires_at,
            },
        );
        Ok(())
    }

    fn take_redeem_material(&self, handle: &str, now: DateTime<Utc>) -> Result<RedeemCapability> {
        match self.redeem_cache.remove(handle) {
            Some((_, entry)) => {
                let expires_at = entry.expires_at;
                if let Some(expiry) = expires_at.as_ref() {
                    if now > *expiry {
                        return Err(anyhow!(
                            "redeem token for handle {handle} expired at {expiry}"
                        ));
                    }
                }
                Ok(match entry.material {
                    RedeemMaterial::Token(token) => RedeemCapability::Token {
                        token: (*token).clone(),
                        expires_at,
                    },
                    RedeemMaterial::Shares(shares) => {
                        RedeemCapability::Shares { shares, expires_at }
                    }
                })
            }
            None => Err(anyhow!("redeem material for handle {handle} not loaded")),
        }
    }
}

#[derive(Debug, Clone)]
struct RedeemCacheEntry {
    material: RedeemMaterial,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
enum RedeemMaterial {
    Token(Zeroizing<String>),
    Shares(Vec<ThresholdShareMaterial>),
}

impl RedeemCacheEntry {
    /// Check if this cache entry has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => Utc::now() > expiry,
            None => false, // No expiry means never expires
        }
    }
}

enum RedeemCapability {
    Token {
        token: String,
        expires_at: Option<DateTime<Utc>>,
    },
    Shares {
        shares: Vec<ThresholdShareMaterial>,
        expires_at: Option<DateTime<Utc>>,
    },
}

fn validate_threshold_shares(shares: &[ThresholdShareMaterial]) -> Result<()> {
    if shares.is_empty() {
        return Err(anyhow!("threshold shares cannot be empty"));
    }
    for share in shares {
        if share.x == 0 {
            return Err(anyhow!("threshold share x must be in 1..=255"));
        }
        if share.y.len() != SHARE_Y_LEN {
            return Err(anyhow!("threshold share y must be exactly 32 bytes"));
        }
    }
    Ok(())
}

fn proto_shares_to_material(
    shares: Vec<GrpcThresholdShare>,
) -> Result<Vec<ThresholdShareMaterial>> {
    if shares.is_empty() {
        return Ok(Vec::new());
    }
    let materials = shares
        .into_iter()
        .map(|share| {
            if share.x == 0 || share.x > u8::MAX as u32 {
                return Err(anyhow!("threshold share x must be in 1..=255"));
            }
            Ok(ThresholdShareMaterial {
                x: share.x as u8,
                y: share.y,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_threshold_shares(&materials)?;
    Ok(materials)
}

fn material_to_proto_shares(shares: &[ThresholdShareMaterial]) -> Result<Vec<GrpcThresholdShare>> {
    validate_threshold_shares(shares)?;
    Ok(shares
        .iter()
        .map(|share| GrpcThresholdShare {
            x: share.x as u32,
            y: share.y.clone(),
        })
        .collect())
}

fn validate_expiry(expires_at: Option<DateTime<Utc>>) -> Result<()> {
    if let Some(expiry) = expires_at {
        if Utc::now() > expiry {
            return Err(anyhow!("redeem material expired at {expiry}"));
        }
    }
    Ok(())
}

fn option_json_to_struct(value: Option<Value>) -> Result<Option<Struct>> {
    match value {
        None => Ok(None),
        Some(Value::Object(map)) => json_map_to_struct(map).map(Some),
        Some(other) => Err(anyhow!(
            "metadata JSON must be an object, received {other:?}"
        )),
    }
}

fn json_map_to_struct(map: JsonMap<String, Value>) -> Result<Struct> {
    let mut struct_fields = BTreeMap::new();
    for (key, value) in map {
        struct_fields.insert(key, serde_value_to_prost(&value)?);
    }
    Ok(Struct {
        fields: struct_fields,
    })
}

fn serde_value_to_prost(value: &Value) -> Result<ProstValue> {
    let kind = match value {
        Value::Null => ProstKind::NullValue(0),
        Value::Bool(b) => ProstKind::BoolValue(*b),
        Value::Number(num) => {
            let float = num
                .as_f64()
                .ok_or_else(|| anyhow!("metadata number cannot be represented as f64"))?;
            ProstKind::NumberValue(float)
        }
        Value::String(s) => ProstKind::StringValue(s.clone()),
        Value::Array(values) => {
            let mut converted = Vec::with_capacity(values.len());
            for value in values {
                converted.push(serde_value_to_prost(value)?);
            }
            ProstKind::ListValue(ListValue { values: converted })
        }
        Value::Object(map) => {
            let mut struct_fields = BTreeMap::new();
            for (key, value) in map.iter() {
                struct_fields.insert(key.clone(), serde_value_to_prost(value)?);
            }
            ProstKind::StructValue(Struct {
                fields: struct_fields,
            })
        }
    };

    Ok(ProstValue { kind: Some(kind) })
}

fn optional_timestamp(ts: Option<Timestamp>) -> Result<Option<DateTime<Utc>>> {
    ts.map(|ts| timestamp_to_datetime(&ts)).transpose()
}

fn required_timestamp(ts: Option<Timestamp>, field: &str) -> Result<DateTime<Utc>> {
    let ts = ts.ok_or_else(|| anyhow!("response missing required field {field}"))?;
    timestamp_to_datetime(&ts)
}

fn timestamp_to_datetime(ts: &Timestamp) -> Result<DateTime<Utc>> {
    let nanos = ts.nanos;
    if nanos < 0 {
        return Err(anyhow!("timestamp nanos cannot be negative"));
    }

    Utc.timestamp_opt(ts.seconds, nanos as u32)
        .single()
        .ok_or_else(|| anyhow!("invalid timestamp (out of range)"))
}

fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn map_status(status: Status) -> anyhow::Error {
    anyhow!(status.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        broker_proto::DescribeChannelResponse, broker_proto::SecretLifecycle,
        AttenuateHandleV2Params, GrpcThresholdShare, MintDischargeParams, SecretBrokerGrpcAdapter,
        SecretBrokerGrpcAdapterConfig, ThirdPartyCaveatParams, ThresholdShareMaterial,
        UnwrapSecretV2Params, SHARE_Y_LEN,
    };
    use dashmap::DashMap;
    use std::sync::Arc;
    use tonic::transport::Channel;
    use url::Url;

    fn test_adapter(client_principal_id: Option<&str>) -> SecretBrokerGrpcAdapter {
        let endpoint: Url = "https://broker.example.test:50052".parse().expect("url");
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let config = SecretBrokerGrpcAdapterConfig::new(endpoint, channel)
            .client_principal_id(client_principal_id.map(str::to_string));
        SecretBrokerGrpcAdapter {
            channel: config.channel,
            endpoint: config.endpoint,
            client_principal_id: config.client_principal_id,
            redeem_cache: Arc::new(DashMap::new()),
        }
    }

    fn valid_share(x: u8) -> ThresholdShareMaterial {
        ThresholdShareMaterial {
            x,
            y: vec![0xAB; SHARE_Y_LEN],
        }
    }

    #[tokio::test]
    async fn resolve_v2_unwrap_principal_allows_cross_principal_bootstrap_target() {
        let adapter = test_adapter(Some("spiffe://secretbroker.local/workload/client-a"));
        let channel = DescribeChannelResponse {
            authenticated_transport: true,
            principal_id: "spiffe://secretbroker.local/workload/client-a".into(),
            peer_cert_sha256: vec![0x01, 0x02, 0x03],
            ..Default::default()
        };

        let resolved = adapter
            .resolve_v2_unwrap_principal(
                SecretLifecycle::ServiceBootstrap,
                Some("spiffe://secretbroker.local/workload/tenant-a".into()),
                &channel,
            )
            .expect("cross-principal bootstrap target should be accepted");

        assert_eq!(resolved, "spiffe://secretbroker.local/workload/tenant-a");
    }

    #[tokio::test]
    async fn resolve_v2_unwrap_principal_rejects_client_broker_principal_mismatch() {
        let adapter = test_adapter(Some("spiffe://secretbroker.local/workload/client-a"));
        let channel = DescribeChannelResponse {
            authenticated_transport: true,
            principal_id: "spiffe://secretbroker.local/core/other".into(),
            peer_cert_sha256: vec![0x04, 0x05, 0x06],
            ..Default::default()
        };

        let err = adapter
            .resolve_v2_unwrap_principal(SecretLifecycle::RenewableLease, None, &channel)
            .expect_err("principal mismatch should fail");

        assert!(
            err.to_string()
                .contains("broker channel principal mismatch: client=spiffe://secretbroker.local/workload/client-a broker=spiffe://secretbroker.local/core/other")
        );
    }

    #[tokio::test]
    async fn resolve_v2_unwrap_principal_requires_authenticated_transport_for_lease() {
        let adapter = test_adapter(None);
        let channel = DescribeChannelResponse {
            authenticated_transport: false,
            principal_id: "spiffe://secretbroker.local/workload/client-a".into(),
            ..Default::default()
        };

        let err = adapter
            .resolve_v2_unwrap_principal(SecretLifecycle::RenewableLease, None, &channel)
            .expect_err("unauthenticated transport should fail");

        assert!(err
            .to_string()
            .contains("broker DescribeChannel reports unauthenticated transport"));
    }

    #[tokio::test]
    async fn resolve_v2_unwrap_principal_requires_peer_cert_for_lease() {
        let adapter = test_adapter(None);
        let channel = DescribeChannelResponse {
            authenticated_transport: true,
            principal_id: "spiffe://secretbroker.local/workload/client-a".into(),
            ..Default::default()
        };

        let err = adapter
            .resolve_v2_unwrap_principal(SecretLifecycle::RenewableLease, None, &channel)
            .expect_err("lease channel without peer certificate lineage should fail");

        assert!(err
            .to_string()
            .contains("broker DescribeChannel reports no peer certificate lineage"));
    }

    #[test]
    fn unwrap_secret_v2_params_accept_discharges() {
        let params = UnwrapSecretV2Params {
            handle: "broker:v2:test".into(),
            discharges: vec!["d1".into(), "d2".into()],
            ..Default::default()
        };

        assert_eq!(params.discharges, vec!["d1", "d2"]);
    }

    #[test]
    fn attenuate_handle_v2_params_accept_third_party_caveat() {
        let params = AttenuateHandleV2Params {
            handle: "broker:v2:test".into(),
            third_party: Some(ThirdPartyCaveatParams {
                location: "https://discharge.example".into(),
                condition: "tenant = alpha".into(),
            }),
            ..Default::default()
        };

        let caveat = params
            .third_party
            .expect("third-party caveat should be present");
        assert_eq!(caveat.location, "https://discharge.example");
        assert_eq!(caveat.condition, "tenant = alpha");
    }

    #[tokio::test]
    async fn unwrap_secret_v2_rejects_token_and_shares_together() {
        let adapter = test_adapter(None);
        let err = adapter
            .unwrap_secret_v2(UnwrapSecretV2Params {
                handle: "broker:v2:test".into(),
                redeem_token: Some("AQID".into()),
                redeem_shares: vec![valid_share(1)],
                ..Default::default()
            })
            .await
            .expect_err("conflicting redeem inputs should fail before any RPC");

        assert!(err
            .to_string()
            .contains("unwrap_secret_v2 requires either redeem_token or redeem_shares, not both"));
    }

    #[tokio::test]
    async fn mint_discharge_rejects_missing_required_fields_before_channel_lookup() {
        let adapter = test_adapter(None);
        let cases = [
            (
                MintDischargeParams {
                    primary_handle: String::new(),
                    location: "https://discharge.example".into(),
                    caveat_id: "opaque-caveat".into(),
                },
                "mint_discharge requires primary_handle",
            ),
            (
                MintDischargeParams {
                    primary_handle: "broker:v2:test".into(),
                    location: String::new(),
                    caveat_id: "opaque-caveat".into(),
                },
                "mint_discharge requires location",
            ),
            (
                MintDischargeParams {
                    primary_handle: "broker:v2:test".into(),
                    location: "https://discharge.example".into(),
                    caveat_id: "   ".into(),
                },
                "mint_discharge requires opaque caveat_id",
            ),
        ];

        for (params, expected) in cases {
            let err = adapter
                .mint_discharge(params)
                .await
                .expect_err("missing required discharge inputs should fail closed");
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?}, got {err}"
            );
        }
    }

    #[test]
    fn validate_threshold_shares_and_material_to_proto_fail_closed_on_invalid_material() {
        let invalid_cases = [
            (
                "x zero",
                vec![ThresholdShareMaterial {
                    x: 0,
                    y: vec![0x11; SHARE_Y_LEN],
                }],
                "threshold share x must be in 1..=255",
            ),
            (
                "wrong y length",
                vec![ThresholdShareMaterial {
                    x: 1,
                    y: vec![0x22; SHARE_Y_LEN - 1],
                }],
                "threshold share y must be exactly 32 bytes",
            ),
        ];

        for (label, shares, expected) in invalid_cases {
            let err = super::validate_threshold_shares(&shares)
                .expect_err("invalid threshold material should fail closed");
            assert!(
                err.to_string().contains(expected),
                "{label}: expected {expected:?}, got {err}"
            );

            let err = super::material_to_proto_shares(&shares)
                .expect_err("invalid threshold material should not convert to proto");
            assert!(
                err.to_string().contains(expected),
                "{label}: expected {expected:?}, got {err}"
            );
        }
    }

    #[test]
    fn proto_shares_to_material_fails_closed_on_invalid_proto_share_shapes() {
        let invalid_cases = [
            (
                "x zero",
                vec![GrpcThresholdShare {
                    x: 0,
                    y: vec![0x33; SHARE_Y_LEN],
                }],
                "threshold share x must be in 1..=255",
            ),
            (
                "x too large",
                vec![GrpcThresholdShare {
                    x: 256,
                    y: vec![0x44; SHARE_Y_LEN],
                }],
                "threshold share x must be in 1..=255",
            ),
            (
                "wrong y length",
                vec![GrpcThresholdShare {
                    x: 1,
                    y: vec![0x55; SHARE_Y_LEN - 1],
                }],
                "threshold share y must be exactly 32 bytes",
            ),
        ];

        for (label, shares, expected) in invalid_cases {
            let err = super::proto_shares_to_material(shares)
                .expect_err("invalid proto threshold shares should fail closed");
            assert!(
                err.to_string().contains(expected),
                "{label}: expected {expected:?}, got {err}"
            );
        }
    }
}
