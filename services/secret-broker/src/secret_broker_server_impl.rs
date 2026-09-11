//! SecretBrokerService implementation for the standalone authenticated runtime.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use tonic::{Request, Response, Status};

use crate::secret_broker_impl::crypto_engine::service::EncryptionAlgorithm;
use crate::secret_broker_impl::{handlers, BrokerClientContext, SecretBrokerState};
use crate::secret_broker_proto::secret_broker_service_server::SecretBrokerService;
use crate::secret_broker_proto::*;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct SecretBrokerGrpc {
    state: Arc<SecretBrokerState>,
}

impl SecretBrokerGrpc {
    pub(crate) fn new(state: Arc<SecretBrokerState>) -> Self {
        Self { state }
    }

    fn request_context<T>(&self, request: &Request<T>) -> Option<BrokerClientContext> {
        request.extensions().get::<BrokerClientContext>().cloned()
    }

    fn broker_context<T>(&self, request: &Request<T>) -> Result<BrokerClientContext, Status> {
        self.request_context(request).ok_or_else(|| {
            Status::failed_precondition(
                "secret-broker requests require authenticated live mTLS connection context",
            )
        })
    }
}

fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn chrono_to_timestamp(dt: DateTime<Utc>) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

fn svc_err(e: impl std::fmt::Debug) -> Status {
    Status::internal(format!("{e:?}"))
}

fn svc_service_err(err: handlers::ServiceError) -> Status {
    match err {
        handlers::ServiceError::InvalidBase64(_)
        | handlers::ServiceError::Serialization(_)
        | handlers::ServiceError::InvalidHandle
        | handlers::ServiceError::InvalidTtl
        | handlers::ServiceError::InvalidAttenuation(_) => {
            Status::invalid_argument(err.to_string())
        }
        handlers::ServiceError::HandleNotFound => Status::not_found(err.to_string()),
        handlers::ServiceError::ExpiredHandle
        | handlers::ServiceError::RevokedHandle
        | handlers::ServiceError::MissingLineage(_) => Status::failed_precondition(err.to_string()),
        handlers::ServiceError::UnauthenticatedTransport
        | handlers::ServiceError::AuthenticatedPrincipalRequired => {
            Status::unauthenticated(err.to_string())
        }
        handlers::ServiceError::SignatureInvalid
        | handlers::ServiceError::ExporterBindingMismatch
        | handlers::ServiceError::RedeemTokenInvalid
        | handlers::ServiceError::RedeemTokenExpired
        | handlers::ServiceError::RedeemTokenUsed
        | handlers::ServiceError::PrincipalMismatch
        | handlers::ServiceError::PeerCertMismatch
        | handlers::ServiceError::AttestationMismatch
        | handlers::ServiceError::UnauthorizedDischargePrincipal => {
            Status::permission_denied(err.to_string())
        }
        handlers::ServiceError::Unavailable(message) => Status::unavailable(message),
        handlers::ServiceError::Storage(_)
        | handlers::ServiceError::Crypto(_)
        | handlers::ServiceError::Database(_) => Status::internal(err.to_string()),
    }
}

fn parse_crypto_algorithm(value: &str) -> Result<EncryptionAlgorithm, Status> {
    match value.trim() {
        "" | "aes-256-gcm" => Ok(EncryptionAlgorithm::Aes256Gcm),
        "chacha20-poly1305" => Ok(EncryptionAlgorithm::ChaCha20Poly1305),
        "xchacha20-poly1305" => Ok(EncryptionAlgorithm::XChaCha20Poly1305),
        "kyber768" => Ok(EncryptionAlgorithm::Kyber768),
        other => Err(Status::invalid_argument(format!(
            "unsupported algorithm: {other}"
        ))),
    }
}

fn default_customer_id(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "default"
    } else {
        trimmed
    }
}

#[tonic::async_trait]
impl SecretBrokerService for SecretBrokerGrpc {
    async fn wrap_secret_v2(
        &self,
        request: Request<WrapSecretV2Request>,
    ) -> Result<Response<WrapSecretResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let now = Utc::now();
        let metadata = req.metadata.map(prost_struct_to_json);
        let lifecycle =
            crate::secret_broker_impl::sealed_store::SecretLifecycle::from_proto_i32(req.lifecycle);
        let initial_lease = if req.initial_lease_seconds > 0 {
            Some(req.initial_lease_seconds)
        } else {
            None
        };
        let ttl_seconds = if req.ttl_seconds > 0 {
            Some(req.ttl_seconds)
        } else {
            None
        };
        let outcome = handlers::wrap_secret_v2_impl(
            &self.state.broker,
            &context,
            handlers::WrapV2Request {
                plaintext: req.plaintext,
                customer_id: empty_to_none(req.customer_id),
                metadata,
                lifecycle,
                ttl_seconds,
                initial_lease_seconds: initial_lease,
                label: empty_to_none(req.label),
                tenant_id: empty_to_none(req.tenant_id),
                provider: empty_to_none(req.provider),
                circuit_id: empty_to_none(req.circuit_id),
                node_id: empty_to_none(req.node_id),
                unwrap_principal_id: empty_to_none(req.unwrap_principal_id),
            },
        )
        .await
        .map_err(svc_service_err)?;
        let redeem_token = BASE64
            .decode(outcome.redeem_token.as_bytes())
            .map_err(|e| Status::internal(format!("redeem token base64 decode: {e}")))?;

        Ok(Response::new(WrapSecretResponse {
            handle: outcome.handle,
            created_at: chrono_to_timestamp(now),
            expires_at: outcome.expires_at.and_then(chrono_to_timestamp),
            redeem_token,
            redeem_token_expires_at: outcome
                .redeem_token_expires_at
                .and_then(chrono_to_timestamp),
        }))
    }

    async fn delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<()>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        handlers::delete_secret_impl(&self.state.broker, &context, &req.handle)
            .await
            .map_err(svc_err)?;
        Ok(Response::new(()))
    }

    async fn mint_aead_key_v2(
        &self,
        request: Request<MintAeadKeyV2Request>,
    ) -> Result<Response<MintAeadKeyV2Response>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let threshold = match req.threshold {
            0 => None,
            value if value <= u8::MAX as u32 => Some(value as u8),
            _ => return Err(Status::invalid_argument("threshold must be <= 255")),
        };
        let num_shares = match req.num_shares {
            0 => None,
            value if value <= u8::MAX as u32 => Some(value as u8),
            _ => return Err(Status::invalid_argument("num_shares must be <= 255")),
        };

        let handler_req = handlers::MintV2Request {
            ttl_seconds: if req.ttl_seconds > 0 {
                Some(req.ttl_seconds)
            } else {
                None
            },
            label: empty_to_none(req.label),
            tenant_id: empty_to_none(req.tenant_id),
            provider: empty_to_none(req.provider),
            threshold,
            num_shares,
            lifecycle: crate::secret_broker_impl::sealed_store::SecretLifecycle::from_proto_i32(
                req.lifecycle,
            ),
            initial_lease_seconds: if req.initial_lease_seconds > 0 {
                Some(req.initial_lease_seconds)
            } else {
                None
            },
            custodian_ids: req.custodian_ids,
            unwrap_principal_id: empty_to_none(req.unwrap_principal_id),
        };

        let effective_threshold = handler_req.threshold.unwrap_or(1) as u32;
        let effective_num_shares = handler_req.num_shares.unwrap_or(1) as u32;

        let result = handlers::mint_aead_key_v2_impl(&self.state.broker, &context, handler_req)
            .await
            .map_err(svc_service_err)?;

        let key_bytes = BASE64
            .decode(result.key.as_bytes())
            .map_err(|e| Status::internal(format!("key base64 decode: {e}")))?;

        let (redeem_token, redeem_shares) = if effective_threshold > 1 {
            // Custodian mode: shares are held by broker (ClaimShare RPC),
            // redeem_token is empty. Non-custodian mode: shares are inline JSON.
            if result.redeem_token.is_empty() {
                // Custodian mode - shares stored in broker, claimed via ClaimShare
                (Vec::new(), Vec::new())
            } else {
                let shares: Vec<crate::secret_broker_impl::threshold::Share> =
                    serde_json::from_str(&result.redeem_token)
                        .map_err(|e| Status::internal(format!("share decode: {e}")))?;
                let proto_shares = shares
                    .into_iter()
                    .map(|share| ThresholdShare {
                        x: share.x as u32,
                        y: share.y.clone(),
                    })
                    .collect();
                (Vec::new(), proto_shares)
            }
        } else {
            let token = BASE64
                .decode(result.redeem_token.as_bytes())
                .map_err(|e| Status::internal(format!("redeem token base64 decode: {e}")))?;
            (token, Vec::new())
        };

        Ok(Response::new(MintAeadKeyV2Response {
            key: key_bytes,
            handle: result.handle,
            expires_at: result.expires_at.and_then(chrono_to_timestamp),
            redeem_token,
            redeem_shares,
            redeem_token_expires_at: result.redeem_token_expires_at.and_then(chrono_to_timestamp),
            threshold: effective_threshold,
            num_shares: effective_num_shares,
        }))
    }

    async fn unwrap_secret_v2(
        &self,
        request: Request<UnwrapSecretV2Request>,
    ) -> Result<Response<UnwrapSecretResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();

        let redeem_token = if !req.redeem_shares.is_empty() {
            let shares = req
                .redeem_shares
                .into_iter()
                .map(|share| {
                    if share.x == 0 || share.x > u8::MAX as u32 {
                        return Err(Status::invalid_argument("share x must be in 1..=255"));
                    }
                    if share.y.len() != crate::secret_broker_impl::threshold::SHARE_LENGTH {
                        return Err(Status::invalid_argument("share y must be exactly 32 bytes"));
                    }
                    Ok(crate::secret_broker_impl::threshold::Share {
                        x: share.x as u8,
                        y: share.y,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            serde_json::to_string(&shares)
                .map_err(|e| Status::internal(format!("share encode: {e}")))?
        } else if !req.redeem_token.is_empty() {
            BASE64.encode(&req.redeem_token)
        } else {
            return Err(Status::invalid_argument(
                "either redeem_token or redeem_shares must be provided",
            ));
        };

        let discharges = req
            .discharges
            .into_iter()
            .filter_map(|d| {
                crate::secret_broker_impl::macaroon_caveats::DischargeMacaroon::deserialize(
                    &d.token,
                )
                .ok()
            })
            .collect();
        let unwrap_req = handlers::UnwrapV2Request {
            handle: req.handle,
            redeem_token,
            tenant_id: empty_to_none(req.tenant_id),
            provider: empty_to_none(req.provider),
            circuit_id: empty_to_none(req.circuit_id),
            node_id: empty_to_none(req.node_id),
            discharges,
        };

        let resp = handlers::unwrap_secret_v2_impl(&self.state.broker, &context, unwrap_req)
            .await
            .map_err(svc_service_err)?;

        let plaintext_bytes = BASE64
            .decode(resp.plaintext.as_bytes())
            .map_err(|e| Status::internal(format!("base64 decode: {e}")))?;

        Ok(Response::new(UnwrapSecretResponse {
            plaintext: plaintext_bytes,
        }))
    }

    async fn attenuate_handle_v2(
        &self,
        request: Request<AttenuateHandleV2Request>,
    ) -> Result<Response<AttenuateHandleV2Response>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let result = handlers::attenuate_handle_v2_impl(
            &self.state.broker,
            &context,
            handlers::AttenuateV2Request {
                handle: req.handle,
                tenant_id: empty_to_none(req.tenant_id),
                provider: empty_to_none(req.provider),
                circuit_id: empty_to_none(req.circuit_id),
                node_id: empty_to_none(req.node_id),
                action: empty_to_none(req.action),
                max_uses: if req.max_uses == 0 {
                    None
                } else {
                    Some(req.max_uses)
                },
                third_party: req.third_party.map(|tp| handlers::ThirdPartyCaveatRequest {
                    location: tp.location,
                    condition: tp.condition,
                }),
            },
        )
        .await
        .map_err(svc_err)?;

        Ok(Response::new(AttenuateHandleV2Response {
            handle: result.handle,
            third_party_caveat_id: result.third_party_caveat_id.unwrap_or_default(),
        }))
    }

    async fn issue_postgres_credentials(
        &self,
        request: Request<IssuePostgresCredentialsRequest>,
    ) -> Result<Response<IssuePostgresCredentialsResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let result = handlers::issue_postgres_credentials_impl(
            &self.state.broker,
            &context,
            handlers::PostgresCredentialParams {
                audience: req.audience,
                scope: req.scope,
                ttl_seconds: if req.ttl_seconds == 0 {
                    None
                } else {
                    Some(req.ttl_seconds)
                },
                application_name: empty_to_none(req.application_name),
            },
        )
        .await
        .map_err(svc_service_err)?;

        Ok(Response::new(IssuePostgresCredentialsResponse {
            database_url: result.database_url,
            username: result.username,
            password: result.password,
            expires_at: result.expires_at.and_then(chrono_to_timestamp),
            ca_certificate_pem: result.ca_certificate_pem.unwrap_or_default(),
            server_cert_fingerprint: result.server_cert_fingerprint.unwrap_or_default(),
        }))
    }

    async fn crypto_encrypt(
        &self,
        request: Request<CryptoEncryptRequest>,
    ) -> Result<Response<CryptoEncryptResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let key_id = empty_to_none(req.key_id);
        let result = self
            .state
            .broker
            .crypto()
            .encrypt_data_with_key(
                &req.plaintext,
                parse_crypto_algorithm(&req.algorithm)?,
                key_id.as_deref(),
                default_customer_id(&req.customer_id),
            )
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoEncryptResponse {
            ciphertext: result.ciphertext.clone(),
            key_id: result.key_id.clone().unwrap_or_default(),
            nonce: result.nonce.clone(),
        }))
    }

    async fn crypto_decrypt(
        &self,
        request: Request<CryptoDecryptRequest>,
    ) -> Result<Response<CryptoDecryptResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let key_id = req.key_id.trim();
        if key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        let result = self
            .state
            .broker
            .crypto()
            .decrypt_data(
                &req.ciphertext,
                parse_crypto_algorithm(&req.algorithm)?,
                key_id,
                default_customer_id(&req.customer_id),
            )
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoDecryptResponse {
            plaintext: result.plaintext.clone(),
            verified: result.verified,
        }))
    }

    async fn crypto_sign(
        &self,
        request: Request<CryptoSignRequest>,
    ) -> Result<Response<CryptoSignResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let key_id = req.key_id.trim();
        if key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        let signature = self
            .state
            .broker
            .crypto()
            .sign_data(&req.data, key_id)
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoSignResponse { signature }))
    }

    async fn crypto_verify(
        &self,
        request: Request<CryptoVerifyRequest>,
    ) -> Result<Response<CryptoVerifyResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let key_id = req.key_id.trim();
        if key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        let valid = self
            .state
            .broker
            .crypto()
            .verify_signature(&req.data, &req.signature, key_id)
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoVerifyResponse { valid }))
    }

    async fn crypto_keygen(
        &self,
        request: Request<CryptoKeygenRequest>,
    ) -> Result<Response<CryptoKeygenResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let algorithm = req.algorithm.trim();
        if algorithm.is_empty() {
            return Err(Status::invalid_argument("algorithm is required"));
        }
        let keypair = self
            .state
            .broker
            .crypto()
            .generate_key_pair(algorithm, default_customer_id(&req.customer_id))
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoKeygenResponse {
            key_id: keypair.key_id.clone(),
            public_key: keypair.public_key.clone(),
            algorithm: keypair.algorithm.clone(),
        }))
    }

    async fn crypto_random(
        &self,
        request: Request<CryptoRandomRequest>,
    ) -> Result<Response<CryptoRandomResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let random = self
            .state
            .broker
            .crypto()
            .generate_random_bytes(req.length as usize)
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoRandomResponse {
            random,
            length: req.length,
        }))
    }

    async fn crypto_pubkey(
        &self,
        request: Request<CryptoPubkeyRequest>,
    ) -> Result<Response<CryptoPubkeyResponse>, Status> {
        let _context = self.broker_context(&request)?;
        let req = request.into_inner();
        let key_id = req.key_id.trim();
        if key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        let public_key = self
            .state
            .broker
            .crypto()
            .get_public_key(key_id)
            .await
            .map_err(svc_err)?;

        Ok(Response::new(CryptoPubkeyResponse {
            key_id: key_id.to_string(),
            public_key,
        }))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "ok".to_string(),
            checked_at: chrono_to_timestamp(Utc::now()),
        }))
    }

    async fn describe_channel(
        &self,
        request: Request<DescribeChannelRequest>,
    ) -> Result<Response<DescribeChannelResponse>, Status> {
        let context = self.broker_context(&request)?;
        let exporter = context.exporter().to_vec();
        let exporter_hash = Sha256::digest(&exporter).to_vec();
        Ok(Response::new(DescribeChannelResponse {
            session_id: context
                .session_id()
                .ok_or_else(|| Status::internal("authenticated TLS context is missing session ID"))?
                .to_string(),
            tls_exporter: exporter,
            tls_exporter_hash: exporter_hash,
            authenticated_transport: context.has_authenticated_transport(),
            principal_id: context.principal_id().unwrap_or_default().to_string(),
            peer_cert_sha256: context.peer_cert_sha256().unwrap_or_default().to_vec(),
            attestation_digest: context.attestation_digest().unwrap_or_default().to_vec(),
        }))
    }

    async fn renew_lease(
        &self,
        request: Request<RenewLeaseRequest>,
    ) -> Result<Response<RenewLeaseResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let result = handlers::renew_lease_impl(
            &self.state.broker,
            &context,
            handlers::RenewLeaseRequest {
                handle: req.handle,
                lease_duration_seconds: req.lease_duration_seconds,
            },
        )
        .await
        .map_err(svc_service_err)?;
        Ok(Response::new(RenewLeaseResponse {
            lease_expires_at: chrono_to_timestamp(result.lease_expires_at),
            renewal_count: result.renewal_count,
        }))
    }

    async fn revoke_secret(
        &self,
        request: Request<RevokeSecretRequest>,
    ) -> Result<Response<RevokeSecretResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let reason = if req.reason.is_empty() {
            None
        } else {
            Some(req.reason)
        };
        let result = handlers::revoke_secret_impl(
            &self.state.broker,
            &context,
            handlers::RevokeSecretRequest {
                handle: req.handle,
                reason,
            },
        )
        .await
        .map_err(svc_service_err)?;
        Ok(Response::new(RevokeSecretResponse {
            revoked: result.revoked,
            revoked_at: result.revoked_at.and_then(chrono_to_timestamp),
        }))
    }

    async fn rotate_secret(
        &self,
        request: Request<RotateSecretRequest>,
    ) -> Result<Response<RotateSecretResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let customer_id = if req.customer_id.is_empty() {
            None
        } else {
            Some(req.customer_id)
        };
        let metadata = req.metadata.map(prost_struct_to_json);
        let ttl = if req.ttl_seconds == 0 {
            None
        } else {
            Some(req.ttl_seconds)
        };
        let rotation_reason = if req.rotation_reason.is_empty() {
            None
        } else {
            Some(req.rotation_reason)
        };
        let result = handlers::rotate_secret_impl(
            &self.state.broker,
            &context,
            handlers::RotateSecretRequest {
                old_handle: req.old_handle,
                new_plaintext: req.new_plaintext,
                customer_id,
                metadata,
                ttl_seconds: ttl,
                rotation_reason,
                lifecycle: crate::secret_broker_impl::sealed_store::SecretLifecycle::from_proto_i32(
                    req.lifecycle,
                ),
                threshold: if req.threshold > 0 {
                    Some(req.threshold as u8)
                } else {
                    None
                },
                num_shares: if req.num_shares > 0 {
                    Some(req.num_shares as u8)
                } else {
                    None
                },
            },
        )
        .await
        .map_err(svc_service_err)?;
        Ok(Response::new(RotateSecretResponse {
            new_handle: result.new_handle,
            created_at: chrono_to_timestamp(result.created_at),
            expires_at: result.expires_at.and_then(chrono_to_timestamp),
            redeem_token: result.redeem_token.into_bytes(),
            redeem_token_expires_at: result.redeem_token_expires_at.and_then(chrono_to_timestamp),
            old_revoked: result.old_revoked,
            new_shares: result
                .new_shares
                .iter()
                .map(|s| ThresholdShare {
                    x: s.x as u32,
                    y: s.y.to_vec(),
                })
                .collect(),
        }))
    }

    async fn mint_discharge(
        &self,
        request: Request<MintDischargeRequest>,
    ) -> Result<Response<MintDischargeResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let result = handlers::mint_discharge_impl(
            &self.state.broker,
            &context,
            handlers::MintDischargeRequest {
                location: req.location,
                primary_handle: req.primary_handle,
                caveat_id: req.caveat_id,
            },
        )
        .await
        .map_err(svc_service_err)?;
        Ok(Response::new(MintDischargeResponse {
            discharge_token: result.discharge_token,
        }))
    }

    async fn claim_share(
        &self,
        request: Request<ClaimShareRequest>,
    ) -> Result<Response<ClaimShareResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let authenticated_principal = context
            .principal_id()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Status::permission_denied(
                    "ClaimShare requires an authenticated broker principal identity",
                )
            })?;
        if !req.custodian_id.trim().is_empty() && req.custodian_id.trim() != authenticated_principal
        {
            return Err(Status::permission_denied(
                "custodian_id must match the authenticated broker principal identity",
            ));
        }
        let result = handlers::claim_share_impl(
            &self.state.broker,
            &context,
            handlers::ClaimShareRequest {
                handle: req.handle,
                custodian_id: authenticated_principal.to_string(),
            },
        )
        .await
        .map_err(svc_err)?;
        Ok(Response::new(ClaimShareResponse {
            share: Some(ThresholdShare {
                x: result.x as u32,
                y: result.y,
            }),
            commitments: result.commitments,
            previously_claimed: result.previously_claimed,
        }))
    }

    async fn distribute_share(
        &self,
        request: Request<DistributeShareRequest>,
    ) -> Result<Response<DistributeShareResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let share = req
            .share
            .ok_or_else(|| Status::invalid_argument("share is required"))?;
        if share.x == 0 || share.x > 255 {
            return Err(Status::invalid_argument("share x must be 1..=255"));
        }
        if share.y.len() != crate::secret_broker_impl::threshold::SHARE_LENGTH {
            return Err(Status::invalid_argument("share y must be 32 bytes"));
        }
        let result = handlers::distribute_share_impl(
            &self.state.broker,
            &context,
            handlers::DistributeShareRequest {
                handle: req.handle,
                share_index: req.share_index,
                share: crate::secret_broker_impl::threshold::Share {
                    x: share.x as u8,
                    y: share.y,
                },
                custodian_id: req.custodian_id,
            },
        )
        .await
        .map_err(svc_err)?;
        Ok(Response::new(DistributeShareResponse {
            accepted: result.accepted,
            ack_token: result.ack_token,
        }))
    }

    async fn combine_shares(
        &self,
        request: Request<CombineSharesRequest>,
    ) -> Result<Response<CombineSharesResponse>, Status> {
        let context = self.broker_context(&request)?;
        let req = request.into_inner();
        let shares = req
            .shares
            .into_iter()
            .map(|s| {
                if s.x == 0 || s.x > 255 {
                    return Err(Status::invalid_argument("share x must be 1..=255"));
                }
                if s.y.len() != crate::secret_broker_impl::threshold::SHARE_LENGTH {
                    return Err(Status::invalid_argument("share y must be 32 bytes"));
                }
                Ok(crate::secret_broker_impl::threshold::Share {
                    x: s.x as u8,
                    y: s.y,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = handlers::combine_shares_impl(
            &self.state.broker,
            &context,
            handlers::CombineSharesRequest {
                handle: req.handle,
                shares,
                tenant_id: if req.tenant_id.is_empty() {
                    None
                } else {
                    Some(req.tenant_id)
                },
                provider: if req.provider.is_empty() {
                    None
                } else {
                    Some(req.provider)
                },
                custodian_ids: req.custodian_ids,
            },
        )
        .await
        .map_err(svc_err)?;
        Ok(Response::new(CombineSharesResponse {
            plaintext: result.plaintext,
        }))
    }
}

fn prost_struct_to_json(s: prost_types::Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in s.fields {
        map.insert(k, prost_value_to_json(v));
    }
    serde_json::Value::Object(map)
}

fn prost_value_to_json(v: prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match v.kind {
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::json!(n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(b),
        Some(Kind::StructValue(s)) => prost_struct_to_json(s),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.into_iter().map(prost_value_to_json).collect())
        }
        None => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::{tempdir, TempDir};
    use tonic::{Code, Request};
    use uuid::Uuid;

    use super::{svc_service_err, SecretBrokerGrpc};
    use crate::secret_broker_impl::crypto_engine::{CryptoConfig, CryptoEngineService};
    use crate::secret_broker_impl::sealed_store::SealedStore;
    use crate::secret_broker_impl::state::{BrokerState, BrokerStateConfig};
    use crate::secret_broker_impl::{BrokerClientContext, SecretBrokerState};

    struct TestBrokerHarness {
        state: Arc<SecretBrokerState>,
        _sealed_store_dir: TempDir,
        _crypto_store_dir: TempDir,
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
            state: Arc::new(SecretBrokerState {
                broker: BrokerState::new(
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
            }),
            _sealed_store_dir: sealed_store_dir,
            _crypto_store_dir: crypto_store_dir,
        }
    }

    fn authenticated_context(principal: &str, tag: u8) -> BrokerClientContext {
        BrokerClientContext::from_tls_exporter(
            vec![tag; 32],
            Some(Uuid::new_v4()),
            Some(principal.to_string()),
            Some(vec![tag; 32]),
            Some(vec![tag.wrapping_add(1); 32]),
        )
    }

    #[tokio::test]
    async fn broker_context_rejects_missing_live_connection() {
        let harness = test_broker_state().await;
        let grpc = SecretBrokerGrpc::new(harness.state);

        let err = grpc
            .broker_context(&Request::new(()))
            .expect_err("broker must reject requests without live mTLS context");

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(
            err.message().contains("authenticated live mTLS"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn broker_context_uses_authenticated_request_context() {
        let harness = test_broker_state().await;
        let grpc = SecretBrokerGrpc::new(harness.state);
        let expected = authenticated_context("spiffe://trust.example/workload", 17);
        let mut request = Request::new(());
        request.extensions_mut().insert(expected.clone());

        let actual = grpc
            .broker_context(&request)
            .expect("request-scoped broker context should satisfy non-dev mode");

        assert!(actual.has_authenticated_transport());
        assert_eq!(actual.principal_id(), expected.principal_id());
        assert_eq!(actual.peer_cert_sha256(), expected.peer_cert_sha256());
        assert_eq!(actual.attestation_digest(), expected.attestation_digest());
    }

    #[test]
    fn identity_failures_map_to_truthful_grpc_statuses() {
        let missing_identity = svc_service_err(
            crate::secret_broker_impl::handlers::ServiceError::AuthenticatedPrincipalRequired,
        );
        assert_eq!(missing_identity.code(), Code::Unauthenticated);

        let missing_lineage = svc_service_err(
            crate::secret_broker_impl::handlers::ServiceError::MissingLineage(
                "peer certificate lineage on the authenticated broker transport",
            ),
        );
        assert_eq!(missing_lineage.code(), Code::FailedPrecondition);

        let wrong_principal =
            svc_service_err(crate::secret_broker_impl::handlers::ServiceError::PrincipalMismatch);
        assert_eq!(wrong_principal.code(), Code::PermissionDenied);

        let wrong_peer_cert =
            svc_service_err(crate::secret_broker_impl::handlers::ServiceError::PeerCertMismatch);
        assert_eq!(wrong_peer_cert.code(), Code::PermissionDenied);

        let wrong_attestation =
            svc_service_err(crate::secret_broker_impl::handlers::ServiceError::AttestationMismatch);
        assert_eq!(wrong_attestation.code(), Code::PermissionDenied);
    }
}
