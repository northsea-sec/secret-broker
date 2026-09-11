//! Authenticated client for the Secret Broker.
//!
//! `SecretBrokerClient` is the only public transport constructor. It always
//! uses a client certificate, an explicit trust root, an explicit server name,
//! and either verified RA-TLS or explicit loopback-only local mTLS.

use std::{
    collections::HashSet,
    env, fmt, fs,
    io::Cursor,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use rustls_pemfile::{certs, read_all, Item};
use serde_json::Value;
use tokio::runtime::Handle;
use tonic::transport::{Channel, Endpoint, Uri};
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::ra_tls::{
    attestation::{Attestation, VerifiedAttestation},
    qvl::quote::Report,
    vendor::TEEVendor,
};
use crate::{
    broker_proto, AttenuateHandleV2Params, AttenuateHandleV2Result, ClaimShareResult,
    CryptoDecryptParams, CryptoDecryptResult, CryptoEncryptParams, CryptoEncryptResult,
    CryptoKeyPairResult, CryptoKeygenParams, CryptoSignParams, CryptoVerifyParams,
    MintAeadKeyV2Lease, MintAeadKeyV2Params, MintDischargeParams, PostgresCredentialLease,
    PostgresCredentialParams, RenewLeaseResult, RevokeResult, RotateParams, RotateResult,
    SecretBrokerGrpcAdapter, SecretBrokerGrpcAdapterConfig, ThresholdShareMaterial,
    UnwrapSecretV2Params, WrapResponse, WrapV2Params,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Peer-authentication mode for Secret Broker connections.
///
/// `Enforced` verifies the ordinary TLS chain, server name, client mTLS
/// identity, RA-TLS quote, PCCS collateral, measurement policy, and server
/// subject. `Local` verifies ordinary TLS plus mutual TLS, and is accepted
/// only for a loopback endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    Enforced,
    Local,
}

impl AttestationMode {
    fn from_env() -> Result<Self> {
        let raw = match env::var("SECRET_BROKER_CLIENT_MODE") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => "enforced".to_owned(),
            Err(error) => return Err(anyhow!("failed to read SECRET_BROKER_CLIENT_MODE: {error}")),
        };
        Self::parse(&raw).with_context(|| "invalid SECRET_BROKER_CLIENT_MODE")
    }

    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enforced" => Ok(Self::Enforced),
            "local" => Ok(Self::Local),
            _ => bail!("Secret Broker mode must be exactly enforced or local; got {raw:?}"),
        }
    }
}

/// A non-permissive measurement policy loaded from the explicit policy file.
#[derive(Debug, Clone)]
pub struct MeasurementPolicy {
    allowed_mrtd: HashSet<String>,
    allowed_mrenclave: HashSet<String>,
    allowed_mrsigner: HashSet<String>,
    min_isvsvn: Option<u16>,
    expected_compose_hash: Option<String>,
}

impl MeasurementPolicy {
    fn accepts_tdx_mrtd(&self, mrtd: &str) -> bool {
        self.allowed_mrtd.contains(&normalize_measurement(mrtd))
    }

    fn accepts_sgx(&self, mrenclave: &str, mrsigner: &str, isvsvn: u16) -> bool {
        self.allowed_mrenclave.iter().next().is_some()
            && !self.allowed_mrsigner.is_empty()
            && self
                .allowed_mrenclave
                .contains(&normalize_measurement(mrenclave))
            && self
                .allowed_mrsigner
                .contains(&normalize_measurement(mrsigner))
            && self
                .min_isvsvn
                .map(|minimum| isvsvn >= minimum)
                .unwrap_or(true)
    }

    fn requires_compose_hash(&self) -> bool {
        self.expected_compose_hash.is_some()
    }

    fn accepts_compose_hash(&self, value: &str) -> bool {
        self.expected_compose_hash.as_deref() == Some(normalize_measurement(value).as_str())
    }
}

/// Named, measured identity policy for an enforced Secret Broker connection.
#[derive(Debug, Clone)]
pub struct ClientPolicy {
    policy_name: String,
    measurement: MeasurementPolicy,
}

impl ClientPolicy {
    /// Load a policy from an explicitly configured JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read Secret Broker policy {}", path.display()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse Secret Broker policy {}", path.display()))?;
        Self::from_json(value)
    }

    /// Stable policy identity for auditing and connection errors.
    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    fn from_json(value: Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("Secret Broker client policy must be a JSON object"))?;
        let policy_name = required_json_string(object, "policy_name")?;
        let allowed_mrtd = required_or_empty_measurement_set(object, "allowed_mrtd")?;
        let allowed_mrenclave = required_or_empty_measurement_set(object, "allowed_mrenclave")?;
        let allowed_mrsigner = required_or_empty_measurement_set(object, "allowed_mrsigner")?;
        let min_isvsvn = match object.get("min_isvsvn") {
            None | Some(Value::Null) => None,
            Some(Value::Number(value)) => {
                let value = value
                    .as_u64()
                    .ok_or_else(|| anyhow!("min_isvsvn must be an unsigned integer"))?;
                u16::try_from(value)
                    .map(Some)
                    .map_err(|_| anyhow!("min_isvsvn must fit in u16"))?
            }
            Some(_) => bail!("min_isvsvn must be an unsigned integer or null"),
        };
        let expected_compose_hash = match object.get("expected_compose_hash") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => {
                let value = normalize_measurement(value);
                if value.is_empty() {
                    bail!("expected_compose_hash must not be empty");
                }
                Some(value)
            }
            Some(_) => bail!("expected_compose_hash must be a string or null"),
        };

        if allowed_mrenclave.is_empty() != allowed_mrsigner.is_empty() {
            bail!("SGX policy must provide both allowed_mrenclave and allowed_mrsigner");
        }
        if allowed_mrtd.is_empty()
            && allowed_mrenclave.is_empty()
            && expected_compose_hash.is_none()
        {
            bail!(
                "Secret Broker policy must constrain a TDX measurement, an SGX measurement pair, or a compose hash"
            );
        }

        Ok(Self {
            policy_name,
            measurement: MeasurementPolicy {
                allowed_mrtd,
                allowed_mrenclave,
                allowed_mrsigner,
                min_isvsvn,
                expected_compose_hash,
            },
        })
    }
}

/// Parsed mTLS client identity. Its private key is never exposed through this
/// public API or included in debug output.
pub struct ClientIdentity {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientIdentity")
            .field("certificate_count", &self.certificates.len())
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl ClientIdentity {
    /// Parse a client certificate chain and its matching private key from PEM.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        Ok(Self {
            certificates: parse_certificates(cert_pem, "client certificate")?,
            private_key: parse_private_key(key_pem)?,
        })
    }

    /// Read and parse a client certificate chain and private key from explicit paths.
    pub fn from_paths(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();
        let cert_pem = fs::read(cert_path).with_context(|| {
            format!("failed to read client certificate {}", cert_path.display())
        })?;
        let key_pem = fs::read(key_path)
            .with_context(|| format!("failed to read client private key {}", key_path.display()))?;
        Self::from_pem(&cert_pem, &key_pem)
    }
}

/// Fully explicit connection configuration for [`SecretBrokerClient`].
///
/// Call [`SecretBrokerClientConfig::from_env`] for the canonical environment
/// configuration. `connect` repeats validation so programmatic callers cannot
/// bypass the same trust invariants.
pub struct SecretBrokerClientConfig {
    pub endpoint: Url,
    pub attestation_mode: AttestationMode,
    pub policy: Option<ClientPolicy>,
    pub subject_allowlist: Option<HashSet<String>>,
    pub pccs_url: Option<Url>,
    pub client_identity: ClientIdentity,
    pub client_ca_certificates: Vec<CertificateDer<'static>>,
    pub server_name: String,
    pub timeout: Duration,
}

impl fmt::Debug for SecretBrokerClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBrokerClientConfig")
            .field("endpoint", &self.endpoint)
            .field("attestation_mode", &self.attestation_mode)
            .field(
                "policy",
                &self.policy.as_ref().map(ClientPolicy::policy_name),
            )
            .field("subject_allowlist", &self.subject_allowlist)
            .field("pccs_url", &self.pccs_url)
            .field("client_identity", &self.client_identity)
            .field(
                "client_ca_certificate_count",
                &self.client_ca_certificates.len(),
            )
            .field("server_name", &self.server_name)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SecretBrokerClientConfig {
    /// Parse the sole supported Secret Broker client environment schema.
    pub fn from_env() -> Result<Self> {
        let endpoint = parse_endpoint(&required_env("SECRET_BROKER_ENDPOINT")?)?;
        let attestation_mode = AttestationMode::from_env()?;
        let client_cert_path = required_env_path("SECRET_BROKER_CLIENT_CERT")?;
        let client_key_path = required_env_path("SECRET_BROKER_CLIENT_KEY")?;
        let client_ca_path = required_env_path("SECRET_BROKER_CLIENT_CA_CERT")?;
        let server_name = required_env("SECRET_BROKER_CLIENT_SERVER_NAME")?;
        validate_server_name(&server_name)?;
        let timeout = parse_timeout()?;
        let client_identity = ClientIdentity::from_paths(&client_cert_path, &client_key_path)?;
        let client_ca_certificates = Self::load_ca_certificates(&client_ca_path)?;

        let (policy, subject_allowlist, pccs_url) = match attestation_mode {
            AttestationMode::Enforced => {
                let policy_path = required_env_path("SECRET_BROKER_CLIENT_POLICY_FILE")?;
                let subjects =
                    parse_subject_allowlist(&required_env("SECRET_BROKER_CLIENT_SUBJECTS")?)?;
                let pccs_url = parse_pccs_url(&required_env("SECRET_BROKER_PCCS_URL")?)?;
                (
                    Some(ClientPolicy::from_file(policy_path)?),
                    Some(subjects),
                    Some(pccs_url),
                )
            }
            AttestationMode::Local => (None, None, None),
        };

        let config = Self {
            endpoint,
            attestation_mode,
            policy,
            subject_allowlist,
            pccs_url,
            client_identity,
            client_ca_certificates,
            server_name,
            timeout,
        };
        config.validate()?;
        Ok(config)
    }

    /// Read the explicit server trust anchor bundle for programmatic configuration.
    pub fn load_ca_certificates(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
        let path = path.as_ref();
        let pem = fs::read(path).with_context(|| {
            format!(
                "failed to read Secret Broker client CA certificate {}",
                path.display()
            )
        })?;
        parse_certificates(&pem, "client CA certificate")
    }

    fn validate(&self) -> Result<()> {
        validate_endpoint(&self.endpoint)?;
        validate_server_name(&self.server_name)?;
        if self.timeout.is_zero() {
            bail!("Secret Broker client timeout must be greater than zero");
        }
        if self.client_identity.certificates.is_empty() {
            bail!("Secret Broker client identity must contain at least one certificate");
        }
        if self.client_ca_certificates.is_empty() {
            bail!("Secret Broker client CA bundle must contain at least one certificate");
        }

        match self.attestation_mode {
            AttestationMode::Enforced => {
                let policy = self.policy.as_ref().ok_or_else(|| {
                    anyhow!("enforced Secret Broker mode requires a client measurement policy")
                })?;
                if policy.policy_name().trim().is_empty() {
                    bail!("enforced Secret Broker policy name must not be empty");
                }
                if self
                    .subject_allowlist
                    .as_ref()
                    .filter(|subjects| !subjects.is_empty())
                    .is_none()
                {
                    bail!("enforced Secret Broker mode requires a non-empty subject allowlist");
                }
                let pccs = self.pccs_url.as_ref().ok_or_else(|| {
                    anyhow!("enforced Secret Broker mode requires SECRET_BROKER_PCCS_URL")
                })?;
                validate_pccs_url(pccs)?;
            }
            AttestationMode::Local => {
                if !endpoint_is_loopback(&self.endpoint) {
                    bail!(
                        "SECRET_BROKER_CLIENT_MODE=local is permitted only for a loopback SECRET_BROKER_ENDPOINT"
                    );
                }
                if self.policy.is_some()
                    || self.subject_allowlist.is_some()
                    || self.pccs_url.is_some()
                {
                    bail!("local Secret Broker mode must not carry enforced-attestation policy fields");
                }
            }
        }
        Ok(())
    }
}

/// Authenticated, typed Secret Broker client.
#[derive(Debug, Clone)]
pub struct SecretBrokerClient {
    adapter: SecretBrokerGrpcAdapter,
}

impl SecretBrokerClient {
    /// Construct and eagerly connect a trusted client from the canonical
    /// environment configuration.
    pub async fn from_env() -> Result<Self> {
        Self::connect(SecretBrokerClientConfig::from_env()?).await
    }

    /// Eagerly establish the configured authenticated connection.
    pub async fn connect(config: SecretBrokerClientConfig) -> Result<Self> {
        config.validate()?;
        let server_name = parse_server_name(&config.server_name)?;
        let tls_config = build_client_tls_config(&config)?;
        let channel = connect_authenticated_channel(
            &config.endpoint,
            server_name,
            tls_config,
            config.timeout,
        )
        .await?;
        let adapter = SecretBrokerGrpcAdapter::new(SecretBrokerGrpcAdapterConfig::new(
            config.endpoint,
            channel,
        ));
        Ok(Self { adapter })
    }

    pub fn endpoint(&self) -> &Url {
        self.adapter.endpoint()
    }

    pub async fn describe_channel(&self) -> Result<broker_proto::DescribeChannelResponse> {
        self.adapter.describe_channel().await
    }

    pub async fn wrap_bytes_v2(
        &self,
        plaintext: &[u8],
        params: WrapV2Params,
    ) -> Result<WrapResponse> {
        self.adapter.wrap_bytes_v2(plaintext, params).await
    }

    pub async fn wrap_json_v2<T: serde::Serialize + ?Sized>(
        &self,
        payload: &T,
        params: WrapV2Params,
    ) -> Result<WrapResponse> {
        self.adapter.wrap_json_v2(payload, params).await
    }

    pub fn preload_redeem_token(
        &self,
        handle: impl Into<String>,
        token: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.adapter.preload_redeem_token(handle, token, expires_at)
    }

    pub fn preload_redeem_shares(
        &self,
        handle: impl Into<String>,
        shares: Vec<ThresholdShareMaterial>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.adapter
            .preload_redeem_shares(handle, shares, expires_at)
    }

    pub async fn mint_aead_key_v2(
        &self,
        params: MintAeadKeyV2Params,
    ) -> Result<MintAeadKeyV2Lease> {
        self.adapter.mint_aead_key_v2(params).await
    }

    pub async fn unwrap_secret_v2(&self, params: UnwrapSecretV2Params) -> Result<Vec<u8>> {
        self.adapter.unwrap_secret_v2(params).await
    }

    /// Add caveats to a handle and return its public capability material.
    ///
    /// A third-party attenuation returns the broker-issued opaque caveat ID that
    /// must be supplied unchanged to [`Self::mint_discharge`].
    pub async fn attenuate_handle_v2(
        &self,
        params: AttenuateHandleV2Params,
    ) -> Result<AttenuateHandleV2Result> {
        self.adapter.attenuate_handle_v2(params).await
    }

    pub async fn mint_discharge(&self, params: MintDischargeParams) -> Result<String> {
        self.adapter.mint_discharge(params).await
    }

    pub async fn issue_postgres_credentials(
        &self,
        params: PostgresCredentialParams,
    ) -> Result<PostgresCredentialLease> {
        self.adapter.issue_postgres_credentials(params).await
    }

    pub async fn crypto_encrypt(&self, params: CryptoEncryptParams) -> Result<CryptoEncryptResult> {
        self.adapter.crypto_encrypt(params).await
    }

    pub async fn crypto_decrypt(&self, params: CryptoDecryptParams) -> Result<CryptoDecryptResult> {
        self.adapter.crypto_decrypt(params).await
    }

    pub async fn crypto_sign(&self, params: CryptoSignParams) -> Result<Vec<u8>> {
        self.adapter.crypto_sign(params).await
    }

    pub async fn crypto_verify(&self, params: CryptoVerifyParams) -> Result<bool> {
        self.adapter.crypto_verify(params).await
    }

    pub async fn crypto_keygen(&self, params: CryptoKeygenParams) -> Result<CryptoKeyPairResult> {
        self.adapter.crypto_keygen(params).await
    }

    pub async fn crypto_random(&self, length: u32) -> Result<Vec<u8>> {
        self.adapter.crypto_random(length).await
    }

    pub async fn crypto_pubkey(&self, key_id: &str) -> Result<Vec<u8>> {
        self.adapter.crypto_pubkey(key_id).await
    }

    pub async fn delete_secret(&self, handle: &str) -> Result<()> {
        self.adapter.delete_secret(handle).await
    }

    pub async fn renew_lease(
        &self,
        handle: &str,
        lease_duration_seconds: u64,
    ) -> Result<RenewLeaseResult> {
        self.adapter
            .renew_lease(handle, lease_duration_seconds)
            .await
    }

    pub async fn revoke_secret(&self, handle: &str, reason: Option<&str>) -> Result<RevokeResult> {
        self.adapter.revoke_secret(handle, reason).await
    }

    pub async fn rotate_secret(
        &self,
        old_handle: &str,
        new_plaintext: &[u8],
        params: RotateParams,
    ) -> Result<RotateResult> {
        self.adapter
            .rotate_secret(old_handle, new_plaintext, params)
            .await
    }

    pub async fn claim_share(&self, handle: &str, custodian_id: &str) -> Result<ClaimShareResult> {
        self.adapter.claim_share(handle, custodian_id).await
    }
}

fn required_env(key: &str) -> Result<String> {
    let raw = env::var(key).with_context(|| format!("{key} is required"))?;
    let value = raw.trim();
    if value.is_empty() {
        bail!("{key} must not be empty");
    }
    Ok(value.to_owned())
}

fn required_env_path(key: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(required_env(key)?))
}

fn parse_timeout() -> Result<Duration> {
    match env::var("SECRET_BROKER_CLIENT_TIMEOUT_SECS") {
        Ok(raw) => {
            let value = raw.trim();
            if value.is_empty() {
                bail!("SECRET_BROKER_CLIENT_TIMEOUT_SECS must not be empty");
            }
            let seconds = value
                .parse::<u64>()
                .with_context(|| "SECRET_BROKER_CLIENT_TIMEOUT_SECS must be a positive integer")?;
            if seconds == 0 {
                bail!("SECRET_BROKER_CLIENT_TIMEOUT_SECS must be greater than zero");
            }
            Ok(Duration::from_secs(seconds))
        }
        Err(env::VarError::NotPresent) => Ok(DEFAULT_TIMEOUT),
        Err(error) => Err(anyhow!(
            "failed to read SECRET_BROKER_CLIENT_TIMEOUT_SECS: {error}"
        )),
    }
}

fn parse_endpoint(raw: &str) -> Result<Url> {
    let endpoint = Url::parse(raw).context("invalid SECRET_BROKER_ENDPOINT")?;
    validate_endpoint(&endpoint)?;
    Ok(endpoint)
}

fn validate_endpoint(endpoint: &Url) -> Result<()> {
    if endpoint.scheme() != "https" {
        bail!("SECRET_BROKER_ENDPOINT must use https");
    }
    if endpoint.host_str().is_none() {
        bail!("SECRET_BROKER_ENDPOINT must include a host");
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        bail!("SECRET_BROKER_ENDPOINT must not contain user information");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        bail!("SECRET_BROKER_ENDPOINT must not contain a query or fragment");
    }
    if endpoint.path() != "/" && !endpoint.path().is_empty() {
        bail!("SECRET_BROKER_ENDPOINT must not contain a path");
    }
    Ok(())
}

fn parse_pccs_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("invalid SECRET_BROKER_PCCS_URL")?;
    validate_pccs_url(&url)?;
    Ok(url)
}

fn validate_pccs_url(url: &Url) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("SECRET_BROKER_PCCS_URL must be an http(s) URL with a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("SECRET_BROKER_PCCS_URL must not contain user information");
    }
    if url.fragment().is_some() {
        bail!("SECRET_BROKER_PCCS_URL must not contain a fragment");
    }
    Ok(())
}

fn parse_subject_allowlist(raw: &str) -> Result<HashSet<String>> {
    let mut subjects = HashSet::new();
    for entry in raw.split(',') {
        let subject = entry.trim().to_ascii_lowercase();
        if subject.is_empty() {
            bail!("SECRET_BROKER_CLIENT_SUBJECTS must not contain empty values");
        }
        if !subjects.insert(subject) {
            bail!("SECRET_BROKER_CLIENT_SUBJECTS must not contain duplicate values");
        }
    }
    if subjects.is_empty() {
        bail!("SECRET_BROKER_CLIENT_SUBJECTS must not be empty");
    }
    Ok(subjects)
}

fn endpoint_is_loopback(endpoint: &Url) -> bool {
    let Some(host) = endpoint.host_str() else {
        return false;
    };
    let normalized = host.trim().to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn validate_server_name(raw: &str) -> Result<()> {
    let _ = parse_server_name(raw)?;
    Ok(())
}

fn parse_server_name(raw: &str) -> Result<ServerName<'static>> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("SECRET_BROKER_CLIENT_SERVER_NAME must not be empty");
    }
    match value.parse::<IpAddr>() {
        Ok(address) => Ok(ServerName::IpAddress(address.into())),
        Err(_) => ServerName::try_from(value.to_owned())
            .map_err(|error| anyhow!("invalid SECRET_BROKER_CLIENT_SERVER_NAME: {error}")),
    }
}

fn parse_certificates(pem: &[u8], label: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certificates = certs(&mut Cursor::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse {label} PEM"))?;
    if certificates.is_empty() {
        bail!("{label} PEM bundle did not contain any certificates");
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    for item in read_all(&mut cursor) {
        match item.context("failed to parse client private key PEM")? {
            Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Sec1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            _ => continue,
        }
    }
    bail!("client private key PEM bundle did not contain a supported key")
}

fn build_client_tls_config(config: &SecretBrokerClientConfig) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for certificate in &config.client_ca_certificates {
        roots
            .add(CertificateDer::from(certificate.as_ref().to_vec()))
            .map_err(|error| anyhow!("failed to add Secret Broker CA certificate: {error}"))?;
    }

    let client_certificates = config
        .client_identity
        .certificates
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_ref().to_vec()))
        .collect::<Vec<_>>();
    let builder = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to configure supported TLS protocol versions")?
    .with_root_certificates(roots.clone());
    let mut tls_config = builder
        .with_client_auth_cert(
            client_certificates,
            config.client_identity.private_key.clone_key(),
        )
        .context("failed to configure Secret Broker client certificate")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    if matches!(config.attestation_mode, AttestationMode::Enforced) {
        let chain_verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .context("failed to configure Secret Broker server CA verifier")?;
        let policy = config
            .policy
            .clone()
            .ok_or_else(|| anyhow!("missing enforced Secret Broker policy"))?;
        let subject_allowlist = config
            .subject_allowlist
            .clone()
            .ok_or_else(|| anyhow!("missing enforced Secret Broker subject allowlist"))?;
        let pccs_url = config
            .pccs_url
            .as_ref()
            .ok_or_else(|| anyhow!("missing enforced Secret Broker PCCS URL"))?
            .to_string();
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(RaTlsServerVerifier {
                chain_verifier,
                policy,
                subject_allowlist,
                pccs_url,
            }));
    }

    Ok(Arc::new(tls_config))
}

async fn connect_authenticated_channel(
    endpoint: &Url,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<Channel> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow!("Secret Broker endpoint is missing a host"))?
        .to_owned();
    let port = endpoint.port_or_known_default().unwrap_or(443);
    let mut transport_endpoint = endpoint.clone();
    transport_endpoint
        .set_scheme("http")
        .map_err(|_| anyhow!("failed to construct Secret Broker connector endpoint"))?;
    let endpoint = Endpoint::from_shared(transport_endpoint.to_string())
        .context("invalid Secret Broker connector endpoint")?
        .connect_timeout(timeout)
        .timeout(timeout);

    let connector = tower::service_fn(move |_uri: Uri| {
        let host = host.clone();
        let server_name = server_name.clone();
        let tls_config = tls_config.clone();
        async move {
            let tcp = tokio::time::timeout(
                timeout,
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Secret Broker TCP connection to {host}:{port} timed out").into()
            })?
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Secret Broker TCP connection to {host}:{port} failed: {error}").into()
            })?;
            tcp.set_nodelay(true)
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("failed to set TCP_NODELAY for Secret Broker: {error}").into()
                })?;
            let tls = tokio_rustls::TlsConnector::from(tls_config)
                .connect(server_name, tcp)
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("Secret Broker TLS handshake failed: {error}").into()
                })?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(hyper_util::rt::TokioIo::new(tls))
        }
    });

    endpoint
        .connect_with_connector(connector)
        .await
        .map_err(|error| anyhow!("failed to connect authenticated Secret Broker channel: {error}"))
}

struct RaTlsServerVerifier {
    chain_verifier: Arc<WebPkiServerVerifier>,
    policy: ClientPolicy,
    subject_allowlist: HashSet<String>,
    pccs_url: String,
}

impl fmt::Debug for RaTlsServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RaTlsServerVerifier")
            .field("policy", &self.policy.policy_name())
            .field("subject_count", &self.subject_allowlist.len())
            .field("pccs_url", &self.pccs_url)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RaTlsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        self.chain_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let certificate = CertificateDer::from(end_entity.as_ref().to_vec());
        let policy = self.policy.clone();
        let subject_allowlist = self.subject_allowlist.clone();
        let pccs_url = self.pccs_url.clone();
        run_attestation_verification(async move {
            verify_peer_certificate(certificate, policy, subject_allowlist, &pccs_url).await
        })?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.chain_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.chain_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain_verifier.supported_verify_schemes()
    }
}

fn run_attestation_verification<T>(
    future: impl std::future::Future<Output = Result<T>>,
) -> std::result::Result<T, RustlsError> {
    let handle = Handle::try_current().map_err(|error| {
        RustlsError::General(format!(
            "Tokio runtime is required for RA-TLS verification: {error}"
        ))
    })?;
    tokio::task::block_in_place(|| {
        handle
            .block_on(future)
            .map_err(|error| RustlsError::General(error.to_string()))
    })
}

async fn verify_peer_certificate(
    certificate: CertificateDer<'static>,
    policy: ClientPolicy,
    subject_allowlist: HashSet<String>,
    pccs_url: &str,
) -> Result<()> {
    let (_, certificate_view) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|error| anyhow!("failed to parse Secret Broker server certificate: {error}"))?;
    let subject = certificate_view
        .subject()
        .iter_common_name()
        .next()
        .and_then(|common_name| common_name.as_str().ok())
        .map(|common_name| common_name.trim().to_ascii_lowercase())
        .filter(|common_name| !common_name.is_empty())
        .ok_or_else(|| anyhow!("Secret Broker server certificate has no usable common name"))?;
    if !subject_allowlist.contains(&subject) {
        bail!("Secret Broker server subject {subject:?} is not in the configured allowlist");
    }

    let attestation = Attestation::from_der(certificate.as_ref())?.ok_or_else(|| {
        anyhow!("Secret Broker server certificate does not contain RA-TLS attestation")
    })?;
    if matches!(
        attestation.detect_vendor_from_quote()?,
        TEEVendor::AmdSevSnp
    ) {
        bail!("AMD SEV-SNP RA-TLS verification is not implemented by this client and is rejected");
    }
    let public_key = certificate_view
        .public_key()
        .subject_public_key
        .data
        .to_vec();
    let verified = attestation
        .verify_with_ra_pubkey(&public_key, pccs_url)
        .await
        .context("Secret Broker RA-TLS attestation verification failed")?;
    enforce_measurement_policy(&policy.measurement, &verified)
}

fn enforce_measurement_policy(
    policy: &MeasurementPolicy,
    verified: &VerifiedAttestation,
) -> Result<()> {
    let compose_hash = verified.decode_compose_hash().ok();
    if policy.requires_compose_hash() {
        let compose_hash = compose_hash.ok_or_else(|| {
            anyhow!("Secret Broker RA-TLS attestation is missing a policy-required compose hash")
        })?;
        if !policy.accepts_compose_hash(&compose_hash) {
            bail!("Secret Broker RA-TLS compose hash was rejected by policy");
        }
    }

    match &verified.report.report {
        Report::TD10(report) => {
            if !policy.accepts_tdx_mrtd(&hex::encode(report.mr_td)) {
                bail!("Secret Broker TDX MR_TD was rejected by policy");
            }
        }
        Report::TD15(report) => {
            if !policy.accepts_tdx_mrtd(&hex::encode(report.base.mr_td)) {
                bail!("Secret Broker TDX MR_TD was rejected by policy");
            }
        }
        Report::SgxEnclave(report) => {
            if !policy.accepts_sgx(
                &hex::encode(report.mr_enclave),
                &hex::encode(report.mr_signer),
                report.isv_svn,
            ) {
                bail!("Secret Broker SGX measurements were rejected by policy");
            }
        }
    }
    Ok(())
}

fn required_json_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Secret Broker policy field {key} must be a string"))?;
    let value = value.trim();
    if value.is_empty() {
        bail!("Secret Broker policy field {key} must not be empty");
    }
    Ok(value.to_owned())
}

fn required_or_empty_measurement_set(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<HashSet<String>> {
    let Some(value) = object.get(key) else {
        return Ok(HashSet::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| anyhow!("Secret Broker policy field {key} must be an array"))?;
    let mut result = HashSet::new();
    for item in values {
        let raw = item
            .as_str()
            .ok_or_else(|| anyhow!("Secret Broker policy field {key} must contain only strings"))?;
        let normalized = normalize_measurement(raw);
        if normalized.is_empty() {
            bail!("Secret Broker policy field {key} must not contain empty values");
        }
        if !result.insert(normalized) {
            bail!("Secret Broker policy field {key} must not contain duplicate values");
        }
    }
    Ok(result)
}

fn normalize_measurement(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{parse_subject_allowlist, AttestationMode, ClientPolicy};
    use serde_json::json;

    #[test]
    fn policy_rejects_empty_measurement_authority() {
        let error = ClientPolicy::from_json(json!({
            "policy_name": "empty",
            "allowed_mrtd": [],
            "allowed_mrenclave": [],
            "allowed_mrsigner": [],
            "expected_compose_hash": null
        }))
        .expect_err("unconstrained policy must fail");
        assert!(error.to_string().contains("must constrain"));
    }

    #[test]
    fn policy_rejects_partial_sgx_authority() {
        let error = ClientPolicy::from_json(json!({
            "policy_name": "partial-sgx",
            "allowed_mrtd": [],
            "allowed_mrenclave": ["aa"],
            "allowed_mrsigner": [],
            "expected_compose_hash": null
        }))
        .expect_err("partial SGX policy must fail");
        assert!(error.to_string().contains("both"));
    }

    #[test]
    fn policy_rejects_unlisted_measurement() {
        let policy = ClientPolicy::from_json(json!({
            "policy_name": "tdx-only",
            "allowed_mrtd": ["ABCDEF"],
            "allowed_mrenclave": [],
            "allowed_mrsigner": [],
            "expected_compose_hash": null
        }))
        .expect("policy");
        assert!(policy.measurement.accepts_tdx_mrtd("abcdef"));
        assert!(!policy.measurement.accepts_tdx_mrtd("fedcba"));
    }

    #[test]
    fn subject_parser_rejects_empty_and_duplicate_values() {
        assert!(parse_subject_allowlist("broker,,other").is_err());
        assert!(parse_subject_allowlist("broker,BROKER").is_err());
    }

    #[test]
    fn disabled_and_spiffe_modes_are_rejected() {
        assert!(AttestationMode::parse("disabled").is_err());
        assert!(AttestationMode::parse("spiffe").is_err());
    }
}
