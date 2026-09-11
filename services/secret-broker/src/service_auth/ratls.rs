use std::{collections::HashSet, future::Future, io::Cursor, path::Path, sync::Arc};

use crate::ra_tls::attestation::{Attestation, VerifiedAttestation};
use crate::ra_tls::qvl::quote::Report;
use crate::ra_tls::vendor::TEEVendor;
use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::Error as RustlsError;
use rustls::{ClientConfig, RootCertStore};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pemfile::{read_all, Item};
use tokio::runtime::{Handle, RuntimeFlavor};
use tracing::{info, warn};
use x509_parser::{
    extensions::GeneralName,
    prelude::{FromDer, X509Certificate},
};

/// Determines how strictly RA-TLS attestation is enforced for outbound clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    Enforced,
    Stub,
    Disabled,
    Local,
}

impl AttestationMode {
    pub fn is_enforced(self) -> bool {
        matches!(self, AttestationMode::Enforced)
    }

    pub(crate) fn is_non_production(self) -> bool {
        matches!(
            self,
            AttestationMode::Stub | AttestationMode::Disabled | AttestationMode::Local
        )
    }

    pub(crate) fn env_name(self) -> &'static str {
        match self {
            AttestationMode::Enforced => "enforced",
            AttestationMode::Stub => "stub",
            AttestationMode::Disabled => "disabled",
            AttestationMode::Local => "local",
        }
    }
}

/// Measurement allow-list for fully verified RA-TLS attestation.
///
/// Intel TDX / SGX can satisfy these measurement constraints through the
/// vendored RA-TLS verifier today. AMD SEV-SNP is intentionally fenced below:
/// the platform remains valid in the host platform via Aleph's documented
/// launch-measure baseline, but this verifier does not yet have full
/// KDS-backed AMD parity.
#[derive(Debug, Clone)]
pub struct MeasurementPolicy {
    allowed_mrtd: HashSet<String>,
    allowed_mrenclave: HashSet<String>,
    allowed_mrsigner: HashSet<String>,
    min_isvsvn: Option<u16>,
    expected_compose_hash: Option<String>,
}

impl MeasurementPolicy {
    pub fn allow_all() -> Self {
        Self {
            allowed_mrtd: HashSet::new(),
            allowed_mrenclave: HashSet::new(),
            allowed_mrsigner: HashSet::new(),
            min_isvsvn: None,
            expected_compose_hash: None,
        }
    }

    pub fn allows_tdx_mrtd(&self, mrtd: &str) -> bool {
        self.allowed_mrtd.is_empty() || self.allowed_mrtd.contains(&mrtd.to_lowercase())
    }

    pub fn allows_sgx_measurements(&self, mrenclave: &str, mrsigner: &str, isvsvn: u16) -> bool {
        let mrenclave_ok = self.allowed_mrenclave.is_empty()
            || self.allowed_mrenclave.contains(&mrenclave.to_lowercase());
        let mrsigner_ok = self.allowed_mrsigner.is_empty()
            || self.allowed_mrsigner.contains(&mrsigner.to_lowercase());
        let isvsvn_ok = match self.min_isvsvn {
            Some(min) => isvsvn >= min,
            None => true,
        };
        mrenclave_ok && mrsigner_ok && isvsvn_ok
    }

    pub fn allows_compose_hash(&self, compose_hash: &str) -> bool {
        match &self.expected_compose_hash {
            Some(expected) => expected == &compose_hash.to_lowercase(),
            None => true,
        }
    }

    pub fn expects_compose_hash(&self) -> bool {
        self.expected_compose_hash.is_some()
    }

    fn is_allow_all(&self) -> bool {
        self.allowed_mrtd.is_empty()
            && self.allowed_mrenclave.is_empty()
            && self.allowed_mrsigner.is_empty()
            && self.min_isvsvn.is_none()
            && self.expected_compose_hash.is_none()
    }
}

/// Named policy describing which measurements are accepted.
#[derive(Debug, Clone)]
pub struct ClientPolicy {
    pub policy_name: String,
    pub measurement: MeasurementPolicy,
}

impl ClientPolicy {
    pub fn allow_all() -> Self {
        Self {
            policy_name: "allow-all".into(),
            measurement: MeasurementPolicy::allow_all(),
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "failed to read client policy file: {}",
                path.as_ref().display()
            )
        })?;
        Self::from_policy_text(&raw)
    }

    fn from_policy_text(raw: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(raw)
            .or_else(|_| toml::from_str(raw))
            .context("failed to parse policy (supported: JSON, TOML)")?;
        Self::from_value(value)
    }

    fn from_value(value: serde_json::Value) -> Result<Self> {
        let measurement = MeasurementPolicy {
            allowed_mrtd: value
                .get("allowed_mrtd")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str())
                        .map(|s| s.to_lowercase())
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default(),
            allowed_mrenclave: value
                .get("allowed_mrenclave")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str())
                        .map(|s| s.to_lowercase())
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default(),
            allowed_mrsigner: value
                .get("allowed_mrsigner")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str())
                        .map(|s| s.to_lowercase())
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default(),
            min_isvsvn: value
                .get("min_isvsvn")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
            expected_compose_hash: value
                .get("expected_compose_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase()),
        };

        Ok(Self {
            policy_name: value
                .get("policy_name")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string(),
            measurement,
        })
    }

    pub fn production() -> Result<Self> {
        let (path, source) = policy_file_from_env()?;
        let policy = Self::from_file(&path)?;
        policy.validate_for_mode(AttestationMode::Enforced, source)?;
        Ok(policy)
    }

    pub(crate) fn validate_for_mode(
        &self,
        mode: AttestationMode,
        policy_source: &str,
    ) -> Result<()> {
        // Enforced: allow-all is always rejected - requires real measurements.
        // Local: allow-all is also rejected - even loopback connections must
        //   have an explicit policy file so the trust boundary is auditable.
        //   Only Stub/Disabled (compile-gated to dev/test builds) may use
        //   allow-all, because they cannot appear in production binaries.
        if (mode.is_enforced() || matches!(mode, AttestationMode::Local))
            && self.measurement.is_allow_all()
        {
            bail!(
                "{} resolves to an unrestricted RA-TLS policy; {} mode requires at least one measurement or compose-hash constraint",
                policy_source,
                mode.env_name()
            );
        }
        Ok(())
    }
}

/// PEM-encoded identity bundle with parsed components for client auth.
#[derive(Debug)]
pub struct ClientIdentity {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub identity_pem: Vec<u8>,
}

fn missing_client_identity_error(attestation_mode: AttestationMode) -> anyhow::Error {
    match attestation_mode {
        AttestationMode::Enforced => {
            anyhow!("client attestation mode is enforced but client cert/key are not configured")
        }
        AttestationMode::Local => {
            anyhow!("client attestation mode is local but client cert/key are not configured")
        }
        AttestationMode::Stub | AttestationMode::Disabled => {
            anyhow!("client identity is optional in non-enforced dev modes")
        }
    }
}

pub fn parse_client_identity(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    attestation_mode: AttestationMode,
) -> Result<Option<ClientIdentity>> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            let cert_bytes = std::fs::read(cert)
                .with_context(|| format!("failed to read client cert {cert}"))?;
            let key_bytes =
                std::fs::read(key).with_context(|| format!("failed to read client key {key}"))?;
            client_identity_from_pem_bytes(&cert_bytes, &key_bytes).map(Some)
        }
        (None, None) if matches!(attestation_mode, AttestationMode::Local) => {
            bail!(missing_client_identity_error(attestation_mode))
        }
        (None, None) => Ok(None),
        _ if attestation_mode.is_enforced()
            || matches!(attestation_mode, AttestationMode::Local) =>
        {
            bail!(missing_client_identity_error(attestation_mode))
        }
        _ => Ok(None),
    }
}

pub fn parse_client_identity_from_pem(
    cert_pem: Option<&str>,
    key_pem: Option<&str>,
    attestation_mode: AttestationMode,
) -> Result<Option<ClientIdentity>> {
    match (cert_pem, key_pem) {
        (Some(cert), Some(key)) => {
            client_identity_from_pem_bytes(cert.as_bytes(), key.as_bytes()).map(Some)
        }
        (None, None) if matches!(attestation_mode, AttestationMode::Local) => {
            bail!(missing_client_identity_error(attestation_mode))
        }
        (None, None) => Ok(None),
        _ if attestation_mode.is_enforced()
            || matches!(attestation_mode, AttestationMode::Local) =>
        {
            bail!(missing_client_identity_error(attestation_mode))
        }
        _ => Ok(None),
    }
}

fn client_identity_from_pem_bytes(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<ClientIdentity> {
    let certs = parse_cert_chain(cert_bytes).context("failed to parse client certificate chain")?;
    let key = parse_private_key(key_bytes).context("failed to parse client private key")?;

    let mut pem_bundle = cert_bytes.to_vec();
    pem_bundle.extend_from_slice(key_bytes);

    Ok(ClientIdentity {
        cert_chain: certs,
        private_key: key,
        identity_pem: pem_bundle,
    })
}

pub fn build_rustls_client_config(
    policy: ClientPolicy,
    subject_allowlist: Option<HashSet<String>>,
    pccs_url: Option<String>,
    client_identity: Option<&ClientIdentity>,
) -> Result<Arc<ClientConfig>> {
    let base_builder = ClientConfig::builder().with_root_certificates(RootCertStore::empty());

    let mut tls_config = if let Some(identity) = client_identity {
        base_builder
            .with_client_auth_cert(
                identity.cert_chain.clone(),
                identity.private_key.clone_key(),
            )
            .context("failed to configure client certificate for attested client")?
    } else {
        base_builder.with_no_client_auth()
    };

    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(RaTlsServerVerifier::new(
            policy,
            subject_allowlist,
            pccs_url,
        )));

    Ok(Arc::new(tls_config))
}

pub fn load_policy_from_env(mode: AttestationMode) -> Result<ClientPolicy> {
    match policy_file_from_env() {
        Ok((path, source)) => {
            let policy = ClientPolicy::from_file(path)?;
            policy.validate_for_mode(mode, source)?;
            Ok(policy)
        }
        Err(err) if mode.is_non_production() => {
            warn!(
                mode = ?mode,
                error = %err,
                "No RA-TLS policy file configured; explicit non-production mode is using allow-all measurements",
            );
            Ok(ClientPolicy::allow_all())
        }
        Err(err) => Err(anyhow!("{}", err)),
    }
}

fn policy_file_from_env() -> Result<(String, &'static str)> {
    let path = std::env::var("RATLS_CLIENT_POLICY_FILE")
        .context("RATLS_CLIENT_POLICY_FILE must be set when RA-TLS attestation is enforced")?;
    Ok((path, "RATLS_CLIENT_POLICY_FILE"))
}

fn run_attestation_verification<T>(
    future: impl Future<Output = Result<T>>,
) -> Result<T, RustlsError> {
    let handle = Handle::try_current().map_err(|err| {
        RustlsError::General(format!("RA-TLS verification requires Tokio runtime: {err}"))
    })?;

    match handle.runtime_flavor() {
        RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| handle.block_on(future))
            .map_err(|err| RustlsError::General(err.to_string())),
        RuntimeFlavor::CurrentThread => Err(RustlsError::General(
            "RA-TLS verification requires a multi-thread Tokio runtime".into(),
        )),
        _ => Err(RustlsError::General(
            "RA-TLS verification requires a supported Tokio runtime".into(),
        )),
    }
}

#[derive(Debug)]
struct RaTlsServerVerifier {
    policy: ClientPolicy,
    subject_allowlist: Option<HashSet<String>>,
    pccs_url: Option<String>,
}

impl RaTlsServerVerifier {
    fn new(
        policy: ClientPolicy,
        subject_allowlist: Option<HashSet<String>>,
        pccs_url: Option<String>,
    ) -> Self {
        Self {
            policy,
            subject_allowlist,
            pccs_url,
        }
    }
}

impl ServerCertVerifier for RaTlsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let certificate = CertificateDer::from(end_entity.as_ref().to_vec());
        let policy = self.policy.clone();
        let allowlist = self.subject_allowlist.clone();
        let pccs_url = self.pccs_url.clone();

        let result = run_attestation_verification(verify_peer_certificate_async(
            certificate,
            policy,
            allowlist,
            pccs_url,
        ));

        match result {
            Ok(identity) => {
                info!(
                    subject = identity.subject.as_deref().unwrap_or("<unknown>"),
                    compose_hash = identity.compose_hash.as_deref().unwrap_or("<none>"),
                    tee_kind = identity.tee_kind,
                    "RA-TLS server verified"
                );
                Ok(ServerCertVerified::assertion())
            }
            Err(err) => {
                warn!(error = %err, "RA-TLS server verification failed");
                Err(RustlsError::General(format!(
                    "RA-TLS verification failed: {err}"
                )))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "unexpected TLS 1.2 signature verification call".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "unexpected TLS 1.3 signature verification call".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

struct VerifiedIdentity {
    subject: Option<String>,
    compose_hash: Option<String>,
    tee_kind: &'static str,
}

fn normalize_spiffe_id(uri: &str) -> Option<String> {
    if !uri.starts_with("spiffe://") {
        return None;
    }
    let rest = &uri[9..];
    let slash = rest.find('/')?;
    let trust_domain = &rest[..slash];
    let path = &rest[slash..];
    if trust_domain.is_empty() || !path.starts_with('/') {
        return None;
    }
    Some(format!(
        "spiffe://{}{}",
        trust_domain.to_ascii_lowercase(),
        path
    ))
}

fn certificate_principal(cert: &X509Certificate<'_>) -> Option<String> {
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for general_name in san.value.general_names.iter() {
            if let GeneralName::URI(uri) = general_name {
                if let Some(spiffe) = normalize_spiffe_id(uri) {
                    return Some(spiffe);
                }
            }
        }
    }

    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|value| value.to_string())
}

fn enforce_subject_allowlist(
    cert: &X509Certificate<'_>,
    allowlist: &HashSet<String>,
) -> Result<Option<String>> {
    let subject = certificate_principal(cert).ok_or_else(|| {
        anyhow!("peer certificate missing SPIFFE URI SAN or subject CN while a subject allowlist is configured")
    })?;
    let lower = subject.trim().to_lowercase();
    if !allowlist.contains(&lower) {
        bail!("peer principal '{subject}' not allowlisted");
    }
    Ok(Some(subject))
}

pub(crate) const AMD_RATLS_BASELINE_ONLY_MESSAGE: &str =
    "AMD SEV-SNP attestation requires the documented Aleph launch-measure flow and local identity path; this local compatibility channel is not full verified-attestation parity";

pub(crate) fn reject_unsupported_verified_ratls_vendor(vendor: TEEVendor) -> Result<()> {
    if matches!(vendor, TEEVendor::AmdSevSnp) {
        bail!(AMD_RATLS_BASELINE_ONLY_MESSAGE);
    }
    Ok(())
}

async fn verify_peer_certificate_async(
    certificate: CertificateDer<'static>,
    policy: ClientPolicy,
    subject_allowlist: Option<HashSet<String>>,
    pccs_url: Option<String>,
) -> Result<VerifiedIdentity> {
    let (_, cert) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|err| anyhow!("failed to parse X.509 certificate: {err}"))?;

    let subject = if let Some(allowlist) = &subject_allowlist {
        enforce_subject_allowlist(&cert, allowlist)?
    } else {
        certificate_principal(&cert)
    };

    let attestation = Attestation::from_der(certificate.as_ref())
        .context("certificate missing RA-TLS attestation extensions")?
        .ok_or_else(|| anyhow!("certificate does not contain RA-TLS attestation"))?;
    let vendor = attestation
        .detect_vendor_from_quote()
        .context("failed to classify RA-TLS quote vendor")?;
    reject_unsupported_verified_ratls_vendor(vendor)?;

    let spki = cert.public_key();
    let pubkey = spki.subject_public_key.data.to_vec();

    let verified = attestation
        .verify_with_ra_pubkey(&pubkey, pccs_url.as_deref())
        .await
        .context("RA-TLS attestation verification failed")?;

    let compose_hash = verified
        .decode_compose_hash()
        .ok()
        .filter(|hash| !hash.is_empty());

    if policy.measurement.expects_compose_hash() {
        let compose_hash = compose_hash
            .as_deref()
            .ok_or_else(|| anyhow!("attestation missing compose hash while policy requires it"))?;
        if !policy.measurement.allows_compose_hash(compose_hash) {
            bail!("compose hash '{compose_hash}' rejected by policy");
        }
    } else if let Some(hash) = compose_hash.as_deref() {
        if !policy.measurement.allows_compose_hash(hash) {
            bail!("compose hash '{hash}' rejected by policy");
        }
    }

    let tee_kind = enforce_measurement_policy(&policy.measurement, &verified)?;

    Ok(VerifiedIdentity {
        subject,
        compose_hash,
        tee_kind,
    })
}

fn enforce_measurement_policy(
    policy: &MeasurementPolicy,
    verified: &VerifiedAttestation,
) -> Result<&'static str> {
    match &verified.report.report {
        Report::TD10(td10) => {
            let mrtd = hex::encode(td10.mr_td);
            if !policy.allows_tdx_mrtd(&mrtd) {
                bail!("TDX MR_TD {mrtd} rejected by policy");
            }
            Ok("tdx")
        }
        Report::TD15(td15) => {
            let mrtd = hex::encode(td15.base.mr_td);
            if !policy.allows_tdx_mrtd(&mrtd) {
                bail!("TDX (TD15) MR_TD {mrtd} rejected by policy");
            }
            Ok("tdx")
        }
        Report::SgxEnclave(enclave) => {
            let mrenclave = hex::encode(enclave.mr_enclave);
            let mrsigner = hex::encode(enclave.mr_signer);
            if !policy.allows_sgx_measurements(&mrenclave, &mrsigner, enclave.isv_svn) {
                bail!(
                    "SGX measurements rejected (mrenclave={mrenclave}, mrsigner={mrsigner}, isv_svn={})",
                    enclave.isv_svn
                );
            }
            Ok("sgx")
        }
    }
}

fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = Cursor::new(pem);
    let mut certs = Vec::new();
    for item in read_all(&mut cursor) {
        match item? {
            Item::X509Certificate(cert) => certs.push(cert.into_owned()),
            _ => continue,
        }
    }

    if certs.is_empty() {
        bail!("no certificates found in client cert bundle");
    }

    Ok(certs)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    for item in read_all(&mut cursor) {
        match item? {
            Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Sec1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            _ => continue,
        }
    }

    bail!("no supported private key found in PEM bundle")
}

#[cfg(test)]
mod tests {
    use super::{
        certificate_principal, enforce_subject_allowlist, load_policy_from_env,
        reject_unsupported_verified_ratls_vendor, run_attestation_verification, AttestationMode,
        ClientPolicy, AMD_RATLS_BASELINE_ONLY_MESSAGE,
    };
    use crate::ra_tls::vendor::TEEVendor;
    use crate::test_support::env_lock;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::pki_types::CertificateDer;
    use std::collections::HashSet;
    use tempfile::tempdir;
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn write_policy_file(contents: &str) -> tempfile::TempDir {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("policy.json"), contents).expect("write policy");
        dir
    }

    fn issue_test_cert(
        common_name: Option<&str>,
        spiffe_id: Option<&str>,
    ) -> CertificateDer<'static> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("client key");
        let mut params = CertificateParams::new(vec![]).expect("client params");
        let mut dn = DistinguishedName::new();
        if let Some(common_name) = common_name {
            dn.push(DnType::CommonName, common_name);
        }
        params.distinguished_name = dn;
        if let Some(spiffe_id) = spiffe_id {
            params.subject_alt_names = vec![rcgen::SanType::URI(
                spiffe_id.try_into().expect("spiffe uri"),
            )];
        }
        let cert = params.self_signed(&key).expect("client cert");
        CertificateDer::from(cert.der().to_vec())
    }

    fn parse_test_cert<'a>(cert: &'a CertificateDer<'static>) -> X509Certificate<'a> {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref()).expect("parse x509");
        parsed
    }

    #[test]
    fn enforced_mode_rejects_unrestricted_policy_file() {
        let _guard = env_lock();
        let dir = write_policy_file("{}");
        let path = dir.path().join("policy.json");
        std::env::set_var("RATLS_CLIENT_POLICY_FILE", &path);

        let err = load_policy_from_env(AttestationMode::Enforced)
            .expect_err("enforced mode must reject an unrestricted policy");
        assert!(err
            .to_string()
            .contains("requires at least one measurement or compose-hash constraint"));

        std::env::remove_var("RATLS_CLIENT_POLICY_FILE");
    }

    #[test]
    fn local_mode_defaults_to_allow_all_without_policy_file() {
        let _guard = env_lock();
        std::env::remove_var("RATLS_CLIENT_POLICY_FILE");

        let policy = load_policy_from_env(AttestationMode::Local)
            .expect("local mode should allow an explicit non-production policy");
        assert_eq!(policy.policy_name, ClientPolicy::allow_all().policy_name);
    }

    #[test]
    fn attestation_runtime_bridge_rejects_current_thread_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");

        let err = runtime.block_on(async {
            run_attestation_verification(async { Ok::<_, anyhow::Error>(()) })
                .expect_err("current-thread runtime must fail closed")
        });

        assert!(err.to_string().contains("multi-thread Tokio runtime"));
    }

    #[test]
    fn attestation_runtime_bridge_runs_on_multi_thread_runtime() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("multi-thread runtime");

        let value = runtime.block_on(async {
            run_attestation_verification(async { Ok::<_, anyhow::Error>(7u8) })
                .expect("multi-thread runtime should support RA-TLS verification")
        });

        assert_eq!(value, 7);
    }

    #[test]
    fn amd_vendor_is_rejected_with_baseline_only_message() {
        let err = reject_unsupported_verified_ratls_vendor(TEEVendor::AmdSevSnp)
            .expect_err("amd vendor must be fenced from full verified RA-TLS parity");
        assert!(err.to_string().contains(AMD_RATLS_BASELINE_ONLY_MESSAGE));
    }

    #[test]
    fn intel_vendors_remain_supported() {
        reject_unsupported_verified_ratls_vendor(TEEVendor::IntelTDX)
            .expect("intel TDX should remain eligible");
        reject_unsupported_verified_ratls_vendor(TEEVendor::IntelSGX)
            .expect("intel SGX should remain eligible");
    }

    #[test]
    fn certificate_principal_prefers_spiffe_uri_san() {
        let cert = issue_test_cert(
            Some("ignored-common-name"),
            Some("spiffe://secretbroker.local/tor-auth"),
        );
        let parsed = parse_test_cert(&cert);
        assert_eq!(
            certificate_principal(&parsed).as_deref(),
            Some("spiffe://secretbroker.local/tor-auth")
        );
    }

    #[test]
    fn subject_allowlist_accepts_spiffe_uri_san_without_cn() {
        let cert = issue_test_cert(None, Some("spiffe://secretbroker.local/tenant-lifecycle"));
        let parsed = parse_test_cert(&cert);
        let allowlist =
            HashSet::from([String::from("spiffe://secretbroker.local/tenant-lifecycle")]);

        let principal = enforce_subject_allowlist(&parsed, &allowlist)
            .expect("SPIFFE URI SAN should satisfy allowlist without a CN");

        assert_eq!(
            principal.as_deref(),
            Some("spiffe://secretbroker.local/tenant-lifecycle")
        );
    }

    #[test]
    fn subject_allowlist_rejects_non_allowlisted_principal() {
        let cert = issue_test_cert(Some("tenant-lifecycle"), None);
        let parsed = parse_test_cert(&cert);
        let allowlist = HashSet::from([String::from("spiffe://secretbroker.local/admin-control")]);

        let err = enforce_subject_allowlist(&parsed, &allowlist)
            .expect_err("principal outside the allowlist must fail closed");

        assert!(err
            .to_string()
            .contains("peer principal 'tenant-lifecycle' not allowlisted"));
    }

    #[test]
    fn subject_allowlist_rejects_cert_without_cn_or_spiffe() {
        let cert = issue_test_cert(None, None);
        let parsed = parse_test_cert(&cert);
        let allowlist = HashSet::from([String::from("spiffe://secretbroker.local/admin-control")]);

        let err = enforce_subject_allowlist(&parsed, &allowlist)
            .expect_err("missing CN and SPIFFE URI SAN must fail closed");

        assert!(err
            .to_string()
            .contains("missing SPIFFE URI SAN or subject CN"));
    }
}
