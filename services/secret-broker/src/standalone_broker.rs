use std::env;
use std::fs;
use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, bail, Context, Result};
use futures::{stream::FuturesUnordered, Stream};
use pin_project::pin_project;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, read_all, Item};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{server::Connected, Server};
use tracing::info;
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::secret_broker_impl::{
    broker_state_from_env, discharge_attestation_required_from_env, BrokerClientContext,
    SecretBrokerState,
};
use crate::secret_broker_proto::secret_broker_service_server::SecretBrokerServiceServer;
use crate::secret_broker_server_impl::SecretBrokerGrpc;

const DEFAULT_STANDALONE_BROKER_BIND_ADDR: &str = "127.0.0.1:50052";
const BROKER_TLS_CERT_ENV: &str = "SECRET_BROKER_TLS_CERT";
const BROKER_TLS_KEY_ENV: &str = "SECRET_BROKER_TLS_KEY";
const BROKER_TLS_CA_CERT_ENV: &str = "SECRET_BROKER_TLS_CA_CERT";
const TLS_EXPORTER_LABEL: &[u8] = b"SECRET_BROKER_EXPORTER";
const TLS_EXPORTER_CONTEXT: &[u8] = b"secret-broker-attestation";

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

fn principal_id_from_peer_cert(cert: &CertificateDer<'_>) -> Result<Option<String>> {
    let (_, cert) = parse_x509_certificate(cert.as_ref())
        .map_err(|err| anyhow!("failed to parse peer X.509 certificate: {err}"))?;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for general_name in san.value.general_names.iter() {
            if let GeneralName::URI(uri) = general_name {
                if let Some(spiffe) = normalize_spiffe_id(uri) {
                    return Ok(Some(spiffe));
                }
            }
        }
    }
    Ok(None)
}

fn peer_cert_sha256(cert: &CertificateDer<'_>) -> Vec<u8> {
    Sha256::digest(cert.as_ref()).to_vec()
}

fn standalone_broker_pccs_url() -> Option<String> {
    env::var("SECRET_BROKER_PCCS_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn standalone_broker_require_attestation() -> Result<bool> {
    let value = match env::var("SECRET_BROKER_REQUIRE_ATTESTATION") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(true),
        Err(error) => {
            return Err(error).context("failed to read SECRET_BROKER_REQUIRE_ATTESTATION")
        }
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!(
            "SECRET_BROKER_REQUIRE_ATTESTATION must be one of true, false, 1, 0, yes, no, on, or off"
        ),
    }
}

async fn attestation_digest_from_peer_cert(
    cert: &CertificateDer<'_>,
    pccs_url: Option<&str>,
) -> Result<Option<Vec<u8>>> {
    crate::tls_setup::attestation_digest_from_cert(cert, pccs_url)
        .await
        .map(|digest| digest.map(|value| value.to_vec()))
}

fn enforce_standalone_peer_attestation_digest(
    attestation_digest: Option<Vec<u8>>,
    require_attestation: bool,
) -> Result<Option<Vec<u8>>> {
    if require_attestation && attestation_digest.is_none() {
        bail!("standalone broker peer certificate is missing required RA-TLS attestation evidence")
    }
    Ok(attestation_digest)
}

async fn broker_context_from_tls_connection(
    server_conn: &rustls::ServerConnection,
    session_id: Uuid,
    principal_requirement: &str,
    attestation_requirement: &str,
    require_attestation: bool,
) -> Result<BrokerClientContext> {
    let mut exporter = [0u8; 32];
    server_conn
        .export_keying_material(
            &mut exporter,
            TLS_EXPORTER_LABEL,
            Some(TLS_EXPORTER_CONTEXT),
        )
        .map_err(|_| anyhow!("unable to derive standalone broker TLS exporter"))?;

    let cert = server_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| {
            anyhow!("standalone broker mTLS session is missing the authenticated peer certificate")
        })?;

    let principal_id = principal_id_from_peer_cert(cert)?
        .ok_or_else(|| anyhow!("standalone broker {}", principal_requirement))?;
    let pccs_url = standalone_broker_pccs_url();
    let attestation_digest = attestation_digest_from_peer_cert(cert, pccs_url.as_deref())
        .await
        .with_context(|| attestation_requirement.to_string())?;
    let attestation_digest =
        enforce_standalone_peer_attestation_digest(attestation_digest, require_attestation)?;

    Ok(BrokerClientContext::from_tls_exporter(
        exporter,
        Some(session_id),
        Some(principal_id),
        Some(peer_cert_sha256(cert)),
        attestation_digest,
    ))
}

fn validate_attestation_scope(
    bind_addr: SocketAddr,
    require_peer_attestation: bool,
    require_discharge_attestation: bool,
) -> Result<()> {
    if !bind_addr.ip().is_loopback()
        && (!require_peer_attestation || !require_discharge_attestation)
    {
        bail!(
            "attestation relaxation is permitted only on a loopback bind; non-loopback secret-broker listeners require peer and discharge attestation"
        );
    }
    Ok(())
}

pub async fn run_from_env() -> Result<()> {
    let bind_addr = env::var("SECRET_BROKER_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_STANDALONE_BROKER_BIND_ADDR.to_string())
        .parse::<SocketAddr>()
        .context("invalid SECRET_BROKER_BIND_ADDR")?;
    let require_peer_attestation = standalone_broker_require_attestation()?;
    let require_discharge_attestation = discharge_attestation_required_from_env()?;
    validate_attestation_scope(
        bind_addr,
        require_peer_attestation,
        require_discharge_attestation,
    )?;

    let broker = broker_state_from_env(require_discharge_attestation).await?;
    let state = Arc::new(SecretBrokerState { broker });
    let grpc = SecretBrokerGrpc::new(state);
    let tls_config = Arc::new(load_server_tls_config_from_env()?);
    let incoming = bind_tls_incoming(bind_addr, tls_config, require_peer_attestation).await?;

    info!(%bind_addr, "standalone secret-broker listening");

    Server::builder()
        .add_service(SecretBrokerServiceServer::new(grpc))
        .serve_with_incoming(incoming)
        .await
        .context("standalone secret-broker gRPC server terminated")
}

#[derive(Clone, Debug)]
struct StandaloneTlsBundle {
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    ca_cert_path: PathBuf,
}

fn load_server_tls_config_from_env() -> Result<ServerConfig> {
    let bundle = tls_bundle_from_env()?;
    let server_cert_pem = fs::read(&bundle.server_cert_path).with_context(|| {
        format!(
            "failed to read broker server certificate from {}",
            bundle.server_cert_path.display()
        )
    })?;
    let server_key_pem = fs::read(&bundle.server_key_path).with_context(|| {
        format!(
            "failed to read broker server private key from {}",
            bundle.server_key_path.display()
        )
    })?;
    let ca_cert_pem = fs::read(&bundle.ca_cert_path).with_context(|| {
        format!(
            "failed to read broker client CA certificate from {}",
            bundle.ca_cert_path.display()
        )
    })?;

    let cert_chain = load_cert_chain_from_pem(&server_cert_pem)?;
    let private_key = load_private_key_from_pem(&server_key_pem)?;
    let client_roots = load_root_store_from_pem(&ca_cert_pem)?;
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .context("failed to build broker client certificate verifier")?;

    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to set broker TLS protocol versions")?
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(cert_chain, private_key)
    .context("failed to build standalone broker ServerConfig")?;
    config.alpn_protocols = vec![b"h2".to_vec()];

    info!(
        cert_path = %bundle.server_cert_path.display(),
        key_path = %bundle.server_key_path.display(),
        ca_path = %bundle.ca_cert_path.display(),
        "loaded standalone broker TLS identity bundle"
    );

    Ok(config)
}

fn tls_bundle_from_env() -> Result<StandaloneTlsBundle> {
    Ok(StandaloneTlsBundle {
        server_cert_path: required_env_path(BROKER_TLS_CERT_ENV)?,
        server_key_path: required_env_path(BROKER_TLS_KEY_ENV)?,
        ca_cert_path: required_env_path(BROKER_TLS_CA_CERT_ENV)?,
    })
}

fn required_env_path(key: &str) -> Result<PathBuf> {
    let value = env::var(key).with_context(|| format!("{key} is required"))?;
    if value.trim().is_empty() {
        bail!("{key} must not be empty");
    }
    Ok(PathBuf::from(value))
}

fn load_cert_chain_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chain = certs(&mut Cursor::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM bundle")?;
    if chain.is_empty() {
        return Err(anyhow!(
            "certificate PEM bundle did not contain any certificates"
        ));
    }
    Ok(chain)
}

fn load_private_key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    for item in read_all(&mut cursor) {
        match item.context("failed to parse private key PEM bundle")? {
            Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Sec1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            _ => continue,
        }
    }

    Err(anyhow!(
        "private key PEM bundle did not contain a supported private key"
    ))
}

fn load_root_store_from_pem(pem: &[u8]) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let roots = certs(&mut Cursor::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse CA PEM bundle")?;
    if roots.is_empty() {
        return Err(anyhow!("CA PEM bundle did not contain any certificates"));
    }
    for cert in roots {
        root_store
            .add(cert)
            .map_err(|err| anyhow!("failed to add CA cert to root store: {err}"))?;
    }
    Ok(root_store)
}

async fn bind_tls_incoming(
    bind_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    require_attestation: bool,
) -> Result<BrokerTlsIncoming> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind standalone broker listener on {bind_addr}"))?;
    let acceptor = TlsAcceptor::from(server_config);
    Ok(BrokerTlsIncoming::new(
        listener,
        acceptor,
        require_attestation,
    ))
}

#[pin_project]
struct BrokerTlsStream {
    #[pin]
    inner: TlsStream<TcpStream>,
    context: BrokerClientContext,
}

impl BrokerTlsStream {
    fn new(inner: TlsStream<TcpStream>, context: BrokerClientContext) -> Self {
        Self { inner, context }
    }
}

impl tokio::io::AsyncRead for BrokerTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BrokerTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl Connected for BrokerTlsStream {
    type ConnectInfo = BrokerClientContext;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.context.clone()
    }
}

#[pin_project]
struct BrokerTlsIncoming {
    #[pin]
    incoming: TcpListenerStream,
    acceptor: TlsAcceptor,
    require_attestation: bool,
    #[pin]
    pending: FuturesUnordered<HandshakeFuture>,
}

type HandshakeFuture =
    Pin<Box<dyn futures::Future<Output = Result<BrokerTlsStream, io::Error>> + Send>>;

impl BrokerTlsIncoming {
    fn new(listener: TcpListener, acceptor: TlsAcceptor, require_attestation: bool) -> Self {
        Self {
            incoming: TcpListenerStream::new(listener),
            acceptor,
            require_attestation,
            pending: FuturesUnordered::new(),
        }
    }
}

impl Stream for BrokerTlsIncoming {
    type Item = Result<BrokerTlsStream, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if let Poll::Ready(Some(result)) = this.pending.as_mut().poll_next(cx) {
            return Poll::Ready(Some(result));
        }

        match this.incoming.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                let acceptor = this.acceptor.clone();
                let require_attestation = *this.require_attestation;
                this.pending.push(Box::pin(async move {
                    let tls_stream = acceptor.accept(stream).await.map_err(io::Error::other)?;

                    let (_, server_conn) = tls_stream.get_ref();
                    let context = broker_context_from_tls_connection(
                        server_conn,
                        Uuid::new_v4(),
                        "peer certificate must carry a SPIFFE URI SAN",
                        "failed to derive standalone broker peer attestation digest",
                        require_attestation,
                    )
                    .await
                    .map_err(io::Error::other)?;

                    Ok(BrokerTlsStream::new(tls_stream, context))
                }));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => {
                if let Poll::Ready(result) = this.pending.as_mut().poll_next(cx) {
                    return Poll::Ready(result);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        enforce_standalone_peer_attestation_digest, principal_id_from_peer_cert,
        validate_attestation_scope,
    };
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::pki_types::CertificateDer;

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
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        if let Some(spiffe_id) = spiffe_id {
            params.subject_alt_names = vec![rcgen::SanType::URI(
                spiffe_id.try_into().expect("spiffe uri"),
            )];
        }
        let cert = params.self_signed(&key).expect("client cert");
        CertificateDer::from(cert.der().to_vec())
    }

    #[test]
    fn principal_id_from_peer_cert_prefers_spiffe_uri() {
        let cert = issue_test_cert(
            Some("ignored-common-name"),
            Some("spiffe://secretbroker.local/secret-broker-client/test"),
        );
        let principal = principal_id_from_peer_cert(&cert).expect("parse cert");
        assert_eq!(
            principal.as_deref(),
            Some("spiffe://secretbroker.local/secret-broker-client/test")
        );
    }

    #[test]
    fn principal_id_from_peer_cert_rejects_cn_only_cert() {
        let cert = issue_test_cert(Some("ignored-common-name"), None);
        let principal = principal_id_from_peer_cert(&cert).expect("parse cert");
        assert!(
            principal.is_none(),
            "CN-only certificate must not authenticate broker principal"
        );
    }

    #[test]
    fn principal_id_from_peer_cert_rejects_spiffe_without_workload_path() {
        let cert = issue_test_cert(
            Some("ignored-common-name"),
            Some("spiffe://secretbroker.local"),
        );
        let principal = principal_id_from_peer_cert(&cert).expect("parse cert");
        assert!(
            principal.is_none(),
            "SPIFFE URI SAN without a workload path must not authenticate broker principal"
        );
    }

    #[test]
    fn attestation_relaxation_is_loopback_only() {
        let loopback = "127.0.0.1:50052".parse().expect("loopback socket");
        validate_attestation_scope(loopback, false, false)
            .expect("loopback mTLS may omit attestation for local proof");

        let network = "0.0.0.0:50052".parse().expect("network socket");
        let err = validate_attestation_scope(network, false, true)
            .expect_err("non-loopback peer-attestation relaxation must fail");
        assert!(err.to_string().contains("loopback"));
        assert!(validate_attestation_scope(network, true, false).is_err());
        validate_attestation_scope(network, true, true)
            .expect("non-loopback fully attested mode must be accepted");
    }

    #[test]
    fn standalone_attestation_policy_requires_digest_when_configured() {
        let err = enforce_standalone_peer_attestation_digest(None, true)
            .expect_err("missing attestation digest must fail when attestation is required");
        assert!(err
            .to_string()
            .contains("missing required RA-TLS attestation evidence"));
    }

    #[test]
    fn standalone_attestation_policy_allows_missing_digest_when_relaxed() {
        let digest = enforce_standalone_peer_attestation_digest(None, false)
            .expect("missing digest should remain allowed in loopback relaxed mode");
        assert!(digest.is_none());

        let present = enforce_standalone_peer_attestation_digest(Some(vec![1u8; 32]), true)
            .expect("present digest should satisfy attestation policy");
        assert_eq!(present, Some(vec![1u8; 32]));
    }
}
