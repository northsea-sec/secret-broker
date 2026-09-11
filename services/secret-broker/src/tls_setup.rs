//! RA-TLS certificate evidence helpers used by the standalone broker boundary.

use std::io::Cursor;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

use crate::ra_tls::attestation::Attestation;
use crate::ra_tls::qvl::quote::Report;
use crate::service_auth::ratls::reject_unsupported_verified_ratls_vendor;

pub async fn attestation_digest_from_cert(
    cert: &CertificateDer<'_>,
    pccs_url: Option<&str>,
) -> Result<Option<[u8; 32]>> {
    let attestation = match Attestation::from_der(cert.as_ref())
        .context("failed to parse RA-TLS attestation extensions")?
    {
        Some(attestation) => attestation,
        None => return Ok(None),
    };
    let vendor = attestation
        .detect_vendor_from_quote()
        .context("failed to classify RA-TLS quote vendor while deriving digest")?;
    reject_unsupported_verified_ratls_vendor(vendor)
        .context("unsupported RA-TLS vendor for attestation digest derivation")?;

    let (_, parsed_cert) = parse_x509_certificate(cert.as_ref()).map_err(|error| {
        anyhow!("failed to parse X.509 certificate for attestation digest: {error}")
    })?;
    let public_key = parsed_cert.public_key().subject_public_key.data.to_vec();
    let verified = attestation
        .verify_with_ra_pubkey(&public_key, pccs_url)
        .await
        .context("RA-TLS attestation verification failed while deriving digest")?;

    let mut hasher = Sha256::new();
    match &verified.report.report {
        Report::TD10(td10) => {
            hasher.update(b"tdx");
            hasher.update(hex::encode(td10.mr_td));
        }
        Report::TD15(td15) => {
            hasher.update(b"tdx");
            hasher.update(hex::encode(td15.base.mr_td));
        }
        Report::SgxEnclave(enclave) => {
            hasher.update(b"sgx");
            hasher.update(hex::encode(enclave.mr_enclave));
            hasher.update(hex::encode(enclave.mr_signer));
            hasher.update(enclave.isv_svn.to_string());
        }
    }
    if let Some(compose_hash) = verified
        .decode_compose_hash()
        .ok()
        .filter(|value| !value.is_empty())
    {
        hasher.update(b"compose");
        hasher.update(compose_hash.to_ascii_lowercase());
    }

    Ok(Some(hasher.finalize().into()))
}

pub async fn attestation_digest_from_pem_bundle(
    pem_bundle: &[u8],
    pccs_url: Option<&str>,
) -> Result<Option<[u8; 32]>> {
    let cert = certs(&mut Cursor::new(pem_bundle))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM bundle for attestation digest")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("certificate PEM bundle did not contain any certificates"))?;
    attestation_digest_from_cert(&cert, pccs_url).await
}
