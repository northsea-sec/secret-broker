//! RA-TLS attestation verification using Intel DCAP quote validation.
//!
//! The implementation has no dependency on a vendored platform source tree. The only
//! third-party dependency is the `dcap-qvl` crate published on crates.io,
//! which implements Intel DCAP quote verification in pure Rust.
//!
//! Wire format:
//! - The X.509 extension OIDs used to extract the embedded quote and event log
//!   match the publicly-documented Phala RA-TLS conventions (numeric OID arcs
//!   are public identifiers, not a code dependency).
//! - The report-data binding is sha512("ratls-cert" || ":" || peer_pubkey_der),
//!   padded/truncated to 64 bytes — matching the producer-side binding used by
//!   peers that emit RA-TLS certs in this wire format.
//!
//! Scope:
//! - Intel TDX and SGX quotes are verified end-to-end against PCCS collateral
//!   via `dcap_qvl::verify::verify`.
//! - Every unrecognized quote header is classified as unsupported. The parser
//!   does not guess a TEE vendor from bytes it cannot fully verify.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use x509_parser::der_parser::oid::Oid;
use x509_parser::prelude::{FromDer, X509Certificate};

// Phala RA-TLS X.509 extension OIDs (1.3.6.1.4.1.62397.1.{1,2}). These are
// public numeric identifiers; matching them here does not introduce any code
// dependency on Phala's crates.
const PHALA_RATLS_QUOTE_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 1];
const PHALA_RATLS_EVENT_LOG_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 2];

// Report-data binding tag for RA-TLS certs.
const RA_TLS_BINDING_TAG: &[u8] = b"ratls-cert";

pub mod vendor {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TEEVendor {
        UnsupportedQuoteFormat,
        IntelTDX,
        IntelSGX,
    }
}

pub mod qvl {
    pub mod quote {
        // The variant names of dcap-qvl Report (TD10/TD15/SgxEnclave) and
        // the inner-type field names (mr_td / base.mr_td / mr_enclave /
        // mr_signer / isv_svn) match the call-site pattern-match shape, so
        // we re-export Report directly with no aliasing.
        pub use dcap_qvl::quote::Report;
    }
}

pub mod attestation {
    use super::*;
    use vendor::TEEVendor;

    /// Attestation extracted from a peer's RA-TLS certificate. Holds the raw
    /// quote bytes and (optionally) the TDX event log.
    #[derive(Debug, Clone)]
    pub struct Attestation {
        quote: Vec<u8>,
        raw_event_log: Vec<u8>,
    }

    /// Successful verification result. The `report` field holds the
    /// `dcap_qvl::verify::VerifiedReport`, which itself exposes
    /// `report: dcap_qvl::quote::Report`. Call-sites access the inner enum
    /// as `verified.report.report`.
    #[derive(Debug, Clone)]
    pub struct VerifiedAttestation {
        pub report: dcap_qvl::verify::VerifiedReport,
        raw_event_log: Vec<u8>,
    }

    impl Attestation {
        /// Parse a peer X.509 certificate and extract the RA-TLS quote +
        /// event-log extensions. Returns `Ok(None)` when the certificate has
        /// no PHALA_RATLS_QUOTE extension (caller decides whether absence is
        /// a hard error or allowed under an `attestation_optional` policy).
        pub fn from_der(cert_der: &[u8]) -> Result<Option<Self>> {
            let (_, cert) = X509Certificate::from_der(cert_der)
                .map_err(|err| anyhow!("failed to parse X.509 certificate: {err}"))?;
            let Some(quote) = get_extension_octets(&cert, PHALA_RATLS_QUOTE_OID)? else {
                return Ok(None);
            };
            let raw_event_log =
                get_extension_octets(&cert, PHALA_RATLS_EVENT_LOG_OID)?.unwrap_or_default();
            Ok(Some(Self {
                quote,
                raw_event_log,
            }))
        }

        /// Classify the TEE vendor from the leading bytes of the quote.
        ///
        /// Intel SGX/TDX quotes start with a version u16 LE in
        /// {3, 4, 5} and have a tee_type u32 LE at offset 4. Every other
        /// header is unsupported because this implementation cannot verify it.
        pub fn detect_vendor_from_quote(&self) -> Result<TEEVendor> {
            if self.quote.len() < 8 {
                bail!(
                    "quote too short ({} bytes) to determine vendor",
                    self.quote.len()
                );
            }
            let version = u16::from_le_bytes([self.quote[0], self.quote[1]]);
            let tee_type =
                u32::from_le_bytes([self.quote[4], self.quote[5], self.quote[6], self.quote[7]]);
            const TEE_TYPE_SGX: u32 = 0x0000_0000;
            const TEE_TYPE_TDX: u32 = 0x0000_0081;
            match (version, tee_type) {
                (3, TEE_TYPE_SGX) => Ok(TEEVendor::IntelSGX),
                (4 | 5, TEE_TYPE_TDX) => Ok(TEEVendor::IntelTDX),
                (4 | 5, TEE_TYPE_SGX) => Ok(TEEVendor::IntelSGX),
                _ => Ok(TEEVendor::UnsupportedQuoteFormat),
            }
        }

        /// Verify a supported Intel quote against PCS collateral and check that
        /// its `report_data` is bound to the peer certificate public key.
        pub async fn verify_with_ra_pubkey(
            &self,
            pubkey_der: &[u8],
            pccs_url: &str,
        ) -> Result<VerifiedAttestation> {
            let vendor = self.detect_vendor_from_quote()?;
            if matches!(vendor, TEEVendor::UnsupportedQuoteFormat) {
                bail!(
                    "unsupported RA-TLS quote format; this build verifies Intel SGX and TDX DCAP evidence"
                );
            }

            // Compute the expected report_data binding. sha512 output is
            // exactly 64 bytes, matching the quote's report_data field
            // width; no padding or truncation needed.
            let mut hasher = Sha512::new();
            hasher.update(RA_TLS_BINDING_TAG);
            hasher.update(b":");
            hasher.update(pubkey_der);
            let expected_report_data: [u8; 64] = hasher.finalize().into();

            // Cheap fail-fast: compare the binding before doing any network
            // I/O for PCCS collateral.
            let actual_report_data = decode_report_data(&self.quote)
                .context("failed to decode report_data from quote for pubkey binding check")?;
            if actual_report_data != expected_report_data {
                bail!(
                    "RA-TLS quote report_data does not match peer public key binding (tag {:?})",
                    std::str::from_utf8(RA_TLS_BINDING_TAG).unwrap_or("<non-utf8>")
                );
            }

            let pccs_url = pccs_url.trim();
            if pccs_url.is_empty() {
                bail!("PCCS URL is required for RA-TLS verification");
            }

            let collateral = dcap_qvl::collateral::get_collateral(pccs_url, &self.quote)
                .await
                .context("failed to fetch quote collateral from PCCS")?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before UNIX epoch")?
                .as_secs();

            let verified = dcap_qvl::verify::verify(&self.quote, &collateral, now)
                .map_err(|err| anyhow!("DCAP quote verification failed: {err:?}"))?;

            Ok(VerifiedAttestation {
                report: verified,
                raw_event_log: self.raw_event_log.clone(),
            })
        }
    }

    impl VerifiedAttestation {
        /// Decode the compose hash from the TDX event log. The event log is
        /// a JSON-encoded array of `TdxEventLog` records emitted by
        /// cc-eventlog on the producer side; we mirror that wire format
        /// here without depending on cc-eventlog as a crate.
        ///
        /// Returns `Err` if the event log is absent, malformed, or has no
        /// `compose-hash` / `upgraded-app-id` record under IMR 3.
        pub fn decode_compose_hash(&self) -> Result<String> {
            if self.raw_event_log.is_empty() {
                bail!("event log missing — cannot decode compose hash");
            }
            #[derive(Deserialize)]
            struct TdxEventLog {
                imr: u32,
                event: String,
                #[serde(with = "serde_human_bytes")]
                event_payload: Vec<u8>,
                // The producer emits more fields (event_type, digest); we
                // ignore them here. Deserializer is non-strict by default.
            }
            let events: Vec<TdxEventLog> = serde_json::from_slice(&self.raw_event_log)
                .context("failed to parse RA-TLS event log JSON")?;
            for ev in &events {
                if ev.imr == 3 && (ev.event == "compose-hash" || ev.event == "upgraded-app-id") {
                    return Ok(hex::encode(&ev.event_payload));
                }
            }
            bail!("compose-hash event not found in event log")
        }
    }

    /// Extract the bytes of an X.509 extension matching `oid_arc`. Strips one
    /// layer of DER OCTET STRING wrapping (the producer-side wire format
    /// inserts that wrapper via `yasna::construct_der + write_bytes`).
    fn get_extension_octets(cert: &X509Certificate, oid_arc: &[u64]) -> Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid_arc).map_err(|_| anyhow!("invalid RA-TLS OID arc"))?;
        let Some(ext) = cert
            .get_extension_unique(&oid)
            .context("failed to read X.509 extension")?
        else {
            return Ok(None);
        };
        let inner = yasna::parse_der(ext.value, |reader| reader.read_bytes()).map_err(|error| {
            anyhow!("RA-TLS extension is not a valid DER OCTET STRING: {error:?}")
        })?;
        Ok(Some(inner))
    }

    /// Pull the 64-byte report_data field out of a parsed quote. dcap-qvl
    /// handles the version-specific offsets internally; we just destructure
    /// the Report enum to access the right field.
    fn decode_report_data(quote: &[u8]) -> Result<[u8; 64]> {
        let parsed = dcap_qvl::quote::Quote::parse(quote)
            .map_err(|err| anyhow!("failed to parse quote: {err:?}"))?;
        match parsed.report {
            dcap_qvl::quote::Report::SgxEnclave(r) => Ok(r.report_data),
            dcap_qvl::quote::Report::TD10(r) => Ok(r.report_data),
            dcap_qvl::quote::Report::TD15(r) => Ok(r.base.report_data),
        }
    }
}
