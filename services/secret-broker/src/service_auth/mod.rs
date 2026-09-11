//! RA-TLS client identity and attestation verification used by the broker TLS boundary.

pub mod ratls;

pub use ratls::{
    build_rustls_client_config, parse_client_identity, parse_client_identity_from_pem,
    AttestationMode, ClientIdentity, ClientPolicy, MeasurementPolicy,
};
