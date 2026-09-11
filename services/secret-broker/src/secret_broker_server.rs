//! Canonical SecretBrokerService gRPC server surface for the standalone broker.
//!
//! `secret_broker_server_impl.rs` contains the underlying implementation.

use std::sync::Arc;

use anyhow::Result;

use crate::secret_broker_impl::EmbeddedBrokerState;

pub use crate::secret_broker_server_impl::SecretBrokerGrpc;

pub async fn embedded_from_env(is_dev_mode: bool) -> Result<SecretBrokerGrpc> {
    let state = Arc::new(EmbeddedBrokerState::from_env().await?);
    Ok(SecretBrokerGrpc::new(state, is_dev_mode))
}
