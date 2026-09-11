// Zeroize derive macro generates code that triggers unused_assignments lint FP
// for fields marked with #[zeroize(skip)] - the fields ARE used in runtime code
#![allow(unused_assignments)]

pub mod config;
pub mod engine;
pub mod hardware_security;
pub mod key_manager;
pub mod performance_monitor;
pub mod quantum_resistant;
pub mod sealed_key_store;
pub mod service;

pub use config::CryptoConfig;
pub use service::CryptoEngineService;
