//! Backend logic — pure functions called by the UI. No window state lives
//! here; this layer is what would be the Node Express server in the legacy
//! architecture.

pub mod artifact_catalog;
pub mod aws;
pub mod build;
pub mod embedded_config;
pub mod keypair;
pub mod ledger;
pub mod sigv4;
