//! Shared crypto helpers — used by `builder-app` at build time (encryption)
//! and by `collector` at runtime (decryption). One implementation, two
//! callers, guaranteed bit-compatible.

pub mod credential_vault;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
