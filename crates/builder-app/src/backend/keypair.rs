//! RSA-4096 keypair generation. Matches the legacy Node behaviour but
//! runs in a background thread so the UI stays responsive.

use anyhow::Result;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub bits: usize,
    pub public_pem: String,
    pub private_pem: String,
    pub fingerprint_sha256: String,
    pub elapsed_ms: u128,
}

pub fn generate(bits: usize) -> Result<Keypair> {
    let start = std::time::Instant::now();
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits)?;
    let pub_key = RsaPublicKey::from(&priv_key);
    let elapsed_ms = start.elapsed().as_millis();

    let public_pem = pub_key.to_public_key_pem(LineEnding::LF)?;
    let private_pem = priv_key.to_pkcs8_pem(LineEnding::LF)?.to_string();

    let pub_der = pub_key.to_public_key_der()?;
    let fingerprint_sha256 = hex::encode(Sha256::digest(pub_der.as_bytes()));

    Ok(Keypair {
        bits,
        public_pem,
        private_pem,
        fingerprint_sha256,
        elapsed_ms,
    })
}
