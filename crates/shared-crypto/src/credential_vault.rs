//! Build-time AWS credential vault — bit-compatible with the collector's
//! existing `credential_vault::decrypt_vault` (see [`collector/src/credential_vault.rs`]).
//!
//! Layout of the vault blob (matches the collector's expectations exactly):
//!
//! ```text
//! [8B  "DFIRV001" marker]
//! [12B AES-GCM nonce]
//! [8B  frag1]   ┐
//! [8B  frag2]   │  AES-256 key, split into 4 fragments,
//! [8B  frag3]   │  each XOR'd with sha256(build_id:build_timestamp)[..8]
//! [8B  frag4]   ┘
//! [ciphertext + 16B AES-GCM tag]
//! ```
//!
//! Separately, an HMAC-SHA256 is computed over the entire blob with
//! `build_id` as the key and embedded in the config as `vault_hmac` for
//! tamper detection at decrypt time.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const VAULT_MARKER: &[u8; 8] = b"DFIRV001";

#[derive(Debug, Clone)]
pub struct VaultedBlob {
    pub blob: Vec<u8>,
    pub blob_base64: String,
    pub hmac_hex: String,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// Encrypt the access key + secret into a single opaque blob.
pub fn encrypt(
    creds: &Credentials,
    build_id: &str,
    build_timestamp: &str,
) -> Result<VaultedBlob> {
    let plaintext = serde_json::json!({
        "a": creds.access_key_id,
        "s": creds.secret_access_key,
    })
    .to_string();

    let derivation = format!("{build_id}:{build_timestamp}");
    let master_hash = Sha256::digest(derivation.as_bytes());
    let xor_key = &master_hash[..8];

    let mut aes_key = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut aes_key);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow!("AES key init: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("AES-GCM encrypt: {e}"))?;

    let mut frags = [[0u8; 8]; 4];
    for i in 0..8 {
        frags[0][i] = aes_key[i] ^ xor_key[i];
        frags[1][i] = aes_key[8 + i] ^ xor_key[i];
        frags[2][i] = aes_key[16 + i] ^ xor_key[i];
        frags[3][i] = aes_key[24 + i] ^ xor_key[i];
    }

    let mut blob = Vec::with_capacity(8 + 12 + 32 + ciphertext.len());
    blob.extend_from_slice(VAULT_MARKER);
    blob.extend_from_slice(&nonce_bytes);
    for f in &frags {
        blob.extend_from_slice(f);
    }
    blob.extend_from_slice(&ciphertext);

    let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(build_id.as_bytes())
        .map_err(|e| anyhow!("HMAC key: {e}"))?;
    mac.update(&blob);
    let hmac_bytes = mac.finalize().into_bytes();

    let result = VaultedBlob {
        blob_base64: base64::engine::general_purpose::STANDARD.encode(&blob),
        hmac_hex: hex::encode(hmac_bytes),
        blob,
    };

    aes_key.fill(0);
    Ok(result)
}

/// Decrypt a vault blob back into plaintext credentials. Used by the
/// collector at runtime and by the shared roundtrip tests.
pub fn decrypt(
    blob: &[u8],
    build_id: &str,
    build_timestamp: &str,
) -> Result<Credentials> {
    if blob.len() < 8 || &blob[0..8] != VAULT_MARKER {
        bail!("invalid vault marker");
    }
    let payload = &blob[8..];
    if payload.len() < 12 + 32 + 16 {
        bail!("vault payload too short");
    }

    let derivation = format!("{build_id}:{build_timestamp}");
    let master_hash = Sha256::digest(derivation.as_bytes());
    let xor_key = &master_hash[..8];

    let nonce_bytes = &payload[0..12];
    let frag1 = &payload[12..20];
    let frag2 = &payload[20..28];
    let frag3 = &payload[28..36];
    let frag4 = &payload[36..44];
    let ciphertext = &payload[44..];

    let mut aes_key = [0u8; 32];
    for i in 0..8 {
        aes_key[i] = frag1[i] ^ xor_key[i];
        aes_key[8 + i] = frag2[i] ^ xor_key[i];
        aes_key[16 + i] = frag3[i] ^ xor_key[i];
        aes_key[24 + i] = frag4[i] ^ xor_key[i];
    }

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow!("AES key init: {e}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow!("AES-GCM decrypt: {e}"))?;

    aes_key.fill(0);

    let v: serde_json::Value =
        serde_json::from_slice(&plain).context("vault plaintext is not JSON")?;
    Ok(Credentials {
        access_key_id: v
            .get("a")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing 'a'"))?
            .to_string(),
        secret_access_key: v
            .get("s")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing 's'"))?
            .to_string(),
    })
}

/// Verify the HMAC of a vault blob using `build_id` as the key.
pub fn verify_hmac(blob: &[u8], expected_hmac: &[u8], build_id: &str) -> bool {
    let Ok(mut mac) = <Hmac::<Sha256> as Mac>::new_from_slice(build_id.as_bytes()) else {
        return false;
    };
    mac.update(blob);
    mac.verify_slice(expected_hmac).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_plaintext() {
        let creds = Credentials {
            access_key_id: "AKIAEXAMPLE0000000".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        };
        let build_id = "0e7f3da0-deadbeef-cafef00d-12345678";
        let ts = "2026-05-21T10:00:00.000Z";

        let vault = encrypt(&creds, build_id, ts).expect("encrypt");
        let recovered = decrypt(&vault.blob, build_id, ts).expect("decrypt");

        assert_eq!(recovered.access_key_id, creds.access_key_id);
        assert_eq!(recovered.secret_access_key, creds.secret_access_key);
    }

    #[test]
    fn hmac_is_consistent() {
        let creds = Credentials {
            access_key_id: "AKIA".into(),
            secret_access_key: "sk".into(),
        };
        let vault = encrypt(&creds, "bid", "ts").unwrap();
        let hmac_bytes = hex::decode(&vault.hmac_hex).unwrap();
        assert!(verify_hmac(&vault.blob, &hmac_bytes, "bid"));
        assert!(!verify_hmac(&vault.blob, &hmac_bytes, "wrong"));
    }

    #[test]
    fn wrong_build_id_fails_decrypt() {
        let creds = Credentials {
            access_key_id: "AKIA".into(),
            secret_access_key: "sk".into(),
        };
        let vault = encrypt(&creds, "right", "ts").unwrap();
        assert!(decrypt(&vault.blob, "wrong", "ts").is_err());
    }
}
