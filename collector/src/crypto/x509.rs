//! Hybrid encryption: AES-256-GCM bulk + RSA-OAEP-SHA256 key wrapping.
//!
//! Container layout (single file, e.g. `collection.zip.enc`):
//!     [4-byte BE u32 header_len] [JSON header bytes] [AES-GCM nonce 12B]
//!     [GCM ciphertext (= ZIP plaintext) + 16B auth tag]
//!
//! JSON header (cleartext, included in AAD):
//!     {
//!       "version": 1,
//!       "scheme": "rsa-oaep-sha256+aes-256-gcm",
//!       "build_id": "...",
//!       "created_at": "<iso8601>",
//!       "wrapped_key_b64": "<base64 RSA-OAEP-SHA256(aes_key)>",
//!       "key_fingerprint_sha256": "<hex sha256 of pubkey DER>"
//!     }
//!
//! Decrypt logic (analyst-side helper):
//!   1. Read header_len, parse JSON.
//!   2. RSA-OAEP-SHA256 unwrap aes_key with the IR private key.
//!   3. AES-256-GCM decrypt the body using nonce and the JSON header bytes
//!      as additional authenticated data.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::Oaep;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(serde::Serialize)]
struct Header<'a> {
    version: u32,
    scheme: &'a str,
    build_id: &'a str,
    created_at: String,
    wrapped_key_b64: String,
    nonce_b64: String,
    key_fingerprint_sha256: String,
}

pub fn encrypt_file(plain_path: &Path, enc_path: &Path, pubkey_pem: &str) -> Result<()> {
    let pubkey = RsaPublicKey::from_public_key_pem(pubkey_pem.trim())
        .context("parsing RSA public key PEM")?;

    // 1. Generate a fresh AES-256 key + 96-bit GCM nonce.
    let mut aes_key = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut aes_key);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // 2. RSA-OAEP-SHA256 wrap the AES key.
    let padding = Oaep::new::<Sha256>();
    let wrapped = pubkey
        .encrypt(&mut rand::thread_rng(), padding, &aes_key)
        .context("RSA-OAEP wrapping AES key")?;

    // 3. Compute key fingerprint = SHA256 of public key DER.
    let pubkey_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&pubkey)
        .context("encoding RSA public key as DER")?;
    let mut hasher = Sha256::new();
    hasher.update(pubkey_der.as_bytes());
    let fingerprint = hex::encode(hasher.finalize());

    let header = Header {
        version: 1,
        scheme: "rsa-oaep-sha256+aes-256-gcm",
        build_id: option_env!("DFIR_BUILD_ID").unwrap_or("runtime"),
        created_at: chrono::Utc::now().to_rfc3339(),
        wrapped_key_b64: base64::engine::general_purpose::STANDARD.encode(wrapped),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        key_fingerprint_sha256: fingerprint,
    };
    let header_json = serde_json::to_vec(&header)?;

    // 4. Read plaintext (the ZIP) into memory. For huge collections, this could
    // be streamed via aes-gcm-stream, but multi-GB ZIPs would already be
    // problematic for the host's memory footprint — analysts running DeepDive
    // bundles should ensure adequate RAM or use the SFTP/local fallback path.
    let mut plain = Vec::new();
    File::open(plain_path)
        .with_context(|| format!("open plaintext {}", plain_path.display()))?
        .read_to_end(&mut plain)?;

    // 5. AES-256-GCM with the JSON header as AAD.
    let cipher = Aes256Gcm::new_from_slice(&aes_key).context("AES key")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &plain,
                aad: &header_json,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;

    // 6. Write [u32 header_len][header_json][ciphertext]. Note: nonce is in header.
    let mut out = File::create(enc_path)
        .with_context(|| format!("create encrypted output {}", enc_path.display()))?;
    let hl = (header_json.len() as u32).to_be_bytes();
    out.write_all(b"DFIR")?;            // magic
    out.write_all(&[1u8])?;             // version
    out.write_all(&hl)?;
    out.write_all(&header_json)?;
    out.write_all(&ct)?;
    out.flush()?;

    // 7. Wipe the AES key from memory (best-effort).
    aes_key.fill(0);
    Ok(())
}
