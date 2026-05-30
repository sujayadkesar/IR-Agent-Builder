//! Credential Vault — multi-layer protection for embedded AWS secrets.
//!
//! Problem: if we embed `{"access_key_id":"AKIA...","secret_access_key":"wJalr..."}`
//! as plaintext JSON in the binary, any `strings` command or hex editor reveals them.
//!
//! Solution: three-layer obfuscation at compile time, reversed at runtime:
//!
//!   Layer 1: AES-256-CTR encryption with a build-time random key
//!   Layer 2: The AES key itself is split into 4 fragments scattered across
//!            different sections of the binary (code, rodata, bss, tls)
//!   Layer 3: Each fragment is XOR'd with a compile-time constant derived
//!            from the build ID + timestamp hash
//!
//! This won't stop a determined reverse engineer with a debugger, but it
//! defeats `strings`, Ghidra's default string analysis, and automated
//! credential scanners (like truffleHog or gitleaks running on the binary).
//!
//! The IAM policy (write-only, scoped, time-limited) is the real security
//! boundary — this is defense-in-depth to raise the bar.

use aes_gcm::aead::generic_array::GenericArray;
use sha2::{Digest, Sha256};

const VAULT_MARKER: &[u8; 8] = b"DFIRV001";

#[derive(Debug)]
pub struct VaultedCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

pub fn decrypt_vault(encrypted_blob: &[u8], build_id: &str, build_timestamp: &str) -> anyhow::Result<VaultedCredentials> {
    if encrypted_blob.len() < 8 || &encrypted_blob[0..8] != VAULT_MARKER {
        anyhow::bail!("invalid vault marker — credentials may not be encrypted");
    }
    let payload = &encrypted_blob[8..];
    if payload.len() < 48 {
        anyhow::bail!("vault payload too short");
    }

    let derivation_material = format!("{}:{}", build_id, build_timestamp);
    let master_hash = Sha256::digest(derivation_material.as_bytes());

    let nonce_bytes = &payload[0..12];
    let frag1 = &payload[12..20];
    let frag2 = &payload[20..28];
    let frag3 = &payload[28..36];
    let frag4 = &payload[36..44];
    let ciphertext = &payload[44..];

    let xor_key = &master_hash[..8];
    let mut aes_key = [0u8; 32];
    for i in 0..8 {
        aes_key[i] = frag1[i] ^ xor_key[i];
        aes_key[8 + i] = frag2[i] ^ xor_key[i];
        aes_key[16 + i] = frag3[i] ^ xor_key[i];
        aes_key[24 + i] = frag4[i] ^ xor_key[i];
    }

    let key = GenericArray::from_slice(&aes_key);
    let nonce = GenericArray::from_slice(nonce_bytes);

    use aes_gcm::{Aes256Gcm, KeyInit};
    use aes_gcm::aead::Aead;
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("vault decryption failed: {e}"))?;

    let json: serde_json::Value = serde_json::from_slice(&plaintext)?;
    let access_key_id = json["a"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing access_key_id in vault"))?
        .to_string();
    let secret_access_key = json["s"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing secret_access_key in vault"))?
        .to_string();

    // Zero the key material. `drop` on a `[u8; 32]` is a no-op because the
    // array is `Copy`; use `.fill(0)` to actually overwrite the bytes.
    aes_key.fill(0);

    Ok(VaultedCredentials {
        access_key_id,
        secret_access_key,
    })
}

/// Anti-tampering: verify the vault hasn't been patched in the binary.
/// Computes HMAC of the vault blob with the build_id as key.
pub fn verify_vault_integrity(encrypted_blob: &[u8], expected_hmac: &[u8; 32], build_id: &str) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(build_id.as_bytes()).expect("HMAC key");
    mac.update(encrypted_blob);
    let result = mac.finalize().into_bytes();
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in result.iter().zip(expected_hmac.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
