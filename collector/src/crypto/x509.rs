//! Hybrid encryption: AES-256-GCM bulk + RSA-OAEP-SHA256 key wrapping.
//!
//! The bulk encryption is CHUNKED (streamed) so containers of ANY size encrypt
//! and decrypt in constant memory — a forensic ZIP can be many GB and must
//! never be loaded whole into RAM (doing so OOM-aborted the collector).
//!
//! Container layout (`collection.zip.enc`):
//!     [4B magic "DFIR"] [1B version] [4B BE u32 header_len] [JSON header]
//!     then, repeated until EOF:  [4B BE u32 chunk_ct_len] [chunk ciphertext+16B tag]
//!
//! version 2 (current, chunked): each plaintext chunk (size chosen at build/run
//! time — fixed MiB or auto-by-RAM, clamped to a 64 KiB floor) is sealed with
//!   nonce = header.nonce_b64(8 bytes) || u32_BE(chunk_index)
//!   AAD   = header_json_bytes || u32_BE(chunk_index) || 1-byte is_last_flag
//! Binding the index + last-flag into the AAD makes reordering, dropping, or
//! truncating chunks fail authentication.
//!
//! version 1 (legacy, single-shot): one AES-GCM seal over the whole body with a
//! 12-byte nonce in `nonce_b64` and the header bytes as AAD. Still decryptable
//! by `docs/decrypt.md` / `decrypt.py` for containers built before v2.
//!
//! JSON header (cleartext, authenticated):
//!     { "version", "scheme", "build_id", "created_at", "wrapped_key_b64",
//!       "nonce_b64" (8-byte base in v2 / 12-byte nonce in v1),
//!       "key_fingerprint_sha256" }

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::Oaep;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const MIB: u64 = 1024 * 1024;
/// Default plaintext bytes per chunk (256 MiB) used by Auto mode when the
/// endpoint's RAM can't be read. Memory use is O(chunk), not O(file).
pub const DEFAULT_CHUNK: usize = 256 * 1024 * 1024;
/// Auto mode never picks below this floor or above this cap.
const AUTO_MIN: u64 = 64 * MIB;
const AUTO_MAX: u64 = 512 * MIB;
/// Hard ceiling on per-chunk PLAINTEXT (2 GiB). Each chunk's ciphertext length
/// is written as a `u32` (`[u32 BE ct_len][ct+16B tag]`), so the sealed chunk
/// MUST stay below 2^32 bytes — at exactly 4096 MiB the `u32` wraps and silently
/// produces an un-decryptable container. 2 GiB leaves ample margin (and also
/// keeps peak memory, ~3x the chunk, sane).
const MAX_CHUNK: u64 = 2048 * MIB;
const CHUNK_FLOOR: u64 = 64 * 1024;
const FORMAT_VERSION: u8 = 2;

/// Resolve the per-chunk plaintext size (bytes) for streaming encryption.
///
/// `chunk_mb > 0` → that fixed size, clamped to `[64 KiB, MAX_CHUNK]`. `chunk_mb
/// == 0` → Auto: peak memory is ~3x the chunk (lookahead chunk + current + one
/// ciphertext), so we target ~1/8 of available RAM, clamped to [64 MiB, 512 MiB].
/// `available_ram == 0` (unknown) falls back to `DEFAULT_CHUNK`. The MAX_CHUNK
/// clamp is what prevents the `u32` chunk-length prefix from overflowing.
pub fn resolve_chunk_bytes(chunk_mb: u64, available_ram: u64) -> usize {
    if chunk_mb > 0 {
        return (chunk_mb.saturating_mul(MIB)).clamp(CHUNK_FLOOR, MAX_CHUNK) as usize;
    }
    if available_ram == 0 {
        return DEFAULT_CHUNK;
    }
    (available_ram / 8).clamp(AUTO_MIN, AUTO_MAX) as usize
}

#[derive(serde::Serialize)]
struct Header<'a> {
    version: u32,
    scheme: &'a str,
    build_id: &'a str,
    created_at: String,
    wrapped_key_b64: String,
    /// v2: 8-byte nonce base (per-chunk nonce = base || u32_BE(index)).
    nonce_b64: String,
    key_fingerprint_sha256: String,
}

/// Encrypt `plain_path` -> `enc_path`. `chunk_bytes` is the plaintext bytes
/// sealed per chunk (the caller resolves the user's setting or the RAM-based
/// auto value). It is clamped to `[64 KiB, MAX_CHUNK]` here as the last line of
/// defense: the MAX_CHUNK ceiling guarantees a sealed chunk stays under 2^32
/// bytes so the `u32` length prefix can never overflow, regardless of caller.
pub fn encrypt_file(
    plain_path: &Path,
    enc_path: &Path,
    pubkey_pem: &str,
    build_id: &str,
    chunk_bytes: usize,
) -> Result<()> {
    let chunk_bytes = (chunk_bytes as u64).clamp(CHUNK_FLOOR, MAX_CHUNK) as usize;
    let pubkey = RsaPublicKey::from_public_key_pem(pubkey_pem.trim())
        .context("parsing RSA public key PEM")?;

    // Fresh AES-256 key + 8-byte nonce base (per-chunk nonce = base || counter).
    let mut aes_key = [0u8; 32];
    let mut nonce_base = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut aes_key);
    rand::thread_rng().fill_bytes(&mut nonce_base);

    let padding = Oaep::new::<Sha256>();
    let wrapped = pubkey
        .encrypt(&mut rand::thread_rng(), padding, &aes_key)
        .context("RSA-OAEP wrapping AES key")?;

    let pubkey_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&pubkey)
        .context("encoding RSA public key as DER")?;
    let fingerprint = hex::encode(Sha256::digest(pubkey_der.as_bytes()));

    let header = Header {
        version: FORMAT_VERSION as u32,
        scheme: "rsa-oaep-sha256+aes-256-gcm-chunked",
        build_id,
        created_at: chrono::Utc::now().to_rfc3339(),
        wrapped_key_b64: base64::engine::general_purpose::STANDARD.encode(wrapped),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_base),
        key_fingerprint_sha256: fingerprint,
    };
    let header_json = serde_json::to_vec(&header)?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key).context("AES key")?;

    let mut input = BufReader::new(
        File::open(plain_path).with_context(|| format!("open plaintext {}", plain_path.display()))?,
    );
    let mut out = BufWriter::new(
        File::create(enc_path).with_context(|| format!("create {}", enc_path.display()))?,
    );
    out.write_all(b"DFIR")?;
    out.write_all(&[FORMAT_VERSION])?;
    out.write_all(&(header_json.len() as u32).to_be_bytes())?;
    out.write_all(&header_json)?;

    // Stream: one-chunk lookahead so we can mark the final chunk in its AAD.
    let mut idx: u32 = 0;
    let mut cur = read_chunk(&mut input, chunk_bytes)?;
    loop {
        let next = read_chunk(&mut input, chunk_bytes)?;
        let is_last = next.is_empty();
        let ct = seal_chunk(&cipher, &nonce_base, &header_json, idx, is_last, &cur)?;
        // Defensive: ciphertext length is written as a u32. The MAX_CHUNK clamp
        // already guarantees this holds; assert it so a future change can't
        // silently reintroduce the overflow.
        debug_assert!(ct.len() < u32::MAX as usize, "chunk ciphertext exceeds u32 length prefix");
        out.write_all(&(ct.len() as u32).to_be_bytes())?;
        out.write_all(&ct)?;
        if is_last {
            break;
        }
        cur = next;
        // The per-chunk nonce/AAD embed `idx` as a u32; bail before it could wrap
        // (which would reuse a nonce under the same key) rather than corrupt.
        idx = idx
            .checked_add(1)
            .ok_or_else(|| anyhow!("collection too large: exceeds the {} chunk maximum for this chunk size", u32::MAX))?;
    }
    out.flush()?;
    aes_key.fill(0);
    Ok(())
}

fn seal_chunk(
    cipher: &Aes256Gcm,
    nonce_base: &[u8; 8],
    header_json: &[u8],
    idx: u32,
    is_last: bool,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(nonce_base);
    nonce[8..].copy_from_slice(&idx.to_be_bytes());
    let mut aad = Vec::with_capacity(header_json.len() + 5);
    aad.extend_from_slice(header_json);
    aad.extend_from_slice(&idx.to_be_bytes());
    aad.push(is_last as u8);
    cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &aad })
        .map_err(|e| anyhow!("AES-GCM encrypt (chunk {idx}) failed: {e}"))
}

/// Read up to `chunk` bytes, growing the buffer only as data arrives so a tiny
/// file never allocates the full chunk size. Returns `<chunk` bytes only at EOF.
fn read_chunk<R: Read>(r: &mut R, chunk: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    (&mut *r).take(chunk as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Decrypt a container produced by `encrypt_file` (analyst-side; also exercised
/// by the round-trip tests). Streams chunk-by-chunk in constant memory.
#[allow(dead_code)]
pub fn decrypt_file(enc_path: &Path, out_path: &Path, privkey_pem: &str) -> Result<()> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    let mut input = BufReader::new(File::open(enc_path).context("open container")?);
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic).context("read magic")?;
    if &magic != b"DFIR" {
        bail!("bad magic: {magic:?}");
    }
    let mut ver = [0u8; 1];
    input.read_exact(&mut ver)?;
    let mut hl = [0u8; 4];
    input.read_exact(&mut hl)?;
    let header_len = u32::from_be_bytes(hl) as usize;
    let mut header_json = vec![0u8; header_len];
    input.read_exact(&mut header_json)?;
    let header: serde_json::Value = serde_json::from_slice(&header_json).context("parse header")?;

    let priv_key = RsaPrivateKey::from_pkcs8_pem(privkey_pem.trim()).context("parse private key")?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(header["wrapped_key_b64"].as_str().ok_or_else(|| anyhow!("no wrapped_key"))?)?;
    let aes_key = priv_key
        .decrypt(Oaep::new::<Sha256>(), &wrapped)
        .context("RSA-OAEP unwrap")?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key).context("AES key")?;
    let nonce_b = base64::engine::general_purpose::STANDARD
        .decode(header["nonce_b64"].as_str().ok_or_else(|| anyhow!("no nonce"))?)?;

    let mut out = BufWriter::new(File::create(out_path).context("create output")?);

    if ver[0] == 1 {
        // Legacy single-shot: nonce(12) + whole-body GCM, AAD = header bytes.
        // Validate length first — Nonce::from_slice PANICS on a non-12-byte slice,
        // so a malformed/corrupt container must be rejected with a clean error
        // (mirrors the v2 guard below).
        if nonce_b.len() != 12 {
            bail!("v1 nonce must be 12 bytes, got {}", nonce_b.len());
        }
        let mut body = Vec::new();
        input.read_to_end(&mut body)?;
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce_b), Payload { msg: &body, aad: &header_json })
            .map_err(|e| anyhow!("v1 decrypt failed: {e}"))?;
        out.write_all(&pt)?;
        out.flush()?;
        return Ok(());
    }
    if ver[0] != FORMAT_VERSION {
        bail!("unsupported container version {}", ver[0]);
    }
    let mut base = [0u8; 8];
    if nonce_b.len() != 8 {
        bail!("v2 nonce base must be 8 bytes, got {}", nonce_b.len());
    }
    base.copy_from_slice(&nonce_b);

    // Stream chunks with one-record lookahead to mark the final chunk.
    let mut idx: u32 = 0;
    let mut cur = match read_record(&mut input)? {
        Some(c) => c,
        None => bail!("container has no chunks"),
    };
    loop {
        let next = read_record(&mut input)?;
        let is_last = next.is_none();
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&base);
        nonce[8..].copy_from_slice(&idx.to_be_bytes());
        let mut aad = Vec::with_capacity(header_json.len() + 5);
        aad.extend_from_slice(&header_json);
        aad.extend_from_slice(&idx.to_be_bytes());
        aad.push(is_last as u8);
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &cur, aad: &aad })
            .map_err(|e| anyhow!("decrypt chunk {idx} failed (tampered/truncated?): {e}"))?;
        out.write_all(&pt)?;
        idx += 1;
        match next {
            Some(n) => cur = n,
            None => break,
        }
    }
    out.flush()?;
    Ok(())
}

/// Read one `[u32 BE len][len bytes]` record; `None` on clean EOF at a boundary.
#[allow(dead_code)]
fn read_record<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len_buf[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(None); // clean EOF
            }
            bail!("truncated chunk length");
        }
        got += n;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).context("truncated chunk body")?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    fn keypair() -> (String, String) {
        // Small key — tests only need correctness, not strength.
        let mut rng = rand::thread_rng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk = RsaPublicKey::from(&sk);
        (
            pk.to_public_key_pem(LineEnding::LF).unwrap(),
            sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        )
    }

    // Tiny chunk so the multi-chunk paths stay fast; the production CHUNK is
    // 400 MiB but encrypt_file clamps to a 64 KiB floor, so this exercises the
    // real boundary/lookahead logic without huge allocations.
    const TEST_CHUNK: usize = 64 * 1024;

    fn roundtrip(plain: &[u8]) {
        let (pubpem, privpem) = keypair();
        let dir = std::env::temp_dir();
        let p = dir.join(format!("x509t_plain_{}", plain.len()));
        let e = dir.join(format!("x509t_enc_{}", plain.len()));
        let d = dir.join(format!("x509t_dec_{}", plain.len()));
        std::fs::write(&p, plain).unwrap();
        encrypt_file(&p, &e, &pubpem, "testbuild", TEST_CHUNK).unwrap();
        decrypt_file(&e, &d, &privpem).unwrap();
        assert_eq!(std::fs::read(&d).unwrap(), plain, "roundtrip mismatch len={}", plain.len());
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&e);
        let _ = std::fs::remove_file(&d);
    }

    #[test]
    fn roundtrip_small() {
        roundtrip(b"hello forensic world");
    }

    #[test]
    fn chunk_resolution() {
        // Fixed size honored (MiB -> bytes).
        assert_eq!(resolve_chunk_bytes(400, 99 * MIB), 400 * MIB as usize);
        // Fixed size below the 64 KiB floor is raised to it.
        assert_eq!(resolve_chunk_bytes(0, 0), DEFAULT_CHUNK); // auto, RAM unknown
        // Auto on a roomy box clamps to the 512 MiB cap.
        assert_eq!(resolve_chunk_bytes(0, 64 * 1024 * MIB), AUTO_MAX as usize);
        // Auto on a tiny box clamps up to the 64 MiB floor.
        assert_eq!(resolve_chunk_bytes(0, 128 * MIB), AUTO_MIN as usize);
        // Auto in between picks ~1/8 of available RAM.
        assert_eq!(resolve_chunk_bytes(0, 2048 * MIB), (2048 / 8) * MIB as usize);
        // Fixed size is capped at MAX_CHUNK so the u32 chunk-length prefix can
        // never overflow (regression for the 4096 MiB cliff).
        assert_eq!(resolve_chunk_bytes(4096, 99 * MIB), MAX_CHUNK as usize);
        assert_eq!(resolve_chunk_bytes(999_999, 99 * MIB), MAX_CHUNK as usize);
    }

    #[test]
    fn huge_chunk_arg_is_clamped_and_round_trips() {
        // A caller passing an enormous chunk size must not overflow the u32
        // length prefix; encrypt_file clamps it to MAX_CHUNK and still works.
        let (pubpem, privpem) = keypair();
        let dir = std::env::temp_dir();
        let p = dir.join("x509t_hugechunk_plain");
        let e = dir.join("x509t_hugechunk_enc");
        let d = dir.join("x509t_hugechunk_dec");
        let data = vec![0x5Au8; 200_000];
        std::fs::write(&p, &data).unwrap();
        encrypt_file(&p, &e, &pubpem, "b", usize::MAX).unwrap();
        decrypt_file(&e, &d, &privpem).unwrap();
        assert_eq!(std::fs::read(&d).unwrap(), data);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&e);
        let _ = std::fs::remove_file(&d);
    }

    #[test]
    fn roundtrip_exact_chunk_boundary() {
        roundtrip(&vec![0xABu8; TEST_CHUNK]); // exactly one chunk
    }

    #[test]
    fn roundtrip_multi_chunk() {
        // 2.5 chunks → exercises the lookahead / last-flag logic across chunks.
        let data: Vec<u8> =
            (0..(TEST_CHUNK * 2 + TEST_CHUNK / 2)).map(|i| (i % 251) as u8).collect();
        roundtrip(&data);
    }

    #[test]
    fn tamper_is_detected() {
        let (pubpem, privpem) = keypair();
        let dir = std::env::temp_dir();
        let p = dir.join("x509t_tamper_plain");
        let e = dir.join("x509t_tamper_enc");
        let d = dir.join("x509t_tamper_dec");
        std::fs::write(&p, vec![7u8; TEST_CHUNK + 100]).unwrap();
        encrypt_file(&p, &e, &pubpem, "b", TEST_CHUNK).unwrap();
        // Flip a byte in the first chunk's ciphertext (after the header).
        let mut bytes = std::fs::read(&e).unwrap();
        let flip = bytes.len() - 50;
        bytes[flip] ^= 0xFF;
        std::fs::write(&e, &bytes).unwrap();
        assert!(decrypt_file(&e, &d, &privpem).is_err(), "tamper must fail auth");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&e);
        let _ = std::fs::remove_file(&d);
    }
}
