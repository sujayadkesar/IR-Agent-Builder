//! Crypto primitives.
//!
//! `x509` submodule implements the hybrid encryption scheme:
//!   Container = JSON header || AES-256-GCM(ZIP, key, nonce, AAD)
//!   where `key` is freshly generated per run and RSA-OAEP-SHA256 wrapped.

pub mod x509;

use anyhow::Result;
use std::path::Path;

/// Best-effort secure delete: overwrite file with zeros, then unlink.
/// On modern SSDs with wear-levelling this is not perfectly secure; callers
/// should prefer not to write the plaintext to disk in the first place. We
/// use this as a defence-in-depth measure for the local zip plaintext.
pub fn secure_delete(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    let metadata = std::fs::metadata(path);
    if let Ok(m) = metadata {
        let len = m.len();
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 1024 * 1024];
            let mut written = 0u64;
            while written < len {
                let n = std::cmp::min(zeros.len() as u64, len - written) as usize;
                f.write_all(&zeros[..n]).ok();
                written += n as u64;
            }
            f.flush().ok();
            f.seek(SeekFrom::Start(0)).ok();
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}
