//! Upload dispatch.
//!
//! Three modes:
//!   1. `local`   — filesystem copy / UNC path
//!   2. `s3`      — single PutObject (≤100MB) or multipart (>100MB)
//!   3. `chunked` — streaming chunk-based upload (Binalyze AIR-style)
//!
//! The chunked mode is activated when:
//!   - chunk_upload.enabled = true in config
//!   - Disk space is below the threshold
//!   - The estimated collection size exceeds available space

pub mod s3;
pub mod chunked;

use anyhow::{bail, Result};
use std::path::Path;

use crate::config::UploadCfg;

pub fn dispatch(cfg: &UploadCfg, file: &Path, object_key_suffix: &str) -> Result<()> {
    match cfg.kind.as_str() {
        "local" => {
            let dest = cfg
                .local_path
                .clone()
                .unwrap_or_else(|| {
                    #[cfg(target_os = "windows")]
                    { "C:\\IR\\Output".to_string() }
                    #[cfg(not(target_os = "windows"))]
                    { "/tmp/dfir-output".to_string() }
                });
            local_copy(file, Path::new(&dest))
        }
        "s3" => {
            let s3 = cfg.s3.as_ref().ok_or_else(|| anyhow::anyhow!("missing s3 config"))?;
            s3::upload(s3, file, object_key_suffix)
        }
        other => bail!("unknown upload kind: {other}"),
    }
}

fn local_copy(file: &Path, dest_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dest_dir)?;
    let dest = dest_dir.join(file.file_name().ok_or_else(|| anyhow::anyhow!("no filename"))?);
    log::info!("Local upload: {} -> {}", file.display(), dest.display());
    std::fs::copy(file, dest)?;
    Ok(())
}
