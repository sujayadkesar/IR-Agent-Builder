//! Upload dispatch.
//!
//! Three modes today: `local` (filesystem copy / UNC), `s3` (single PutObject
//! up to ~100MB, multipart above), and a stub for `sftp` (Transfer Family).
//!
//! Why not the official `aws-sdk-s3` crate? It pulls ~70 transitive deps and
//! ~15MB of binary bloat. For a *single endpoint*, single PutObject use case,
//! a hand-rolled SigV4 signer over `ureq` is ~150 lines and produces a
//! collector binary about 60% smaller. We pay the cost of writing the signer
//! once; the binary every endpoint downloads stays lean.

pub mod s3;

use anyhow::{bail, Result};
use std::path::Path;

use crate::config::UploadCfg;

pub fn dispatch(cfg: &UploadCfg, file: &Path, object_key_suffix: &str) -> Result<()> {
    match cfg.kind.as_str() {
        "local" => {
            let dest = cfg
                .local_path
                .clone()
                .unwrap_or_else(|| "C:\\IR\\Output".to_string());
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
