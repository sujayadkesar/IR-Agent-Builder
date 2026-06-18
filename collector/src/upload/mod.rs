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

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::config::UploadCfg;

pub fn dispatch(cfg: &UploadCfg, file: &Path, object_key_suffix: &str) -> Result<()> {
    match cfg.kind.as_str() {
        "local" => {
            let raw = cfg.local_path.as_deref().unwrap_or("").trim();
            if raw.is_empty() {
                bail!(
                    "local upload selected but no output path was configured in the build \
                     (Step 3). Nothing was written."
                );
            }
            // Expand environment variables so a single build is portable across
            // endpoints with different usernames (e.g. %USERPROFILE%\\IR-Output).
            let dest = expand_env(raw);
            log::info!("[local] resolved output path: '{raw}' -> '{dest}'");
            local_copy(file, Path::new(&dest))
        }
        "s3" => {
            let s3 = cfg.s3.as_ref().ok_or_else(|| anyhow::anyhow!("missing s3 config"))?;
            s3::upload(s3, file, object_key_suffix)
        }
        other => bail!("unknown upload kind: {other}"),
    }
}

/// Expand environment variables in a user-supplied path so one build works on
/// any endpoint regardless of username. Windows `%VAR%` syntax is supported on
/// all platforms; on Unix, a leading `~` expands to `$HOME`. Unknown variables
/// are left untouched rather than blanked out.
fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                if var.is_empty() {
                    out.push('%'); // "%%" -> literal "%"
                } else if let Ok(val) = std::env::var(var) {
                    out.push_str(&val);
                } else {
                    // Unknown var — leave the token verbatim.
                    out.push('%');
                    out.push_str(var);
                    out.push('%');
                }
                rest = &after[end + 1..];
            }
            None => {
                // Unbalanced '%' — emit the remainder literally.
                out.push('%');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(stripped) = out.strip_prefix('~') {
            if let Ok(home) = std::env::var("HOME") {
                return format!("{home}{stripped}");
            }
        }
    }
    out
}

fn local_copy(file: &Path, dest_dir: &Path) -> Result<()> {
    let existed = dest_dir.exists();
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("creating local output dir {}", dest_dir.display()))?;
    log::info!(
        "[local] output dir {} ({})",
        dest_dir.display(),
        if existed { "existed" } else { "created" }
    );
    let dest = dest_dir.join(file.file_name().ok_or_else(|| anyhow::anyhow!("no filename"))?);
    let n = std::fs::copy(file, &dest)
        .with_context(|| format!("copying {} -> {}", file.display(), dest.display()))?;
    log::info!("[local] wrote {} ({} bytes)", dest.display(), n);
    Ok(())
}
