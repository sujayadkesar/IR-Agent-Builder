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
pub mod resume;

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::config::UploadCfg;

pub fn dispatch(cfg: &UploadCfg, file: &Path, object_key_suffix: &str) -> Result<()> {
    match cfg.kind.as_str() {
        "local" => local_dispatch(cfg, file),
        "s3" => {
            let s3 = cfg.s3.as_ref().ok_or_else(|| anyhow::anyhow!("missing s3 config"))?;
            s3::upload(s3, file, object_key_suffix)
        }
        other => bail!("unknown upload kind: {other}"),
    }
}

/// Like `dispatch`, but the S3 path records resume state so an interrupted
/// upload can be finished by a re-run. Used for the evidence container (the
/// sidecar log still uses plain `dispatch` — it is tiny and not worth resuming).
pub fn dispatch_resumable(
    cfg: &UploadCfg,
    file: &Path,
    object_key_suffix: &str,
    build_id: &str,
) -> Result<()> {
    match cfg.kind.as_str() {
        "local" => local_dispatch(cfg, file),
        "s3" => {
            let s3 = cfg.s3.as_ref().ok_or_else(|| anyhow::anyhow!("missing s3 config"))?;
            s3::upload_resumable(s3, file, object_key_suffix, build_id)
        }
        other => bail!("unknown upload kind: {other}"),
    }
}

fn local_dispatch(cfg: &UploadCfg, file: &Path) -> Result<()> {
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

/// At startup, finish an upload that a previous run left interrupted. Strictly
/// best-effort: returns `true` only when an upload was fully completed (the
/// caller then exits without collecting — re-collecting would produce a
/// different container and corrupt the resume). Any mismatch or permanent error
/// discards the state and returns `false` so the collector proceeds with a fresh
/// collection (never a hard gate, so a dead upload can't wedge every future run).
pub fn try_resume(cfg: &UploadCfg, build_id: &str) -> bool {
    let state = match resume::load() {
        Some(s) => s,
        None => return false,
    };
    if cfg.kind != "s3" {
        resume::clear();
        return false;
    }
    if state.build_id != build_id {
        log::warn!("[resume] pending-upload state is from a different build; discarding");
        resume::clear();
        return false;
    }
    let cpath = state.container_path.clone();
    let meta = match std::fs::metadata(&cpath) {
        Ok(m) => m,
        Err(_) => {
            log::warn!("[resume] pending container {cpath} is gone; discarding state");
            resume::clear();
            return false;
        }
    };
    if meta.len() != state.file_size {
        log::warn!(
            "[resume] pending container size changed ({} vs {}); discarding state",
            meta.len(),
            state.file_size
        );
        resume::clear();
        return false;
    }
    let s3 = match cfg.s3.as_ref() {
        Some(s) => s,
        None => {
            resume::clear();
            return false;
        }
    };
    log::warn!(
        "[resume] RESUMING a previous run's interrupted upload of {} (key={}, created {}); \
         NOT collecting fresh evidence this run",
        state.container_path,
        state.object_key,
        state.created_at
    );
    match s3::resume_pending(s3, state) {
        Ok(()) => {
            log::info!("[resume] pending upload finished");
            true
        }
        Err(e) => {
            log::warn!("[resume] could not finish pending upload ({e:#}); discarding state and collecting fresh");
            resume::clear();
            false
        }
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
