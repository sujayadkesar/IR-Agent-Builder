//! File-pattern based artifact collection.
//!
//! Most forensic artifacts (Prefetch, Amcache, Registry hives, EVTX, LNK, etc.)
//! are simply files in well-known locations. This module:
//!   1. Expands a list of glob-like patterns rooted at `collect_root`
//!      (which is either C:\ or a VSS snapshot mount path).
//!   2. Copies each match into `<scratch>/<artifact_name>/<relative_path>`.
//!   3. For locked files (Registry hives, EVTX), retries via the raw NTFS
//!      reader (when running on a VSS snapshot, files are unlocked anyway).

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use super::ArtifactStats;

/// Expand patterns rooted at `collect_root`, copy matches to scratch dir.
pub fn collect(
    artifact_name: &str,
    collect_root: &Path,
    scratch: &Path,
    patterns: &[&str],
) -> Result<ArtifactStats> {
    let dest_root = scratch.join(artifact_name);
    std::fs::create_dir_all(&dest_root)
        .with_context(|| format!("creating dest dir {}", dest_root.display()))?;

    let mut stats = ArtifactStats::default();
    for pattern in patterns {
        let abs = join_pattern(collect_root, pattern);
        // glob crate handles ? and *; ** is also supported.
        let entries = match glob::glob(&abs.to_string_lossy()) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("[{artifact_name}] bad glob pattern {pattern}: {e}");
                continue;
            }
        };
        for entry in entries.flatten() {
            if !entry.is_file() {
                continue;
            }
            let rel = entry
                .strip_prefix(collect_root)
                .unwrap_or(&entry)
                .to_path_buf();
            let dest = dest_root.join(&rel);
            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match copy_with_fallback(&entry, &dest) {
                Ok(bytes) => {
                    stats.add_file(bytes);
                    log::debug!("[{artifact_name}] copied {} ({bytes} B)", entry.display());
                }
                Err(e) => log::warn!("[{artifact_name}] copy failed {}: {e:#}", entry.display()),
            }
        }
    }

    if stats.file_count == 0 {
        log::warn!("[{artifact_name}] no files matched");
    }
    Ok(stats)
}

fn join_pattern(root: &Path, pattern: &str) -> PathBuf {
    // Normalize separators and join.
    let pat = pattern.replace('\\', "/");
    root.join(pat)
}

fn copy_with_fallback(src: &Path, dst: &Path) -> Result<u64> {
    // Strategy ladder — try cheap-but-strict, then progressively more
    // expensive techniques that bypass increasing layers of the OS:
    //   1. std::fs::copy            — works for normal files
    //   2. shared-read open + read  — works for files held with FILE_SHARE_READ
    //   3. raw NTFS read            — bypasses the file system entirely
    //                                  (the universal fallback Velociraptor uses)
    match std::fs::copy(src, dst) {
        Ok(b) => return Ok(b),
        Err(e) if is_sharing_violation(&e) => {
            log::debug!("std copy sharing violation for {}; trying shared-read", src.display());
        }
        Err(e) => return Err(anyhow::anyhow!(e)),
    }

    #[cfg(windows)]
    {
        match copy_locked_windows(src, dst) {
            Ok(b) => return Ok(b),
            Err(e) => {
                log::debug!("shared-read fallback failed for {}: {e:#}; trying raw NTFS", src.display());
            }
        }
        // Raw NTFS read — universal lock bypass.
        let path_str = src.to_string_lossy().to_string();
        match crate::acquisition::read_locked_file(&path_str, dst) {
            Ok(b) if b > 0 => {
                log::info!("raw NTFS recovered {} ({b} B)", src.display());
                Ok(b)
            }
            Ok(_) => Err(anyhow::anyhow!("raw NTFS read returned 0 bytes for {}", src.display())),
            Err(e) => Err(anyhow::anyhow!("all methods failed: {e:#}")),
        }
    }
    #[cfg(not(windows))]
    {
        Err(anyhow::anyhow!("file is locked and raw NTFS only supported on Windows"))
    }
}

#[cfg(windows)]
fn is_sharing_violation(e: &std::io::Error) -> bool {
    // ERROR_SHARING_VIOLATION = 32
    e.raw_os_error() == Some(32)
}

#[cfg(not(windows))]
fn is_sharing_violation(_: &std::io::Error) -> bool { false }

#[cfg(windows)]
fn copy_locked_windows(src: &Path, dst: &Path) -> Result<u64> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;

    // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE = 7
    const SHARE_ALL: u32 = 0x00000001 | 0x00000002 | 0x00000004;

    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .open(src)
        .with_context(|| format!("shared-read open {}", src.display()))?;
    let mut output = std::fs::File::create(dst)
        .with_context(|| format!("create {}", dst.display()))?;

    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = input.read(&mut buf).context("read")?;
        if n == 0 { break; }
        output.write_all(&buf[..n]).context("write")?;
        total += n as u64;
    }
    output.flush()?;
    Ok(total)
}

/// Raw-volume read for files that aren't accessible via the normal filesystem
/// (e.g. `$MFT`, `$LogFile`, USN journal). For an MVP this calls out to a
/// fallback implementation that uses raw `\\.\C:` reads — gated to the
/// most common case.
pub fn collect_raw_volume(
    artifact_name: &str,
    collect_root: &Path,
    scratch: &Path,
    files: &[&str],
) -> Result<ArtifactStats> {
    let dest_root = scratch.join(artifact_name);
    std::fs::create_dir_all(&dest_root)?;

    let mut stats = ArtifactStats::default();
    for f in files {
        // When VSS snapshot is mounted, raw $MFT lives at `<vss>/$MFT` and is readable
        // with shared mode. We try this first.
        let candidate = collect_root.join(f.replace('\\', "/"));
        let dst = dest_root.join(sanitize_filename(f));
        if candidate.exists() {
            match copy_with_fallback(&candidate, &dst) {
                Ok(b) => {
                    stats.add_file(b);
                    log::info!("[{artifact_name}] raw volume copied {} ({b} B)", f);
                    continue;
                }
                Err(e) => log::warn!("[{artifact_name}] raw fallback for {f}: {e:#}"),
            }
        }
        log::warn!("[{artifact_name}] {f} not collected (no VSS or locked)");
    }
    Ok(stats)
}

fn sanitize_filename(f: &str) -> String {
    f.replace(['$', '/', '\\', ':'], "_")
}

/// Memory acquisition stub. We invoke `winpmem.exe` if it's been dropped
/// next to the collector EXE. (The builder may bundle it as a sibling file;
/// or you can switch to in-process memory using `Microsoft-Windows-Kernel`
/// support in a follow-up.)
pub fn memory_dump(artifact_name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let dest_root = scratch.join(artifact_name);
    std::fs::create_dir_all(&dest_root)?;

    // Find winpmem next to collector exe
    let exe = std::env::current_exe()?;
    let pmem = exe
        .parent()
        .map(|p| p.join("winpmem.exe"))
        .ok_or_else(|| anyhow!("could not resolve exe directory"))?;
    if !pmem.exists() {
        return Err(anyhow!(
            "winpmem.exe not found beside Collector.exe — drop it alongside or skip memory.fulldump"
        ));
    }

    let dump_path = dest_root.join("physmem.aff4");
    let status = std::process::Command::new(&pmem)
        .arg("-o")
        .arg(&dump_path)
        .status()
        .context("invoking winpmem")?;
    if !status.success() {
        return Err(anyhow!("winpmem failed with {status:?}"));
    }

    let bytes = std::fs::metadata(&dump_path).map(|m| m.len()).unwrap_or(0);
    let mut stats = ArtifactStats::default();
    stats.add_file(bytes);
    Ok(stats)
}
