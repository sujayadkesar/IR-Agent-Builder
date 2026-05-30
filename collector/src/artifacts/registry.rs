//! Live registry hive collection — bypasses file locks via the registry API.
//!
//! Why not just copy `C:\Windows\System32\config\SAM`?
//!   The Windows kernel keeps SAM/SECURITY/SOFTWARE/SYSTEM open with
//!   `FILE_SHARE_NONE` while the system is running. Even with admin and
//!   `FILE_SHARE_READ`, the open will fail with ERROR_SHARING_VIOLATION
//!   (os error 32). That's exactly what bit us in the previous run.
//!
//! How professional IR tools solve this:
//!   - **KAPE / Velociraptor**: take a VSS snapshot, then read the file copy
//!     inside the snapshot (where it's no longer locked).
//!   - **Mimikatz / impacket secretsdump / SAMDump2**: call the registry
//!     API `RegSaveKey()` with `SeBackupPrivilege`, which asks the kernel
//!     to flush the loaded hive to a fresh file.
//!   - **Binalyze AIR / Velociraptor (raw NTFS path)**: parse `\\.\C:` raw
//!     and reconstruct the file from MFT extents, bypassing the file system
//!     entirely.
//!
//! This module implements approach #2 — the simplest and most portable.
//! `reg.exe save HKLM\SAM <out>` shells out to a Windows builtin that
//! internally calls `RegSaveKeyExW()` with backup privileges. It works on
//! every Windows edition (Home/Pro/Enterprise/Server) and doesn't require
//! VSS support.
//!
//! For the analyst this is BETTER than file copies in some ways:
//!   - The output is the *current* live state of the hive (file copies
//!     reflect the last in-memory→disk flush, which can be hours stale).
//!   - The output already has transaction log replay applied.
//!   - We can also dump per-user `HKU\<SID>` for currently-loaded users,
//!     which corresponds to NTUSER.DAT in the file system.
//!
//! Caveats:
//!   - We won't get the LOG1/LOG2 transaction logs (those are on disk only).
//!     If VSS is available, the file-copy artifact should still run as a
//!     belt-and-braces strategy.
//!   - Unloaded user hives can't be dumped this way — they require either
//!     VSS or raw NTFS read of the file.
//!   - `Amcache.hve` lives at `C:\Windows\AppCompat\Programs\Amcache.hve`
//!     and is sometimes loaded into HKLM\Amcache by the compatibility
//!     telemetry agent. We try `reg load`+`reg save` for it; if that fails,
//!     the patterns module's raw-NTFS fallback can still get it.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::ArtifactStats;

/// Acquire all standard hives via `reg save`.
pub fn collect_live(artifact_name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let dest = scratch.join(artifact_name);
    std::fs::create_dir_all(&dest)?;

    let mut stats = ArtifactStats::default();

    // ----- HKLM and built-in user hives (always loaded) ---------------------
    let system_hives: &[(&str, &str)] = &[
        ("HKLM\\SAM",      "SAM.hive"),
        ("HKLM\\SECURITY", "SECURITY.hive"),
        ("HKLM\\SOFTWARE", "SOFTWARE.hive"),
        ("HKLM\\SYSTEM",   "SYSTEM.hive"),
        ("HKLM\\HARDWARE", "HARDWARE.hive"),
        ("HKU\\.DEFAULT",  "DEFAULT.hive"),
    ];
    for (hive, filename) in system_hives {
        match save_hive(hive, &dest.join(filename)) {
            Ok(b) => {
                stats.add_file(b);
                log::info!("[{artifact_name}] reg save {hive} -> {filename} ({} KB)", b / 1024);
            }
            Err(e) => log::warn!("[{artifact_name}] reg save {hive} FAILED: {e:#}"),
        }
    }

    // ----- Per-user NTUSER.DAT-equivalent for every loaded HKU subkey -------
    // List loaded SIDs from the running registry. This catches every user
    // currently logged on (interactive, RDP, service accounts).
    match list_loaded_user_sids() {
        Ok(sids) => {
            log::info!("[{artifact_name}] {} loaded user hives in HKU", sids.len());
            for sid in sids {
                let key = format!("HKU\\{sid}");
                let safe_sid = sid.replace([':', '\\', '/'], "_");
                let ntuser = dest.join(format!("NTUSER.DAT.{safe_sid}.hive"));
                match save_hive(&key, &ntuser) {
                    Ok(b) => {
                        stats.add_file(b);
                        log::info!("[{artifact_name}] reg save {key} -> NTUSER.DAT.{safe_sid}.hive ({} KB)", b / 1024);
                    }
                    Err(e) => log::warn!("[{artifact_name}] reg save {key} failed: {e:#}"),
                }
                // UsrClass.dat-equivalent (HKU\<sid>_Classes) — only some users have it.
                let classes_key = format!("HKU\\{sid}_Classes");
                let usrclass = dest.join(format!("UsrClass.dat.{safe_sid}.hive"));
                if let Ok(b) = save_hive(&classes_key, &usrclass) {
                    stats.add_file(b);
                    log::info!("[{artifact_name}] reg save {classes_key} -> UsrClass.dat.{safe_sid}.hive ({} KB)", b / 1024);
                }
            }
        }
        Err(e) => log::warn!("[{artifact_name}] could not enumerate loaded user SIDs: {e:#}"),
    }

    // ----- Amcache (compatibility appraiser hive) ---------------------------
    // Amcache.hve isn't permanently loaded — try `reg load`+`reg save` first.
    // If the file is currently held by CompatTelRunner.exe (the usual case),
    // fall back to a raw NTFS read of the file directly.
    let amcache_dst = dest.join("Amcache.hve");
    match collect_amcache(&dest) {
        Ok(b) => {
            stats.add_file(b);
            log::info!("[{artifact_name}] Amcache.hve via reg load+save ({} KB)", b / 1024);
        }
        Err(e) => {
            log::warn!("[{artifact_name}] reg load/save Amcache failed ({e:#}); trying raw NTFS");
            match crate::acquisition::read_locked_file(
                r"C:\Windows\AppCompat\Programs\Amcache.hve",
                &amcache_dst,
            ) {
                Ok(b) if b > 0 => {
                    stats.add_file(b);
                    log::info!("[{artifact_name}] Amcache.hve via raw NTFS ({} KB)", b / 1024);
                }
                Ok(_) => log::warn!("[{artifact_name}] raw NTFS Amcache returned 0 bytes"),
                Err(re) => log::warn!("[{artifact_name}] raw NTFS Amcache failed: {re:#}"),
            }
        }
    }

    Ok(stats)
}

fn save_hive(key: &str, output_path: &Path) -> Result<u64> {
    // /y forces overwrite. We also explicitly remove first because some
    // system hives can leave a sparse marker that confuses /y.
    let _ = std::fs::remove_file(output_path);

    let output = Command::new("reg")
        .arg("save")
        .arg(key)
        .arg(output_path)
        .arg("/y")
        .output()
        .with_context(|| format!("running reg save {key}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "reg save {key} status={:?} stderr={} stdout={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim(),
        );
    }
    let size = std::fs::metadata(output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    if size == 0 {
        anyhow::bail!("reg save reported success but output is 0 bytes");
    }
    Ok(size)
}

fn list_loaded_user_sids() -> Result<Vec<String>> {
    let output = Command::new("reg")
        .args(["query", "HKU"])
        .output()
        .context("reg query HKU")?;
    if !output.status.success() {
        anyhow::bail!(
            "reg query HKU failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut sids = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        // Lines look like:  HKEY_USERS\S-1-5-21-...
        if let Some(rest) = line.strip_prefix("HKEY_USERS\\") {
            if rest.is_empty() || rest == ".DEFAULT" || rest.contains("_Classes") {
                continue;
            }
            sids.push(rest.to_string());
        }
    }
    Ok(sids)
}

/// Acquire only Amcache.hve via `reg load`+`reg save`, falling through to a
/// raw NTFS read if the kernel won't release the file long enough for
/// `reg load` to succeed (which is the typical case while CompatTelRunner
/// or its background scheduler is mapping the hive).
pub fn collect_amcache_only(artifact_name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let dest = scratch.join(artifact_name);
    std::fs::create_dir_all(&dest)?;
    let mut stats = ArtifactStats::default();

    // Try 1: `reg load` + `reg save` — gives us the LIVE in-memory state if the
    // file is currently mappable. Most reliable when nothing has it open.
    match collect_amcache(&dest) {
        Ok(b) => {
            stats.add_file(b);
            log::info!("[{artifact_name}] Amcache.hve via reg load+save ({} KB)", b / 1024);
            return Ok(stats);
        }
        Err(e) => log::warn!("[{artifact_name}] reg load+save failed ({e:#}); falling back to raw NTFS"),
    }

    // Try 2: raw NTFS read of the locked file via \\.\C:. This bypasses the
    // file system, so it works even when CompatTelRunner has the hive mapped.
    let dst = dest.join("Amcache.hve");
    match crate::acquisition::read_locked_file(r"C:\Windows\AppCompat\Programs\Amcache.hve", &dst) {
        Ok(b) if b > 0 => {
            stats.add_file(b);
            log::info!("[{artifact_name}] Amcache.hve via raw NTFS ({} KB)", b / 1024);
        }
        Ok(_) => log::warn!("[{artifact_name}] raw NTFS read of Amcache returned 0 bytes"),
        Err(e) => log::warn!("[{artifact_name}] raw NTFS read of Amcache failed: {e:#}"),
    }
    Ok(stats)
}

fn collect_amcache(dest: &Path) -> Result<u64> {
    // Use a throwaway HKLM key that's guaranteed not to clash with anything.
    const THROWAWAY: &str = "HKLM\\DFIR_Amcache_Acquire";
    let amcache_path = PathBuf::from(r"C:\Windows\AppCompat\Programs\Amcache.hve");
    if !amcache_path.exists() {
        anyhow::bail!("Amcache.hve not present at expected path");
    }

    // 1. reg load
    let load = Command::new("reg")
        .args(["load", THROWAWAY])
        .arg(&amcache_path)
        .output()
        .context("reg load Amcache")?;
    if !load.status.success() {
        anyhow::bail!(
            "reg load Amcache failed: {}",
            String::from_utf8_lossy(&load.stderr).trim()
        );
    }
    let amcache_path = dest.join("Amcache.hve");

    // 2. reg save (use a closure so we can reliably unload on the way out)
    let result = save_hive(THROWAWAY, &amcache_path);

    // 3. reg unload (always — even if save failed, otherwise the throwaway
    //    key leaks for the lifetime of the running OS).
    let _ = Command::new("reg")
        .args(["unload", THROWAWAY])
        .output();

    result
}
