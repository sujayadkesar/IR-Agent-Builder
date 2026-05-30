//! Volume Shadow Copy creation.
//!
//! Strategy (in order):
//!   1. WMI `Win32_ShadowCopy::Create("C:\\", "ClientAccessible")` via PowerShell.
//!      This is the ONLY method that works on Windows Home editions and is the
//!      same call internally used by Veeam/Backup-Exec/Volume Backup tools.
//!      Returns a DeviceObject path like
//!      `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42`.
//!   2. `vssadmin create shadow /for=C:` — works only on Server SKUs and
//!      sometimes Pro. Kept as a fallback because it's slightly faster and
//!      more reliable on Server hosts that have admin policy locking down
//!      WMI access.
//!
//! Once we have a DeviceObject, we create an NTFS junction at
//! `%TEMP%\dfir-vss-<pid>` so the rest of the collector can read files via
//! a normal directory tree.
//!
//! What if BOTH methods fail? We continue without a snapshot. The
//! patterns module's `copy_with_fallback` will (a) try shared-read open
//! and (b) fall through to the raw NTFS reader (`crate::acquisition`)
//! which bypasses file-system locks entirely.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
pub fn create_system_snapshot() -> Result<PathBuf> {
    // 1. Try WMI via PowerShell. This works on Home / Pro / Enterprise / Server.
    match create_via_wmi() {
        Ok(p) => {
            log::info!("VSS snapshot created via WMI Win32_ShadowCopy.Create");
            return Ok(p);
        }
        Err(e) => log::warn!("WMI VSS create failed ({e:#}); trying vssadmin fallback"),
    }
    // 2. Fall back to vssadmin (Server-only).
    match create_via_vssadmin() {
        Ok(p) => {
            log::info!("VSS snapshot created via vssadmin");
            Ok(p)
        }
        Err(e) => bail!("All VSS creation methods failed; last error: {e:#}"),
    }
}

#[cfg(not(windows))]
pub fn create_system_snapshot() -> Result<PathBuf> {
    bail!("VSS only available on Windows")
}

#[cfg(windows)]
fn create_via_wmi() -> Result<PathBuf> {
    // PowerShell script that:
    //   1. Calls Win32_ShadowCopy::Create("C:\\", "ClientAccessible")
    //   2. Looks up the resulting ShadowCopy by its returned ShadowID
    //   3. Writes ONLY the DeviceObject path to stdout, with no decoration
    //
    // We intentionally request "ClientAccessible" so the snapshot is mountable
    // via a junction (vs. "NoAutoRelease" which is harder to read from).
    let ps_script = r#"
$ErrorActionPreference = 'Stop'
$class = [WMIClass]'\\.\root\cimv2:Win32_ShadowCopy'
$result = $class.Create('C:\', 'ClientAccessible')
if ($result.ReturnValue -ne 0) {
    Write-Error "Win32_ShadowCopy.Create returned non-zero: $($result.ReturnValue)"
    exit 1
}
$snap = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
if (-not $snap) {
    Write-Error "Created shadow but could not look it up by ID $($result.ShadowID)"
    exit 1
}
[Console]::Out.Write($snap.DeviceObject)
"#;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", ps_script,
        ])
        .output()
        .context("invoking powershell for WMI VSS create")?;

    if !output.status.success() {
        bail!(
            "WMI VSS create failed status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !device.starts_with(r"\\?\GLOBALROOT") {
        bail!(
            "Unexpected device path from WMI: {device:?} (stderr: {})",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    log::info!("WMI shadow device: {device}");
    junction_to(&device)
}

#[cfg(windows)]
fn create_via_vssadmin() -> Result<PathBuf> {
    let output = Command::new("vssadmin")
        .args(["create", "shadow", "/for=C:"])
        .output()
        .context("invoking vssadmin")?;

    if !output.status.success() {
        bail!(
            "vssadmin failed status={:?} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let device = stdout
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Shadow Copy Volume Name:")
                .or_else(|| l.trim().strip_prefix("Shadow Copy Volume:"))
                .map(|s| s.trim().to_string())
        })
        .ok_or_else(|| anyhow!("could not parse VSS device path from vssadmin output:\n{stdout}"))?;
    junction_to(&device)
}

#[cfg(windows)]
fn junction_to(device: &str) -> Result<PathBuf> {
    let mount_point = std::env::temp_dir().join(format!("dfir-vss-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mount_point);

    // mklink /J target_link target_path — the trailing backslash on the
    // GLOBALROOT path is critical or the junction creation fails.
    let target_with_trailing = format!("{}\\", device.trim_end_matches('\\'));
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&mount_point)
        .arg(&target_with_trailing)
        .status()
        .context("creating VSS junction via mklink")?;
    if !status.success() {
        bail!("mklink /J failed status={status:?}");
    }
    Ok(mount_point)
}

pub fn release_snapshot(mount: &Path) -> Result<()> {
    // Just remove the junction. The shadow copy itself stays in the system
    // copy store; Windows GCs it via volume shadow storage rules. Explicit
    // deletion would require parsing the shadow ID from the junction
    // target — a follow-up if storage pressure becomes an issue.
    let _ = std::fs::remove_dir(mount);
    Ok(())
}
