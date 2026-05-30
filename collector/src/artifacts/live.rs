//! Live system artifacts — invoked at collection time by shelling out to
//! native Windows tooling (no third-party dependency) and capturing structured
//! output. Each function writes a single text file (often JSONL) under
//! `<scratch>/<artifact_name>/output.txt`.
//!
//! For a production tool these would be replaced with direct Win32 API calls
//! (e.g. `GetExtendedTcpTable` instead of `netstat`), but shelling out gives
//! us a working baseline that mirrors what an analyst would produce on-screen.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use super::ArtifactStats;

fn write_command_output(
    artifact_name: &str,
    scratch: &Path,
    cmd: &str,
    args: &[&str],
    out_filename: &str,
) -> Result<ArtifactStats> {
    let dest = scratch.join(artifact_name);
    std::fs::create_dir_all(&dest)?;
    let path = dest.join(out_filename);
    log::info!("[{artifact_name}] running {cmd} {}", args.join(" "));
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;

    let mut buf = Vec::with_capacity(output.stdout.len() + output.stderr.len() + 64);
    buf.extend_from_slice(b"== stdout ==\r\n");
    buf.extend_from_slice(&output.stdout);
    if !output.stderr.is_empty() {
        buf.extend_from_slice(b"\r\n== stderr ==\r\n");
        buf.extend_from_slice(&output.stderr);
    }
    std::fs::write(&path, &buf)?;

    let mut stats = ArtifactStats::default();
    stats.add_file(buf.len() as u64);
    Ok(stats)
}

pub fn netstat(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "netstat", &["-anob"], "netstat.txt")
}

pub fn pslist(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(
        name, scratch, "tasklist",
        &["/v", "/fo", "csv"],
        "tasklist.csv",
    )
}

pub fn dnscache(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "ipconfig", &["/displaydns"], "dnscache.txt")
}

pub fn arpcache(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "arp", &["-a"], "arp.txt")
}

pub fn services(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut s = ArtifactStats::default();
    s = combine(
        s,
        write_command_output(name, scratch, "sc", &["query", "type=", "service", "state=", "all"], "services.txt")?,
    );
    s = combine(
        s,
        write_command_output(name, scratch, "wmic", &["service", "get", "name,displayname,pathname,startname,startmode,state", "/format:csv"], "services.csv")
            .unwrap_or_default(),
    );
    Ok(s)
}

pub fn systeminfo(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "systeminfo", &[], "systeminfo.txt")
}

pub fn usbhistory(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    // Best-effort dump of USBSTOR via reg query
    write_command_output(
        name, scratch,
        "reg",
        &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "/s"],
        "usbstor.txt",
    )
}

pub fn wifihistory(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "netsh", &["wlan", "show", "profiles"], "wifi.txt")
}

pub fn shares(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "net", &["share"], "shares.txt")
}

pub fn firewallrules(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(
        name, scratch,
        "netsh",
        &["advfirewall", "firewall", "show", "rule", "name=all"],
        "firewall.txt",
    )
}

pub fn autoruns(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    // Native PowerShell equivalent: enumerate Run/RunOnce + Startup folders
    let ps_cmd = r#"
$out = @()
$keys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $keys) {
    if (Test-Path $k) {
        Get-ItemProperty $k | Get-Member -MemberType NoteProperty | ForEach-Object {
            $out += [PSCustomObject]@{ Hive=$k; Name=$_.Name; Value=(Get-ItemProperty $k).$($_.Name) }
        }
    }
}
$out | ConvertTo-Json -Depth 3
"#;
    write_command_output(name, scratch, "powershell", &["-NoProfile", "-Command", ps_cmd], "autoruns.json")
}

fn combine(a: ArtifactStats, b: ArtifactStats) -> ArtifactStats {
    ArtifactStats {
        file_count: a.file_count + b.file_count,
        bytes: a.bytes + b.bytes,
    }
}
