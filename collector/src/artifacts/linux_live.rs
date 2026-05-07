//! Linux live system artifacts — native Linux commands for forensic collection.
//! Mirrors the Windows live.rs module but uses Linux-native tools.

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
    buf.extend_from_slice(b"== stdout ==\n");
    buf.extend_from_slice(&output.stdout);
    if !output.stderr.is_empty() {
        buf.extend_from_slice(b"\n== stderr ==\n");
        buf.extend_from_slice(&output.stderr);
    }
    std::fs::write(&path, &buf)?;

    let mut stats = ArtifactStats::default();
    stats.add_file(buf.len() as u64);
    Ok(stats)
}

fn write_bash_output(
    artifact_name: &str,
    scratch: &Path,
    script: &str,
    out_filename: &str,
) -> Result<ArtifactStats> {
    write_command_output(artifact_name, scratch, "bash", &["-c", script], out_filename)
}

pub fn connections(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "ss", &["-tulnpe"], "ss.txt")?);
    stats = combine(stats, write_command_output(name, scratch, "netstat", &["-tulnpe"], "netstat.txt").unwrap_or_default());
    Ok(stats)
}

pub fn processes(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "ps", &["auxwwf"], "ps_aux.txt")?);
    stats = combine(stats, write_bash_output(name, scratch,
        "ls -la /proc/[0-9]*/exe 2>/dev/null", "proc_exe_links.txt").unwrap_or_default());
    Ok(stats)
}

pub fn osinfo(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "uname", &["-a"], "uname.txt")?);
    stats = combine(stats, write_command_output(name, scratch, "hostnamectl", &[], "hostnamectl.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "df", &["-h"], "df.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "mount", &[], "mount.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "lsmod", &[], "lsmod.txt").unwrap_or_default());
    Ok(stats)
}

pub fn users(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "last", &["-Faiwx"], "last.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "lastb", &["-Faiwx"], "lastb.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "lastlog", &[], "lastlog.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "who", &["-a"], "who.txt").unwrap_or_default());
    Ok(stats)
}

pub fn firewall(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "iptables", &["-L", "-n", "-v", "--line-numbers"], "iptables.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "iptables", &["-t", "nat", "-L", "-n", "-v"], "iptables_nat.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "nft", &["list", "ruleset"], "nftables.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "ip", &["addr", "show"], "ip_addr.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "ip", &["route", "show"], "ip_route.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "ip", &["neigh", "show"], "ip_neigh.txt").unwrap_or_default());
    Ok(stats)
}

pub fn dns_config(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "resolvectl", &["status"], "resolvectl.txt").unwrap_or_default());
    Ok(stats)
}

pub fn packages(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "dpkg", &["-l"], "dpkg_list.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "rpm", &["-qa"], "rpm_list.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "snap", &["list"], "snap_list.txt").unwrap_or_default());
    Ok(stats)
}

pub fn crontabs(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_bash_output(name, scratch,
        "for user in $(cut -f1 -d: /etc/passwd); do echo \"=== $user ===\"; crontab -l -u $user 2>/dev/null; done",
        "user_crontabs.txt")?);
    Ok(stats)
}

pub fn systemd_units(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "systemctl", &["list-units", "--all", "--no-pager"], "systemctl_units.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "systemctl", &["list-timers", "--all", "--no-pager"], "systemctl_timers.txt").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "systemctl", &["list-unit-files", "--no-pager"], "systemctl_unit_files.txt").unwrap_or_default());
    Ok(stats)
}

pub fn audit_rules(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    write_command_output(name, scratch, "auditctl", &["-l"], "auditctl_rules.txt")
}

pub fn docker_info(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "docker", &["ps", "-a", "--no-trunc", "--format", "json"], "docker_ps.json").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "docker", &["images", "--no-trunc", "--format", "json"], "docker_images.json").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "docker", &["network", "ls", "--no-trunc", "--format", "json"], "docker_networks.json").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "docker", &["info", "--format", "json"], "docker_info.json").unwrap_or_default());
    Ok(stats)
}

pub fn kubernetes_info(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_command_output(name, scratch, "kubectl", &["get", "pods", "--all-namespaces", "-o", "json"], "kubectl_pods.json").unwrap_or_default());
    stats = combine(stats, write_command_output(name, scratch, "crictl", &["ps", "-a", "-o", "json"], "crictl_ps.json").unwrap_or_default());
    Ok(stats)
}

pub fn proc_maps(name: &str, scratch: &Path) -> Result<ArtifactStats> {
    let mut stats = ArtifactStats::default();
    stats = combine(stats, write_bash_output(name, scratch,
        "for pid in /proc/[0-9]*/; do echo \"=== PID $(basename $pid) ===\"; cat $pid/cmdline 2>/dev/null | tr '\\0' ' '; echo; cat $pid/maps 2>/dev/null; echo; done",
        "proc_maps.txt")?);
    stats = combine(stats, write_bash_output(name, scratch,
        "for pid in /proc/[0-9]*/; do echo \"=== PID $(basename $pid) ===\"; cat $pid/status 2>/dev/null; echo; done",
        "proc_status.txt")?);
    Ok(stats)
}

pub fn journal_logs(name: &str, scratch: &Path, days: u32) -> Result<ArtifactStats> {
    write_command_output(
        name, scratch, "journalctl",
        &["--no-pager", "--since", &format!("{days} days ago"), "--output", "json"],
        "journal.json",
    )
}

fn combine(a: ArtifactStats, b: ArtifactStats) -> ArtifactStats {
    ArtifactStats {
        file_count: a.file_count + b.file_count,
        bytes: a.bytes + b.bytes,
    }
}
