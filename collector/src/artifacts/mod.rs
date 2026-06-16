//! Artifact dispatcher.
//!
//! Each artifact is identified by a stable namespaced name (e.g. `execution.prefetch`).
//! The dispatcher routes names to the right module on the right platform.
//!
//! Output convention:
//!   - File-based artifacts copy raw files under `<scratch>/<artifact_name>/...`
//!   - Live-system artifacts emit a single output file with structured data.
//!
//! NEW: YAML-driven artifacts use the embedded_sources map from config to
//! determine collection behavior at runtime. Legacy hardcoded match arms
//! remain for backward compatibility.

pub mod kape;
pub mod live;
#[cfg(not(target_os = "windows"))]
pub mod linux_live;
pub mod patterns;
pub mod registry;

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::config::Config;

#[derive(Debug, Default, Clone, Copy)]
pub struct ArtifactStats {
    pub file_count: u64,
    pub bytes: u64,
}

impl ArtifactStats {
    pub fn add_file(&mut self, bytes: u64) {
        self.file_count += 1;
        self.bytes += bytes;
    }
}

pub fn run_artifact(
    name: &str,
    collect_root: &Path,
    scratch: &Path,
    cfg: &Config,
) -> Result<ArtifactStats> {
    // First, check if this artifact has YAML-driven embedded sources
    if let Some(source_def) = cfg.embedded_sources.get(name) {
        return run_yaml_artifact(name, collect_root, scratch, cfg, source_def);
    }

    // Legacy hardcoded dispatch for backward compatibility
    #[cfg(target_os = "windows")]
    {
        run_windows_artifact(name, collect_root, scratch, cfg)
    }
    #[cfg(not(target_os = "windows"))]
    {
        run_linux_artifact(name, collect_root, scratch, cfg)
    }
}

/// YAML-driven artifact execution — reads source definitions from embedded config.
fn run_yaml_artifact(
    name: &str,
    collect_root: &Path,
    scratch: &Path,
    _cfg: &Config,
    source_def: &crate::config::EmbeddedArtifactSource,
) -> Result<ArtifactStats> {
    let mut total_stats = ArtifactStats::default();

    for source in &source_def.sources {
        let source_type = source.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match source_type {
            "file_pattern" => {
                if let Some(globs) = source.get("globs").and_then(|v| v.as_array()) {
                    let glob_strs: Vec<&str> = globs.iter()
                        .filter_map(|g| g.as_str())
                        .collect();
                    let base = source.get("base")
                        .and_then(|v| v.as_str())
                        .map(|b| std::path::PathBuf::from(b))
                        .unwrap_or_else(|| collect_root.to_path_buf());
                    match patterns::collect(name, &base, scratch, &glob_strs) {
                        Ok(stats) => {
                            total_stats.file_count += stats.file_count;
                            total_stats.bytes += stats.bytes;
                        }
                        Err(e) => log::warn!("[yaml] file_pattern source failed for {name}: {e}"),
                    }
                }
            }
            "command" => {
                let cmd = source.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
                let args: Vec<&str> = source.get("args")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|a| a.as_str()).collect())
                    .unwrap_or_default();
                let output_file = source.get("output_file").and_then(|v| v.as_str()).unwrap_or("output.txt");

                if !cmd.is_empty() {
                    let dest = scratch.join(name);
                    std::fs::create_dir_all(&dest)?;
                    let path = dest.join(output_file);
                    log::info!("[yaml] running {cmd} {}", args.join(" "));

                    match std::process::Command::new(cmd).args(&args).output() {
                        Ok(output) => {
                            let mut buf = Vec::new();
                            buf.extend_from_slice(b"== stdout ==\n");
                            buf.extend_from_slice(&output.stdout);
                            if !output.stderr.is_empty() {
                                buf.extend_from_slice(b"\n== stderr ==\n");
                                buf.extend_from_slice(&output.stderr);
                            }
                            std::fs::write(&path, &buf)?;
                            total_stats.add_file(buf.len() as u64);
                        }
                        Err(e) => log::warn!("[yaml] command {cmd} failed: {e}"),
                    }
                }
            }
            "registry" => {
                #[cfg(target_os = "windows")]
                {
                    // NOTE: `collect_live` saves the full standard hive set; the
                    // per-source `hives` list is not yet honored individually.
                    if source.get("hives").and_then(|v| v.as_array()).is_some() {
                        let method = source.get("method").and_then(|v| v.as_str()).unwrap_or("reg_save");
                        match method {
                            "reg_save" => {
                                match registry::collect_live(name, scratch) {
                                    Ok(stats) => {
                                        total_stats.file_count += stats.file_count;
                                        total_stats.bytes += stats.bytes;
                                    }
                                    Err(e) => log::warn!("[yaml] registry reg_save failed for {name}: {e}"),
                                }
                            }
                            _ => log::warn!("[yaml] unsupported registry method: {method}"),
                        }
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    log::warn!("[yaml] registry sources not supported on Linux: {name}");
                }
            }
            "raw_ntfs" => {
                #[cfg(target_os = "windows")]
                {
                    if let Some(files) = source.get("files").and_then(|v| v.as_array()) {
                        let file_strs: Vec<&str> = files.iter().filter_map(|f| f.as_str()).collect();
                        match patterns::collect_raw_volume(name, collect_root, scratch, &file_strs) {
                            Ok(stats) => {
                                total_stats.file_count += stats.file_count;
                                total_stats.bytes += stats.bytes;
                            }
                            Err(e) => log::warn!("[yaml] raw_ntfs failed for {name}: {e}"),
                        }
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    log::warn!("[yaml] raw_ntfs sources not supported on Linux: {name}");
                }
            }
            other => log::warn!("[yaml] unknown source type '{other}' in artifact {name}"),
        }
    }

    Ok(total_stats)
}

#[cfg(target_os = "windows")]
fn run_windows_artifact(
    name: &str,
    collect_root: &Path,
    scratch: &Path,
    cfg: &Config,
) -> Result<ArtifactStats> {
    match name {
        // ---------- Evidence of execution ----------
        "execution.prefetch" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/Prefetch/*.pf"],
        ),
        "execution.amcache" => {
            let live_stats = registry::collect_amcache_only(name, scratch).unwrap_or_default();
            let file_stats = patterns::collect(
                &format!("{name}.files"), collect_root, scratch,
                &[
                    "Windows/AppCompat/Programs/Amcache.hve.LOG1",
                    "Windows/AppCompat/Programs/Amcache.hve.LOG2",
                    "Windows/AppCompat/Programs/RecentFileCache.bcf",
                ],
            ).unwrap_or_default();
            Ok(ArtifactStats {
                file_count: live_stats.file_count + file_stats.file_count,
                bytes:      live_stats.bytes      + file_stats.bytes,
            })
        }
        "execution.shimcache" => {
            let dest = scratch.join(name);
            std::fs::create_dir_all(&dest)?;
            std::fs::write(
                dest.join("README.txt"),
                "ShimCache (AppCompatCache) lives inside the SYSTEM registry \
                 hive. Parse with AppCompatCacheParser.exe or RegRipper.\n",
            )?;
            let mut stats = ArtifactStats::default();
            stats.add_file(std::fs::metadata(dest.join("README.txt"))?.len());
            Ok(stats)
        }
        "execution.bam" | "execution.userassist" | "execution.muicache" => Ok(ArtifactStats::default()),

        // ---------- File system ----------
        "filesystem.mft" => patterns::collect_raw_volume(
            name, collect_root, scratch, &["$MFT", "$LogFile", "$Extend/$UsnJrnl:$J"],
        ),
        "filesystem.lnk" => patterns::collect(
            name, collect_root, scratch,
            &[
                "Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk",
                "Users/*/AppData/Roaming/Microsoft/Office/Recent/*.lnk",
                "Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*",
                "Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*",
            ],
        ),
        "filesystem.recyclebin" => patterns::collect(name, collect_root, scratch, &["$Recycle.Bin/**/*"]),

        // ---------- Registry ----------
        "registry.hives" => {
            let live_stats = registry::collect_live(name, scratch)?;
            let file_stats = patterns::collect(
                &format!("{name}.files"), collect_root, scratch,
                &[
                    "Windows/System32/config/SAM.LOG1", "Windows/System32/config/SAM.LOG2",
                    "Windows/System32/config/SECURITY.LOG1", "Windows/System32/config/SECURITY.LOG2",
                    "Windows/System32/config/SOFTWARE.LOG1", "Windows/System32/config/SOFTWARE.LOG2",
                    "Windows/System32/config/SYSTEM.LOG1", "Windows/System32/config/SYSTEM.LOG2",
                    "Windows/System32/config/RegBack/*",
                    "Users/*/NTUSER.DAT.LOG1", "Users/*/NTUSER.DAT.LOG2",
                    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1",
                    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2",
                ],
            ).unwrap_or_default();
            Ok(ArtifactStats {
                file_count: live_stats.file_count + file_stats.file_count,
                bytes:      live_stats.bytes      + file_stats.bytes,
            })
        }

        // ---------- Event logs ----------
        "eventlogs.security" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Security.evtx"]),
        "eventlogs.system" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/System.evtx"]),
        "eventlogs.application" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Application.evtx"]),
        "eventlogs.powershell" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell*.evtx", "Windows/System32/winevt/Logs/Windows PowerShell.evtx"]),
        "eventlogs.sysmon" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon*.evtx"]),
        "eventlogs.defender" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender*.evtx"]),
        "eventlogs.rdp" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices*.evtx", "Windows/System32/winevt/Logs/Microsoft-Windows-RemoteDesktop*.evtx"]),
        "eventlogs.taskscheduler" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler*.evtx"]),
        "eventlogs.wmi" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity*.evtx"]),
        "eventlogs.bits" => patterns::collect(name, collect_root, scratch, &["Windows/System32/winevt/Logs/Microsoft-Windows-Bits-Client*.evtx"]),

        // ---------- Browser ----------
        "browser.chrome" => {
            let scope = cfg.artifact_param_str(name, "scope", "standard");
            let profiles = cfg.artifact_param_str(name, "profiles", "all");
            let pat = chromium_patterns("Google/Chrome/User Data", scope, profiles);
            patterns::collect(name, collect_root, scratch, &pat.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "browser.edge" => {
            let scope = cfg.artifact_param_str(name, "scope", "standard");
            let profiles = cfg.artifact_param_str(name, "profiles", "all");
            let pat = chromium_patterns("Microsoft/Edge/User Data", scope, profiles);
            patterns::collect(name, collect_root, scratch, &pat.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "browser.firefox" => {
            let scope = cfg.artifact_param_str(name, "scope", "standard");
            let pat = firefox_patterns_win(scope);
            patterns::collect(name, collect_root, scratch, &pat.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }

        // ---------- Cloud / modern ----------
        "cloud.onedrive" => patterns::collect(name, collect_root, scratch, &["Users/*/AppData/Local/Microsoft/OneDrive/logs/**/*"]),
        "cloud.outlook" => patterns::collect(name, collect_root, scratch, &["Users/*/AppData/Local/Microsoft/Outlook/*.ost", "Users/*/Documents/Outlook Files/*.pst"]),
        "cloud.teams" => patterns::collect(name, collect_root, scratch, &["Users/*/AppData/Roaming/Microsoft/Teams/**/*"]),
        "cred.dpapi" => patterns::collect(name, collect_root, scratch, &["Windows/System32/Microsoft/Protect/**/*", "Users/*/AppData/Roaming/Microsoft/Protect/**/*", "Users/*/AppData/Local/Microsoft/Credentials/*", "Users/*/AppData/Roaming/Microsoft/Credentials/*"]),

        // ---------- Persistence ----------
        "persistence.scheduledtasks" => patterns::collect(name, collect_root, scratch, &["Windows/System32/Tasks/**/*", "Windows/Tasks/**/*"]),
        "persistence.startupfolders" => patterns::collect(name, collect_root, scratch, &["Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*", "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/*"]),

        // ---------- Live system ----------
        "live.netstat" => live::netstat(name, scratch),
        "live.pslist" => live::pslist(name, scratch),
        "live.dnscache" => live::dnscache(name, scratch),
        "live.arpcache" => live::arpcache(name, scratch),
        "live.services" => live::services(name, scratch),
        "live.systeminfo" => live::systeminfo(name, scratch),
        "live.usbhistory" => live::usbhistory(name, scratch),
        "live.wifihistory" => live::wifihistory(name, scratch),
        "live.shares" => live::shares(name, scratch),
        "live.firewallrules" => live::firewallrules(name, scratch),
        "live.autoruns" => live::autoruns(name, scratch),

        // ---------- Memory ----------
        "memory.fulldump" => patterns::memory_dump(name, scratch),

        unknown => Err(anyhow!("unknown artifact: {unknown}")),
    }
}

#[cfg(not(target_os = "windows"))]
fn run_linux_artifact(
    name: &str,
    collect_root: &Path,
    scratch: &Path,
    cfg: &Config,
) -> Result<ArtifactStats> {
    match name {
        // ---------- System ----------
        "linux.system.osinfo" => {
            let mut stats = linux_live::osinfo(name, scratch)?;
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/os-release", "etc/hostname", "etc/machine-id", "etc/timezone",
                "proc/version", "proc/cmdline", "proc/uptime",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.system.users" => {
            let mut stats = linux_live::users(name, scratch)?;
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/passwd", "etc/shadow", "etc/group", "etc/gshadow",
                "etc/sudoers", "etc/sudoers.d/*", "etc/login.defs",
                "etc/pam.d/*",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.system.ssh" => patterns::collect(name, collect_root, scratch, &[
            "etc/ssh/sshd_config", "etc/ssh/ssh_config", "etc/ssh/ssh_host_*",
            "home/*/.ssh/authorized_keys", "home/*/.ssh/authorized_keys2",
            "home/*/.ssh/known_hosts", "home/*/.ssh/config", "home/*/.ssh/id_*",
            "root/.ssh/authorized_keys", "root/.ssh/authorized_keys2",
            "root/.ssh/known_hosts", "root/.ssh/config", "root/.ssh/id_*",
        ]),
        "linux.system.packages" => linux_live::packages(name, scratch),

        // ---------- Logs ----------
        "linux.logs.syslog" => {
            let days: u32 = cfg.artifact_param_str(name, "journal_days", "30").parse().unwrap_or(30);
            let mut stats = linux_live::journal_logs(name, scratch, days).unwrap_or_default();
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "var/log/syslog", "var/log/syslog.*",
                "var/log/messages", "var/log/messages.*",
                "var/log/kern.log", "var/log/kern.log.*",
                "var/log/daemon.log", "var/log/daemon.log.*",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.logs.auth" => patterns::collect(name, collect_root, scratch, &[
            "var/log/auth.log", "var/log/auth.log.*",
            "var/log/secure", "var/log/secure.*",
            "var/log/faillog", "var/log/btmp", "var/log/btmp.*",
            "var/log/wtmp", "var/log/wtmp.*", "var/log/utmp", "var/log/lastlog",
        ]),
        "linux.logs.audit" => {
            let mut stats = linux_live::audit_rules(name, scratch).unwrap_or_default();
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "var/log/audit/audit.log", "var/log/audit/audit.log.*",
                "etc/audit/auditd.conf", "etc/audit/audit.rules", "etc/audit/rules.d/*",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.logs.application" => patterns::collect(name, collect_root, scratch, &[
            "var/log/apache2/**/*", "var/log/httpd/**/*", "var/log/nginx/**/*",
            "var/log/mysql/**/*", "var/log/postgresql/**/*",
            "var/log/mail.log", "var/log/mail.log.*",
            "var/log/cron", "var/log/cron.*",
            "var/log/dpkg.log", "var/log/dpkg.log.*",
            "var/log/apt/**/*", "var/log/yum.log", "var/log/dnf.log",
        ]),

        // ---------- Network ----------
        "linux.network.connections" => linux_live::connections(name, scratch),
        "linux.network.processes" => linux_live::processes(name, scratch),
        "linux.network.firewall" => linux_live::firewall(name, scratch),
        "linux.network.dns" => {
            let mut stats = linux_live::dns_config(name, scratch).unwrap_or_default();
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/resolv.conf", "etc/hosts", "etc/nsswitch.conf",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }

        // ---------- Persistence ----------
        "linux.persistence.crontabs" => {
            let mut stats = linux_live::crontabs(name, scratch)?;
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/crontab", "etc/cron.d/*", "etc/cron.daily/*",
                "etc/cron.hourly/*", "etc/cron.weekly/*", "etc/cron.monthly/*",
                "etc/anacrontab", "var/spool/cron/crontabs/*", "var/spool/cron/*",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.persistence.systemd" => {
            let mut stats = linux_live::systemd_units(name, scratch)?;
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/systemd/system/**/*.service", "etc/systemd/system/**/*.timer",
                "etc/systemd/system/**/*.socket",
                "usr/lib/systemd/system/**/*.service", "usr/lib/systemd/system/**/*.timer",
                "home/*/.config/systemd/user/**/*.service",
                "root/.config/systemd/user/**/*.service",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.persistence.initscripts" => patterns::collect(name, collect_root, scratch, &[
            "etc/rc.local", "etc/init.d/*", "etc/rc*.d/*",
            "etc/profile", "etc/profile.d/*", "etc/bash.bashrc", "etc/environment",
            "home/*/.bashrc", "home/*/.bash_profile", "home/*/.profile",
            "home/*/.bash_logout", "home/*/.zshrc", "home/*/.zprofile",
            "root/.bashrc", "root/.bash_profile", "root/.profile",
            "etc/ld.so.preload", "etc/ld.so.conf", "etc/ld.so.conf.d/*",
        ]),
        "linux.persistence.kernel_modules" => {
            let mut stats = ArtifactStats::default();
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/modprobe.d/*", "etc/modules", "etc/modules-load.d/*",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }

        // ---------- Browser ----------
        "linux.browser.chrome" => patterns::collect(name, collect_root, scratch, &[
            "home/*/.config/google-chrome/Default/History",
            "home/*/.config/google-chrome/Default/Cookies",
            "home/*/.config/google-chrome/Default/Login Data",
            "home/*/.config/google-chrome/Default/Web Data",
            "home/*/.config/google-chrome/Default/Bookmarks",
            "home/*/.config/google-chrome/Local State",
            "home/*/.config/chromium/Default/History",
            "home/*/.config/chromium/Default/Cookies",
            "home/*/.config/chromium/Default/Login Data",
            "home/*/.config/chromium/Local State",
        ]),
        "linux.browser.firefox" => patterns::collect(name, collect_root, scratch, &[
            "home/*/.mozilla/firefox/*/places.sqlite",
            "home/*/.mozilla/firefox/*/cookies.sqlite",
            "home/*/.mozilla/firefox/*/formhistory.sqlite",
            "home/*/.mozilla/firefox/*/logins.json",
            "home/*/.mozilla/firefox/*/key4.db",
            "home/*/.mozilla/firefox/*/sessionstore.jsonlz4",
            "home/*/.mozilla/firefox/profiles.ini",
        ]),

        // ---------- Memory ----------
        "linux.memory.proc_maps" => linux_live::proc_maps(name, scratch),
        "linux.memory.lime_dump" => {
            log::warn!("[{name}] LiME kernel module must be loaded manually");
            Ok(ArtifactStats::default())
        }

        // ---------- Containers ----------
        "linux.containers.docker" => {
            let mut stats = linux_live::docker_info(name, scratch)?;
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "var/lib/docker/containers/*/*.log",
                "var/lib/docker/containers/*/config.v2.json",
                "etc/docker/daemon.json",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }
        "linux.containers.kubernetes" => {
            let mut stats = linux_live::kubernetes_info(name, scratch)?;
            let file_stats = patterns::collect(name, collect_root, scratch, &[
                "etc/kubernetes/**/*", "var/lib/kubelet/config.yaml",
                "var/log/pods/**/*", "var/log/containers/**/*",
            ]).unwrap_or_default();
            stats.file_count += file_stats.file_count;
            stats.bytes += file_stats.bytes;
            Ok(stats)
        }

        unknown => Err(anyhow!("unknown artifact: {unknown}")),
    }
}

fn chromium_patterns(relative_user_data_dir: &str, scope: &str, profiles: &str) -> Vec<String> {
    let profile_glob = if profiles == "default" { "Default" } else { "*" };
    let base = format!("Users/*/AppData/Local/{relative_user_data_dir}");
    match scope {
        "minimal" => vec![format!("{base}/{profile_glob}/History")],
        "full" => vec![
            format!("{base}/{profile_glob}/**/*"),
            format!("{base}/Local State"),
        ],
        _ => vec![
            format!("{base}/{profile_glob}/History"),
            format!("{base}/{profile_glob}/Cookies"),
            format!("{base}/{profile_glob}/Login Data"),
            format!("{base}/{profile_glob}/Login Data For Account"),
            format!("{base}/{profile_glob}/Web Data"),
            format!("{base}/{profile_glob}/Bookmarks"),
            format!("{base}/{profile_glob}/Top Sites"),
            format!("{base}/{profile_glob}/Shortcuts"),
            format!("{base}/{profile_glob}/Sessions/*"),
            format!("{base}/{profile_glob}/Visited Links"),
            format!("{base}/{profile_glob}/Network/*"),
            format!("{base}/{profile_glob}/Preferences"),
            format!("{base}/Local State"),
        ],
    }
}

fn firefox_patterns_win(scope: &str) -> Vec<String> {
    let base = "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles".to_string();
    match scope {
        "minimal" => vec![format!("{base}/*/places.sqlite")],
        "full" => vec![format!("{base}/*/**/*")],
        _ => vec![
            format!("{base}/*/places.sqlite"), format!("{base}/*/cookies.sqlite"),
            format!("{base}/*/formhistory.sqlite"), format!("{base}/*/downloads.sqlite"),
            format!("{base}/*/logins.json"), format!("{base}/*/key4.db"),
            format!("{base}/*/cert9.db"), format!("{base}/*/sessionstore.jsonlz4"),
        ],
    }
}
