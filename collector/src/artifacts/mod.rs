//! Artifact dispatcher.
//!
//! Each artifact is identified by a stable namespaced name (e.g. `execution.prefetch`).
//! The dispatcher in `run_artifact` matches the name and calls the right module.
//! Each module returns an `ArtifactStats` so the run report can summarize totals.
//!
//! Output convention:
//!   - File-based artifacts copy raw files preserving their relative path under
//!     `<scratch>/<artifact_name>/...` (e.g. `<scratch>/execution.prefetch/Windows/Prefetch/*.pf`).
//!   - Live-system artifacts emit a single `<artifact_name>.jsonl` file with one
//!     JSON object per row, mirroring Velociraptor's JSONL output convention.

pub mod kape;
pub mod live;
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
    // The pattern table below is the core of the artifact catalog. It mirrors §2.1–2.7
    // of the research doc — the names line up with what the UI exposes to the user.
    match name {
        // ---------- Evidence of execution ----------
        "execution.prefetch" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/Prefetch/*.pf"],
        ),
        "execution.amcache" => {
            // Amcache.hve is locked under normal operation. Two strategies:
            //   (a) `reg load`+`reg save` — we pull the live state. This is
            //       what `registry::collect_live()` does specifically for
            //       Amcache via `collect_amcache()`.
            //   (b) File copy of the .hve + LOG files — succeeds only when
            //       VSS is on or when telemetry agent has briefly closed
            //       the file. Provides the LOG transaction journal which
            //       reg save does not.
            // Both run; we report the union.
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
            // Shimcache (AppCompatCache) is not a separate file — it lives
            // INSIDE the SYSTEM hive at HKLM\SYSTEM\CurrentControlSet\Control\
            // Session Manager\AppCompatCache. The `registry.hives` artifact
            // captures the SYSTEM hive in full via `reg save`, so shimcache
            // is already inside that capture. This artifact emits a small
            // marker file so the analyst knows where to look.
            let dest = scratch.join(name);
            std::fs::create_dir_all(&dest)?;
            std::fs::write(
                dest.join("README.txt"),
                "ShimCache (AppCompatCache) lives inside the SYSTEM registry \
                 hive at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session \
                 Manager\\AppCompatCache. Make sure the `registry.hives` \
                 artifact is enabled — the SYSTEM.hive file in that \
                 collection contains shimcache. Parse it with tools like \
                 AppCompatCacheParser.exe (Eric Zimmerman) or RegRipper.\n",
            )?;
            log::info!("[{name}] noted: shimcache lives inside SYSTEM hive (collected by registry.hives)");
            let mut stats = ArtifactStats::default();
            stats.add_file(std::fs::metadata(dest.join("README.txt"))?.len());
            Ok(stats)
        }
        "execution.bam" => Ok(ArtifactStats::default()), // satisfied by SYSTEM hive
        "execution.userassist" | "execution.muicache" => Ok(ArtifactStats::default()),

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
        "filesystem.recyclebin" => patterns::collect(
            name, collect_root, scratch,
            &["$Recycle.Bin/**/*"],
        ),

        // ---------- Registry ----------
        // Live registry collection: ALWAYS use `reg save` (RegSaveKey) — it
        // works regardless of file locks on the underlying hive files. If
        // VSS is available we ALSO copy the on-disk hives + LOG1/LOG2
        // transaction logs (useful for forensic timeline reconstruction);
        // when VSS is off and the hives are locked, those copies fail
        // silently while reg save still produces complete dumps. The
        // analyst gets the live state at minimum, plus disk-level files
        // when they're accessible.
        "registry.hives" => {
            let live_stats = registry::collect_live(name, scratch)?;
            let file_stats = patterns::collect(
                &format!("{name}.files"),
                collect_root,
                scratch,
                &[
                    "Windows/System32/config/SAM.LOG1",
                    "Windows/System32/config/SAM.LOG2",
                    "Windows/System32/config/SECURITY.LOG1",
                    "Windows/System32/config/SECURITY.LOG2",
                    "Windows/System32/config/SOFTWARE.LOG1",
                    "Windows/System32/config/SOFTWARE.LOG2",
                    "Windows/System32/config/SYSTEM.LOG1",
                    "Windows/System32/config/SYSTEM.LOG2",
                    "Windows/System32/config/RegBack/*",
                    "Users/*/NTUSER.DAT.LOG1",
                    "Users/*/NTUSER.DAT.LOG2",
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
        "eventlogs.security" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Security.evtx"],
        ),
        "eventlogs.system" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/System.evtx"],
        ),
        "eventlogs.application" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Application.evtx"],
        ),
        "eventlogs.powershell" => patterns::collect(
            name, collect_root, scratch,
            &[
                "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell*.evtx",
                "Windows/System32/winevt/Logs/Windows PowerShell.evtx",
            ],
        ),
        "eventlogs.sysmon" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon*.evtx"],
        ),
        "eventlogs.defender" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender*.evtx"],
        ),
        "eventlogs.rdp" => patterns::collect(
            name, collect_root, scratch,
            &[
                "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices*.evtx",
                "Windows/System32/winevt/Logs/Microsoft-Windows-RemoteDesktop*.evtx",
            ],
        ),
        "eventlogs.taskscheduler" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler*.evtx"],
        ),
        "eventlogs.wmi" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity*.evtx"],
        ),
        "eventlogs.bits" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/winevt/Logs/Microsoft-Windows-Bits-Client*.evtx"],
        ),

        // ---------- Browser ----------
        // Each browser artifact reads two parameters from cfg.artifact_params:
        //   scope    — minimal | standard | full
        //   profiles — default | all  (Chrome/Edge only; Firefox uses *.default-release)
        // The patterns adapt accordingly. See docs/live-acquisition.md and
        // catalog.js for the matrix.
        "browser.chrome" => {
            let scope    = cfg.artifact_param_str(name, "scope",    "standard");
            let profiles = cfg.artifact_param_str(name, "profiles", "all");
            log::info!("[{name}] scope={scope} profiles={profiles}");
            let pat = chromium_patterns("Google/Chrome/User Data", scope, profiles);
            patterns::collect(name, collect_root, scratch, &pat.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "browser.edge" => {
            let scope    = cfg.artifact_param_str(name, "scope",    "standard");
            let profiles = cfg.artifact_param_str(name, "profiles", "all");
            log::info!("[{name}] scope={scope} profiles={profiles}");
            let pat = chromium_patterns("Microsoft/Edge/User Data", scope, profiles);
            patterns::collect(name, collect_root, scratch, &pat.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }
        "browser.firefox" => {
            let scope = cfg.artifact_param_str(name, "scope", "standard");
            log::info!("[{name}] scope={scope}");
            let pat = firefox_patterns(scope);
            patterns::collect(name, collect_root, scratch, &pat.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        }

        // ---------- Cloud / modern ----------
        "cloud.onedrive" => patterns::collect(
            name, collect_root, scratch,
            &["Users/*/AppData/Local/Microsoft/OneDrive/logs/**/*"],
        ),
        "cloud.outlook" => patterns::collect(
            name, collect_root, scratch,
            &[
                "Users/*/AppData/Local/Microsoft/Outlook/*.ost",
                "Users/*/Documents/Outlook Files/*.pst",
            ],
        ),
        "cloud.teams" => patterns::collect(
            name, collect_root, scratch,
            &["Users/*/AppData/Roaming/Microsoft/Teams/**/*"],
        ),
        "cred.dpapi" => patterns::collect(
            name, collect_root, scratch,
            &[
                "Windows/System32/Microsoft/Protect/**/*",
                "Users/*/AppData/Roaming/Microsoft/Protect/**/*",
                "Users/*/AppData/Local/Microsoft/Credentials/*",
                "Users/*/AppData/Roaming/Microsoft/Credentials/*",
            ],
        ),

        // ---------- Persistence ----------
        "persistence.scheduledtasks" => patterns::collect(
            name, collect_root, scratch,
            &["Windows/System32/Tasks/**/*", "Windows/Tasks/**/*"],
        ),
        "persistence.startupfolders" => patterns::collect(
            name, collect_root, scratch,
            &[
                "Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*",
                "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/*",
            ],
        ),

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
        "memory.fulldump" => crate::artifacts::patterns::memory_dump(name, scratch),

        unknown => Err(anyhow!("unknown artifact: {unknown}")),
    }
}

/// Chromium-family browser pattern builder (Chrome / Edge / Brave / Opera all
/// share the User Data layout). Generates a glob list scoped by:
///   - `relative_user_data_dir`: e.g. "Google/Chrome/User Data" or "Microsoft/Edge/User Data"
///   - `scope`: "minimal" | "standard" | "full"
///   - `profiles`: "default" | "all"
fn chromium_patterns(relative_user_data_dir: &str, scope: &str, profiles: &str) -> Vec<String> {
    // Match either just "Default" or every profile-named subdir.
    let profile_glob = if profiles == "default" { "Default" } else { "*" };
    let base = format!("Users/*/AppData/Local/{relative_user_data_dir}");

    match scope {
        "minimal" => vec![
            format!("{base}/{profile_glob}/History"),
        ],
        "full" => vec![
            // ** matches recursively. The patterns module's globber walks
            // everything under User Data — extensions, IndexedDB, cache,
            // service worker storage, etc.
            format!("{base}/{profile_glob}/**/*"),
            // Top-level shared files (Local State has the encryption key reference)
            format!("{base}/Local State"),
            format!("{base}/Last Browser"),
            format!("{base}/Last Version"),
        ],
        // "standard" (default)
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

fn firefox_patterns(scope: &str) -> Vec<String> {
    let base = "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles".to_string();
    match scope {
        "minimal" => vec![
            format!("{base}/*/places.sqlite"),
        ],
        "full" => vec![
            format!("{base}/*/**/*"),
        ],
        // "standard" (default)
        _ => vec![
            format!("{base}/*/places.sqlite"),
            format!("{base}/*/cookies.sqlite"),
            format!("{base}/*/formhistory.sqlite"),
            format!("{base}/*/downloads.sqlite"),
            format!("{base}/*/logins.json"),
            format!("{base}/*/key4.db"),
            format!("{base}/*/cert9.db"),
            format!("{base}/*/permissions.sqlite"),
            format!("{base}/*/favicons.sqlite"),
            format!("{base}/*/sessionstore.jsonlz4"),
        ],
    }
}
