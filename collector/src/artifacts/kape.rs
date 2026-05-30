//! KAPE-style file pattern targets.
//!
//! The builder UI lets the user enable named "targets" (e.g. `KapeTriage`,
//! `EventLogs`, `WebBrowsers`). Each target maps to a list of glob patterns,
//! matching the Velociraptor `Windows.KapeFiles.Targets` and the upstream
//! Eric Zimmerman KAPE target catalog.
//!
//! Rather than embed KAPE's full ~600-target YAML database, this module
//! contains a curated subset of the highest-IR-value targets. Adding more is
//! a matter of extending `target_patterns()`.

use anyhow::Result;
use std::path::Path;

use super::patterns;
use super::ArtifactStats;

pub fn run_targets(
    target_names: &[String],
    collect_root: &Path,
    scratch: &Path,
) -> Result<ArtifactStats> {
    let mut total = ArtifactStats::default();
    for t in target_names {
        let patterns_for_target = target_patterns(t);
        if patterns_for_target.is_empty() {
            log::warn!("KAPE target '{t}' has no patterns — skipping");
            continue;
        }
        log::info!("[KAPE] expanding target '{t}' ({} patterns)", patterns_for_target.len());
        let stats = patterns::collect(
            &format!("kape.{t}"),
            collect_root,
            scratch,
            &patterns_for_target.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        )?;
        total.file_count += stats.file_count;
        total.bytes += stats.bytes;
    }
    Ok(total)
}

fn target_patterns(name: &str) -> Vec<String> {
    let s = |x: &str| x.to_string();
    match name {
        "EventLogs" => vec![s("Windows/System32/winevt/Logs/*.evtx")],
        "Registry" => vec![
            s("Windows/System32/config/SAM"),
            s("Windows/System32/config/SYSTEM"),
            s("Windows/System32/config/SOFTWARE"),
            s("Windows/System32/config/SECURITY"),
            s("Windows/System32/config/DEFAULT"),
            s("Windows/System32/config/RegBack/*"),
            s("Users/*/NTUSER.DAT"),
            s("Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"),
        ],
        "Prefetch" => vec![s("Windows/Prefetch/*.pf")],
        "WebBrowsers" => vec![
            s("Users/*/AppData/Local/Google/Chrome/User Data/*/History"),
            s("Users/*/AppData/Local/Google/Chrome/User Data/*/Cookies"),
            s("Users/*/AppData/Local/Microsoft/Edge/User Data/*/History"),
            s("Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite"),
        ],
        "ScheduledTasks" => vec![s("Windows/System32/Tasks/**/*"), s("Windows/Tasks/**/*")],
        "StartupFolders" => vec![
            s("Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*"),
            s("ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/*"),
        ],
        "RecycleBin" => vec![s("$Recycle.Bin/**/*")],
        "BITS" => vec![s("ProgramData/Microsoft/Network/Downloader/qmgr*.dat")],
        "WindowsFirewall" => vec![s("Windows/System32/LogFiles/Firewall/*.log")],
        "RDPCache" => vec![
            s("Users/*/AppData/Local/Microsoft/Terminal Server Client/Cache/*"),
        ],
        "PowerShellConsole" => vec![
            s("Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/*"),
        ],
        "WindowsTimeline" => vec![
            s("Users/*/AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db"),
        ],
        "JumpLists" => vec![
            s("Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*"),
            s("Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*"),
        ],
        "LNKFiles" => vec![
            s("Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk"),
            s("Users/*/AppData/Roaming/Microsoft/Office/Recent/*.lnk"),
        ],
        "SRUM" => vec![s("Windows/System32/sru/SRUDB.dat")],
        "WinDefendDetectionHist" => vec![
            s("ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/**/*"),
        ],
        "Outlook" => vec![
            s("Users/*/AppData/Local/Microsoft/Outlook/*.ost"),
            s("Users/*/Documents/Outlook Files/*.pst"),
        ],
        "DPAPI" => vec![
            s("Windows/System32/Microsoft/Protect/**/*"),
            s("Users/*/AppData/Roaming/Microsoft/Protect/**/*"),
        ],
        "CloudStorage_Metadata" => vec![
            s("Users/*/AppData/Local/Microsoft/OneDrive/settings/Personal/*"),
            s("Users/*/AppData/Local/Microsoft/OneDrive/logs/Personal/*"),
        ],
        "KapeTriage" => {
            // The KAPE "compound" triage target — combines Registry + EventLogs +
            // Prefetch + ScheduledTasks + LNK + JumpLists + RecycleBin + SRUM.
            let mut v = vec![];
            for sub in [
                "Registry", "EventLogs", "Prefetch", "ScheduledTasks", "LNKFiles",
                "JumpLists", "RecycleBin", "SRUM", "BITS", "WindowsFirewall", "RDPCache",
                "PowerShellConsole", "WindowsTimeline",
            ] {
                v.extend(target_patterns(sub));
            }
            v
        }
        _ => vec![],
    }
}
