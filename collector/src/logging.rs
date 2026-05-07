use anyhow::{Context, Result};
use std::path::Path;

/// Initialize the logger.
///
/// `log_path` is the canonical per-run log (gets packed into the evidence ZIP).
/// `persistent_log` is an optional second sink that lives outside the scratch
/// dir, so it survives `delete_after_upload` cleanup. Use this for triage
/// after a "the binary just exited" incident.
pub fn init(log_path: &Path, persistent_log: Option<&Path>) -> Result<()> {
    let level = log::LevelFilter::Info;

    let mut dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}] [{}] [{}] {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(level)
        .chain(
            fern::log_file(log_path)
                .with_context(|| format!("opening log file {}", log_path.display()))?,
        );

    if let Some(p) = persistent_log {
        // Best-effort: if we can't open the persistent log, log to scratch only.
        match fern::log_file(p) {
            Ok(f) => dispatch = dispatch.chain(f),
            Err(e) => eprintln!(
                "WARN: persistent log {} could not be opened: {e}",
                p.display()
            ),
        }
    }

    // Always write to stderr too — when run from a console (admin cmd / PowerShell),
    // this gives the operator immediate visibility. When launched headlessly via GPO
    // there's no attached console, so the stderr writes silently no-op.
    let dispatch = dispatch.chain(std::io::stderr());

    dispatch.apply().context("installing logger")?;
    Ok(())
}
