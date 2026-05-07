// DFIR Collector — single-shot triage agent.
//
// Lifecycle:
//   1. Verify admin (per embedded config; abort if missing and require_admin=true).
//   2. Parse embedded JSON config (compiled in via include_bytes!).
//   3. Create scratch dir under %TEMP%/dfir-{build_id}/.
//   4. Create VSS snapshot of system volume (best-effort).
//   5. Run each enabled artifact module — stream output (JSONL) into scratch dir.
//   6. Build encrypted ZIP container (AES-256-GCM payload, RSA-OAEP wrapped key).
//   7. Upload to S3 (multipart for >100MB) or copy to local target.
//   8. Cleanup scratch + (optionally) self-delete the original EXE.

mod acquisition;
mod artifacts;
mod config;
mod crypto;
mod elevation;
mod logging;
mod report;
mod upload;
mod vss;
mod zipper;

use anyhow::{Context, Result};
use chrono::Utc;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

const EMBEDDED_CONFIG: &[u8] = include_bytes!("embedded_config.json");

fn main() {
    // Install a panic hook BEFORE anything else. Release builds use
    // panic = "abort", which means a panic exits without unwinding — and
    // without our normal Err handler running. This hook catches the panic
    // and writes details to a known location so we never have a "binary
    // vanished, no logs anywhere" mystery again.
    install_panic_hook();

    if let Err(e) = run() {
        let path = std::env::temp_dir().join("dfir-collector-fatal.log");
        let mut f = std::fs::OpenOptions::new()
            .create(true).append(true).open(&path).ok();
        if let Some(ref mut f) = f {
            let _ = writeln!(
                f, "[{}] FATAL: {:#}",
                Utc::now().to_rfc3339(), e
            );
        }
        eprintln!("DFIR Collector fatal: {e:#}");
        eprintln!("See {} for details", path.display());
        std::process::exit(1);
    }
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let path = std::env::temp_dir().join("dfir-collector-fatal.log");
        let mut f = std::fs::OpenOptions::new()
            .create(true).append(true).open(&path).ok();
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("(non-string panic payload)");
        if let Some(ref mut f) = f {
            let _ = writeln!(
                f, "[{}] PANIC at {location}: {payload}",
                Utc::now().to_rfc3339()
            );
        }
        eprintln!("DFIR Collector PANIC at {location}: {payload}");
    }));
}

fn run() -> Result<()> {
    // 1. Parse embedded config
    let cfg: config::Config =
        serde_json::from_slice(EMBEDDED_CONFIG).context("parsing embedded config JSON")?;

    // 2. Build run identity
    let run_id = Uuid::new_v4();
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "UNKNOWN-HOST".to_string());
    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let collection_name = cfg
        .filename_template
        .replace("%FQDN%", &hostname)
        .replace("%TIMESTAMP%", &timestamp)
        .replace("%UUID%", &run_id.to_string()[..8])
        .replace("%SITE%", &cfg.site_code);

    // 3. Scratch directory
    let scratch = std::env::temp_dir().join(format!("dfir-{}", &run_id.to_string()[..8]));
    std::fs::create_dir_all(&scratch).context("creating scratch dir")?;

    // 4. Logging — TWO sinks:
    //   (a) the canonical scratch/collector.log which gets packed into the ZIP
    //   (b) a *persistent* mirror at %TEMP%\dfir-collector-{build_id}.log that
    //       survives even if the scratch dir is cleaned up on success. This is
    //       the file an admin should look at first when triaging "did the
    //       collector run, and what happened?".
    let log_path = scratch.join("collector.log");
    let persistent_log = std::env::temp_dir()
        .join(format!("dfir-collector-{}.log", &cfg.build_id[..8.min(cfg.build_id.len())]));
    logging::init(&log_path, Some(&persistent_log))?;
    log::info!("DFIR Collector starting build_id={} run_id={}", cfg.build_id, run_id);
    log::info!("scratch_dir = {}", scratch.display());
    log::info!("persistent_log = {}", persistent_log.display());
    eprintln!("DFIR Collector: persistent log -> {}", persistent_log.display());
    log::info!("hostname={hostname} site={} timestamp={timestamp}", cfg.site_code);

    // 5. Admin elevation check
    if cfg.require_admin && !elevation::is_elevated() {
        log::error!("Not running as administrator — aborting (require_admin=true)");
        anyhow::bail!("Administrator privileges required");
    }
    log::info!("Elevation OK (is_elevated={})", elevation::is_elevated());

    // 6. VSS snapshot of system volume (best-effort)
    let vss_root: Option<PathBuf> = if cfg.use_vss {
        match vss::create_system_snapshot() {
            Ok(path) => {
                log::info!("VSS snapshot mounted at {}", path.display());
                Some(path)
            }
            Err(e) => {
                log::warn!("VSS snapshot failed ({e:#}); continuing on live system");
                None
            }
        }
    } else {
        None
    };
    let collect_root = vss_root
        .clone()
        .unwrap_or_else(|| PathBuf::from("C:\\"));

    // 7. Run each artifact module
    let mut summary = report::RunReport::new(&cfg, &hostname, &collection_name, run_id);

    for artifact in &cfg.artifacts {
        log::info!("[ARTIFACT] starting {artifact}");
        let started = std::time::Instant::now();
        match artifacts::run_artifact(artifact, &collect_root, &scratch, &cfg) {
            Ok(stats) => {
                let elapsed = started.elapsed();
                log::info!(
                    "[ARTIFACT] {artifact} OK files={} bytes={} elapsed={:?}",
                    stats.file_count, stats.bytes, elapsed
                );
                summary.record_success(artifact, stats, elapsed);
            }
            Err(e) => {
                log::error!("[ARTIFACT] {artifact} FAILED: {e:#}");
                summary.record_failure(artifact, format!("{e:#}"));
            }
        }
    }

    // 8. KAPE-style file pattern targets
    if !cfg.kape_targets.is_empty() {
        log::info!("Running {} KAPE-style targets", cfg.kape_targets.len());
        match artifacts::kape::run_targets(&cfg.kape_targets, &collect_root, &scratch) {
            Ok(stats) => {
                log::info!("[KAPE] OK files={} bytes={}", stats.file_count, stats.bytes);
                summary.record_success("kape.targets", stats, std::time::Duration::ZERO);
            }
            Err(e) => log::error!("[KAPE] FAILED: {e:#}"),
        }
    }

    // 9. Drop the run report
    summary.finalize();
    let report_path = scratch.join("run_report.json");
    std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)
        .context("writing run_report.json")?;

    // 10. Release VSS snapshot (best-effort)
    if let Some(ref p) = vss_root {
        if let Err(e) = vss::release_snapshot(p) {
            log::warn!("VSS release failed: {e:#}");
        }
    }

    // 11. Build encrypted container
    log::info!("Building encrypted container...");
    let zip_path = scratch.parent().unwrap().join(format!("{collection_name}.zip"));
    zipper::write_directory_as_zip(&scratch, &zip_path)?;
    log::info!("ZIP container: {} ({} bytes)", zip_path.display(), std::fs::metadata(&zip_path)?.len());

    let container_path = if cfg.encryption.scheme == "x509" && !cfg.encryption.rsa_public_key_pem.is_empty() {
        let enc_path = zip_path.with_extension("zip.enc");
        crypto::x509::encrypt_file(&zip_path, &enc_path, &cfg.encryption.rsa_public_key_pem)?;
        // Securely zero & delete plaintext zip
        crypto::secure_delete(&zip_path)?;
        log::info!("Encrypted container: {}", enc_path.display());
        enc_path
    } else {
        log::warn!("Encryption disabled or no public key — container is plaintext");
        zip_path
    };

    // 12. Resolve the upload prefix template using the run's variables.
    // The user-provided template (set in the wizard, default `%SITE%/%FQDN%`)
    // is substituted here — never on the AWS side, so the prefix lands in S3
    // exactly as composed below. We also upload the run log as a sidecar
    // object next to the container, so an analyst can tail recent runs from
    // S3 without downloading the full evidence ZIP.
    let prefix_template = upload_prefix_template(&cfg.upload).to_string();
    let resolved_prefix = resolve_template(&prefix_template, &cfg.site_code, &hostname, &timestamp, &run_id.to_string()[..8])
        .trim_end_matches('/')
        .to_string();
    let container_filename = container_path.file_name().unwrap().to_string_lossy().to_string();
    let object_key = if resolved_prefix.is_empty() {
        container_filename.clone()
    } else {
        format!("{}/{}", resolved_prefix, container_filename)
    };

    let upload_started = std::time::Instant::now();
    upload::dispatch(&cfg.upload, &container_path, &object_key)?;
    log::info!("Upload complete in {:?}", upload_started.elapsed());

    // 13. Sidecar: upload the run log next to the container so admins can
    // diagnose runs without unpacking the full evidence ZIP. Best-effort —
    // failures here don't fail the run.
    let log_object_key = swap_extension(&object_key, "log");
    if let Err(e) = upload::dispatch(&cfg.upload, &log_path, &log_object_key) {
        log::warn!("Sidecar log upload failed (non-fatal): {e:#}");
    } else {
        log::info!("Sidecar log uploaded as {log_object_key}");
    }

    // 14. Cleanup
    if cfg.delete_after_upload {
        let _ = crypto::secure_delete(&container_path);
        let _ = std::fs::remove_dir_all(&scratch);
        log::info!("Local cleanup complete");
    }

    log::info!("DFIR Collector finished successfully");
    Ok(())
}

fn upload_prefix_template(u: &config::UploadCfg) -> &str {
    match u.kind.as_str() {
        "s3" => u
            .s3
            .as_ref()
            .and_then(|s| if s.prefix_template.is_empty() { None } else { Some(s.prefix_template.as_str()) })
            .unwrap_or("%SITE%/%FQDN%"),
        _ => "%SITE%/%FQDN%",
    }
}

fn resolve_template(tmpl: &str, site: &str, fqdn: &str, ts: &str, uuid: &str) -> String {
    tmpl.replace("%SITE%", site)
        .replace("%FQDN%", fqdn)
        .replace("%TIMESTAMP%", ts)
        .replace("%UUID%", uuid)
}

/// Swap the final extension of an S3 key. e.g.
///   "APAC-HYD/host/foo.zip.enc" -> "APAC-HYD/host/foo.zip.log"
///   "APAC-HYD/host/foo.zip"     -> "APAC-HYD/host/foo.log"
fn swap_extension(key: &str, new_ext: &str) -> String {
    if let Some(idx) = key.rfind('.') {
        format!("{}.{}", &key[..idx], new_ext)
    } else {
        format!("{key}.{new_ext}")
    }
}
