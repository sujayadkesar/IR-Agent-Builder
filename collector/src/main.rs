// DFIR Collector — single-shot triage agent.
//
// Lifecycle:
//   1. Verify admin/root (per embedded config).
//   2. Parse embedded JSON config (compiled in via include_bytes!).
//   3. Decrypt credential vault if present (anti-RE protection).
//   4. Create scratch dir.
//   5. Determine upload strategy: traditional ZIP or streaming chunks.
//   6. Create VSS snapshot (Windows) or bind-mount (Linux) — best-effort.
//   7. Run each enabled artifact module.
//   8. Build encrypted container OR stream chunks to S3.
//   9. Upload + cleanup.

mod artifacts;
mod config;
mod crypto;
mod elevation;
mod logging;
mod report;
mod upload;
mod zipper;

// Platform-specific modules
#[cfg(target_os = "windows")]
mod acquisition;
#[cfg(target_os = "windows")]
mod vss;

use anyhow::{Context, Result};
use chrono::Utc;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

const EMBEDDED_CONFIG: &[u8] = include_bytes!("embedded_config.json");

fn main() {
    install_panic_hook();

    if let Err(e) = run() {
        let path = temp_dir().join("dfir-collector-fatal.log");
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
        let path = temp_dir().join("dfir-collector-fatal.log");
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

/// Cross-platform temp directory.
fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}

fn run() -> Result<()> {
    // 1. Parse embedded config
    let mut cfg: config::Config =
        serde_json::from_slice(EMBEDDED_CONFIG).context("parsing embedded config JSON")?;

    // 2. Decrypt credential vault if present (anti-RE protection)
    if let Some(ref mut s3) = cfg.upload.s3 {
        if !s3.credential_vault.is_empty() {
            log::info!("Credential vault detected — decrypting...");
            let vault_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &s3.credential_vault,
            ).context("decoding vault base64")?;

            // Verify integrity before decryption (constant-time HMAC compare).
            if !s3.credential_vault_hmac.is_empty() {
                let expected_hmac = hex::decode(&s3.credential_vault_hmac)
                    .map_err(|_| anyhow::anyhow!("invalid vault HMAC hex"))?;
                if !shared_crypto::credential_vault::verify_hmac(
                    &vault_bytes, &expected_hmac, &cfg.build_id,
                ) {
                    anyhow::bail!("credential vault integrity check failed — binary may have been tampered with");
                }
            }

            let creds = shared_crypto::credential_vault::decrypt(
                &vault_bytes,
                &cfg.build_id,
                &cfg.build_timestamp,
            )?;
            s3.access_key_id = creds.access_key_id;
            s3.secret_access_key = creds.secret_access_key;
            s3.credential_vault.clear();
            s3.credential_vault_hmac.clear();
            log::info!("Credential vault decrypted successfully");
        }
    }

    // 3. Build run identity
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

    // 4. Scratch directory
    let scratch = temp_dir().join(format!("dfir-{}", &run_id.to_string()[..8]));
    std::fs::create_dir_all(&scratch).context("creating scratch dir")?;

    // 5. Logging
    let log_path = scratch.join("collector.log");
    let persistent_log = temp_dir()
        .join(format!("dfir-collector-{}.log", &cfg.build_id[..8.min(cfg.build_id.len())]));
    logging::init(&log_path, Some(&persistent_log))?;
    log::info!("DFIR Collector starting build_id={} run_id={}", cfg.build_id, run_id);
    log::info!("platform={} scratch_dir={}", std::env::consts::OS, scratch.display());
    log::info!("persistent_log = {}", persistent_log.display());
    eprintln!("DFIR Collector: persistent log -> {}", persistent_log.display());
    log::info!("hostname={hostname} site={} timestamp={timestamp}", cfg.site_code);

    // Startup banner — one line that captures the whole collection profile, so
    // the log immediately shows what this build was configured to do.
    let output_target = match cfg.upload.kind.as_str() {
        "local" => cfg.upload.local_path.clone().unwrap_or_else(|| "(default)".into()),
        "s3" => cfg.upload.s3.as_ref().map(|s| format!("s3://{}", s.bucket)).unwrap_or_default(),
        other => other.to_string(),
    };
    log::info!(
        "[startup] profile: artifacts={} kape_targets={} use_vss={} encryption={} require_admin={} silent={} upload_kind={} output={}",
        cfg.artifacts.len(), cfg.kape_targets.len(), cfg.use_vss, cfg.encryption.scheme,
        cfg.require_admin, cfg.silent, cfg.upload.kind, output_target,
    );

    // 6. Admin/root elevation check
    if cfg.require_admin && !elevation::is_elevated() {
        log::error!(
            "ABORTING BEFORE COLLECTION: not elevated but require_admin=true. \
             No artifacts will be collected and no ZIP will be produced. \
             Re-run this collector as Administrator/root, or rebuild with \
             require_admin disabled (Step 5)."
        );
        anyhow::bail!("Administrator/root privileges required - re-run elevated");
    }
    log::info!("Elevation OK (is_elevated={})", elevation::is_elevated());

    // 7. Determine if streaming upload should be used
    // Rough estimate: ~50 MB average per selected artifact.
    let estimated_size_mb: u64 = cfg.artifacts.len() as u64 * 50;
    let want_streaming = upload::chunked::should_use_streaming(
        &scratch, &cfg.chunk_upload, estimated_size_mb
    );
    // SECURITY: the chunked streaming path does NOT yet encrypt (or properly
    // compress) its output. If X509 encryption is configured, never stream —
    // fall back to the traditional encrypt-then-upload path so we never ship
    // plaintext evidence to S3. (Streaming+encryption is a tracked follow-up.)
    let encryption_active =
        cfg.encryption.scheme == "x509" && !cfg.encryption.rsa_public_key_pem.is_empty();
    let use_streaming = want_streaming && !encryption_active;
    if want_streaming && encryption_active {
        log::warn!(
            "Chunked streaming was selected but X509 encryption is enabled; the streaming \
             path does not encrypt yet. Falling back to traditional encrypt-then-upload to \
             avoid uploading plaintext evidence."
        );
    }
    log::info!("Upload strategy: {}", if use_streaming { "STREAMING CHUNKS" } else { "TRADITIONAL ZIP" });

    // 8. Start chunked uploader thread if streaming
    let chunked_uploader = if use_streaming && cfg.upload.kind == "s3" {
        let s3_cfg = cfg.upload.s3.as_ref()
            .ok_or_else(|| anyhow::anyhow!("streaming mode requires S3 config"))?
            .clone();
        let prefix_template = upload_prefix_template(&cfg.upload).to_string();
        let resolved_prefix = resolve_template(
            &prefix_template, &cfg.site_code, &hostname, &timestamp, &run_id.to_string()[..8]
        ).trim_end_matches('/').to_string();
        let object_key = if resolved_prefix.is_empty() {
            format!("{collection_name}.zip")
        } else {
            format!("{resolved_prefix}/{collection_name}.zip")
        };

        let uploader = upload::chunked::ChunkedUploader::start(
            s3_cfg, object_key, cfg.chunk_upload.clone()
        )?;
        log::info!("[streaming] chunked uploader started");
        Some(uploader)
    } else {
        None
    };

    // 9. VSS snapshot (Windows only) or equivalent (Linux: best-effort)
    #[cfg(target_os = "windows")]
    let vss_mount: Option<PathBuf>;
    let collect_root: PathBuf;
    #[cfg(target_os = "windows")]
    {
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
        vss_mount = vss_root.clone();
        collect_root = vss_root.unwrap_or_else(|| PathBuf::from("C:\\"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        collect_root = PathBuf::from("/");
    }

    // 10. Run each artifact module
    let mut summary = report::RunReport::new(&cfg, &hostname, &collection_name, run_id);
    let chunk_dir = scratch.join("_chunks");
    if use_streaming {
        std::fs::create_dir_all(&chunk_dir).context("creating chunk dir")?;
    }
    let mut chunk_index: u32 = 0;

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

                // If streaming, pack and queue this artifact's output as a chunk
                if let Some(ref uploader) = chunked_uploader {
                    let artifact_dir = scratch.join(artifact);
                    if artifact_dir.exists() {
                        match upload::chunked::pack_artifact_chunk(
                            artifact, &artifact_dir, &chunk_dir, chunk_index
                        ) {
                            Ok(chunk) => {
                                chunk_index += 1;
                                if let Err(e) = uploader.queue_chunk(chunk) {
                                    log::error!("[streaming] failed to queue chunk for {artifact}: {e}");
                                } else {
                                    // Delete the local artifact dir to reclaim space
                                    let _ = std::fs::remove_dir_all(&artifact_dir);
                                    log::info!("[streaming] chunk queued, local dir freed for {artifact}");
                                }
                            }
                            Err(e) => log::error!("[streaming] failed to pack chunk for {artifact}: {e}"),
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("[ARTIFACT] {artifact} FAILED: {e:#}");
                summary.record_failure(artifact, format!("{e:#}"));
            }
        }
    }

    // 11. KAPE-style file pattern targets
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

    // 12. Write run report
    summary.finalize();
    let report_path = scratch.join("run_report.json");
    std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)
        .context("writing run_report.json")?;

    // 13. Release VSS snapshot junction (Windows only).
    #[cfg(target_os = "windows")]
    {
        if let Some(mount) = vss_mount.as_ref() {
            log::info!("Releasing VSS snapshot junction at {}", mount.display());
            if let Err(e) = vss::release_snapshot(mount) {
                log::warn!("VSS junction release failed (non-fatal): {e:#}");
            }
        }
    }

    // 14. Upload — either finalize streaming or traditional ZIP
    if let Some(uploader) = chunked_uploader {
        // Queue the run report as a final chunk
        let report_chunk_path = chunk_dir.join("run_report_chunk.bin");
        std::fs::copy(&report_path, &report_chunk_path)?;
        let final_chunk = upload::chunked::ChunkInfo {
            artifact_name: "run_report".to_string(),
            chunk_path: report_chunk_path,
            chunk_index,
            size_bytes: std::fs::metadata(&report_path)?.len(),
            is_final: true,
        };
        let _ = uploader.queue_chunk(final_chunk);
        uploader.finalize()?;
        log::info!("Streaming upload finalized");
    } else {
        // Traditional: ZIP → encrypt → upload
        let zip_path = scratch.parent().unwrap().join(format!("{collection_name}.zip"));
        log::info!(
            "[zip] packing scratch dir {} -> {}",
            scratch.display(), zip_path.display()
        );
        zipper::write_directory_as_zip(&scratch, &zip_path)
            .with_context(|| format!("creating ZIP at {}", zip_path.display()))?;
        // Explicit post-condition check — the #1 thing to confirm for "no ZIP".
        match std::fs::metadata(&zip_path) {
            Ok(m) => log::info!("[zip] OK: {} exists, {} bytes", zip_path.display(), m.len()),
            Err(e) => {
                log::error!("[zip] FAILED: {} does not exist after write: {e}", zip_path.display());
                anyhow::bail!("ZIP container was not created at {}", zip_path.display());
            }
        }

        let container_path = if cfg.encryption.scheme == "x509" && !cfg.encryption.rsa_public_key_pem.is_empty() {
            let enc_path = zip_path.with_extension("zip.enc");
            crypto::x509::encrypt_file(&zip_path, &enc_path, &cfg.encryption.rsa_public_key_pem)?;
            crypto::secure_delete(&zip_path)?;
            log::info!("Encrypted container: {}", enc_path.display());
            enc_path
        } else {
            log::warn!("Encryption disabled or no public key — container is plaintext");
            zip_path
        };

        let prefix_template = upload_prefix_template(&cfg.upload).to_string();
        let resolved_prefix = resolve_template(
            &prefix_template, &cfg.site_code, &hostname, &timestamp, &run_id.to_string()[..8]
        ).trim_end_matches('/').to_string();
        let container_filename = container_path.file_name().unwrap().to_string_lossy().to_string();
        let object_key = if resolved_prefix.is_empty() {
            container_filename.clone()
        } else {
            format!("{}/{}", resolved_prefix, container_filename)
        };

        let upload_started = std::time::Instant::now();
        upload::dispatch(&cfg.upload, &container_path, &object_key)?;
        log::info!("Upload complete in {:?}", upload_started.elapsed());

        // Sidecar log upload
        let log_object_key = swap_extension(&object_key, "log");
        if let Err(e) = upload::dispatch(&cfg.upload, &log_path, &log_object_key) {
            log::warn!("Sidecar log upload failed (non-fatal): {e:#}");
        } else {
            log::info!("Sidecar log uploaded as {log_object_key}");
        }

        // 15. Cleanup
        if cfg.delete_after_upload {
            let _ = crypto::secure_delete(&container_path);
            let _ = std::fs::remove_dir_all(&scratch);
            log::info!("Local cleanup complete");
        }
    }

    let ok_count = (summary.artifacts.len() as u32).saturating_sub(summary.failures);
    log::info!(
        "[summary] artifacts: {} ok, {} failed | {} files, {} bytes collected | output={}",
        ok_count, summary.failures, summary.total_files, summary.total_bytes, output_target,
    );
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

fn swap_extension(key: &str, new_ext: &str) -> String {
    if let Some(idx) = key.rfind('.') {
        format!("{}.{}", &key[..idx], new_ext)
    } else {
        format!("{key}.{new_ext}")
    }
}
