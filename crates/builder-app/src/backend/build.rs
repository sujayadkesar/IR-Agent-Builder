//! Build orchestrator — spawns `cargo build` against the collector, streams
//! every stdout/stderr line back over an mpsc channel, and notifies the egui
//! context to repaint each time a new line arrives (the SSE equivalent).

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use eframe::egui;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;

use super::embedded_config;
use super::ledger::{self, BuildRecord};
use crate::spec::{BuildSpec, TargetPlatform, UploadKind};

// `build_id` is carried on these events/handle for traceability and future
// UI use (e.g. cross-referencing the ledger), even though the current frame
// loop keys off the live build state rather than the id.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum BuildEvent {
    Log(String),
    Complete {
        build_id: String,
        exe_path: PathBuf,
        sha256: String,
        size_bytes: u64,
    },
    Failed {
        build_id: String,
        message: String,
    },
}

pub struct BuildHandle {
    pub rx: mpsc::Receiver<BuildEvent>,
    #[allow(dead_code)]
    pub build_id: String,
}

/// Kick off a release build of the collector. Returns immediately; the
/// caller polls `handle.rx` each frame.
pub fn spawn(
    workspace_root: PathBuf,
    spec: &BuildSpec,
    catalog: &super::artifact_catalog::Catalog,
    ledger_path: PathBuf,
    ctx: egui::Context,
) -> Result<BuildHandle> {
    let build_id = uuid::Uuid::new_v4().to_string();
    let build_timestamp = Utc::now().to_rfc3339();

    // Resolve embedded_sources from selected artifacts + per-artifact params.
    let params_map: std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>> =
        spec.artifact_params
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().map(|(k2, v2)| (k2.clone(), v2.clone())).collect()))
            .collect();
    let embedded_sources = catalog.to_embedded_format(&spec.artifacts, &params_map);

    let built = embedded_config::build_from_spec(spec, &build_id, &build_timestamp, embedded_sources)?;

    let collector_cfg_path = workspace_root
        .join("collector")
        .join("src")
        .join("embedded_config.json");
    std::fs::write(
        &collector_cfg_path,
        serde_json::to_string_pretty(&built.json)?,
    )
    .with_context(|| format!("writing {}", collector_cfg_path.display()))?;

    let (tx, rx) = mpsc::channel::<BuildEvent>();

    // Owned values moved into the thread
    let target_platform_owned = match spec.target_platform {
        TargetPlatform::Windows => "windows".to_string(),
        TargetPlatform::Linux => "linux".to_string(),
    };
    let spec_for_thread = spec.clone();
    let build_id_t = build_id.clone();
    let build_timestamp_t = build_timestamp.clone();
    let cred_vault_used = built.credential_vault_used;

    std::thread::spawn(move || {
        let result = run_cargo_build(
            &workspace_root,
            &collector_cfg_path,
            &target_platform_owned,
            &build_id_t,
            &tx,
            &ctx,
        );

        // Always restore placeholder, even on failure. If this write fails,
        // the file on disk may still contain real AWS credentials and other
        // secrets from the build we just ran — surface this loudly.
        let placeholder_json = serde_json::to_string_pretty(&embedded_config::placeholder())
            .expect("placeholder JSON is statically valid");
        if let Err(e) = std::fs::write(&collector_cfg_path, &placeholder_json) {
            let _ = tx.send(BuildEvent::Log(format!(
                "SECURITY WARNING: failed to restore placeholder embedded_config.json: {e}. \
                 Real credentials may still be present at {}. Delete or overwrite this file manually.",
                collector_cfg_path.display()
            )));
        }

        match result {
            Ok((exe_path, sha256, size_bytes)) => {
                // Record to ledger
                if let Ok(ledger) = ledger::Ledger::open(&ledger_path) {
                    let rec = BuildRecord {
                        build_id: build_id_t.clone(),
                        build_timestamp: build_timestamp_t.clone(),
                        target_platform: target_platform_owned.clone(),
                        site_code: spec_for_thread.site_code.clone(),
                        artifact_count: spec_for_thread.artifacts.len() as i64,
                        artifacts: spec_for_thread.artifacts.clone(),
                        kape_targets: spec_for_thread.kape_targets.clone(),
                        encryption_scheme: match spec_for_thread.encryption.scheme {
                            crate::spec::EncryptionScheme::X509 => "x509".into(),
                            crate::spec::EncryptionScheme::None => "none".into(),
                        },
                        upload_kind: match spec_for_thread.upload.kind {
                            UploadKind::S3 => "s3".into(),
                            UploadKind::Local => "local".into(),
                        },
                        credential_vault_used: cred_vault_used,
                        chunk_upload_enabled: spec_for_thread.chunk_upload.enabled,
                        s3_bucket: if spec_for_thread.upload.kind == UploadKind::S3 {
                            Some(spec_for_thread.upload.bucket.clone())
                        } else {
                            None
                        },
                        s3_region: if spec_for_thread.upload.kind == UploadKind::S3 {
                            Some(spec_for_thread.upload.region.clone())
                        } else {
                            None
                        },
                        binary_size_bytes: size_bytes as i64,
                        binary_sha256: sha256.clone(),
                        exe_path: exe_path.to_string_lossy().to_string(),
                    };
                    if let Err(e) = ledger.record(&rec) {
                        let _ = tx.send(BuildEvent::Log(format!(
                            "WARN: ledger insert failed: {e}"
                        )));
                    }
                }

                let _ = tx.send(BuildEvent::Complete {
                    build_id: build_id_t,
                    exe_path,
                    sha256,
                    size_bytes,
                });
            }
            Err(e) => {
                let _ = tx.send(BuildEvent::Failed {
                    build_id: build_id_t,
                    message: format!("{e:#}"),
                });
            }
        }
        ctx.request_repaint();
    });

    Ok(BuildHandle { rx, build_id })
}

fn run_cargo_build(
    workspace_root: &Path,
    _collector_cfg_path: &Path,
    target_platform: &str,
    build_id: &str,
    tx: &mpsc::Sender<BuildEvent>,
    ctx: &egui::Context,
) -> Result<(PathBuf, String, u64)> {
    let log = |line: String| {
        let _ = tx.send(BuildEvent::Log(line));
        ctx.request_repaint();
    };

    log(format!("Build {build_id} starting (target={target_platform})"));

    let mut args: Vec<String> = vec![
        "build".into(),
        "--release".into(),
        "-p".into(),
        "dfir-collector".into(),
        "--bin".into(),
        "Collector".into(),
    ];
    let target_triple = match target_platform {
        "linux" if cfg!(windows) => Some("x86_64-unknown-linux-gnu"),
        "windows" if !cfg!(windows) => Some("x86_64-pc-windows-gnu"),
        _ => None,
    };
    if let Some(t) = target_triple {
        args.push("--target".into());
        args.push(t.to_string());
        log(format!("Cross-compiling for {target_platform} (target={t})"));
    }

    log(format!("Running: cargo {}", args.join(" ")));

    let mut cmd = Command::new("cargo");
    cmd.args(&args)
        .current_dir(workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().with_context(|| "spawning cargo")?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

    let tx_out = tx.clone();
    let ctx_out = ctx.clone();
    let t_stdout = std::thread::spawn(move || stream_lines(stdout, tx_out, ctx_out));
    let tx_err = tx.clone();
    let ctx_err = ctx.clone();
    let t_stderr = std::thread::spawn(move || stream_lines(stderr, tx_err, ctx_err));

    let status = child.wait().context("waiting on cargo")?;
    let _ = t_stdout.join();
    let _ = t_stderr.join();

    if !status.success() {
        return Err(anyhow!(
            "cargo build failed (exit code {})",
            status.code().unwrap_or(-1)
        ));
    }

    let binary_ext = if target_platform == "windows" { ".exe" } else { "" };
    let binary_name = format!("Collector{binary_ext}");
    let target_bin_dir = if let Some(t) = target_triple {
        workspace_root.join("target").join(t).join("release")
    } else {
        workspace_root.join("target").join("release")
    };
    let src_bin = target_bin_dir.join(&binary_name);
    if !src_bin.exists() {
        return Err(anyhow!("build output not found at {}", src_bin.display()));
    }

    // Copy to builds/<build_id>/Collector_<short>.<ext>
    let short = &build_id[..8.min(build_id.len())];
    let out_dir = workspace_root.join("builds").join(build_id);
    std::fs::create_dir_all(&out_dir)?;
    let out_name = if target_platform == "linux" {
        format!("Collector_{short}_linux")
    } else {
        format!("Collector_{short}.exe")
    };
    let out_exe = out_dir.join(&out_name);
    std::fs::copy(&src_bin, &out_exe)?;

    let size_bytes = std::fs::metadata(&out_exe)?.len();
    let sha256 = sha256_file(&out_exe)?;

    // Also write build metadata
    let meta = serde_json::json!({
        "build_id": build_id,
        "target_platform": target_platform,
        "binary_sha256": sha256,
        "binary_size_bytes": size_bytes,
        "binary_path": out_exe.to_string_lossy(),
    });
    let _ = std::fs::write(
        out_dir.join("build_metadata.json"),
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    );

    log(format!(
        "Output: {} ({:.2} MB)",
        out_exe.display(),
        size_bytes as f64 / 1024.0 / 1024.0
    ));
    log(format!("SHA256: {sha256}"));
    log("BUILD COMPLETE".into());

    Ok((out_exe, sha256, size_bytes))
}

fn stream_lines<R: Read + Send + 'static>(
    reader: R,
    tx: mpsc::Sender<BuildEvent>,
    ctx: egui::Context,
) {
    let buf = BufReader::new(reader);
    for line in buf.lines().map_while(Result::ok) {
        let _ = tx.send(BuildEvent::Log(redact_secrets(&line)));
        ctx.request_repaint();
    }
}

/// Redact AWS-looking access key IDs (20-char ASCII, fixed prefixes) from
/// log output before they reach the UI. Safe for arbitrary UTF-8 input: the
/// 20-byte scan window only matches when both ends are on char boundaries,
/// so multi-byte characters in cargo output (e.g. accented path components)
/// can never trigger a slice panic.
fn redact_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        // i is always on a char boundary because we only ever advance by a
        // full char's byte length or by exactly 20 (after verifying that
        // i + 20 is itself on a boundary).
        if i + 20 <= s.len()
            && s.is_char_boundary(i + 20)
            && is_aws_access_key(&s[i..i + 20])
        {
            out.push_str("AKIA****REDACTED****");
            i += 20;
            continue;
        }
        let c = s[i..].chars().next().expect("i is a char boundary");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

fn is_aws_access_key(s: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "AKIA", "ASIA", "AIDA", "AGPA", "AROA", "AIPA", "ANPA", "ANVA",
    ];
    if s.len() != 20 {
        return false;
    }
    if !PREFIXES.iter().any(|p| s.starts_with(p)) {
        return false;
    }
    s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn sha256_file(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_access_key() {
        let s = "uploading with key AKIAIOSFODNN7EXAMPLE now";
        assert_eq!(redact_secrets(s), "uploading with key AKIA****REDACTED**** now");
    }

    #[test]
    fn ignores_non_aws_strings() {
        let s = "this is just regular log output";
        assert_eq!(redact_secrets(s), s);
    }

    #[test]
    fn handles_non_ascii_safely() {
        // Path with multi-byte chars near where the scan window would land.
        let s = "compiling crate at C:\\Users\\админ\\project (AKIAIOSFODNN7EXAMPLE)";
        let result = redact_secrets(s);
        assert!(result.contains("AKIA****REDACTED****"));
        assert!(result.contains("админ"));
    }

    #[test]
    fn does_not_redact_too_short_or_long() {
        assert_eq!(redact_secrets("AKIAIOSFODNN7EXAMPL"), "AKIAIOSFODNN7EXAMPL");        // 19 chars
        assert_eq!(redact_secrets("AKIAIOSFODNN7EXAMPLES"), "AKIA****REDACTED****S");    // 21 chars matches first 20
    }
}
