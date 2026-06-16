use eframe::egui;

use crate::app::{App, BuildStatus};
use crate::spec::{EncryptionScheme, TargetPlatform, UploadKind};
use super::theme;
use super::widgets::{section_label, step_header};

const RIGHT_RAIL_WIDTH: f32 = 280.0;

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    step_header(ui, 6, "Build Collector", "Review configuration, build the collector, and download the executable.");

    let avail = ui.available_width();
    let left_width = (avail - RIGHT_RAIL_WIDTH - 16.0).max(420.0);

    ui.horizontal_top(|ui| {
        // ---- LEFT COLUMN: collector output preview + build log ----
        ui.allocate_ui_with_layout(
            egui::vec2(left_width, ui.available_height()),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                collector_output_card(ui, app);
                ui.add_space(16.0);
                issues_block(ui, app);
                // Build log fills whatever vertical space is left in the column.
                let log_h = ui.available_height().max(240.0);
                build_log_card(ui, app, log_h);
            },
        );

        ui.add_space(16.0);

        // ---- RIGHT RAIL: actions, summary, download ----
        ui.allocate_ui_with_layout(
            egui::vec2(RIGHT_RAIL_WIDTH, ui.available_height()),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                build_actions_card(ui, app);
                ui.add_space(12.0);
                build_summary_card(ui, app);
                ui.add_space(12.0);
                download_card(ui, app);
            },
        );
    });
}

// ---------------------------- LEFT COLUMN ----------------------------

fn collector_output_card(ui: &mut egui::Ui, app: &mut App) {
    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_label(ui, "Collector Output");
        ui.add_space(6.0);

        let target_triple = match app.spec.target_platform {
            TargetPlatform::Windows => "x86_64-pc-windows-msvc",
            TargetPlatform::Linux   => "x86_64-unknown-linux-gnu",
        };
        let filename = preview_filename(app);
        let path = app
            .build
            .as_ref()
            .and_then(|b| b.result_path.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(not built yet)".to_string());
        let size = app
            .build
            .as_ref()
            .and_then(|b| b.result_path.as_ref())
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| format!("{:.1} MB", m.len() as f64 / 1024.0 / 1024.0))
            .unwrap_or_else(|| "—".to_string());

        ui.label(
            egui::RichText::new(filename)
                .size(20.0)
                .monospace()
                .color(theme::TEXT),
        );
        ui.add_space(4.0);
        ui.label(egui::RichText::new(path).small().color(theme::MUTED));

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            output_meta(ui, "File Size",    &size);
            ui.add_space(28.0);
            output_meta(ui, "Version",      env!("CARGO_PKG_VERSION"));
            ui.add_space(28.0);
            output_meta(ui, "Build Target", target_triple);
        });
    });
}

fn output_meta(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(label).size(10.0).color(theme::MUTED));
        ui.label(egui::RichText::new(value).size(13.0).monospace().color(theme::TEXT));
    });
}

fn build_log_card(ui: &mut egui::Ui, app: &App, height: f32) {
    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_label(ui, "Build Log (live)");
        ui.add_space(6.0);

        let frame = egui::Frame::default()
            .fill(theme::BG_CODE)
            .stroke(egui::Stroke::new(1.0, theme::BORDER_SUBTLE))
            .rounding(egui::Rounding::same(4.0))
            .inner_margin(egui::Margin::same(10.0));

        frame.show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height((height - 64.0).max(160.0))
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    match app.build.as_ref() {
                        None => {
                            ui.label(
                                egui::RichText::new("awaiting cargo output…")
                                    .small()
                                    .monospace()
                                    .color(theme::MUTED_DIM),
                            );
                        }
                        Some(live) if live.logs.is_empty() => {
                            ui.label(
                                egui::RichText::new("starting cargo…")
                                    .small()
                                    .monospace()
                                    .color(theme::MUTED_DIM),
                            );
                        }
                        Some(live) => {
                            for line in &live.logs {
                                render_log_line(ui, line);
                            }
                        }
                    }
                });
        });
    });
}

/// Render a single log line with light syntax coloring: timestamps muted,
/// "INFO" cyan-ish, "SUCCESS"/"FAILED" tinted, plain text default.
fn render_log_line(ui: &mut egui::Ui, line: &str) {
    let mut job = egui::text::LayoutJob::default();
    let mono = egui::FontId::monospace(12.0);

    // Pull off the optional [HH:MM:SS.mmm] timestamp prefix the build
    // orchestrator prepends.
    let (ts, rest) = strip_timestamp(line);
    if let Some(ts) = ts {
        job.append(
            &format!("[{ts}] "),
            0.0,
            egui::TextFormat {
                font_id: mono.clone(),
                color: theme::MUTED_DIM,
                ..Default::default()
            },
        );
    }

    // Crude tag highlighting.
    let (tag, body) = split_tag(rest);
    if let Some(tag) = tag {
        let tag_color = match tag {
            "INFO"            => theme::ACCENT,
            "SUCCESS"         => theme::SUCCESS,
            "WARN" | "WARNING"=> theme::WARNING,
            "ERROR" | "FAILED"=> theme::DANGER,
            _                  => theme::MUTED,
        };
        job.append(
            &format!("{tag} "),
            0.0,
            egui::TextFormat {
                font_id: mono.clone(),
                color: tag_color,
                ..Default::default()
            },
        );
    }

    job.append(
        body,
        0.0,
        egui::TextFormat {
            font_id: mono,
            color: theme::TEXT,
            ..Default::default()
        },
    );

    ui.add(egui::Label::new(job).wrap());
}

fn strip_timestamp(line: &str) -> (Option<&str>, &str) {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('[') {
        return (None, line);
    }
    if let Some(end) = trimmed.find(']') {
        let ts = &trimmed[1..end];
        let rest = trimmed[end + 1..].trim_start();
        if ts.chars().all(|c| c.is_ascii_digit() || matches!(c, ':' | '.' | '-')) {
            return (Some(ts), rest);
        }
    }
    (None, line)
}

fn split_tag(line: &str) -> (Option<&str>, &str) {
    const TAGS: &[&str] = &["INFO", "SUCCESS", "WARN", "WARNING", "ERROR", "FAILED"];
    for t in TAGS {
        if let Some(rest) = line.strip_prefix(t) {
            if rest.starts_with(' ') || rest.starts_with('\t') {
                return (Some(t), rest.trim_start());
            }
        }
    }
    (None, line)
}

fn issues_block(ui: &mut egui::Ui, app: &App) {
    let issues = validate(app);
    if issues.is_empty() {
        return;
    }
    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_label(ui, "Issues to resolve");
        ui.add_space(4.0);
        for i in &issues {
            ui.colored_label(theme::WARNING, format!("• {i}"));
        }
    });
}

// ---------------------------- RIGHT RAIL ----------------------------

fn build_actions_card(ui: &mut egui::Ui, app: &mut App) {
    theme::panel_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_label(ui, "Build Actions");
        ui.add_space(10.0);

        let issues = validate(app);
        let is_running = matches!(
            app.build.as_ref().map(|b| &b.status),
            Some(BuildStatus::Running)
        );
        let can_build = issues.is_empty() && !is_running;

        // Primary BUILD button — solid blue.
        let label = if is_running {
            format!("{}  Building…", egui_phosphor::regular::SPINNER)
        } else {
            format!("{}  BUILD COLLECTOR", egui_phosphor::regular::PLAY)
        };
        let build_btn = egui::Button::new(
            egui::RichText::new(label).strong().color(egui::Color32::WHITE),
        )
        .fill(if can_build { theme::ACCENT } else { theme::MUTED_DIM })
        .stroke(egui::Stroke::NONE)
        .rounding(egui::Rounding::same(6.0))
        .min_size(egui::vec2(ui.available_width(), 38.0));
        if ui.add_enabled(can_build, build_btn).clicked() {
            let ctx = ui.ctx().clone();
            if let Err(e) = app.start_build(ctx) {
                log::error!("could not start build: {e}");
            }
        }
        ui.add_space(8.0);

        // Stop Build (disabled placeholder — real cancellation is Phase 5+)
        let stop_btn = secondary_button(
            &format!("{}  Stop Build", egui_phosphor::regular::STOP),
            ui.available_width(),
        );
        let _ = ui.add_enabled(is_running, stop_btn);
        ui.add_space(8.0);

        // Open Output Folder — enabled if we have a result_path
        let has_output = app
            .build
            .as_ref()
            .and_then(|b| b.result_path.as_ref())
            .is_some();
        let open_btn = secondary_button(
            &format!("{}  Open Output Folder", egui_phosphor::regular::FOLDER_OPEN),
            ui.available_width(),
        );
        if ui.add_enabled(has_output, open_btn).clicked() {
            if let Some(p) = app.build.as_ref().and_then(|b| b.result_path.as_ref()) {
                reveal_in_explorer(p);
            }
        }
    });
}

fn build_summary_card(ui: &mut egui::Ui, app: &App) {
    theme::panel_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_label(ui, "Build Summary");
        ui.add_space(8.0);

        egui::Grid::new("summary_grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .min_col_width(80.0)
            .show(ui, |ui| {
                let status = match app.build.as_ref().map(|b| &b.status) {
                    Some(BuildStatus::Complete) => "Success".to_string(),
                    Some(BuildStatus::Running)  => "Running…".to_string(),
                    Some(BuildStatus::Failed(_))=> "Failed".to_string(),
                    None                        => "Not started".to_string(),
                };
                let status_color = match app.build.as_ref().map(|b| &b.status) {
                    Some(BuildStatus::Complete)  => theme::SUCCESS,
                    Some(BuildStatus::Running)   => theme::ACCENT,
                    Some(BuildStatus::Failed(_)) => theme::DANGER,
                    None                         => theme::MUTED,
                };
                ui.label(egui::RichText::new("Status").small().color(theme::MUTED));
                ui.label(egui::RichText::new(status).color(status_color).strong().size(12.0));
                ui.end_row();

                kv(ui, "Profile",   &app.spec.site_code);
                kv(ui, "OS Target", match app.spec.target_platform {
                    TargetPlatform::Windows => "Windows",
                    TargetPlatform::Linux   => "Linux",
                });
                kv(ui, "Artifacts", &format!("{}", app.spec.artifacts.len()));
                kv(ui, "Upload",    &upload_label(&app.spec.upload.kind));
                kv(ui, "Encryption", match app.spec.encryption.scheme {
                    EncryptionScheme::X509 => "RSA-4096 / AES-256",
                    EncryptionScheme::None => "None",
                });
                if let Some(live) = app.build.as_ref() {
                    if let Some(ref sha) = live.result_sha256 {
                        let short = &sha[..16.min(sha.len())];
                        kv(ui, "SHA256", &format!("{short}…"));
                    }
                }
            });
    });
}

fn download_card(ui: &mut egui::Ui, app: &App) {
    theme::panel_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_label(ui, "Download / Share");
        ui.add_space(10.0);

        let has_output = app
            .build
            .as_ref()
            .and_then(|b| b.result_path.as_ref())
            .is_some();

        let download_btn = egui::Button::new(
            egui::RichText::new(format!("{}  Download Executable", egui_phosphor::regular::DOWNLOAD_SIMPLE))
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(if has_output { theme::SUCCESS } else { theme::MUTED_DIM })
        .stroke(egui::Stroke::NONE)
        .rounding(egui::Rounding::same(6.0))
        .min_size(egui::vec2(ui.available_width(), 36.0));
        if ui.add_enabled(has_output, download_btn).clicked() {
            if let Some(p) = app.build.as_ref().and_then(|b| b.result_path.as_ref()) {
                reveal_in_explorer(p);
            }
        }
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let half = (ui.available_width() - 6.0) / 2.0;
            let sha_btn = secondary_button(
                &format!("{}  SHA256", egui_phosphor::regular::FINGERPRINT),
                half,
            );
            if ui.add_enabled(has_output, sha_btn).clicked() {
                if let Some(sha) = app.build.as_ref().and_then(|b| b.result_sha256.as_ref()) {
                    ui.output_mut(|o| o.copied_text = sha.clone());
                }
            }
            ui.add_space(6.0);
            let path_btn = secondary_button(
                &format!("{}  Copy Path", egui_phosphor::regular::COPY),
                half,
            );
            if ui.add_enabled(has_output, path_btn).clicked() {
                if let Some(p) = app.build.as_ref().and_then(|b| b.result_path.as_ref()) {
                    ui.output_mut(|o| o.copied_text = p.display().to_string());
                }
            }
        });
    });
}

// ---------------------------- HELPERS ----------------------------

fn secondary_button(label: &str, width: f32) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(label).color(theme::TEXT))
        .fill(theme::BG_CARD)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .rounding(egui::Rounding::same(6.0))
        .min_size(egui::vec2(width, 32.0))
}

fn kv(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.label(egui::RichText::new(k).small().color(theme::MUTED));
    ui.label(egui::RichText::new(v).monospace().size(12.0).color(theme::TEXT));
    ui.end_row();
}

fn upload_label(k: &UploadKind) -> String {
    match k {
        UploadKind::S3 => "S3".into(),
        UploadKind::Local => "Local".into(),
    }
}

fn preview_filename(app: &App) -> String {
    let stem = match app.spec.target_platform {
        TargetPlatform::Windows => "Collector.exe",
        TargetPlatform::Linux   => "Collector",
    };
    if app.spec.filename_template.is_empty() {
        return stem.to_string();
    }
    app.spec.filename_template
        .replace("%SITE%", &app.spec.site_code)
        .replace("%FQDN%", "<FQDN>")
        .replace("%TIMESTAMP%", "<TIMESTAMP>")
        .replace("%UUID%", "<UUID>")
}

fn validate(app: &App) -> Vec<String> {
    let mut out = Vec::new();
    if app.spec.artifacts.is_empty() {
        out.push("No artifacts selected — pick a bundle on Step 2.".into());
    }
    match app.spec.upload.kind {
        UploadKind::S3 => {
            if app.spec.upload.bucket.is_empty()      { out.push("S3 bucket not set (Step 3).".into()); }
            if app.spec.upload.region.is_empty()      { out.push("S3 region not set (Step 3).".into()); }
            if app.spec.upload.access_key_id.is_empty()      { out.push("AWS Access Key ID not set (Step 3).".into()); }
            if app.spec.upload.secret_access_key.is_empty()  { out.push("AWS Secret Access Key not set (Step 3).".into()); }
        }
        UploadKind::Local => {
            if app.spec.upload.local_path.is_empty() {
                out.push("Local output path not set (Step 3).".into());
            }
        }
    }
    if app.spec.encryption.scheme == EncryptionScheme::X509
        && app.spec.encryption.public_key_pem.is_empty()
    {
        out.push("X509 encryption selected but no public key — generate or paste one on Step 4.".into());
    }
    if matches!(app.spec.target_platform, TargetPlatform::Windows)
        && !app.spec.use_vss
        && app.spec.artifacts.iter().any(|a| LOCKED_ARTIFACTS.contains(&a.as_str()))
    {
        out.push("VSS is OFF but selected artifacts require it for locked system files.".into());
    }
    out
}

const LOCKED_ARTIFACTS: &[&str] = &[
    "registry.hives",
    "filesystem.mft",
    "eventlogs.security",
    "eventlogs.system",
    "eventlogs.application",
    "eventlogs.powershell",
    "eventlogs.sysmon",
    "eventlogs.defender",
    "cloud.outlook",
];

#[cfg(target_os = "windows")]
fn reveal_in_explorer(path: &std::path::Path) {
    use std::os::windows::process::CommandExt;

    if !is_within_output_root(path) {
        return;
    }

    let mut arg = std::ffi::OsString::from("/select,");
    arg.push(path.as_os_str());

    let _ = std::process::Command::new("explorer.exe")
        .raw_arg(arg)
        .spawn();
}

#[cfg(not(target_os = "windows"))]
fn reveal_in_explorer(path: &std::path::Path) {
    if !is_within_output_root(path) {
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    }
}

fn is_within_output_root(path: &std::path::Path) -> bool {
    let Ok(canonical) = path.canonicalize() else {
        return false;
    };
    let Ok(output_root) = crate::app::build_output_dir().canonicalize() else {
        return false;
    };
    canonical.starts_with(output_root)
}
