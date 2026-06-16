//! Multi-stat footer — six columns of build totals + Back / Next controls.

use eframe::egui;

use crate::app::App;
use crate::backend::artifact_catalog::Catalog;
use crate::spec::{BuildSpec, EncryptionScheme, UploadKind};
use super::theme;

fn step_complete(app: &App, step: u8, catalog_ok: bool) -> bool {
    if !catalog_ok && step == 2 {
        return false;
    }
    match step {
        1 => !app.spec.site_code.is_empty() && !app.spec.filename_template.is_empty(),
        2 => !app.spec.artifacts.is_empty(),
        3 => match app.spec.upload.kind {
            UploadKind::Local => !app.spec.upload.local_path.is_empty(),
            UploadKind::S3 => !app.spec.upload.bucket.is_empty()
                && !app.spec.upload.region.is_empty()
                && !app.spec.upload.access_key_id.is_empty()
                && !app.spec.upload.secret_access_key.is_empty(),
        },
        4 => match app.spec.encryption.scheme {
            EncryptionScheme::None => true,
            EncryptionScheme::X509 => !app.spec.encryption.public_key_pem.is_empty(),
        },
        5 => true,
        6 => app.build.as_ref().is_some_and(|b| matches!(b.status, crate::app::BuildStatus::Complete)),
        _ => false,
    }
}

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    // Top hairline divider separating the footer from the content.
    let r = ui.max_rect();
    ui.painter().hline(r.x_range(), r.top(), egui::Stroke::new(1.0, theme::BORDER));

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        let catalog = app.catalog.as_ref().ok();
        let total_artifacts = catalog.map(|c| c.artifacts.len()).unwrap_or(0);
        let (size_mb, time_sec) = catalog
            .map(|c| totals(c, &app.spec.artifacts))
            .unwrap_or((0, 0));

        stat(ui, "Artifacts Selected", &format!("{} / {}", app.spec.artifacts.len(), total_artifacts));
        stat(ui, "Estimated Size",     &format_size(size_mb));
        stat(ui, "Estimated Time",     &format_time(time_sec));
        stat(ui, "Upload",             &upload_label(&app.spec));
        stat(ui, "Encryption",         &encryption_label(&app.spec));
        stat(ui, "Output",             &output_label(app));

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(12.0);
            let catalog_ok = app.catalog.is_ok();
            let current_step_complete = step_complete(app, app.current_step, catalog_ok);
            let next_enabled = app.current_step < 6 && current_step_complete;
            let next_label = if app.current_step == 6 {
                "Done".to_string()
            } else {
                format!("Next  {}", egui_phosphor::regular::CARET_RIGHT)
            };
            let next_btn = egui::Button::new(
                egui::RichText::new(next_label).color(if next_enabled { egui::Color32::WHITE } else { theme::MUTED }),
            )
            .fill(if next_enabled { theme::ACCENT } else { theme::BG_CARD })
            .stroke(egui::Stroke::new(1.0, if next_enabled { theme::ACCENT } else { theme::BORDER }))
            .rounding(egui::Rounding::same(6.0))
            .min_size(egui::vec2(80.0, 32.0));
            if ui.add_enabled(next_enabled, next_btn).clicked() {
                app.current_step = (app.current_step + 1).min(6);
            }

            ui.add_space(6.0);
            let back_enabled = app.current_step > 1;
            let back_btn = egui::Button::new(
                egui::RichText::new(format!("{}  Back", egui_phosphor::regular::CARET_LEFT)).color(theme::TEXT),
            )
            .fill(theme::BG_CARD)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .rounding(egui::Rounding::same(6.0))
            .min_size(egui::vec2(80.0, 32.0));
            if ui.add_enabled(back_enabled, back_btn).clicked() {
                app.current_step = app.current_step.saturating_sub(1).max(1);
            }
        });
    });
    ui.add_space(10.0);
}

fn stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(label)
                .size(10.0)
                .color(theme::MUTED),
        );
        ui.label(
            egui::RichText::new(value)
                .size(15.0)
                .strong()
                .color(theme::TEXT),
        );
    });
    ui.add_space(28.0);
}

fn totals(cat: &Catalog, selected: &[String]) -> (u64, u64) {
    let mut size = 0u64;
    let mut time = 0u64;
    for id in selected {
        if let Some(a) = cat.get(id) {
            size += a.size_mb;
            time += a.time_sec;
        }
    }
    (size, time)
}

fn format_size(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.2} GB", mb as f64 / 1024.0)
    } else {
        format!("{} MB", mb)
    }
}

fn format_time(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn upload_label(spec: &BuildSpec) -> String {
    match spec.upload.kind {
        UploadKind::S3 => {
            if spec.upload.region.is_empty() {
                "S3".into()
            } else {
                format!("S3 ({})", spec.upload.region)
            }
        }
        UploadKind::Local => "Local".into(),
    }
}

fn encryption_label(spec: &BuildSpec) -> String {
    match spec.encryption.scheme {
        EncryptionScheme::X509 => "RSA-4096 / AES-256".into(),
        EncryptionScheme::None => "None".into(),
    }
}

fn output_label(app: &App) -> String {
    match app.build.as_ref() {
        Some(live) => match &live.status {
            crate::app::BuildStatus::Complete => {
                let bytes = live
                    .result_path
                    .as_ref()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .map(|m| m.len())
                    .unwrap_or(0);
                if bytes == 0 {
                    "—".into()
                } else {
                    format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
                }
            }
            crate::app::BuildStatus::Running => "building…".into(),
            crate::app::BuildStatus::Failed(_) => "failed".into(),
        },
        None => "—".into(),
    }
}
