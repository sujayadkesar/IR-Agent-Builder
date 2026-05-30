//! Multi-stat footer — six columns of build totals + Back / Next controls.

use eframe::egui;

use crate::app::App;
use crate::backend::artifact_catalog::Catalog;
use crate::spec::{BuildSpec, EncryptionScheme, UploadKind};
use super::theme;

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    ui.add_space(10.0);
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
            let next_enabled = app.current_step < 6;
            let next_label = if app.current_step == 6 { "Done" } else { "Next  →" };
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
                egui::RichText::new("←  Back").color(theme::TEXT),
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
