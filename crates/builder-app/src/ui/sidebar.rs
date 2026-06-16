//! Left sidebar — vertical stepper, current-profile summary card, and an
//! Export Summary action pinned to the bottom.

use eframe::egui;

use crate::app::App;
use crate::backend::artifact_catalog::Catalog;
use crate::spec::{BuildSpec, EncryptionScheme, TargetPlatform, UploadKind};
use super::theme;

const STEPS: &[(u8, &str, &str)] = &[
    (1, "Target",      "OS, site, naming"),
    (2, "Artifacts",   "What to collect"),
    (3, "Upload",      "S3 or network share"),
    (4, "Encryption",  "Keys & encryption"),
    (5, "Performance", "Tuning & limits"),
    (6, "Build",       "Compile & package"),
];

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    // Reserve room for the pinned Export action at the very bottom; the steps +
    // profile scroll in the space above so nothing is ever clipped, even at the
    // minimum window height.
    let export_block_h = if app.export_error.is_some() { 96.0 } else { 52.0 };
    let scroll_h = (ui.available_height() - export_block_h).max(120.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .max_height(scroll_h)
        .show(ui, |ui| {
            section_label(ui, "BUILD STEPS");
            ui.add_space(6.0);

            let catalog_ok = app.catalog.is_ok();
            for &(id, title, subtitle) in STEPS {
                let state = if app.current_step == id {
                    StepState::Active
                } else if app.current_step > id && step_complete(app, id, catalog_ok) {
                    StepState::Done
                } else if app.current_step > id {
                    StepState::Visited
                } else {
                    StepState::Future
                };
                if step_row(ui, id, title, subtitle, state).clicked() {
                    app.current_step = id;
                }
                ui.add_space(3.0);
            }

            ui.add_space(18.0);
            profile_card(ui, &app.spec, app.catalog.as_ref().ok());
        });

    // ---- Pinned Export action (always visible) ----
    ui.add_space(8.0);
    let btn = egui::Button::new(
        egui::RichText::new(format!("{}  Export Summary (JSON)", egui_phosphor::regular::EXPORT))
            .size(13.0)
            .color(theme::ACCENT),
    )
    .fill(theme::BG_CARD)
    .stroke(egui::Stroke::new(1.0, theme::ACCENT))
    .rounding(egui::Rounding::same(6.0))
    .min_size(egui::vec2(ui.available_width(), 34.0));
    if ui.add(btn).clicked() {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("dfir-summary.json")
            .add_filter("JSON", &["json"])
            .save_file()
        {
            let json = serde_json::to_string_pretty(&app.spec).unwrap_or_default();
            if let Err(e) = std::fs::write(&path, json) {
                app.export_error = Some(format!("Export failed ({}): {}", path.display(), e));
            } else {
                app.export_error = None;
            }
        }
    }
    if let Some(ref msg) = app.export_error {
        ui.add_space(4.0);
        ui.label(egui::RichText::new(msg).size(11.0).color(theme::DANGER));
    }
}

#[derive(Clone, Copy)]
enum StepState {
    Active,
    Done,
    Visited,
    Future,
}

fn step_row(
    ui: &mut egui::Ui,
    n: u8,
    title: &str,
    subtitle: &str,
    state: StepState,
) -> egui::Response {
    let row_height = 54.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), row_height),
        egui::Sense::click(),
    );

    let bg = match state {
        StepState::Active => theme::ACCENT_BG,
        _ if response.hovered() => theme::BG_CARD,
        _ => egui::Color32::TRANSPARENT,
    };
    let painter = ui.painter();
    painter.rect_filled(rect, egui::Rounding::same(8.0), bg);

    if matches!(state, StepState::Active) {
        // Left edge accent bar.
        let bar = egui::Rect::from_min_size(
            egui::pos2(rect.left(), rect.top() + 6.0),
            egui::vec2(3.0, rect.height() - 12.0),
        );
        painter.rect_filled(bar, egui::Rounding::same(2.0), theme::ACCENT);
    }

    // Numbered circle on the left.
    let circle_center = egui::pos2(rect.left() + 26.0, rect.center().y);
    let (circle_bg, circle_fg) = match state {
        StepState::Done    => (theme::SUCCESS, egui::Color32::WHITE),
        StepState::Active  => (theme::ACCENT, egui::Color32::WHITE),
        StepState::Visited => (theme::MUTED_DIM, egui::Color32::WHITE),
        StepState::Future  => (theme::BG_CARD, theme::MUTED),
    };
    painter.circle_filled(circle_center, 14.0, circle_bg);
    if matches!(state, StepState::Done) {
        painter.text(
            circle_center,
            egui::Align2::CENTER_CENTER,
            egui_phosphor::regular::CHECK,
            egui::FontId::proportional(15.0),
            circle_fg,
        );
    } else {
        painter.text(
            circle_center,
            egui::Align2::CENTER_CENTER,
            n.to_string(),
            egui::FontId::proportional(13.0),
            circle_fg,
        );
    }

    // Title + subtitle, vertically centered to the right of the circle.
    let text_x = rect.left() + 50.0;
    let title_color = match state {
        StepState::Future => theme::MUTED,
        _ => theme::TEXT,
    };
    let subtitle_color = if matches!(state, StepState::Active) {
        egui::Color32::from_rgb(0xB9, 0xCD, 0xF7) // light blue — readable on the accent tint
    } else {
        theme::MUTED
    };
    painter.text(
        egui::pos2(text_x, rect.center().y - 9.0),
        egui::Align2::LEFT_CENTER,
        title,
        egui::FontId::proportional(14.0),
        title_color,
    );
    painter.text(
        egui::pos2(text_x, rect.center().y + 10.0),
        egui::Align2::LEFT_CENTER,
        subtitle,
        egui::FontId::proportional(11.0),
        subtitle_color,
    );

    response
}

fn profile_card(ui: &mut egui::Ui, spec: &BuildSpec, catalog: Option<&Catalog>) {
    section_label(ui, "CURRENT PROFILE");
    ui.add_space(4.0);

    theme::panel_frame().show(ui, |ui| {
        egui::Grid::new("profile_grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .min_col_width(60.0)
            .show(ui, |ui| {
                let os_label = match spec.target_platform {
                    TargetPlatform::Windows => "Windows",
                    TargetPlatform::Linux   => "Linux",
                };
                kv(ui, "OS",         os_label);
                kv(ui, "Site",       &spec.site_code);
                kv(ui, "Artifacts",  &format!("{} selected", spec.artifacts.len()));
                if let Some(cat) = catalog {
                    let (size_mb, time_sec) = totals(cat, &spec.artifacts);
                    kv(ui, "Est. Size", &format_size(size_mb));
                    kv(ui, "Est. Time", &format_time(time_sec));
                }
                kv(ui, "Upload To",  match spec.upload.kind {
                    UploadKind::S3    => "S3",
                    UploadKind::Local => "Local",
                });
                kv(ui, "Encryption", match spec.encryption.scheme {
                    EncryptionScheme::X509 => "RSA-4096 / AES-256",
                    EncryptionScheme::None => "None (plaintext)",
                });
            });
    });
}

fn kv(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.label(egui::RichText::new(k).small().color(theme::MUTED));
    ui.label(egui::RichText::new(v).color(theme::TEXT).monospace().size(12.0));
    ui.end_row();
}

fn section_label(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(11.0)
            .color(theme::MUTED)
            .strong(),
    );
}

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
        5 => true, // always considered done (defaults are reasonable)
        6 => app.build.as_ref().is_some_and(|b| matches!(b.status, crate::app::BuildStatus::Complete)),
        _ => false,
    }
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
