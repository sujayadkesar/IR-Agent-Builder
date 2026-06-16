//! Top application header — shield logo, title + tagline, version chip, and
//! right-aligned Open / Save project actions (load/save the full BuildSpec).

use eframe::egui;

use crate::app::App;
use crate::spec::BuildSpec;
use super::theme;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        logo(ui);
        ui.add_space(12.0);

        ui.vertical(|ui| {
            ui.add_space(1.0);
            ui.label(
                egui::RichText::new("DFIR Agent Builder")
                    .strong()
                    .size(17.0)
                    .color(theme::TEXT),
            );
            ui.label(
                egui::RichText::new("Velociraptor-class triage collector compiler")
                    .size(11.5)
                    .color(theme::MUTED),
            );
        });

        ui.add_space(10.0);
        version_chip(ui);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(16.0);
            if action_button(ui, egui_phosphor::regular::FLOPPY_DISK, "Save Project").clicked() {
                save_project(app);
            }
            ui.add_space(6.0);
            if action_button(ui, egui_phosphor::regular::FOLDER_OPEN, "Open Project").clicked() {
                open_project(app);
            }
        });
    });
    ui.add_space(10.0);

    // Bottom hairline divider separating the header from the content.
    let r = ui.max_rect();
    ui.painter().hline(
        r.x_range(),
        r.bottom(),
        egui::Stroke::new(1.0, theme::BORDER),
    );
}

fn logo(ui: &mut egui::Ui) {
    let size = egui::vec2(34.0, 34.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, egui::Rounding::same(8.0), theme::ACCENT);
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        egui_phosphor::regular::SHIELD_CHECK,
        egui::FontId::proportional(20.0),
        egui::Color32::WHITE,
    );
}

fn version_chip(ui: &mut egui::Ui) {
    let frame = egui::Frame::default()
        .fill(theme::BG_CARD)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(9.0, 3.0));
    frame.show(ui, |ui| {
        ui.label(
            egui::RichText::new(format!("v{APP_VERSION}"))
                .size(11.0)
                .color(theme::MUTED),
        );
    });
}

fn action_button(ui: &mut egui::Ui, icon: &str, label: &str) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(format!("{icon}  {label}")).size(13.0).color(theme::TEXT),
    )
    .fill(theme::BG_CARD)
    .stroke(egui::Stroke::new(1.0, theme::BORDER))
    .rounding(egui::Rounding::same(6.0));
    ui.add(btn)
}

fn save_project(app: &mut App) {
    if let Some(path) = rfd::FileDialog::new()
        .set_file_name("dfir-project.json")
        .add_filter("JSON", &["json"])
        .save_file()
    {
        let json = serde_json::to_string_pretty(&app.spec).unwrap_or_default();
        match std::fs::write(&path, json) {
            Ok(_) => app.export_error = None,
            Err(e) => app.export_error = Some(format!("Save failed ({}): {e}", path.display())),
        }
    }
}

fn open_project(app: &mut App) {
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("JSON", &["json"])
        .pick_file()
    {
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<BuildSpec>(&s).ok())
        {
            Some(spec) => {
                app.spec = spec;
                app.export_error = None;
            }
            None => {
                app.export_error =
                    Some(format!("Open failed: {} is not a valid project file", path.display()));
            }
        }
    }
}
