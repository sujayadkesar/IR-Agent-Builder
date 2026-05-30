//! Top application header — logo, title, version chip, and right-aligned
//! action buttons (Open / Save / CLI Preview / Settings). Action buttons
//! are currently no-ops; they'll be wired in a later phase.

use eframe::egui;
use super::theme;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn view(ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        logo(ui);
        ui.add_space(10.0);

        ui.vertical(|ui| {
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new("DFIR Agent Builder")
                    .strong()
                    .size(16.0)
                    .color(theme::TEXT),
            );
        });

        ui.add_space(8.0);
        version_chip(ui);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            action_button(ui, "Settings");
            action_button(ui, "CLI Preview");
            action_button(ui, "Save Project");
            action_button(ui, "Open Project");
        });
    });
    ui.add_space(8.0);
}

fn logo(ui: &mut egui::Ui) {
    // A square accent badge — stands in for the shield icon in the mockup.
    let size = egui::vec2(32.0, 32.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, egui::Rounding::same(6.0), theme::ACCENT);
    // A simple inset glyph
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "◆",
        egui::FontId::proportional(16.0),
        egui::Color32::WHITE,
    );
}

fn version_chip(ui: &mut egui::Ui) {
    let frame = egui::Frame::default()
        .fill(theme::BG_CARD)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(8.0, 2.0));
    frame.show(ui, |ui| {
        ui.label(
            egui::RichText::new(format!("v{APP_VERSION}"))
                .small()
                .color(theme::MUTED),
        );
    });
}

fn action_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(label).size(12.0).color(theme::MUTED),
    )
    .fill(egui::Color32::TRANSPARENT)
    .stroke(egui::Stroke::NONE)
    .frame(false);
    ui.add(btn)
}
