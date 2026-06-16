//! Shared widget helpers used by all step views.

use eframe::egui;
use super::theme;

/// Page header used at the top of each step's content area. Shows the step
/// number (accent) + title + a one-line subtitle.
pub fn step_header(ui: &mut egui::Ui, num: u8, title: &str, subtitle: &str) {
    let mut job = egui::text::LayoutJob::default();
    let big = egui::FontId::proportional(23.0);
    job.append(
        &format!("{num}  "),
        0.0,
        egui::TextFormat { font_id: big.clone(), color: theme::ACCENT, ..Default::default() },
    );
    job.append(
        title,
        0.0,
        egui::TextFormat { font_id: big, color: theme::TEXT, ..Default::default() },
    );
    ui.label(job);
    ui.add_space(3.0);
    ui.label(egui::RichText::new(subtitle).size(13.0).color(theme::MUTED));
    ui.add_space(18.0);
}

/// Wrap a step's single-column form content in a bordered card constrained to
/// a readable max width. Gives the form structure instead of letting labels
/// float on a wide empty background.
pub fn form_card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    ui.set_max_width(theme::CONTENT_MAX_WIDTH);
    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
}

/// Small UPPERCASE accent caption used to title a sub-section inside a card.
pub fn caption(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(11.0)
            .strong()
            .color(theme::ACCENT),
    );
    ui.add_space(6.0);
}

/// Small UPPERCASE section label, e.g. "BUILD ACTIONS", "CURRENT PROFILE".
pub fn section_label(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(11.0)
            .color(theme::MUTED)
            .strong(),
    );
}
