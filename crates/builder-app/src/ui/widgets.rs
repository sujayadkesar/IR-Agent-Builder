//! Shared widget helpers used by all step views.

use eframe::egui;
use super::theme;

/// Page header used at the top of each step's content area. Shows the step
/// number + title + a one-line subtitle, matching the mockup's "6. Build
/// Collector / Review configuration, build the collector, ..." pattern.
pub fn step_header(ui: &mut egui::Ui, num: u8, title: &str, subtitle: &str) {
    ui.label(
        egui::RichText::new(format!("{num}. {title}"))
            .size(22.0)
            .strong()
            .color(theme::TEXT),
    );
    ui.add_space(2.0);
    ui.label(egui::RichText::new(subtitle).color(theme::MUTED));
    ui.add_space(20.0);
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
