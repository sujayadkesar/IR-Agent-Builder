use eframe::egui;
use crate::spec::{BuildSpec, TargetPlatform};
use super::theme;
use super::widgets::step_header;

pub fn view(ui: &mut egui::Ui, spec: &mut BuildSpec) {
    step_header(ui, 1, "Target", "Pick OS and naming convention");

    egui::Grid::new("step1_grid")
        .num_columns(2)
        .spacing([24.0, 12.0])
        .show(ui, |ui| {
            ui.label("Target OS");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut spec.target_platform, TargetPlatform::Windows, "Windows");
                ui.selectable_value(&mut spec.target_platform, TargetPlatform::Linux,   "Linux");
            });
            ui.end_row();

            ui.label("Site code");
            ui.text_edit_singleline(&mut spec.site_code);
            ui.end_row();

            ui.label("Filename template");
            ui.text_edit_singleline(&mut spec.filename_template);
            ui.end_row();
        });

    ui.add_space(20.0);
    ui.label(
        egui::RichText::new("Available tokens:  %FQDN%   %TIMESTAMP%   %UUID%   %SITE%")
            .small()
            .monospace()
            .color(theme::MUTED),
    );
}
