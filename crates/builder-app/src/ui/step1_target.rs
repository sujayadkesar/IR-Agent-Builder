use eframe::egui;
use crate::spec::{BuildSpec, TargetPlatform};
use super::theme;
use super::widgets::{form_card, step_header};

const FIELD_W: f32 = 440.0;

pub fn view(ui: &mut egui::Ui, spec: &mut BuildSpec) {
    step_header(ui, 1, "Target", "Pick the endpoint OS and the output naming convention");

    form_card(ui, |ui| {
        egui::Grid::new("step1_grid")
            .num_columns(2)
            .spacing([28.0, 16.0])
            .min_col_width(150.0)
            .show(ui, |ui| {
                ui.label("Target OS");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut spec.target_platform, TargetPlatform::Windows, "Windows");
                    ui.selectable_value(&mut spec.target_platform, TargetPlatform::Linux, "Linux");
                });
                ui.end_row();

                ui.label("Site code");
                ui.add(egui::TextEdit::singleline(&mut spec.site_code).desired_width(FIELD_W));
                ui.end_row();

                ui.label("Filename template");
                ui.add(egui::TextEdit::singleline(&mut spec.filename_template).desired_width(FIELD_W));
                ui.end_row();
            });

        ui.add_space(16.0);
        ui.label(
            egui::RichText::new("Available tokens:   %FQDN%   %TIMESTAMP%   %UUID%   %SITE%")
                .small()
                .monospace()
                .color(theme::MUTED),
        );
    });
}
