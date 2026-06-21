use eframe::egui;

use crate::spec::{BuildSpec, OutputFormat};
use super::theme;
use super::widgets::{caption, form_card, step_header};

pub fn view(ui: &mut egui::Ui, spec: &mut BuildSpec) {
    step_header(ui, 5, "Performance", "Resource limits, hardening, and large-collection streaming");

    ui.set_max_width(theme::CONTENT_MAX_WIDTH);

    form_card(ui, |ui| {
        caption(ui, "RESOURCE LIMITS");
        egui::Grid::new("step5_grid")
            .num_columns(2)
            .spacing([28.0, 16.0])
            .min_col_width(190.0)
            .show(ui, |ui| {
                ui.label("CPU limit (%)");
                ui.add(egui::Slider::new(&mut spec.cpu_limit_percent, 0..=100).text("0 = unthrottled"));
                ui.end_row();

                ui.label("Concurrency");
                ui.add(egui::Slider::new(&mut spec.concurrency, 1..=8));
                ui.end_row();

                ui.label("Progress timeout (sec)");
                ui.add(egui::DragValue::new(&mut spec.progress_timeout_seconds).range(60..=86_400).suffix(" s"));
                ui.end_row();

                ui.label("Max collection size");
                ui.add(egui::DragValue::new(&mut spec.max_collection_size_gb).range(0..=512).suffix(" GB  (0 = no cap)"));
                ui.end_row();

                ui.label("Encryption chunk size");
                ui.horizontal(|ui| {
                    ui.checkbox(&mut spec.encrypt_chunk_auto, "Auto (by endpoint RAM)");
                    ui.add_enabled(
                        !spec.encrypt_chunk_auto,
                        egui::DragValue::new(&mut spec.encrypt_chunk_mb).range(16..=4096).suffix(" MiB"),
                    );
                });
                ui.end_row();

                ui.label("Output format");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut spec.output_format, OutputFormat::Jsonl, "JSONL");
                    ui.selectable_value(&mut spec.output_format, OutputFormat::Csv, "CSV");
                });
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Encryption chunk size bounds the collector's peak RAM while sealing the final \
                 archive (~3x this), so multi-GB collections never load whole into memory. Auto \
                 sizes it from the endpoint's available RAM (64–512 MiB).",
            )
            .small()
            .color(theme::MUTED),
        );

        ui.add_space(16.0);
        caption(ui, "HARDENING");
        ui.checkbox(&mut spec.require_admin, "Require admin / root at runtime");
        ui.add_space(4.0);
        ui.checkbox(&mut spec.silent, "Silent mode (suppress all UI on the endpoint)");
        ui.add_space(4.0);
        ui.checkbox(&mut spec.delete_after_upload, "Securely delete plaintext after upload");
        ui.add_space(4.0);
        ui.checkbox(&mut spec.use_vss, "Use VSS snapshot for locked files (Windows)");
    });

    ui.add_space(16.0);

    form_card(ui, |ui| {
        caption(ui, "CHUNKED STREAMING UPLOAD  ·  large collections");
        ui.checkbox(&mut spec.chunk_upload.enabled, "Enable chunked streaming");
        ui.add_space(8.0);

        ui.add_enabled_ui(spec.chunk_upload.enabled, |ui| {
            egui::Grid::new("step5_chunk")
                .num_columns(2)
                .spacing([28.0, 12.0])
                .min_col_width(190.0)
                .show(ui, |ui| {
                    ui.label("Chunk size");
                    ui.add(egui::DragValue::new(&mut spec.chunk_upload.chunk_size_mb).range(16..=2048).suffix(" MB"));
                    ui.end_row();

                    ui.label("Stream mode");
                    ui.checkbox(&mut spec.chunk_upload.stream_mode, "");
                    ui.end_row();

                    ui.label("Low disk threshold");
                    ui.add(egui::DragValue::new(&mut spec.chunk_upload.low_disk_threshold_mb).range(0..=102_400).suffix(" MB"));
                    ui.end_row();
                });
        });

        if !spec.chunk_upload.enabled {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Disabled = one big encrypted container. Enable for endpoints likely to exceed disk headroom (Deep Dive presets).",
                )
                .small()
                .color(theme::MUTED),
            );
        }
    });
}
