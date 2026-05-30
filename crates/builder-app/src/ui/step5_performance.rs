use eframe::egui;

use crate::spec::{BuildSpec, OutputFormat};
use super::theme;
use super::widgets::step_header;

pub fn view(ui: &mut egui::Ui, spec: &mut BuildSpec) {
    step_header(ui, 5, "Performance", "CPU limit, concurrency, output format");

    egui::Grid::new("step5_grid")
        .num_columns(2)
        .spacing([24.0, 14.0])
        .show(ui, |ui| {
            ui.label("CPU limit (%)");
            ui.add(
                egui::Slider::new(&mut spec.cpu_limit_percent, 0..=100)
                    .text("(0 = unthrottled)"),
            );
            ui.end_row();

            ui.label("Concurrency");
            ui.add(egui::Slider::new(&mut spec.concurrency, 1..=8));
            ui.end_row();

            ui.label("Progress timeout (sec)");
            ui.add(egui::DragValue::new(&mut spec.progress_timeout_seconds).range(60..=86_400));
            ui.end_row();

            ui.label("Output format");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut spec.output_format, OutputFormat::Jsonl, "JSONL");
                ui.selectable_value(&mut spec.output_format, OutputFormat::Csv, "CSV");
            });
            ui.end_row();

            ui.label("Max collection size (GB)");
            ui.add(
                egui::DragValue::new(&mut spec.max_collection_size_gb)
                    .range(0..=512)
                    .suffix(" GB"),
            );
            ui.end_row();

            ui.label("Require admin / root");
            ui.checkbox(&mut spec.require_admin, "");
            ui.end_row();

            ui.label("Silent mode");
            ui.checkbox(&mut spec.silent, "");
            ui.end_row();

            ui.label("Delete plaintext after upload");
            ui.checkbox(&mut spec.delete_after_upload, "");
            ui.end_row();

            ui.label("Use VSS snapshot (Windows)");
            ui.checkbox(&mut spec.use_vss, "");
            ui.end_row();
        });

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(12.0);

    ui.label(
        egui::RichText::new("CHUNKED STREAMING UPLOAD (large collections)")
            .small()
            .monospace()
            .color(theme::ACCENT),
    );
    ui.add_space(4.0);

    egui::Grid::new("step5_chunk")
        .num_columns(2)
        .spacing([24.0, 10.0])
        .show(ui, |ui| {
            ui.label("Enabled");
            ui.checkbox(&mut spec.chunk_upload.enabled, "");
            ui.end_row();

            ui.label("Chunk size (MB)");
            ui.add(
                egui::DragValue::new(&mut spec.chunk_upload.chunk_size_mb)
                    .range(16..=2048)
                    .suffix(" MB"),
            );
            ui.end_row();

            ui.label("Stream mode");
            ui.checkbox(&mut spec.chunk_upload.stream_mode, "");
            ui.end_row();

            ui.label("Low disk threshold (MB)");
            ui.add(
                egui::DragValue::new(&mut spec.chunk_upload.low_disk_threshold_mb)
                    .range(0..=102_400)
                    .suffix(" MB"),
            );
            ui.end_row();
        });

    if !spec.chunk_upload.enabled {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Disabled = one big encrypted container. Enable for endpoints likely to exceed disk headroom (DeepDive presets).",
            )
            .small()
            .color(theme::MUTED),
        );
    }
}
