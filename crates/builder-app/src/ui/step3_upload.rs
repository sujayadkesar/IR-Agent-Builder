use eframe::egui;

use crate::app::{App, S3ValidateOutcome};
use crate::backend::aws;
use crate::spec::UploadKind;
use super::theme;
use super::widgets::step_header;

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    step_header(ui, 3, "Upload", "S3 destination + IAM policy generator");

    ui.horizontal(|ui| {
        ui.label("Destination");
        ui.selectable_value(&mut app.spec.upload.kind, UploadKind::Local, "Local / UNC");
        ui.selectable_value(&mut app.spec.upload.kind, UploadKind::S3, "AWS S3");
    });
    ui.add_space(16.0);

    match app.spec.upload.kind {
        UploadKind::Local => local_form(ui, app),
        UploadKind::S3 => s3_form(ui, app),
    }
}

fn local_form(ui: &mut egui::Ui, app: &mut App) {
    egui::Grid::new("step3_local")
        .num_columns(2)
        .spacing([24.0, 12.0])
        .show(ui, |ui| {
            ui.label("Output path");
            ui.text_edit_singleline(&mut app.spec.upload.local_path);
            ui.end_row();
        });
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(
            "Endpoints will drop encrypted containers to this path. Use a UNC path (\\\\fileserver\\IR\\Output) for fleet-wide collection.",
        )
        .small()
        .color(theme::MUTED),
    );
}

fn s3_form(ui: &mut egui::Ui, app: &mut App) {
    egui::Grid::new("step3_s3")
        .num_columns(2)
        .spacing([24.0, 12.0])
        .show(ui, |ui| {
            ui.label("Bucket");
            ui.text_edit_singleline(&mut app.spec.upload.bucket);
            ui.end_row();

            ui.label("Region");
            ui.text_edit_singleline(&mut app.spec.upload.region);
            ui.end_row();

            ui.label("Access key ID");
            ui.text_edit_singleline(&mut app.spec.upload.access_key_id);
            ui.end_row();

            ui.label("Secret access key");
            let resp = egui::TextEdit::singleline(&mut app.spec.upload.secret_access_key)
                .password(true)
                .desired_width(f32::INFINITY);
            ui.add(resp);
            ui.end_row();

            ui.label("KMS key ARN (optional)");
            ui.text_edit_singleline(&mut app.spec.upload.sse_kms_key_id);
            ui.end_row();

            ui.label("Endpoint (optional)");
            ui.text_edit_singleline(&mut app.spec.upload.endpoint);
            ui.end_row();

            ui.label("Prefix template");
            ui.text_edit_singleline(&mut app.spec.upload.prefix_template);
            ui.end_row();

            ui.label("Verify TLS");
            ui.checkbox(&mut app.spec.upload.verify_tls, "");
            ui.end_row();
        });

    ui.add_space(20.0);

    // ----- Validate button -----
    ui.horizontal(|ui| {
        let busy = app.s3_validate_job.is_some();
        let can_validate = !busy
            && !app.spec.upload.bucket.is_empty()
            && !app.spec.upload.region.is_empty()
            && !app.spec.upload.access_key_id.is_empty()
            && !app.spec.upload.secret_access_key.is_empty();

        let label = if busy { "Validating…" } else { "Validate S3 connection" };
        if ui.add_enabled(can_validate, egui::Button::new(label)).clicked() {
            let ctx = ui.ctx().clone();
            app.start_s3_validate(
                app.spec.upload.bucket.clone(),
                app.spec.upload.region.clone(),
                app.spec.upload.access_key_id.clone(),
                app.spec.upload.secret_access_key.clone(),
                if app.spec.upload.endpoint.is_empty() { None } else { Some(app.spec.upload.endpoint.clone()) },
                if app.spec.upload.sse_kms_key_id.is_empty() { None } else { Some(app.spec.upload.sse_kms_key_id.clone()) },
                ctx,
            );
        }
    });

    // In-flight progress (the actual try_recv happens centrally in App::update)
    if let Some(job) = app.s3_validate_job.as_ref() {
        let elapsed = job.started_at.elapsed().as_secs();
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(format!("…sending sentinel PutObject ({elapsed}s)"))
                .small()
                .color(theme::MUTED),
        );
    }
    // Last completed result — survives navigation away from this step.
    if app.s3_validate_job.is_none() {
        if let Some(outcome) = app.s3_validate_last.as_ref() {
            ui.add_space(4.0);
            match outcome {
                S3ValidateOutcome::Ok(msg)  => ui.colored_label(theme::SUCCESS, msg),
                S3ValidateOutcome::Err(msg) => ui.colored_label(theme::DANGER, msg),
            };
        }
    }

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(12.0);

    // ----- IAM policy preview -----
    ui.label(
        egui::RichText::new("WRITE-ONLY IAM POLICY (paste into IAM console)")
            .small()
            .monospace()
            .color(theme::ACCENT),
    );
    let policy = aws::generate_iam_policy(
        if app.spec.upload.bucket.is_empty() { "your-bucket" } else { &app.spec.upload.bucket },
        if app.spec.upload.sse_kms_key_id.is_empty() {
            None
        } else {
            Some(app.spec.upload.sse_kms_key_id.as_str())
        },
        None,
    );
    let policy_json = serde_json::to_string_pretty(&policy).unwrap_or_default();
    ui.add(
        egui::TextEdit::multiline(&mut policy_json.clone())
            .desired_width(f32::INFINITY)
            .desired_rows(14)
            .font(egui::TextStyle::Monospace),
    );
}
