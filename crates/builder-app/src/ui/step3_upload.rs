use eframe::egui;

use crate::app::{App, S3ValidateOutcome};
use crate::backend::aws;
use crate::spec::UploadKind;
use super::theme;
use super::widgets::{caption, form_card, step_header};

const FIELD_W: f32 = 480.0;

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    step_header(ui, 3, "Upload", "Where each endpoint ships its encrypted evidence");

    ui.set_max_width(theme::CONTENT_MAX_WIDTH);

    form_card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label("Destination");
            ui.add_space(8.0);
            ui.selectable_value(&mut app.spec.upload.kind, UploadKind::Local, "Local / UNC");
            ui.selectable_value(&mut app.spec.upload.kind, UploadKind::S3, "AWS S3");
        });
        ui.add_space(14.0);

        match app.spec.upload.kind {
            UploadKind::Local => local_form(ui, app),
            UploadKind::S3 => s3_form(ui, app),
        }
    });

    if matches!(app.spec.upload.kind, UploadKind::S3) {
        ui.add_space(16.0);
        iam_card(ui, app);
    }
}

fn local_form(ui: &mut egui::Ui, app: &mut App) {
    egui::Grid::new("step3_local")
        .num_columns(2)
        .spacing([28.0, 14.0])
        .min_col_width(150.0)
        .show(ui, |ui| {
            ui.label("Output path");
            ui.add(
                egui::TextEdit::singleline(&mut app.spec.upload.local_path)
                    .desired_width(FIELD_W)
                    .hint_text("e.g. %USERPROFILE%\\IR-Output  or  \\\\fileserver\\IR\\Output"),
            );
            ui.end_row();
        });
    ui.add_space(10.0);
    ui.label(
        egui::RichText::new(
            "Required — where each endpoint writes its container. No default is assumed. \
             Environment variables resolve on the target host (e.g. %USERPROFILE%, %TEMP%, \
             %PROGRAMDATA%), so one build works across machines with different usernames. \
             Use a UNC path (\\\\fileserver\\IR\\Output) for fleet-wide central collection.",
        )
        .small()
        .color(theme::MUTED),
    );
}

fn s3_form(ui: &mut egui::Ui, app: &mut App) {
    egui::Grid::new("step3_s3")
        .num_columns(2)
        .spacing([28.0, 12.0])
        .min_col_width(150.0)
        .show(ui, |ui| {
            ui.label("Bucket");
            ui.add(egui::TextEdit::singleline(&mut app.spec.upload.bucket).desired_width(FIELD_W));
            ui.end_row();

            ui.label("Region");
            ui.add(egui::TextEdit::singleline(&mut app.spec.upload.region).desired_width(FIELD_W));
            ui.end_row();

            ui.label("Access key ID");
            ui.add(egui::TextEdit::singleline(&mut app.spec.upload.access_key_id).desired_width(FIELD_W));
            ui.end_row();

            ui.label("Secret access key");
            ui.add(
                egui::TextEdit::singleline(&mut app.spec.upload.secret_access_key)
                    .password(true)
                    .desired_width(FIELD_W),
            );
            ui.end_row();

            ui.label("KMS key ARN (optional)");
            ui.add(egui::TextEdit::singleline(&mut app.spec.upload.sse_kms_key_id).desired_width(FIELD_W));
            ui.end_row();

            ui.label("Endpoint (optional)");
            ui.add(egui::TextEdit::singleline(&mut app.spec.upload.endpoint).desired_width(FIELD_W));
            ui.end_row();

            ui.label("Prefix template");
            ui.add(egui::TextEdit::singleline(&mut app.spec.upload.prefix_template).desired_width(FIELD_W));
            ui.end_row();

            ui.label("Verify TLS");
            ui.checkbox(&mut app.spec.upload.verify_tls, "");
            ui.end_row();
        });

    ui.add_space(16.0);

    // ----- Validate button + result -----
    ui.horizontal(|ui| {
        let busy = app.s3_validate_job.is_some();
        let can_validate = !busy
            && !app.spec.upload.bucket.is_empty()
            && !app.spec.upload.region.is_empty()
            && !app.spec.upload.access_key_id.is_empty()
            && !app.spec.upload.secret_access_key.is_empty();

        let label = if busy {
            format!("{}  Validating…", egui_phosphor::regular::SPINNER)
        } else {
            format!("{}  Validate S3 connection", egui_phosphor::regular::PLUGS_CONNECTED)
        };
        let btn = egui::Button::new(egui::RichText::new(label).color(theme::TEXT))
            .fill(theme::BG_INPUT)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .rounding(egui::Rounding::same(6.0));
        if ui.add_enabled(can_validate, btn).clicked() {
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

    if let Some(job) = app.s3_validate_job.as_ref() {
        let elapsed = job.started_at.elapsed().as_secs();
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(format!("…sending sentinel PutObject ({elapsed}s)"))
                .small()
                .color(theme::MUTED),
        );
        ui.ctx().request_repaint();
    } else if let Some(outcome) = app.s3_validate_last.as_ref() {
        ui.add_space(6.0);
        match outcome {
            S3ValidateOutcome::Ok(msg) => ui.colored_label(theme::SUCCESS, msg),
            S3ValidateOutcome::Err(msg) => ui.colored_label(theme::DANGER, msg),
        };
    }
}

fn iam_card(ui: &mut egui::Ui, app: &mut App) {
    form_card(ui, |ui| {
        caption(ui, "WRITE-ONLY IAM POLICY  ·  paste into the IAM console");
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
        let mut policy_display = policy_json.clone();
        egui::Frame::default()
            .fill(theme::BG_CODE)
            .stroke(egui::Stroke::new(1.0, theme::BORDER_SUBTLE))
            .rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut policy_display)
                        .desired_width(f32::INFINITY)
                        .desired_rows(14)
                        .font(egui::TextStyle::Monospace)
                        .frame(false)
                        .interactive(false),
                );
            });
    });
}
