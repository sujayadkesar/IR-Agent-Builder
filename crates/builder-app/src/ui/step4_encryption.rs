use eframe::egui;

use crate::app::App;
use crate::spec::EncryptionScheme;
use super::theme;
use super::widgets::{caption, form_card, step_header};

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    step_header(ui, 4, "Encryption", "Hybrid RSA-OAEP-SHA256 key-wrap over AES-256-GCM");

    form_card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label("Scheme");
            ui.add_space(8.0);
            ui.selectable_value(&mut app.spec.encryption.scheme, EncryptionScheme::X509, "X509 (recommended)");
            ui.selectable_value(&mut app.spec.encryption.scheme, EncryptionScheme::None, "None (plaintext ZIP)");
        });

        if app.spec.encryption.scheme == EncryptionScheme::None {
            ui.add_space(14.0);
            ui.colored_label(
                theme::WARNING,
                "Containers will be plaintext ZIPs. Acceptable only when the upload destination is fully trusted (e.g. air-gapped UNC).",
            );
            return;
        }

        ui.add_space(18.0);

        let busy = app.keypair_job.is_some();
        let has_public_key = !app.spec.encryption.public_key_pem.is_empty();

        ui.horizontal(|ui| {
            let label = if busy {
                format!("{}  Generating…", egui_phosphor::regular::SPINNER)
            } else if has_public_key {
                format!("{}  Regenerate RSA-4096 keypair", egui_phosphor::regular::ARROWS_CLOCKWISE)
            } else {
                format!("{}  Generate RSA-4096 keypair", egui_phosphor::regular::KEY)
            };
            let btn = egui::Button::new(egui::RichText::new(label).color(egui::Color32::WHITE))
                .fill(if busy { theme::MUTED_DIM } else { theme::ACCENT })
                .stroke(egui::Stroke::NONE)
                .rounding(egui::Rounding::same(6.0));
            if ui.add_enabled(!busy, btn).clicked() {
                let ctx = ui.ctx().clone();
                app.start_keypair_generation(4096, ctx);
            }
            if has_public_key {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("fingerprint  {}", short_fp(&app.spec.encryption.fingerprint_sha256)))
                        .monospace()
                        .small()
                        .color(theme::MUTED),
                );
            }
        });

        if let Some(job) = app.keypair_job.as_ref() {
            let elapsed = job.started_at.elapsed().as_secs();
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!("RSA-{} keygen in progress ({elapsed}s)…", job.bits))
                    .small()
                    .color(theme::MUTED),
            );
            ui.ctx().request_repaint();
        }

        ui.add_space(18.0);
        caption(ui, "PUBLIC KEY  ·  embedded into the collector at build time");
        key_box(ui, &mut app.spec.encryption.public_key_pem, 8, true,
            "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----");

        if app.keypair_generated_this_session && !app.spec.encryption.private_key_pem.is_empty() {
            ui.add_space(16.0);
            ui.colored_label(
                theme::DANGER,
                format!(
                    "{}  PRIVATE KEY — copy to your password manager / KMS NOW. It is never persisted; losing it makes every collection from this build unrecoverable.",
                    egui_phosphor::regular::WARNING
                ),
            );
            ui.add_space(6.0);
            key_box(ui, &mut app.spec.encryption.private_key_pem, 9, false, "");
            ui.add_space(8.0);
            let clear = egui::Button::new(
                egui::RichText::new(format!("{}  I have saved the private key — clear from memory", egui_phosphor::regular::TRASH))
                    .color(theme::TEXT),
            )
            .fill(theme::BG_INPUT)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .rounding(egui::Rounding::same(6.0));
            if ui.add(clear).clicked() {
                app.spec.encryption.private_key_pem.clear();
                app.keypair_generated_this_session = false;
            }
        } else if app.keypair_generated_this_session {
            ui.add_space(10.0);
            ui.colored_label(
                theme::SUCCESS,
                format!("{}  Private key discarded from memory. Make sure you saved it.", egui_phosphor::regular::CHECK_CIRCLE),
            );
        }
    });
}

fn key_box(ui: &mut egui::Ui, text: &mut String, rows: usize, interactive: bool, hint: &str) {
    egui::Frame::default()
        .fill(theme::BG_CODE)
        .stroke(egui::Stroke::new(1.0, theme::BORDER_SUBTLE))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .desired_width(f32::INFINITY)
                    .desired_rows(rows)
                    .font(egui::TextStyle::Monospace)
                    .frame(false)
                    .interactive(interactive)
                    .hint_text(hint),
            );
        });
}

fn short_fp(fp: &str) -> String {
    if fp.len() >= 16 {
        format!("{}…{}", &fp[..8], &fp[fp.len() - 8..])
    } else {
        fp.to_string()
    }
}
