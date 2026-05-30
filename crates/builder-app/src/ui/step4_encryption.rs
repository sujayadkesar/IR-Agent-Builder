use eframe::egui;

use crate::app::App;
use crate::spec::EncryptionScheme;
use super::theme;
use super::widgets::step_header;

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    step_header(ui, 4, "Encryption", "Hybrid RSA-OAEP-SHA256 + AES-256-GCM");

    ui.horizontal(|ui| {
        ui.label("Scheme");
        ui.selectable_value(&mut app.spec.encryption.scheme, EncryptionScheme::X509, "X509 (recommended)");
        ui.selectable_value(&mut app.spec.encryption.scheme, EncryptionScheme::None, "None (plaintext ZIP)");
    });

    if app.spec.encryption.scheme == EncryptionScheme::None {
        ui.add_space(12.0);
        ui.colored_label(
            theme::WARNING,
            "Containers will be plaintext ZIPs. Acceptable only when the upload destination is fully trusted (e.g. air-gapped UNC).",
        );
        return;
    }

    ui.add_space(20.0);

    let has_key = !app.spec.encryption.public_key_pem.is_empty();
    let busy = app.keypair_job.is_some();

    ui.horizontal(|ui| {
        let label = if busy {
            "Generating…"
        } else if has_key {
            "Regenerate RSA-4096 keypair"
        } else {
            "Generate RSA-4096 keypair"
        };
        if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
            let ctx = ui.ctx().clone();
            app.start_keypair_generation(4096, ctx);
        }
        if has_key {
            ui.label(
                egui::RichText::new(format!("fingerprint = {}", short_fp(&app.spec.encryption.fingerprint_sha256)))
                    .monospace()
                    .small()
                    .color(theme::MUTED),
            );
        }
    });

    if let Some(job) = app.keypair_job.as_ref() {
        let elapsed = job.started_at.elapsed().as_secs();
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(format!("…RSA-{} keygen ({elapsed}s)", job.bits))
                .small()
                .color(theme::MUTED),
        );
    }

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(12.0);

    ui.label(
        egui::RichText::new("PUBLIC KEY (embedded into the collector at build time)")
            .small()
            .monospace()
            .color(theme::ACCENT),
    );
    ui.add(
        egui::TextEdit::multiline(&mut app.spec.encryption.public_key_pem)
            .desired_width(f32::INFINITY)
            .desired_rows(8)
            .font(egui::TextStyle::Monospace)
            .hint_text("-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----"),
    );

    if has_key && !app.spec.encryption.private_key_pem.is_empty() {
        ui.add_space(16.0);
        ui.colored_label(
            theme::DANGER,
            "PRIVATE KEY — copy this to your password manager / KMS NOW. It will NOT be persisted. Losing it means every collection from this build is unrecoverable.",
        );
        ui.add(
            egui::TextEdit::multiline(&mut app.spec.encryption.private_key_pem)
                .desired_width(f32::INFINITY)
                .desired_rows(10)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("I have saved the private key — clear from memory").clicked() {
            app.spec.encryption.private_key_pem.clear();
        }
    } else if has_key {
        ui.add_space(8.0);
        ui.colored_label(theme::SUCCESS, "Private key was discarded from memory. Make sure you saved it.");
    }
}

fn short_fp(fp: &str) -> String {
    if fp.len() >= 16 {
        format!("{}…{}", &fp[..8], &fp[fp.len() - 8..])
    } else {
        fp.to_string()
    }
}
