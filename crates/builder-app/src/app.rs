//! Main app state — owned by eframe, mutated every frame.

use eframe::egui;
use std::path::PathBuf;

use crate::backend::artifact_catalog::Catalog;
use crate::backend::build::{BuildEvent, BuildHandle};
use crate::backend::keypair::Keypair;
use crate::spec::BuildSpec;
use crate::ui;

const DEV_STATE_FILE: &str = ".dev-state.json";

pub struct App {
    pub current_step: u8,
    pub spec: BuildSpec,

    /// Resolved at startup from `<workspace>/artifacts/`. None until the
    /// catalog load is attempted; an Err is rendered if it failed.
    pub catalog: Result<Catalog, String>,

    /// In-flight build, if any. Polled each frame for log lines.
    pub build: Option<LiveBuild>,

    /// In-flight keypair generation, if any.
    pub keypair_job: Option<KeypairJob>,

    /// In-flight S3 validation, if any.
    pub s3_validate_job: Option<S3ValidateJob>,

    /// Last completed S3 validation result. Survives navigation away from
    /// Step 3 and back; cleared when the user kicks off a new validation.
    pub s3_validate_last: Option<S3ValidateOutcome>,

    /// Workspace root (where Cargo.toml lives).
    pub workspace_root: PathBuf,

    last_persisted_hash: u64,
}

#[derive(Debug, Clone)]
pub enum S3ValidateOutcome {
    Ok(String),
    Err(String),
}

pub struct LiveBuild {
    pub handle: BuildHandle,
    pub logs: Vec<String>,
    pub status: BuildStatus,
    pub result_path: Option<PathBuf>,
    pub result_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildStatus {
    Running,
    Complete,
    Failed(String),
}

pub struct KeypairJob {
    pub rx: std::sync::mpsc::Receiver<Result<Keypair, String>>,
    pub started_at: std::time::Instant,
    pub bits: usize,
}

pub struct S3ValidateJob {
    pub rx: std::sync::mpsc::Receiver<Result<crate::backend::aws::ValidateResult, String>>,
    pub started_at: std::time::Instant,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        ui::theme::apply(&cc.egui_ctx);

        let workspace_root = detect_workspace_root();
        let artifacts_dir = workspace_root.join("artifacts");
        let catalog = Catalog::load(&artifacts_dir).map_err(|e| {
            format!("could not load artifacts/ from {}: {e}", artifacts_dir.display())
        });
        if let Err(ref msg) = catalog {
            log::error!("{msg}");
        }

        let spec = std::fs::read_to_string(DEV_STATE_FILE)
            .ok()
            .and_then(|s| serde_json::from_str::<BuildSpec>(&s).ok())
            .unwrap_or_default();

        let last_persisted_hash = hash_spec(&spec);

        Self {
            current_step: 1,
            spec,
            catalog,
            build: None,
            keypair_job: None,
            s3_validate_job: None,
            s3_validate_last: None,
            workspace_root,
            last_persisted_hash,
        }
    }

    fn persist_if_dirty(&mut self) {
        let h = hash_spec(&self.spec);
        if h == self.last_persisted_hash {
            return;
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.spec) {
            if std::fs::write(DEV_STATE_FILE, json).is_ok() {
                self.last_persisted_hash = h;
            }
        }
    }

    fn drain_build_events(&mut self) {
        let Some(live) = self.build.as_mut() else { return; };
        loop {
            match live.handle.rx.try_recv() {
                Ok(BuildEvent::Log(line)) => live.logs.push(line),
                Ok(BuildEvent::Complete { exe_path, sha256, size_bytes, .. }) => {
                    live.status = BuildStatus::Complete;
                    live.result_path = Some(exe_path);
                    live.result_sha256 = Some(sha256);
                    live.logs.push(format!(
                        "[builder] binary ready ({:.2} MB)",
                        size_bytes as f64 / 1024.0 / 1024.0
                    ));
                }
                Ok(BuildEvent::Failed { message, .. }) => {
                    live.status = BuildStatus::Failed(message.clone());
                    live.logs.push(format!("[builder] FAILED: {message}"));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
    }

    fn drain_s3_validate_job(&mut self) {
        let Some(job) = self.s3_validate_job.as_ref() else { return; };
        match job.rx.try_recv() {
            Ok(Ok(result)) => {
                let outcome = if result.ok {
                    S3ValidateOutcome::Ok(format!(
                        "[OK] {} (test key: {})",
                        result.message, result.test_key
                    ))
                } else {
                    S3ValidateOutcome::Err(format!("[FAIL] {}", result.message))
                };
                self.s3_validate_last = Some(outcome);
                self.s3_validate_job = None;
            }
            Ok(Err(e)) => {
                self.s3_validate_last = Some(S3ValidateOutcome::Err(format!(
                    "validation error: {e}"
                )));
                self.s3_validate_job = None;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.s3_validate_job = None;
            }
        }
    }

    fn drain_keypair_job(&mut self) {
        let Some(job) = self.keypair_job.as_ref() else { return; };
        match job.rx.try_recv() {
            Ok(Ok(kp)) => {
                self.spec.encryption.public_key_pem = kp.public_pem;
                self.spec.encryption.private_key_pem = kp.private_pem;
                self.spec.encryption.fingerprint_sha256 = kp.fingerprint_sha256;
                self.keypair_job = None;
            }
            Ok(Err(e)) => {
                log::error!("keypair generation failed: {e}");
                self.keypair_job = None;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.keypair_job = None;
            }
        }
    }

    pub fn start_keypair_generation(&mut self, bits: usize, ctx: egui::Context) {
        let (tx, rx) = std::sync::mpsc::channel();
        let started_at = std::time::Instant::now();
        std::thread::spawn(move || {
            let result = crate::backend::keypair::generate(bits)
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.keypair_job = Some(KeypairJob { rx, started_at, bits });
    }

    pub fn start_s3_validate(
        &mut self,
        bucket: String,
        region: String,
        access_key_id: String,
        secret_access_key: String,
        endpoint: Option<String>,
        sse_kms_key_id: Option<String>,
        ctx: egui::Context,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let started_at = std::time::Instant::now();
        // Clear the previous outcome so the UI doesn't keep showing a stale result.
        self.s3_validate_last = None;
        std::thread::spawn(move || {
            let result = crate::backend::aws::validate_s3(crate::backend::aws::ValidateInput {
                bucket: &bucket,
                region: &region,
                access_key_id: &access_key_id,
                secret_access_key: &secret_access_key,
                endpoint: endpoint.as_deref(),
                sse_kms_key_id: sse_kms_key_id.as_deref(),
            })
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        self.s3_validate_job = Some(S3ValidateJob { rx, started_at });
    }

    pub fn start_build(&mut self, ctx: egui::Context) -> Result<(), String> {
        let catalog = self.catalog.as_ref().map_err(|e| e.clone())?;
        let ledger_path = self.workspace_root.join("builds").join("ledger.sqlite");
        let handle = crate::backend::build::spawn(
            self.workspace_root.clone(),
            &self.spec,
            catalog,
            ledger_path,
            ctx,
        )
        .map_err(|e| format!("{e:#}"))?;
        self.build = Some(LiveBuild {
            handle,
            logs: Vec::new(),
            status: BuildStatus::Running,
            result_path: None,
            result_sha256: None,
        });
        Ok(())
    }
}

fn detect_workspace_root() -> PathBuf {
    // The binary is at <root>/target/debug/builder-app.exe or
    // <root>/target/release/builder-app.exe. Walk up from the executable
    // until we find a Cargo.toml that has a [workspace] section.
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        while let Some(p) = cur {
            if p.join("Cargo.toml").exists() && p.join("artifacts").exists() {
                return p;
            }
            cur = p.parent().map(|p| p.to_path_buf());
        }
    }
    // Fallback to current working directory.
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn hash_spec(spec: &BuildSpec) -> u64 {
    use std::hash::Hasher;
    let json = serde_json::to_string(spec).unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write(json.as_bytes());
    h.finish()
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_build_events();
        self.drain_keypair_job();
        self.drain_s3_validate_job();

        // Header (top), then footer (bottom), then sidebar (left), then central.
        // egui requires outer panels to be declared before inner ones.
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::default().fill(ui::theme::BG_PANEL).inner_margin(egui::Margin::ZERO))
            .show(ctx, |ui| {
                ui::header::view(ui);
            });

        egui::TopBottomPanel::bottom("footer")
            .frame(egui::Frame::default().fill(ui::theme::BG_PANEL).inner_margin(egui::Margin::ZERO))
            .show(ctx, |ui| {
                ui::footer::view(ui, self);
            });

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .default_width(280.0)
            .width_range(280.0..=280.0)
            .frame(egui::Frame::default().fill(ui::theme::BG_PANEL).inner_margin(egui::Margin::same(16.0)))
            .show(ctx, |ui| {
                ui::sidebar::view(ui, self);
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(ui::theme::BG_BASE).inner_margin(egui::Margin::same(24.0)))
            .show(ctx, |ui| {
                if let Err(ref msg) = self.catalog {
                    ui.colored_label(ui::theme::DANGER, msg);
                    ui.add_space(8.0);
                }
                let step = self.current_step;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    match step {
                        1 => ui::step1_target::view(ui, &mut self.spec),
                        2 => ui::step2_artifacts::view(ui, self),
                        3 => ui::step3_upload::view(ui, self),
                        4 => ui::step4_encryption::view(ui, self),
                        5 => ui::step5_performance::view(ui, &mut self.spec),
                        6 => ui::step6_review::view(ui, self),
                        _ => { ui.label("invalid step"); }
                    }
                });
            });

        self.persist_if_dirty();
    }
}
