//! DFIR Agent Builder — desktop entry point.
//!
//! Opens a native window via eframe; the wizard runs entirely in-process.
//! No HTTP server, no localhost, no Node dependency.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod backend;
mod spec;
mod ui;

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 640.0])
            .with_title("DFIR Agent Builder"),
        ..Default::default()
    };

    eframe::run_native(
        "DFIR Agent Builder",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
