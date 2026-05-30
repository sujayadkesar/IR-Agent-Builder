use eframe::egui;
use std::collections::HashSet;

use crate::app::App;
use crate::backend::artifact_catalog::{Catalog, CategoryGroup};
use crate::spec::{BuildSpec, TargetPlatform};
use super::theme;
use super::widgets::step_header;

pub fn view(ui: &mut egui::Ui, app: &mut App) {
    step_header(ui, 2, "Artifacts", "Pick what to collect from each endpoint");

    let platform_str = match app.spec.target_platform {
        TargetPlatform::Windows => "windows",
        TargetPlatform::Linux => "linux",
    };

    let Ok(ref catalog) = app.catalog else {
        ui.colored_label(theme::DANGER, "Artifact catalog could not be loaded — see Step 6 for the error message.");
        return;
    };
    let catalog = catalog.clone();
    let groups = catalog.for_platform(platform_str);

    // ----- Bundles row -----
    ui.label(egui::RichText::new("BUNDLES").small().monospace().color(theme::ACCENT));
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        for b in catalog.bundles_for_platform(platform_str) {
            let label = format!("{}  ·  {}", b.name, b.estimate_label);
            if ui.button(label).clicked() {
                app.spec.artifacts = b.artifacts.clone();
                app.spec.kape_targets = b.kape_targets.clone();
            }
        }
    });

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(12.0);

    // ----- Live totals + global Select all / Select none -----
    let (total_size_mb, total_time_sec) = compute_totals(&catalog, &app.spec.artifacts);
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Selected:").small().color(theme::MUTED));
        ui.label(
            egui::RichText::new(format!("{} artifacts", app.spec.artifacts.len()))
                .monospace()
                .color(theme::ACCENT),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("~{} MB", total_size_mb))
                .monospace()
                .color(theme::ACCENT),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("~{}", format_time(total_time_sec)))
                .monospace()
                .color(theme::ACCENT),
        );

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if small_button(ui, "Select none").clicked() {
                let all_ids: Vec<String> = groups
                    .iter()
                    .flat_map(|g| g.items.iter().map(|i| i.id.clone()))
                    .collect();
                deselect_ids(&mut app.spec, &all_ids);
            }
            ui.add_space(4.0);
            if small_button(ui, "Select all").clicked() {
                let all_ids: Vec<String> = groups
                    .iter()
                    .flat_map(|g| g.items.iter().map(|i| i.id.clone()))
                    .collect();
                select_ids(&mut app.spec, &all_ids);
            }
        });
    });
    ui.add_space(12.0);

    // ----- Categories with per-category All/None and collapsible body -----
    for group in &groups {
        category_section(ui, group, &mut app.spec, platform_str);
        ui.add_space(4.0);
    }

    ui.add_space(12.0);

    // ----- KAPE targets summary (Windows only) -----
    if matches!(app.spec.target_platform, TargetPlatform::Windows) {
        ui.label(
            egui::RichText::new("KAPE TARGETS (file-pattern only, layered on top)")
                .small()
                .monospace()
                .color(theme::ACCENT),
        );
        ui.add_space(4.0);
        if app.spec.kape_targets.is_empty() {
            ui.label(egui::RichText::new("none selected").small().color(theme::MUTED));
        } else {
            ui.label(
                egui::RichText::new(app.spec.kape_targets.join(", "))
                    .monospace()
                    .color(theme::ACCENT),
            );
        }
    }
}

/// One category with a custom collapsible header that has All / None buttons
/// on the right side of the section title.
fn category_section(ui: &mut egui::Ui, group: &CategoryGroup, spec: &mut BuildSpec, platform_str: &str) {
    let id = ui.make_persistent_id((platform_str, &group.category));

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
        .show_header(ui, |ui| {
            // How many items in this category are currently selected.
            let category_ids: Vec<&str> =
                group.items.iter().map(|i| i.id.as_str()).collect();
            let selected_count = category_ids
                .iter()
                .filter(|id| spec.artifacts.iter().any(|s| s == *id))
                .count();
            let total = category_ids.len();

            ui.label(
                egui::RichText::new(&group.category)
                    .strong()
                    .color(theme::ACCENT),
            );
            ui.label(
                egui::RichText::new(format!("({selected_count}/{total})"))
                    .small()
                    .color(theme::MUTED),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if small_button(ui, "None").clicked() {
                    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
                    deselect_ids(spec, &ids);
                }
                ui.add_space(4.0);
                if small_button(ui, "All").clicked() {
                    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
                    select_ids(spec, &ids);
                }
            });
        })
        .body(|ui| {
            egui::Grid::new(format!("grid_{}_{}", platform_str, group.category))
                .num_columns(3)
                .striped(true)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for item in &group.items {
                        let mut selected = spec.artifacts.iter().any(|x| x == &item.id);
                        let was_selected = selected;
                        if ui.checkbox(&mut selected, &item.display).changed() {
                            if selected && !was_selected {
                                spec.artifacts.push(item.id.clone());
                            } else if !selected && was_selected {
                                spec.artifacts.retain(|x| x != &item.id);
                            }
                        }
                        ui.label(
                            egui::RichText::new(format!("{} MB · {}s", item.size_mb, item.time_sec))
                                .small()
                                .monospace()
                                .color(theme::MUTED),
                        );
                        ui.label(
                            egui::RichText::new(&item.description)
                                .small()
                                .color(theme::MUTED),
                        );
                        ui.end_row();
                    }
                });
        });
}

/// Small text button used for All / None / Select all / Select none.
fn small_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(label).size(11.5).color(theme::TEXT),
    )
    .fill(theme::BG_PANEL)
    .stroke(egui::Stroke::new(1.0, theme::BORDER))
    .rounding(egui::Rounding::same(4.0))
    .min_size(egui::vec2(56.0, 22.0));
    ui.add(btn)
}

fn select_ids(spec: &mut BuildSpec, ids: &[String]) {
    let existing: HashSet<&str> = spec.artifacts.iter().map(|s| s.as_str()).collect();
    let to_add: Vec<String> = ids
        .iter()
        .filter(|id| !existing.contains(id.as_str()))
        .cloned()
        .collect();
    spec.artifacts.extend(to_add);
}

fn deselect_ids(spec: &mut BuildSpec, ids: &[String]) {
    let drop: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
    spec.artifacts.retain(|x| !drop.contains(x.as_str()));
}

fn compute_totals(catalog: &Catalog, selected: &[String]) -> (u64, u64) {
    let mut size = 0u64;
    let mut time = 0u64;
    for id in selected {
        if let Some(a) = catalog.get(id) {
            size += a.size_mb;
            time += a.time_sec;
        }
    }
    (size, time)
}

fn format_time(secs: u64) -> String {
    if secs >= 3600 {
        format!("{:.1} hr", secs as f64 / 3600.0)
    } else if secs >= 60 {
        format!("{} min", secs / 60)
    } else {
        format!("{} sec", secs)
    }
}
