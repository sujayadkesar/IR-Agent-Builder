//! Visual theme — sampled from the Gemini-generated mockup.
//!
//! Dark technical aesthetic with a blue primary accent. The palette is
//! intentionally limited: 3 grays (background, panel, raised), 1 border,
//! 1 accent (blue), 1 success (green), and a few state colors. Anything
//! else is muted gray.

use eframe::egui;

// ---------- Color palette ----------
pub const BG_BASE:        egui::Color32 = egui::Color32::from_rgb(0x0E, 0x12, 0x19); // app background
pub const BG_PANEL:       egui::Color32 = egui::Color32::from_rgb(0x16, 0x1C, 0x26); // sidebar / footer
pub const BG_CARD:        egui::Color32 = egui::Color32::from_rgb(0x1B, 0x20, 0x2B); // raised cards
pub const BG_CODE:        egui::Color32 = egui::Color32::from_rgb(0x0A, 0x0D, 0x14); // log pane / code
pub const BG_INPUT:       egui::Color32 = egui::Color32::from_rgb(0x14, 0x18, 0x21);

pub const BORDER:         egui::Color32 = egui::Color32::from_rgb(0x26, 0x2C, 0x38);
pub const BORDER_SUBTLE:  egui::Color32 = egui::Color32::from_rgb(0x1F, 0x25, 0x30);

pub const ACCENT:         egui::Color32 = egui::Color32::from_rgb(0x3B, 0x82, 0xF6); // primary blue
#[allow(dead_code)] // available for use in future widget states
pub const ACCENT_HOVER:   egui::Color32 = egui::Color32::from_rgb(0x60, 0x9C, 0xFA);
pub const ACCENT_BG:      egui::Color32 = egui::Color32::from_rgba_premultiplied(0x3B, 0x82, 0xF6, 0x22);

pub const SUCCESS:        egui::Color32 = egui::Color32::from_rgb(0x22, 0xC5, 0x5E);
pub const WARNING:        egui::Color32 = egui::Color32::from_rgb(0xF5, 0xB4, 0x3A);
pub const DANGER:         egui::Color32 = egui::Color32::from_rgb(0xEF, 0x44, 0x44);

pub const TEXT:           egui::Color32 = egui::Color32::from_rgb(0xE5, 0xE9, 0xF0);
pub const MUTED:          egui::Color32 = egui::Color32::from_rgb(0x8B, 0x95, 0xA8);
pub const MUTED_DIM:      egui::Color32 = egui::Color32::from_rgb(0x5A, 0x63, 0x72);

pub fn apply(ctx: &egui::Context) {
    // Register the Phosphor icon font (Private-Use-Area glyphs) as a fallback
    // on both the proportional and monospace families, so icon constants like
    // `egui_phosphor::regular::CHECK` render anywhere.
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = BG_BASE;
    visuals.window_fill = BG_CARD;
    visuals.extreme_bg_color = BG_CODE;
    visuals.faint_bg_color = BG_PANEL;
    visuals.code_bg_color = BG_CODE;

    visuals.override_text_color = Some(TEXT);

    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.noninteractive.bg_fill = BG_PANEL;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);

    visuals.widgets.inactive.bg_fill = BG_INPUT;
    visuals.widgets.inactive.weak_bg_fill = BG_INPUT;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);

    visuals.widgets.hovered.bg_fill = ACCENT_BG;
    visuals.widgets.hovered.weak_bg_fill = ACCENT_BG;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);

    visuals.widgets.active.bg_fill = ACCENT;
    visuals.widgets.active.weak_bg_fill = ACCENT;
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    visuals.selection.bg_fill = ACCENT_BG;
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);

    visuals.hyperlink_color = ACCENT;

    // Subtle rounding on widgets (egui 0.29 uses `Rounding`, not `CornerRadius`).
    let r = egui::Rounding::same(4.0);
    visuals.widgets.noninteractive.rounding = r;
    visuals.widgets.inactive.rounding = r;
    visuals.widgets.hovered.rounding = r;
    visuals.widgets.active.rounding = r;
    visuals.widgets.open.rounding = r;

    ctx.set_visuals(visuals);

    // Type scale — slightly larger than egui's dense defaults for readability
    // on hi-DPI displays, with a clear hierarchy.
    let mut style = (*ctx.style()).clone();
    use egui::{FontFamily, FontId, TextStyle};
    style.text_styles.insert(TextStyle::Small,     FontId::new(11.5, FontFamily::Proportional));
    style.text_styles.insert(TextStyle::Body,      FontId::new(14.0, FontFamily::Proportional));
    style.text_styles.insert(TextStyle::Button,    FontId::new(14.0, FontFamily::Proportional));
    style.text_styles.insert(TextStyle::Heading,   FontId::new(20.0, FontFamily::Proportional));
    style.text_styles.insert(TextStyle::Monospace, FontId::new(12.5, FontFamily::Monospace));

    // Global spacing — roomier item gaps and a comfortable button padding so
    // controls don't feel cramped.
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 26.0;
    style.visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);

    ctx.set_style(style);
}

/// Max readable width for single-column form content. Keeps forms from
/// stretching edge-to-edge on wide windows (the "floating labels in a void"
/// look). Step 2 (dense list) and Step 6 (two-column) opt out.
pub const CONTENT_MAX_WIDTH: f32 = 860.0;

// ---------- Frame helpers ----------

/// Card with a rounded border and panel fill. Used for major content blocks.
pub fn card_frame() -> egui::Frame {
    egui::Frame::default()
        .fill(BG_CARD)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(16.0))
}

/// Tighter card used for inline summary panels (sidebar, right-rail).
pub fn panel_frame() -> egui::Frame {
    egui::Frame::default()
        .fill(BG_PANEL)
        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::same(12.0))
}
