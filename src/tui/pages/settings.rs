//! Settings overlay: palette, diagnostics, rank window.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::palette;

use crate::tui::layout::*;
use crate::tui::state::*;

/// Number of selectable rows in the settings overlay.
/// Palette choices in the order the settings overlay cycles through them.
pub(in crate::tui) const PALETTE_CHOICES: [palette::PaletteChoice; 4] = [
    palette::PaletteChoice::Auto,
    palette::PaletteChoice::Truecolor,
    palette::PaletteChoice::SixteenColor,
    palette::PaletteChoice::Monochrome,
];

pub(in crate::tui) const SETTINGS_SELECTABLE_ROWS: usize = 3;
/// Settings row index for the palette choice.
pub(in crate::tui) const PALETTE_ROW: usize = 0;
/// Settings row index for the diagnostics toggle.
pub(in crate::tui) const DIAGNOSTICS_ROW: usize = 1;
/// Settings row index for the ranking window.
pub(in crate::tui) const RANK_WINDOW_ROW: usize = 2;
/// User-visible label for a palette choice, as shown in the settings overlay.
pub(in crate::tui) fn palette_choice_label(choice: palette::PaletteChoice) -> &'static str {
    match choice {
        palette::PaletteChoice::Auto => "Auto",
        palette::PaletteChoice::Truecolor => "truecolor",
        palette::PaletteChoice::SixteenColor => "16-color",
        palette::PaletteChoice::Monochrome => "monochrome",
    }
}

/// User-visible label for a detected color tier.
pub(in crate::tui) fn color_tier_label(tier: palette::ColorTier) -> &'static str {
    match tier {
        palette::ColorTier::Truecolor => "truecolor",
        palette::ColorTier::Sixteen => "16-color",
        palette::ColorTier::Monochrome => "monochrome",
    }
}

/// Two-character selection marker column: `> ` for the selected row, two
/// spaces otherwise, so rows stay aligned even when the highlight style is not
/// visible (16-color/monochrome tiers).
pub(in crate::tui) fn settings_selection_prefix(selected: bool) -> &'static str {
    if selected { "> " } else { "  " }
}

/// Centered settings overlay: lets the user pick the active palette tier for
/// the session. Drawn on top of the current page when `state.settings_open`.
pub(in crate::tui) fn draw_settings(f: &mut ratatui::Frame, area: Rect, state: &AppState) {
    let popup = centered_rect(area, 70, 11);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette::accent()))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "Settings",
                Style::default()
                    .fg(palette::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]));
    let detected_label = color_tier_label(state.detected_tier);
    let choice_label = palette_choice_label(state.palette_choice);
    let diagnostics_label = if state.diagnostics_draft { "ON" } else { "OFF" };
    let rank_window_label = ranking_window_label(state.rank_window_draft);
    let selection_style = palette::selection_style();
    let palette_selected = state.settings_selection == PALETTE_ROW;
    let mut palette_line = Line::from(vec![
        Span::raw(settings_selection_prefix(palette_selected)),
        Span::styled(
            "Palette: ",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            choice_label.to_string(),
            Style::default().fg(palette::accent()),
        ),
        Span::styled(
            format!("  (detected: {detected_label})"),
            Style::default().fg(palette::muted()),
        ),
    ]);
    let mut diagnostics_line = Line::from(vec![
        Span::raw(settings_selection_prefix(
            state.settings_selection == DIAGNOSTICS_ROW,
        )),
        Span::styled(
            "Diagnostics: ",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(diagnostics_label, Style::default().fg(palette::accent())),
    ]);
    let mut rank_window_line = Line::from(vec![
        Span::raw(settings_selection_prefix(
            state.settings_selection == RANK_WINDOW_ROW,
        )),
        Span::styled(
            "Rank window: ",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(rank_window_label, Style::default().fg(palette::accent())),
    ]);
    if palette_selected {
        palette_line.style = selection_style;
    } else if state.settings_selection == DIAGNOSTICS_ROW {
        diagnostics_line.style = selection_style;
    } else {
        rank_window_line.style = selection_style;
    }
    // File display follows the (actual, draft) matrix: the live file name is
    // shown while diagnostics are actually on (flagged when the draft would
    // stop them on close); a pending path is shown while actually off but
    // drafted on; otherwise "(none)".
    let file_text = match (state.diagnostics_enabled, state.diagnostics_draft) {
        (true, true) => state
            .diagnostics_file
            .as_deref()
            .unwrap_or("(none)")
            .to_string(),
        (true, false) => format!(
            "{} (stops on close)",
            state.diagnostics_file.as_deref().unwrap_or("(none)")
        ),
        (false, true) => {
            let name = state
                .diagnostics_pending_path
                .as_ref()
                .and_then(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "(none)".to_string());
            format!("{name} (pending)")
        }
        (false, false) => "(none)".to_string(),
    };
    let inner = block.inner(popup);
    // Budget for the label: "File: " prefix plus a small right margin, so a
    // long basename cannot overflow or misalign the overlay.
    let label_width = inner.width.saturating_sub(8) as usize;
    let file_label = truncate_with_ellipsis(&file_text, label_width.max(1));
    let lines = vec![
        Line::from(""),
        palette_line,
        diagnostics_line,
        rank_window_line,
        Line::from(vec![
            Span::styled(
                "File: ",
                Style::default()
                    .fg(palette::strong())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(file_label, Style::default().fg(palette::muted())),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "j/k select  h/l change  o or Esc close",
            Style::default().fg(palette::muted()),
        )),
    ];
    f.render_widget(Clear, popup);
    f.render_widget(
        Block::default().style(Style::default().bg(palette::bg())),
        popup,
    );
    f.render_widget(block, popup);
    f.render_widget(Paragraph::new(lines), inner);
}
