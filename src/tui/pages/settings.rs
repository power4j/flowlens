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
/// Settings row index for the ranking window.
pub(in crate::tui) const RANK_WINDOW_ROW: usize = 0;
/// Settings row index for the palette choice.
pub(in crate::tui) const PALETTE_ROW: usize = 1;
/// Settings row index for the diagnostics toggle.
pub(in crate::tui) const DIAGNOSTICS_ROW: usize = 2;
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
    if palette_selected {
        palette_line.style = selection_style;
    } else if state.settings_selection == DIAGNOSTICS_ROW {
        diagnostics_line.style = selection_style;
    } else if state.settings_selection == RANK_WINDOW_ROW {
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
    // Budget for the file hint: two-space indent, "File: " label, and a small
    // right margin, so a long basename cannot overflow or misalign the overlay.
    let label_width = inner.width.saturating_sub(10) as usize;
    let file_label = truncate_with_ellipsis(&file_text, label_width.max(1));
    // The file hint is an indented, muted sub-line of the Diagnostics row: it
    // never carries a selection marker and is never highlighted.
    let file_line = Line::from(vec![
        Span::raw("  "),
        Span::styled("File: ", Style::default().fg(palette::muted())),
        Span::styled(file_label, Style::default().fg(palette::muted())),
    ]);
    let lines = vec![
        Line::from(""),
        rank_window_line,
        palette_line,
        diagnostics_line,
        file_line,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn o_key_opens_and_closes_the_settings_overlay() {
        let mut state = AppState::new();
        assert!(!state.settings_open);

        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(state.settings_open);

        // 'o' toggles back off.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(!state.settings_open);

        // Open again, then Esc closes.
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.settings_open);
    }

    #[test]
    fn o_key_does_not_open_settings_over_modal_overlays() {
        let available_interfaces = interfaces();

        let mut state = AppState::startup(&available_interfaces);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Ignored
        );
        assert!(!state.settings_open);

        state.interface_selector.as_mut().unwrap().activating = Some("eth0".to_string());
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Ignored
        );
        assert!(!state.settings_open);

        let mut state = AppState::startup(&available_interfaces);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('i')),
            KeyOutcome::Changed
        );
        assert!(
            state
                .interface_selector
                .as_ref()
                .unwrap()
                .ip_popup
                .is_some()
        );
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Ignored
        );
        assert!(!state.settings_open);

        let mut state = AppState::new();
        assert_eq!(
            send_key(&mut state, KeyCode::Char('q')),
            KeyOutcome::Changed
        );
        assert!(state.quit_confirm);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Ignored
        );
        assert!(!state.settings_open);
    }

    #[test]
    fn o_key_on_undersized_terminal_does_not_leave_settings_open() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(59, 15)).unwrap();

        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        assert!(!state.settings_open);
        assert!(
            rendered_lines(&terminal)
                .join("\n")
                .contains("Terminal too small (minimum 60x16)")
        );
    }

    #[test]
    fn settings_overlay_renders_rows_and_hint() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.settings_open = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Settings"));
        assert!(rendered.contains("Rank window:"));
        assert!(rendered.contains("Palette:"));
        assert!(rendered.contains("j/k select  h/l change  o or Esc close"));
    }

    #[test]
    fn settings_overlay_lays_out_rank_first_then_file_under_diagnostics() {
        // Layout contract: Rank window is the first row, then Palette, then
        // Diagnostics, with the file hint directly beneath Diagnostics. The
        // file hint is a muted, non-selectable sub-line and must not carry a
        // selection marker.
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.settings_open = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let lines = rendered_lines(&terminal);
        let text = lines.join("\n");
        // Rank is the first rendered row line (across the popup interior).
        let first_line = lines
            .iter()
            .find(|line| {
                line.contains("Rank window:")
                    || line.contains("Palette:")
                    || line.contains("Diagnostics:")
            })
            .expect("a settings row exists");
        assert!(
            first_line.contains("Rank window:"),
            "Rank window must be the first row, got: {first_line:?}"
        );
        // The file hint sits on the line right after Diagnostics and carries
        // no selection marker.
        let diag_idx = lines
            .iter()
            .position(|line| line.contains("Diagnostics:"))
            .expect("Diagnostics row exists");
        assert!(
            lines[diag_idx + 1].contains("  File:"),
            "File hint must directly follow the Diagnostics row"
        );
        assert!(
            text.contains("  File: (none)"),
            "file hint is indented and never a selectable row"
        );
        assert!(
            !text.contains("> File:"),
            "the file hint must not carry the selection marker"
        );
    }

    #[test]
    fn settings_jk_moves_selection_and_clamps() {
        let mut state = AppState::new();
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert_eq!(state.settings_selection, 0);

        // Down/j moves to Palette then Diagnostics and clamps at the bottom.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('j')),
            KeyOutcome::Changed
        );
        assert_eq!(state.settings_selection, 1);
        assert_eq!(send_key(&mut state, KeyCode::Down), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 2);
        assert_eq!(send_key(&mut state, KeyCode::Down), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 2);

        // Up/k moves back through Palette to Rank window and clamps at the top.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('k')),
            KeyOutcome::Changed
        );
        assert_eq!(state.settings_selection, 1);
        assert_eq!(send_key(&mut state, KeyCode::Up), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 0);
        assert_eq!(send_key(&mut state, KeyCode::Up), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 0);
    }

    #[test]
    fn settings_hl_changes_the_selected_item_only() {
        let mut state = AppState::new();
        state.detected_tier = palette::ColorTier::Truecolor;
        state.palette_choice = palette::PaletteChoice::Auto;
        send_key(&mut state, KeyCode::Char('o'));

        // Rank window row selected by default: h/l cycle the rank window.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert_eq!(state.rank_window_draft, RankWindow::Cumulative.next());
        assert!(!state.diagnostics_draft);

        // Move down to Palette: h/l cycle the palette without touching
        // diagnostics or the rank draft.
        send_key(&mut state, KeyCode::Char('j'));
        assert_eq!(state.settings_selection, 1);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert_eq!(state.palette_choice, palette::PaletteChoice::Truecolor);

        // Select Diagnostics: h/l toggle only the draft; the actual state
        // (writer + shared flag) is committed when the overlay closes.
        send_key(&mut state, KeyCode::Char('j'));
        assert_eq!(state.settings_selection, 2);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert!(state.diagnostics_draft);
        assert!(!state.diagnostics_enabled);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert!(!state.diagnostics_draft);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('h')),
            KeyOutcome::Changed
        );
        assert!(state.diagnostics_draft);
        assert!(!state.diagnostics_enabled);
    }

    #[test]
    fn settings_enter_is_ignored() {
        let mut state = AppState::new();
        state.detected_tier = palette::ColorTier::Truecolor;
        state.palette_choice = palette::PaletteChoice::Auto;
        send_key(&mut state, KeyCode::Char('o'));

        // Enter has no action in the settings overlay: it neither closes the
        // overlay nor commits the diagnostics draft.
        assert_eq!(send_key(&mut state, KeyCode::Enter), KeyOutcome::Ignored);
        assert!(state.settings_open, "Enter must not close the overlay");
        assert_eq!(state.palette_choice, palette::PaletteChoice::Auto);
    }

    #[test]
    fn settings_overlay_renders_diagnostics_state_and_file() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.settings_open = true;
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = Some("flowlens-42.log".to_string());
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Diagnostics: ON"));
        assert!(rendered.contains("flowlens-42.log"));
    }

    #[test]
    fn settings_overlay_renders_pending_and_stop_on_close_file_markers() {
        let snapshot = TrafficSnapshot::default();
        let render = |state: &mut AppState| {
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| draw(frame, state, &snapshot, "eth0", "host", Instant::now()))
                .unwrap();
            rendered_lines(&terminal).join("\n")
        };

        // Actual OFF + draft ON: pending path marked (pending).
        let mut state = AppState::new();
        state.settings_open = true;
        state.diagnostics_draft = true;
        state.diagnostics_pending_path = Some(PathBuf::from("flowlens-pending-1.log"));
        let rendered = render(&mut state);
        assert!(rendered.contains("Diagnostics: ON"));
        assert!(rendered.contains("flowlens-pending-1.log (pending)"));

        // Actual ON + draft OFF: live file marked as stopping on close.
        let mut state = AppState::new();
        state.settings_open = true;
        state.diagnostics_enabled = true;
        state.diagnostics_draft = false;
        state.diagnostics_file = Some("flowlens-42.log".to_string());
        let rendered = render(&mut state);
        assert!(rendered.contains("Diagnostics: OFF"));
        assert!(rendered.contains("flowlens-42.log (stops on close)"));

        // Actual OFF + draft OFF: no file.
        let mut state = AppState::new();
        state.settings_open = true;
        let rendered = render(&mut state);
        assert!(rendered.contains("File: (none)"));
    }

    #[test]
    fn diagnostics_toggles_in_settings_only_change_the_draft() {
        // While the overlay is open, h/l flips only the draft: neither the
        // writer nor the shared flag moves, and the pending path is not
        // regenerated.
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();

        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert!(!state.diagnostics_enabled);
        assert!(!state.diagnostics_draft);
        let pending = state.diagnostics_pending_path.clone();
        assert!(pending.is_some());

        send_key(&mut state, KeyCode::Char('j'));
        send_key(&mut state, KeyCode::Char('j')); // select the Diagnostics row
        for _ in 0..4 {
            send_key(&mut state, KeyCode::Char('l')); // draft ON
            assert!(state.diagnostics_draft);
            assert_eq!(state.diagnostics_pending_path, pending);
            assert!(
                !runtime.reconcile(&mut state),
                "overlay toggles must not touch the runtime"
            );
            assert!(runtime.writer.is_none());
            assert!(!enabled.load(Ordering::Relaxed));
            assert!(!state.diagnostics_enabled);

            send_key(&mut state, KeyCode::Char('l')); // draft OFF
            assert!(!state.diagnostics_draft);
            assert_eq!(state.diagnostics_pending_path, pending);
            assert!(!runtime.reconcile(&mut state));
            assert!(runtime.writer.is_none());
            assert!(!state.diagnostics_enabled);
        }
    }

    #[test]
    fn settings_overlay_highlights_the_selected_row() {
        let snapshot = TrafficSnapshot::default();
        let area = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        };
        let popup = centered_rect(area, 70, 11);
        // Layout rows (inside the bordered popup, after an initial blank line):
        // y+2 = Rank window, y+3 = Palette, y+4 = Diagnostics.
        let render_style = |x: u16, y: u16, selection: usize| {
            let mut state = AppState::new();
            state.settings_open = true;
            state.settings_selection = selection;
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
                .unwrap();
            terminal.backend().buffer()[(popup.x + x, popup.y + y)].style()
        };
        // Each row's highlight follows its own selection.
        assert_ne!(
            render_style(1, 2, 0),
            render_style(1, 2, 2),
            "rank window highlight should follow selection"
        );
        assert_ne!(
            render_style(1, 3, 1),
            render_style(1, 3, 0),
            "palette highlight should follow selection"
        );
        assert_ne!(
            render_style(1, 4, 2),
            render_style(1, 4, 1),
            "diagnostics highlight should follow selection"
        );
    }

    #[test]
    fn settings_marker_prefix_is_color_independent() {
        // The `> ` prefix is deliberately independent of the palette: 16-color
        // and monochrome tiers may not render the highlight style (covered by
        // palette::tests::selection_style_reverses_below_truecolor), so the
        // selection must stay identifiable from the marker alone.
        assert_eq!(settings_selection_prefix(true), "> ");
        assert_eq!(settings_selection_prefix(false), "  ");
    }

    #[test]
    fn settings_marker_and_padding_keep_rows_aligned() {
        let snapshot = TrafficSnapshot::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut state = AppState::new();
        state.settings_open = true;
        state.settings_selection = 0;
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("> Rank window:"));
        assert!(rendered.contains("  Palette:"));
        assert!(rendered.contains("  Diagnostics:"));

        // Selecting Diagnostics (row 2) moves the marker to it; Rank window
        // keeps a two-space padding and the file hint stays unpadded.
        state.settings_selection = 2;
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("> Diagnostics:"));
        assert!(rendered.contains("  Rank window:"));
        assert!(rendered.contains("  Palette:"));
        assert!(rendered.contains("  File: (none)"));
    }

    #[test]
    fn settings_overlay_clears_underlying_cells() {
        let state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let area = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        };
        let popup = centered_rect(area, 70, 11);

        terminal
            .draw(|frame| {
                frame.render_widget(
                    Paragraph::new("underlay"),
                    Rect {
                        x: popup.x + 2,
                        y: popup.y + 1,
                        width: 8,
                        height: 1,
                    },
                );
                draw_settings(frame, area, &state);
            })
            .unwrap();

        assert_eq!(
            terminal.backend().buffer()[(popup.x + 2, popup.y + 1)].symbol(),
            " "
        );
    }

    #[test]
    fn settings_overlay_is_not_rendered_when_closed() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(!rendered.contains("Settings"));
    }

    #[test]
    fn overlay_h_and_l_cycle_palette_choice_in_opposite_directions() {
        let mut state = AppState::new();
        // Pin detected_tier to Truecolor so resolve(Auto, Truecolor) stays at
        // Truecolor; the one-step cycle exercised here (Auto -> Truecolor)
        // therefore leaves the global ACTIVE tier unchanged, avoiding
        // interference with parallel tests. The full 4-step cycle (including
        // SixteenColor/Monochrome) is covered by the pure-function test
        // next_palette_choice_cycles_through_all_four_with_wraparound.
        state.detected_tier = palette::ColorTier::Truecolor;
        state.palette_choice = palette::PaletteChoice::Auto;

        // Open the overlay; the default selection is the first row (Rank
        // window), so step down to Palette before cycling it.
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        send_key(&mut state, KeyCode::Char('j'));
        assert_eq!(state.settings_selection, PALETTE_ROW);

        // 'l' advances Auto -> Truecolor (no tier change since detected=Truecolor).
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert_eq!(state.palette_choice, palette::PaletteChoice::Truecolor);

        // 'h' cycles backward. Start from Truecolor so the step stays
        // side-effect-free: prev(Truecolor) == Auto and resolve(Auto,
        // Truecolor) == Truecolor leaves the global ACTIVE tier untouched.
        state.palette_choice = palette::PaletteChoice::Truecolor;
        assert_eq!(
            send_key(&mut state, KeyCode::Char('h')),
            KeyOutcome::Changed
        );
        assert_eq!(state.palette_choice, palette::PaletteChoice::Auto);

        // Enter is a no-op under the unified select/change model.
        state.palette_choice = palette::PaletteChoice::Auto;
        assert_eq!(send_key(&mut state, KeyCode::Enter), KeyOutcome::Ignored);
        assert_eq!(state.palette_choice, palette::PaletteChoice::Auto);
    }

    #[test]
    fn palette_choice_and_tier_labels_match_the_adr_wording() {
        assert_eq!(palette_choice_label(palette::PaletteChoice::Auto), "Auto");
        assert_eq!(
            palette_choice_label(palette::PaletteChoice::Truecolor),
            "truecolor",
        );
        assert_eq!(
            palette_choice_label(palette::PaletteChoice::SixteenColor),
            "16-color",
        );
        assert_eq!(
            palette_choice_label(palette::PaletteChoice::Monochrome),
            "monochrome",
        );

        assert_eq!(color_tier_label(palette::ColorTier::Truecolor), "truecolor");
        assert_eq!(color_tier_label(palette::ColorTier::Sixteen), "16-color");
        assert_eq!(
            color_tier_label(palette::ColorTier::Monochrome),
            "monochrome",
        );
    }

    #[test]
    fn next_palette_choice_cycles_through_all_four_with_wraparound() {
        use palette::PaletteChoice;
        assert_eq!(
            next_palette_choice(PaletteChoice::Auto),
            PaletteChoice::Truecolor,
        );
        assert_eq!(
            next_palette_choice(PaletteChoice::Truecolor),
            PaletteChoice::SixteenColor,
        );
        assert_eq!(
            next_palette_choice(PaletteChoice::SixteenColor),
            PaletteChoice::Monochrome,
        );
        assert_eq!(
            next_palette_choice(PaletteChoice::Monochrome),
            PaletteChoice::Auto,
        );
    }

    #[test]
    fn prev_palette_choice_cycles_backward_through_all_four_with_wraparound() {
        use palette::PaletteChoice;
        assert_eq!(
            prev_palette_choice(PaletteChoice::Auto),
            PaletteChoice::Monochrome,
        );
        assert_eq!(
            prev_palette_choice(PaletteChoice::Truecolor),
            PaletteChoice::Auto,
        );
        assert_eq!(
            prev_palette_choice(PaletteChoice::SixteenColor),
            PaletteChoice::Truecolor,
        );
        assert_eq!(
            prev_palette_choice(PaletteChoice::Monochrome),
            PaletteChoice::SixteenColor,
        );
    }
}
