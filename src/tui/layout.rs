//! Frame layout, chrome, and shared rendering helpers.

use std::time::Instant;

use ratatui::layout::{Alignment, Constraint, Direction as LayoutDir, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::capture::InterfaceInfo;
use crate::palette;
use crate::report::{fmt_elapsed, human_bytes};
use crate::stats::{RankWindow, TrafficSnapshot};

use super::pages::*;
use super::popups::*;
use super::selector::*;
use super::state::*;

pub(super) const MIN_TERMINAL_WIDTH: u16 = 60;
pub(super) const MIN_TERMINAL_HEIGHT: u16 = 16;
#[cfg(test)]
pub(super) fn draw(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
) {
    draw_with_interfaces(f, state, snapshot, Some(interface), &[], host, started_at);
}

pub(super) fn draw_with_interfaces(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: Option<&str>,
    interfaces: &[InterfaceInfo],
    host: &str,
    started_at: Instant,
) {
    draw_with_interfaces_at(
        f,
        state,
        snapshot,
        interface,
        interfaces,
        host,
        started_at,
        chrono::Utc::now(),
    );
}

#[cfg(test)]
pub(super) fn draw_at(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
    now: chrono::DateTime<chrono::Utc>,
) {
    draw_with_interfaces_at(
        f,
        state,
        snapshot,
        Some(interface),
        &[],
        host,
        started_at,
        now,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn draw_with_interfaces_at(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: Option<&str>,
    interfaces: &[InterfaceInfo],
    host: &str,
    started_at: Instant,
    now: chrono::DateTime<chrono::Utc>,
) {
    let area = f.area();
    f.render_widget(
        Block::default().style(Style::default().fg(palette::text()).bg(palette::bg())),
        area,
    );

    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        draw_too_small(f, area);
        if state.quit_confirm {
            draw_quit_confirm(f, area);
        }
        return;
    }

    if let Some(selector) = state.interface_selector.as_ref() {
        draw_interface_selector(f, area, selector, interfaces, interface);
        if state.quit_confirm {
            draw_quit_confirm(f, area);
        }
        return;
    }

    let mode = LayoutMode::from_area(area);
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let interface_label = interface_display_label(interface, interfaces);
    draw_header(
        f,
        chunks[0],
        state.page,
        &interface_label,
        host,
        started_at,
        mode,
        snapshot,
    );
    let body = chunks[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    match state.page {
        Page::Overview => draw_overview(f, body, snapshot, mode, now),
        Page::Processes => match state.process_detail.as_ref() {
            Some(detail) => draw_process_detail(f, body, detail, snapshot, now),
            None => draw_processes(f, body, state, snapshot, mode, now),
        },
        Page::Ips => draw_ips(f, body, state, snapshot, mode, now),
        Page::Domains => draw_domains(f, body, state, snapshot, mode, now),
        Page::About => draw_about(f, body),
    }
    draw_status_bar(f, chunks[2], state, mode);

    if state.settings_open {
        draw_settings(f, area, state);
    }
    if state.quit_confirm {
        draw_quit_confirm(f, area);
    }
}

pub(super) fn draw_too_small(f: &mut ratatui::Frame, area: Rect) {
    let message_area = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(area)[1];
    let lines = vec![
        Line::from(Span::styled(
            "flowlens",
            Style::default()
                .fg(palette::accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("Terminal too small (minimum {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT})"),
            Style::default().fg(palette::muted()),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        message_area,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn draw_header(
    f: &mut ratatui::Frame,
    area: Rect,
    page: Page,
    interface: &str,
    host: &str,
    started_at: Instant,
    mode: LayoutMode,
    snapshot: &TrafficSnapshot,
) {
    let navigation = navigation_line(page, mode);
    if page == Page::About {
        f.render_widget(Paragraph::new(navigation), area);
        return;
    }

    let runtime = runtime_line(interface, host, started_at, mode, snapshot);
    let runtime_width = (runtime.width() as u16).min(area.width / 2);
    let chunks = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(runtime_width)])
        .split(area);
    f.render_widget(Paragraph::new(navigation), chunks[0]);
    f.render_widget(
        Paragraph::new(runtime).alignment(Alignment::Right),
        chunks[1],
    );
}

pub(super) fn navigation_line(page: Page, mode: LayoutMode) -> Line<'static> {
    let mut spans = vec![Span::styled(
        " flowlens ",
        Style::default()
            .fg(palette::accent())
            .add_modifier(Modifier::BOLD),
    )];
    for candidate in Page::ALL {
        let label = match (candidate, mode) {
            (Page::Overview, LayoutMode::Compact) => " 1 ".to_string(),
            (Page::Processes, LayoutMode::Compact) => " 2 ".to_string(),
            (Page::Ips, LayoutMode::Compact) => " 3 ".to_string(),
            (Page::Domains, LayoutMode::Compact) => " 4 ".to_string(),
            (Page::About, LayoutMode::Compact) => " 5 ".to_string(),
            (Page::Overview, _) => " 1 Overview ".to_string(),
            (Page::Processes, _) => " 2 Processes ".to_string(),
            (Page::Ips, _) => " 3 IPs ".to_string(),
            (Page::Domains, _) => " 4 Domains ".to_string(),
            (Page::About, _) => " 5 About ".to_string(),
        };
        let style = if candidate == page {
            Style::default()
                .fg(palette::strong())
                .bg(palette::overview_highlight())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(palette::muted())
        };
        spans.push(Span::styled(label, style));
    }
    Line::from(spans)
}

pub(super) fn runtime_line(
    interface: &str,
    host: &str,
    started_at: Instant,
    mode: LayoutMode,
    snapshot: &TrafficSnapshot,
) -> Line<'static> {
    let mut spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            interface.to_string(),
            Style::default().fg(palette::strong()),
        ),
    ];
    if mode == LayoutMode::Wide {
        spans.push(Span::styled("  ", Style::default()));
        spans.push(Span::styled(
            host.to_string(),
            Style::default().fg(palette::strong()),
        ));
    }
    spans.push(Span::styled("  up ", Style::default().fg(palette::muted())));
    spans.push(Span::styled(
        fmt_elapsed(started_at.elapsed()),
        Style::default().fg(palette::strong()),
    ));
    spans.push(Span::styled(
        "  rank ",
        Style::default().fg(palette::muted()),
    ));
    spans.push(Span::styled(
        ranking_window_indicator(snapshot),
        Style::default().fg(palette::accent()),
    ));
    if mode != LayoutMode::Compact {
        spans.push(Span::styled(
            format!("  {}", chrono::Local::now().format("%H:%M:%S")),
            Style::default().fg(palette::muted()),
        ));
    }
    Line::from(spans)
}

pub(super) fn ranking_window_label(window: RankWindow) -> String {
    match window {
        RankWindow::Cumulative => "total".to_string(),
        RankWindow::Seconds(_) => window.label().to_string(),
    }
}

pub(super) fn ranking_window_indicator(snapshot: &TrafficSnapshot) -> String {
    let Some(window) = snapshot.ranking.window.seconds() else {
        return "total".to_string();
    };
    match snapshot.ranking.coverage_seconds {
        Some(coverage) if coverage < window => format!("{coverage}/{window}s!"),
        _ => format!("{window}s"),
    }
}

pub(super) fn format_rank_value(snapshot: &TrafficSnapshot, bytes: u64) -> String {
    if snapshot.ranking.window == RankWindow::Cumulative {
        human_bytes(bytes)
    } else {
        format!("{}/s", human_bytes(bytes))
    }
}

pub(super) fn panel_block(
    prefix: &str,
    title: &str,
    count: Option<usize>,
    prefix_color: Color,
    border_color: Color,
    footer: Option<String>,
) -> Block<'static> {
    let mut title_spans = vec![
        Span::styled(
            format!(" {prefix} "),
            Style::default()
                .fg(prefix_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            title.to_string(),
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(count) = count {
        title_spans.push(Span::styled(
            format!(" {count} "),
            Style::default().fg(palette::muted()),
        ));
    } else {
        title_spans.push(Span::raw(" "));
    }

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Line::from(title_spans));
    if let Some(footer) = footer {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" {footer} "),
                Style::default().fg(palette::muted()),
            ))
            .alignment(Alignment::Right),
        );
    }
    block
}

/// Truncate a single-line label to at most `max` display columns, keeping the
/// start and end with a middle ellipsis. Used so long diagnostics basenames
/// cannot overflow the settings overlay.
pub(super) fn truncate_with_ellipsis(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let keep_head = (max - 1) / 2;
    let keep_tail = (max - 1) - keep_head;
    let mut out: String = text.chars().take(keep_head).collect();
    out.push('…');
    out.extend(text.chars().skip(count - keep_tail));
    out
}

/// Center a rect of `width_pct`% of `area`'s width and `height` rows, vertically
/// and horizontally. Used for overlay popups.
pub(super) fn centered_rect(area: Rect, width_pct: u16, height: u16) -> Rect {
    let popup_layout = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(area);
    Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Percentage(width_pct),
            Constraint::Fill(1),
        ])
        .split(popup_layout[1])[1]
}

pub(super) fn draw_status_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    mode: LayoutMode,
) {
    if let Some(error) = state.diagnostics_error.as_deref() {
        f.render_widget(
            Paragraph::new(format!(" {error} ")).style(Style::default().fg(palette::coral())),
            area,
        );
        return;
    }
    if let Some(detail) = state.process_detail.as_ref() {
        let hint = match (detail.pause_notice, detail.paused) {
            (Some(reason), _) => format!("{}  Esc:back  q:quit", reason.message()),
            (None, Some(_)) => "Tracking paused  Esc:back  q:quit".to_string(),
            (None, None) => "Esc:back  q:quit".to_string(),
        };
        f.render_widget(
            Paragraph::new(format!(" {hint} ")).style(Style::default().fg(palette::muted())),
            area,
        );
        if let Some(detail) = state.process_detail.as_mut() {
            detail.pause_notice = None;
        }
        return;
    }

    let mut spans = Vec::new();
    push_hint(&mut spans, "i", "interface");
    push_hint(&mut spans, "1-5", "page");
    push_hint(&mut spans, "h/l", "switch");
    push_hint(&mut spans, "o", ":settings");
    if state.page == Page::Ips {
        push_hint(&mut spans, "Tab", "panel");
    }
    if matches!(state.page, Page::Processes | Page::Ips | Page::Domains) {
        if state.page == Page::Processes {
            push_hint(&mut spans, "Enter", ":details");
        }
        push_hint(&mut spans, "j/k", "scroll");
        if mode != LayoutMode::Compact {
            push_hint(&mut spans, "PgUp/PgDn", "page");
            push_hint(&mut spans, "Home/End", "jump");
        }
    }

    let chunks = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(area);
    f.render_widget(Paragraph::new(Line::from(spans)), chunks[0]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "q",
                Style::default()
                    .fg(palette::coral())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(":quit ", Style::default().fg(palette::muted())),
        ]))
        .alignment(Alignment::Right),
        chunks[1],
    );
}

pub(super) fn push_hint(spans: &mut Vec<Span<'static>>, key: &str, action: &str) {
    if !spans.is_empty() {
        spans.push(Span::raw("  "));
    } else {
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        key.to_string(),
        Style::default()
            .fg(palette::accent())
            .add_modifier(Modifier::BOLD),
    ));
    let separator = if action.starts_with(':') { "" } else { " " };
    spans.push(Span::styled(
        format!("{separator}{action}"),
        Style::default().fg(palette::muted()),
    ));
}

/// Build a ratatui TableState at the given offset.
pub(super) fn ratatui_state(len: usize, scroll: usize) -> ratatui::widgets::TableState {
    let mut s = ratatui::widgets::TableState::default();
    if len > 0 {
        s.select(Some(scroll.min(len - 1)));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn top_navigation_renders_page_tabs_with_the_active_page_selected() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let first_line = rendered_lines(&terminal)[0].clone();
        assert!(
            first_line.contains("flowlens  1 Overview  2 Processes  3 IPs  4 Domains  5 About")
        );
        let overview_cell = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "O")
            .expect("Overview tab cell");
        assert_eq!(overview_cell.bg, Color::Rgb(43, 37, 15));
        assert!(overview_cell.modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn undersized_terminal_shows_only_the_minimum_size_message() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(59, 15)).unwrap();

        terminal
            .draw(|frame| {
                draw(
                    frame,
                    &mut state,
                    &snapshot,
                    "private-interface",
                    "private-host",
                    Instant::now(),
                )
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Terminal too small (minimum 60x16)"));
        assert!(!rendered.contains("private-interface"));
        assert!(!rendered.contains("private-host"));
        assert!(!rendered.contains("Traffic"));
    }
}
