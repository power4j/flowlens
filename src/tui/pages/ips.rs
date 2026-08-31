//! IP page: inbound and outbound IP tables.

use ratatui::layout::{Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Cell, Row, Table};

use crate::palette;
use crate::stats::{IpSnapshot, TrafficSnapshot};

use super::detail::relative_last_seen;
use super::processes::{preview_position, selected_position};
use crate::tui::layout::*;
use crate::tui::state::*;

pub(in crate::tui) fn draw_ip_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    inbound: bool,
    now: chrono::DateTime<chrono::Utc>,
) {
    let entries = if inbound {
        snapshot.inbound_ips.as_ref()
    } else {
        snapshot.outbound_ips.as_ref()
    };
    let (prefix, title, color) = ip_theme(inbound);
    let block = panel_block(
        prefix,
        title,
        Some(entries.len()),
        color,
        palette::border(),
        Some(preview_position(entries.len(), area.height)),
    );
    let table = ip_table(entries, color, block, snapshot, now);
    f.render_widget(table, area);
}

pub(in crate::tui) fn ip_theme(inbound: bool) -> (&'static str, &'static str, Color) {
    if inbound {
        ("in", "Inbound IPs", palette::inbound())
    } else {
        ("out", "Outbound IPs", palette::outbound())
    }
}

pub(in crate::tui) fn ip_table(
    entries: &[IpSnapshot],
    color: Color,
    block: Block<'static>,
    snapshot: &TrafficSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) -> Table<'static> {
    let rows = if entries.is_empty() {
        vec![
            Row::new(vec!["No traffic observed", "", ""])
                .style(Style::default().fg(palette::muted())),
        ]
    } else {
        entries
            .iter()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.ip.to_string()),
                    Cell::from(format_rank_value(snapshot, entry.rank_bytes))
                        .style(Style::default().fg(color)),
                    Cell::from(relative_last_seen(entry.last_seen(), now)),
                ])
            })
            .collect()
    };
    Table::new(
        rows,
        [
            Constraint::Min(14),
            Constraint::Length(11),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["Remote address", "Total", "Last seen"])
            .style(Style::default().fg(palette::muted())),
    )
    .column_spacing(1)
    .block(block)
}

pub(in crate::tui) fn draw_ips(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let panes = if mode == LayoutMode::Compact {
        Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(50),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(50),
            ])
            .split(area)
    };

    let inbound_area = panes[0];
    let outbound_area = panes[2];
    state.ip_in_view_height = (inbound_area.height.saturating_sub(3) as usize).max(1);
    state.ip_out_view_height = (outbound_area.height.saturating_sub(3) as usize).max(1);
    state.ip_in_scroll = state
        .ip_in_scroll
        .min(snapshot.inbound_ips.len().saturating_sub(1));
    state.ip_out_scroll = state
        .ip_out_scroll
        .min(snapshot.outbound_ips.len().saturating_sub(1));

    draw_ip_table(
        f,
        inbound_area,
        snapshot.inbound_ips.as_ref(),
        true,
        state.ip_focus == IpFocus::Inbound,
        state.ip_in_scroll,
        snapshot,
        now,
    );
    draw_ip_table(
        f,
        outbound_area,
        snapshot.outbound_ips.as_ref(),
        false,
        state.ip_focus == IpFocus::Outbound,
        state.ip_out_scroll,
        snapshot,
        now,
    );
}

#[allow(clippy::too_many_arguments)]
pub(in crate::tui) fn draw_ip_table(
    f: &mut ratatui::Frame,
    area: Rect,
    entries: &[IpSnapshot],
    inbound: bool,
    focused: bool,
    selected: usize,
    snapshot: &TrafficSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) {
    let (prefix, title, color) = ip_theme(inbound);
    let block = panel_block(
        prefix,
        title,
        Some(entries.len()),
        color,
        palette::border(),
        Some(selected_position(selected, entries.len())),
    );
    let table = ip_table(entries, color, block, snapshot, now)
        .row_highlight_style(if focused {
            Style::default()
                .fg(palette::strong())
                .patch(palette::selection_style())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        })
        .highlight_symbol(if focused { "> " } else { "  " });
    f.render_stateful_widget(table, area, &mut ratatui_state(entries.len(), selected));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn compact_ips_stack_themed_panels_vertically() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.page = Page::Ips;
        let mut terminal = Terminal::new(TestBackend::new(72, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let lines = rendered_lines(&terminal);
        let inbound_y = lines
            .iter()
            .position(|line| line.contains("in Inbound IPs"))
            .expect("inbound panel");
        let outbound_y = lines
            .iter()
            .position(|line| line.contains("out Outbound IPs"))
            .expect("outbound panel");
        assert!(inbound_y < outbound_y);
        assert!(outbound_y - inbound_y >= 8);
    }

    #[test]
    fn ips_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            inbound_ips: vec![IpSnapshot::new(
                "192.0.2.10".parse().unwrap(),
                1024,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
            outbound_ips: vec![IpSnapshot::new(
                "198.51.100.20".parse().unwrap(),
                2048,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Ips;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_at(
                    frame,
                    &mut state,
                    &snapshot,
                    "eth0",
                    "host",
                    Instant::now(),
                    "2026-07-15T08:02:00Z".parse().unwrap(),
                )
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("1.00 KB"));
        assert!(rendered.contains("198.51.100.20"));
        assert!(rendered.contains("2.00 KB"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("2m ago"));
    }
}
