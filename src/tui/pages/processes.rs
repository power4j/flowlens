//! Processes page: ranked process table with preview.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Cell, Row, Table};

use crate::palette;
use crate::report::truncate;
use crate::stats::{ProcessSnapshot, RankWindow, TrafficSnapshot};

use super::detail::{attribution_summary_lines, pending_status_title, relative_last_seen};
use crate::tui::layout::*;
use crate::tui::state::*;

pub(in crate::tui) fn process_name_span(
    process: &ProcessSnapshot,
    max_chars: usize,
) -> Span<'static> {
    Span::raw(truncate(process.display_name(), max_chars))
}

pub(in crate::tui) fn draw_process_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let footer = preview_position(snapshot.processes.len(), area.height);
    let block = panel_block(
        "proc",
        "Top Processes",
        Some(snapshot.processes.len()),
        palette::coral(),
        palette::border(),
        Some(footer),
    );
    // The overview preview is informational, so it must not select a row.
    f.render_widget(process_table(snapshot, mode, block, now), area);
}

pub(in crate::tui) fn process_table(
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    block: Block<'static>,
    now: chrono::DateTime<chrono::Utc>,
) -> Table<'static> {
    let compact = mode == LayoutMode::Compact;
    let rows = process_rows(snapshot, compact, now);
    let header_style = Style::default().fg(palette::muted());
    // ADR 0013: the Attr column — its header uses words consistent with the
    // other headers, the values stay single letters.
    let table = if compact {
        Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(12),
                Constraint::Length(4),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Process", "Total", "Attr", "Last seen"]).style(header_style))
    } else {
        Table::new(
            rows,
            [
                Constraint::Min(13),
                Constraint::Length(8),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(4),
                Constraint::Length(9),
            ],
        )
        .header(
            Row::new(vec![
                "Process",
                "PID",
                "Recv",
                "Sent",
                "Total",
                "Attr",
                "Last seen",
            ])
            .style(header_style),
        )
    };
    table.column_spacing(1).block(block)
}

pub(in crate::tui) fn process_rows(
    snapshot: &TrafficSnapshot,
    compact: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Row<'static>> {
    if snapshot.processes.is_empty() {
        let cells = if compact {
            vec![
                Cell::from("No traffic observed"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]
        } else {
            vec![
                Cell::from("No traffic observed"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]
        };
        return vec![Row::new(cells).style(Style::default().fg(palette::muted()))];
    }

    snapshot
        .processes
        .iter()
        .map(|process| {
            let name = Cell::from(process_name_span(process, 40));
            // ADR 0013: Attr values are single letters, E = exclusive-only,
            // M = mixed (includes shared bytes); the breakdown and legend
            // live on the detail page.
            let traffic = if snapshot.ranking.window == RankWindow::Cumulative {
                crate::stats::ProcTraffic {
                    recv: process.recv,
                    sent: process.sent,
                }
            } else {
                process.rank
            };
            let attr = if process.is_mixed() { "M" } else { "E" };
            if compact {
                Row::new(vec![
                    name,
                    Cell::from(format_rank_value(snapshot, traffic.total()))
                        .style(Style::default().fg(palette::strong())),
                    Cell::from(attr),
                    Cell::from(relative_last_seen(process.last_seen(), now)),
                ])
            } else {
                Row::new(vec![
                    name,
                    Cell::from(
                        process
                            .pid()
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(format_rank_value(snapshot, traffic.recv))
                        .style(Style::default().fg(palette::inbound())),
                    Cell::from(format_rank_value(snapshot, traffic.sent))
                        .style(Style::default().fg(palette::outbound())),
                    Cell::from(format_rank_value(snapshot, traffic.total()))
                        .style(Style::default().fg(palette::strong())),
                    Cell::from(attr),
                    Cell::from(relative_last_seen(process.last_seen(), now)),
                ])
            }
        })
        .collect()
}

pub(in crate::tui) fn selected_position(selected: usize, len: usize) -> String {
    if len == 0 {
        "0/0".to_string()
    } else {
        format!("{}/{}", selected.min(len - 1) + 1, len)
    }
}

pub(in crate::tui) fn preview_position(len: usize, height: u16) -> String {
    if len == 0 {
        return "0/0".to_string();
    }
    let shown = len.min(height.saturating_sub(3) as usize);
    format!("1-{shown}/{len}")
}

pub(in crate::tui) fn draw_processes(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let compact = matches!(mode, LayoutMode::Compact);
    // ADR 0013: top-style layout — the conservation summary is pinned at
    // the top, the main table scrolls independently.
    let summary_lines = attribution_summary_lines(snapshot, compact);
    let summary_height = summary_lines.len() as u16 + 1;
    let view_h = area.height.saturating_sub(3 + summary_height) as usize;
    state.proc_view_height = view_h.max(1);
    state.proc_scroll = state
        .proc_scroll
        .min(snapshot.processes.len().saturating_sub(1));

    let footer = selected_position(state.proc_scroll, snapshot.processes.len());
    let block = panel_block(
        "proc",
        "Processes",
        Some(snapshot.processes.len()),
        palette::coral(),
        palette::border(),
        Some(footer),
    )
    .title(pending_status_title(
        snapshot.pending_attribution_bytes,
        area.width,
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [summary_area, table_area] = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(summary_height),
        ratatui::layout::Constraint::Min(0),
    ])
    .areas(inner);
    f.render_widget(
        ratatui::widgets::Paragraph::new(summary_lines),
        summary_area,
    );
    let table = process_table(snapshot, mode, Block::default(), now)
        .row_highlight_style(
            Style::default()
                .patch(palette::selection_style())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(
        table,
        table_area,
        &mut ratatui_state(snapshot.processes.len(), state.proc_scroll),
    );
}
