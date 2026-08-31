//! Domains page: ranked domain table.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Cell, Row, Table};

use crate::palette;
use crate::report::truncate;
use crate::stats::{RankWindow, TrafficSnapshot};

use super::detail::relative_last_seen;
use super::processes::{preview_position, selected_position};
use crate::tui::layout::*;
use crate::tui::state::*;

/// Overview preview of top outbound domains. Mirrors `draw_ip_preview` and
/// `draw_process_preview`: panel prefix `dom`, title `Top Domains`, rows
/// clipped by height, `preview_position` footer.
pub(in crate::tui) fn draw_domain_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let footer = preview_position(snapshot.outbound_domains.len(), area.height);
    let block = panel_block(
        "dom",
        "Top Domains",
        Some(snapshot.outbound_domains.len()),
        palette::violet(),
        palette::border(),
        Some(footer),
    );
    let table = domain_table(snapshot, mode, block, now);
    f.render_widget(table, area);
}

pub(in crate::tui) fn draw_domains(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let view_h = area.height.saturating_sub(3) as usize;
    state.domain_view_height = view_h.max(1);
    state.domain_scroll = state
        .domain_scroll
        .min(snapshot.outbound_domains.len().saturating_sub(1));

    let footer = selected_position(state.domain_scroll, snapshot.outbound_domains.len());
    let block = panel_block(
        "dom",
        "Domains",
        Some(snapshot.outbound_domains.len()),
        palette::violet(),
        palette::border(),
        Some(footer),
    );
    let table = domain_table(snapshot, mode, block, now)
        .row_highlight_style(
            Style::default()
                .patch(palette::selection_style())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(
        table,
        area,
        &mut ratatui_state(snapshot.outbound_domains.len(), state.domain_scroll),
    );
}

pub(in crate::tui) fn domain_table(
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    block: Block<'static>,
    now: chrono::DateTime<chrono::Utc>,
) -> Table<'static> {
    let compact = mode == LayoutMode::Compact;
    let rows = domain_rows(snapshot, compact, now);
    let header_style = Style::default().fg(palette::muted());
    let table = if compact {
        Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Host", "Total", "Last seen"]).style(header_style))
    } else {
        Table::new(
            rows,
            [
                Constraint::Min(20),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(12),
                Constraint::Length(10),
            ],
        )
        .header(Row::new(vec!["Host", "In", "Out", "Total", "Last seen"]).style(header_style))
    };
    table.column_spacing(1).block(block)
}

pub(in crate::tui) fn domain_rows(
    snapshot: &TrafficSnapshot,
    compact: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Row<'static>> {
    if snapshot.outbound_domains.is_empty() {
        let empty_state = if snapshot.ranking.window == RankWindow::Cumulative {
            "No outbound domains observed"
        } else {
            "No domains in window"
        };
        let cells = if compact {
            vec![Cell::from(empty_state), Cell::from(""), Cell::from("")]
        } else {
            vec![
                Cell::from(empty_state),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]
        };
        return vec![Row::new(cells).style(Style::default().fg(palette::muted()))];
    }

    snapshot
        .outbound_domains
        .iter()
        .map(|domain| {
            let host = Cell::from(truncate(domain.host(), 40));
            let last_seen = Cell::from(relative_last_seen(domain.last_seen(), now));
            if compact {
                Row::new(vec![
                    host,
                    Cell::from(format_rank_value(
                        snapshot,
                        domain.rank_in_bytes.saturating_add(domain.rank_out_bytes),
                    ))
                    .style(Style::default().fg(palette::strong())),
                    last_seen,
                ])
            } else {
                Row::new(vec![
                    host,
                    Cell::from(format_rank_value(snapshot, domain.rank_in_bytes))
                        .style(Style::default().fg(palette::inbound())),
                    Cell::from(format_rank_value(snapshot, domain.rank_out_bytes))
                        .style(Style::default().fg(palette::outbound())),
                    Cell::from(format_rank_value(
                        snapshot,
                        domain.rank_in_bytes.saturating_add(domain.rank_out_bytes),
                    ))
                    .style(Style::default().fg(palette::strong())),
                    last_seen,
                ])
            }
        })
        .collect()
}
