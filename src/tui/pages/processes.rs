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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn eighty_column_processes_keep_full_columns_and_a_visible_selection() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                chrono::Utc::now(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("proc Processes 1"));
        assert!(rendered.contains("Process"));
        assert!(rendered.contains("PID"));
        assert!(rendered.contains("Recv"));
        assert!(rendered.contains("Sent"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("1/1"));
        let selected = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "c" && cell.bg == Color::Rgb(23, 43, 60))
            .expect("selected process row");
        assert!(selected.modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn processes_page_renders_from_snapshot() {
        let observed_at = "2026-07-15T08:00:00Z".parse().unwrap();
        let snapshot = TrafficSnapshot {
            in_bytes: 40,
            out_bytes: 60,
            processes: vec![{
                let mut process = ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl --silent")),
                    None,
                    observed_at,
                    40,
                    60,
                );
                process.window = crate::stats::ProcTraffic { recv: 40, sent: 60 };
                process
            }]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
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
                );
            })
            .unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("curl --silent"));
        assert!(rendered.contains("100 B"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("2m ago"));
    }

    #[test]
    fn processes_page_marks_the_selected_row() {
        let snapshot = TrafficSnapshot {
            processes: vec![
                ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl")),
                    Some(Arc::from("/usr/bin/curl")),
                    chrono::Utc::now(),
                    40,
                    60,
                ),
                ProcessSnapshot::attributed(
                    8,
                    Some(Arc::from("ssh")),
                    Some(Arc::from("/usr/bin/ssh")),
                    chrono::Utc::now(),
                    10,
                    20,
                ),
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                &snapshot,
            ),
            KeyOutcome::Changed
        ));
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
        assert!(rendered.contains("> ssh"));
        assert!(rendered.contains("Process"));
        assert!(rendered.contains("PID"));
        assert!(rendered.contains("Recv"));
        assert!(rendered.contains("Sent"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("Enter:details"));
        assert!(rendered.contains("q:quit"));
        assert!(!rendered.contains("/usr/bin/ssh"));
    }

    #[test]
    fn process_preview_has_no_selection_cursor() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                chrono::Utc::now(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();

        terminal
            .draw(|frame| {
                draw_process_preview(
                    frame,
                    frame.area(),
                    &snapshot,
                    LayoutMode::Standard,
                    chrono::Utc::now(),
                );
            })
            .unwrap();

        let process_line = rendered_lines(&terminal)
            .into_iter()
            .find(|line| line.contains("curl"))
            .expect("process row");
        assert!(!process_line.contains("> "));
    }
}
