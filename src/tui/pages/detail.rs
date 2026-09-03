//! Process detail page: attribution breakdown.

use crate::palette;
use crate::report::{human_bytes, truncate};
use crate::stats::{ProcessSnapshot, RankWindow, TrafficSnapshot};
use ratatui::layout::{Alignment, Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use super::processes::process_name_span;
use crate::tui::layout::*;
use crate::tui::state::*;

pub(in crate::tui) const PENDING_STATUS_SLOT_WIDTH: usize = 12;
/// ADR 0013 record-layer conservation summary (settled basis): total =
/// exclusive + shared + system + unattributed.
/// Wide screens use three lines (conservation + System + Unattributed);
/// compact uses two (System folded into the conservation line).
pub(in crate::tui) fn attribution_summary_lines(
    snapshot: &TrafficSnapshot,
    compact: bool,
) -> Vec<Line<'static>> {
    // The summary uses the same since-start totals as the table.
    let attribution = &snapshot.attribution;
    let muted = Style::default().fg(palette::muted());
    let mut lines = vec![Line::from(vec![
        Span::styled("Total ", muted),
        Span::raw(human_bytes(attribution.total())),
        Span::styled(" = Exclusive ", muted),
        Span::raw(human_bytes(attribution.exclusive.total())),
        Span::styled(" + Shared ", muted),
        Span::raw(human_bytes(attribution.shared.total())),
        Span::styled(" + System ", muted),
        Span::raw(human_bytes(attribution.system.total())),
        Span::styled(" + Unattributed ", muted),
        Span::raw(human_bytes(attribution.unattributed.total())),
    ])];
    let channels: Vec<(&str, &crate::stats::ProcTraffic)> = if compact {
        vec![("Unattributed", &attribution.unattributed)]
    } else {
        vec![
            ("System", &attribution.system),
            ("Unattributed", &attribution.unattributed),
        ]
    };
    // Value columns take the widest value across rows so the
    // System/Unattributed columns align vertically.
    let value_width = channels
        .iter()
        .flat_map(|(_, traffic)| [traffic.recv, traffic.sent, traffic.total()])
        .map(|bytes| human_bytes(bytes).chars().count())
        .max()
        .unwrap_or(0);
    lines.extend(
        channels
            .into_iter()
            .map(|(label, traffic)| channel_summary_line(label, traffic, value_width)),
    );
    lines
}

pub(in crate::tui) fn channel_summary_line(
    label: &str,
    traffic: &crate::stats::ProcTraffic,
    value_width: usize,
) -> Line<'static> {
    let muted = Style::default().fg(palette::muted());
    let label_style = if traffic.total() > 0 {
        Style::default().fg(palette::warn())
    } else {
        muted
    };
    let value = |bytes: u64| format!("{:>width$}", human_bytes(bytes), width = value_width);
    Line::from(vec![
        // Label column padded to the longest label (Unattributed) + 2, so
        // it never touches the value columns.
        Span::styled(format!("{label:<14}"), label_style),
        Span::styled("Recv ", muted),
        Span::raw(value(traffic.recv)),
        Span::styled("  Sent ", muted),
        Span::raw(value(traffic.sent)),
        Span::styled("  Total ", muted),
        Span::raw(value(traffic.total())),
    ])
}

pub(in crate::tui) fn pending_status_title(bytes: u64, area_width: u16) -> Line<'static> {
    let slot_width = if area_width < 44 {
        1
    } else {
        PENDING_STATUS_SLOT_WIDTH
    };
    let label = if slot_width == 1 {
        if bytes == 0 {
            String::new()
        } else {
            "?".to_string()
        }
    } else {
        const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut value = bytes as f64;
        let mut unit_index = 0;
        while unit_index < UNITS.len() - 1 && (value * 100.0).round() / 100.0 >= 1024.0 {
            value /= 1024.0;
            unit_index += 1;
        }
        let unit = UNITS[unit_index];
        let rounded_value = (value * 100.0).round() / 100.0;
        let full = if unit_index == UNITS.len() - 1 && rounded_value >= 1024.0 {
            "?".to_string()
        } else {
            format!("? {value:>7.2} {unit:>2}")
        };
        if full.chars().count() <= PENDING_STATUS_SLOT_WIDTH {
            full
        } else {
            "?".to_string()
        }
    };
    let padding = slot_width.saturating_sub(label.chars().count());
    Line::from(Span::styled(
        format!("{}{}", " ".repeat(padding), label),
        Style::default().fg(if bytes == 0 {
            palette::muted()
        } else {
            palette::warn()
        }),
    ))
    .alignment(Alignment::Right)
}

pub(in crate::tui) fn process_attribution_detail_lines(
    process: &ProcessSnapshot,
    show_breakdown: bool,
) -> Vec<Line<'static>> {
    let exclusive = &process.attribution.exclusive;
    let shared = &process.attribution.shared;
    let label_width = ["Exclusive:", "Shared:", "Total:"]
        .into_iter()
        .map(str::len)
        .max()
        .expect("attribution labels are not empty");
    let value_width = [
        exclusive.total(),
        exclusive.recv,
        exclusive.sent,
        shared.total(),
        shared.recv,
        shared.sent,
        process.total(),
    ]
    .into_iter()
    .map(|bytes| human_bytes(bytes).chars().count())
    .max()
    .unwrap_or(0);
    let value = |bytes: u64| format!("{:>width$}", human_bytes(bytes), width = value_width);
    let mut lines = vec![Line::from(format!(
        "  {label:<label_width$} {total}",
        label = "Exclusive:",
        total = value(exclusive.total()),
    ))];
    if show_breakdown {
        lines.push(Line::from(format!(
            "    Recv: {}",
            human_bytes(exclusive.recv)
        )));
        lines.push(Line::from(format!(
            "    Sent: {}",
            human_bytes(exclusive.sent)
        )));
    }
    lines.push(Line::from(format!(
        "  {label:<label_width$} {total}",
        label = "Shared:",
        total = value(shared.total()),
    )));
    if show_breakdown {
        lines.push(Line::from(format!(
            "    Recv: {}",
            human_bytes(shared.recv)
        )));
        lines.push(Line::from(format!(
            "    Sent: {}",
            human_bytes(shared.sent)
        )));
    }
    lines.push(Line::from(format!(
        "  {label:<label_width$} {total} = Exclusive {exclusive} + Shared {shared}",
        label = "Total:",
        total = value(process.total()),
        exclusive = human_bytes(exclusive.total()),
        shared = human_bytes(shared.total()),
    )));
    lines
}

fn render_attribution_column(
    f: &mut ratatui::Frame,
    area: Rect,
    title: &'static str,
    traffic: crate::stats::ProcTraffic,
) {
    let rows = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);
    let fields = [
        (
            title,
            human_bytes(traffic.total()),
            Style::default()
                .fg(palette::text())
                .add_modifier(Modifier::BOLD),
            Style::default().fg(palette::warn()),
        ),
        (
            "  ├ Recv:",
            human_bytes(traffic.recv),
            Style::default().fg(palette::muted()),
            Style::default().fg(palette::inbound()),
        ),
        (
            "  └ Sent:",
            human_bytes(traffic.sent),
            Style::default().fg(palette::muted()),
            Style::default().fg(palette::outbound()),
        ),
    ];
    for (row, (label, value, label_style, value_style)) in rows.iter().zip(fields) {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(label, label_style),
                Span::raw(" "),
                Span::styled(value, value_style),
            ])),
            *row,
        );
    }
}
pub(in crate::tui) fn draw_process_detail(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Some(detail) = state.process_detail.as_ref() else {
        return;
    };
    let process = detail.process.clone();
    let paused = detail.paused;
    let compact = area.width < 70;

    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(if compact { 11 } else { 7 }),
            Constraint::Length(if compact { 12 } else { 13 }),
            Constraint::Fill(1),
        ])
        .split(area);
    let (header_area, attribution_area, flow_area) = (chunks[0], chunks[1], chunks[2]);

    let header_block = panel_block(
        "proc",
        "Process Details",
        None,
        palette::coral(),
        palette::border(),
        None,
    );

    // Header: lay out regions first, then render each field into its region.
    if !compact {
        let muted = Style::default().fg(palette::muted());
        let value = Style::default().fg(palette::text());
        let recv_fg = Style::default().fg(palette::inbound());
        let sent_fg = Style::default().fg(palette::outbound());
        let total_fg = Style::default().fg(palette::warn());
        let inner = header_block.inner(header_area);
        f.render_widget(header_block, header_area);
        let rows = Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([Constraint::Fill(1), Constraint::Length(1)])
            .split(inner);
        let columns = Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[0]);

        let left = vec![
            Line::from(vec![
                Span::styled("Name: ", muted),
                process_name_span(&process, columns[0].width.saturating_sub(6) as usize),
            ]),
            Line::from(vec![
                Span::styled("PID: ", muted),
                Span::styled(
                    process
                        .pid()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    value,
                ),
            ]),
            Line::from(vec![
                Span::styled("Last seen: ", muted),
                Span::styled(relative_last_seen(process.last_seen(), now), value),
            ]),
        ];
        let right = vec![
            Line::from(vec![
                Span::styled("Recv: ", muted),
                Span::styled(human_bytes(process.recv), recv_fg),
            ]),
            Line::from(vec![
                Span::styled("Sent: ", muted),
                Span::styled(human_bytes(process.sent), sent_fg),
            ]),
            Line::from(vec![
                Span::styled("Total: ", muted),
                Span::styled(human_bytes(process.total()), total_fg),
            ]),
        ];
        f.render_widget(Paragraph::new(left), columns[0]);
        f.render_widget(Paragraph::new(right), columns[1]);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Path: ", muted),
                Span::styled(
                    truncate(
                        process.path().unwrap_or("-"),
                        inner.width.saturating_sub(6) as usize,
                    ),
                    value,
                ),
            ])),
            rows[1],
        );
    } else {
        let muted = Style::default().fg(palette::muted());
        let value = Style::default().fg(palette::text());
        let header_lines = vec![
            Line::from(vec![
                Span::raw("Name: "),
                process_name_span(&process, usize::MAX),
            ]),
            Line::from(format!(
                "PID: {}",
                process
                    .pid()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string())
            )),
            Line::from(format!(
                "Last seen: {}",
                relative_last_seen(process.last_seen(), now)
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Recv: ", muted),
                Span::styled(human_bytes(process.recv), value),
            ]),
            Line::from(vec![
                Span::styled("Sent: ", muted),
                Span::styled(human_bytes(process.sent), value),
            ]),
            Line::from(vec![
                Span::styled("Total: ", muted),
                Span::styled(human_bytes(process.total()), value),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Path: ", muted),
                Span::styled(process.path().unwrap_or("-").to_string(), value),
            ]),
        ];
        f.render_widget(
            Paragraph::new(header_lines).block(header_block),
            header_area,
        );
    }

    // Attribution: split the panel into title, breakdown, divider, and summary regions.
    let selected = if snapshot.ranking.window == RankWindow::Cumulative {
        process.selected
    } else {
        process.rank
    };
    let excl = &process.attribution.exclusive;
    let shr = &process.attribution.shared;
    let attr_block = panel_block(
        "attr",
        "Attribution",
        None,
        palette::accent(),
        palette::border(),
        None,
    );
    if !compact {
        let inner = attr_block.inner(attribution_area);
        f.render_widget(attr_block, attribution_area);
        let rows = Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .split(inner);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Attribution (lifetime)",
                Style::default()
                    .fg(palette::strong())
                    .add_modifier(Modifier::BOLD),
            ))),
            rows[0],
        );
        let columns = Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);
        render_attribution_column(f, columns[0], "Exclusive:", *excl);
        render_attribution_column(f, columns[1], "Shared:", *shr);
        f.render_widget(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(palette::muted())),
            rows[2],
        );

        let mut summary_lines = vec![
            Line::from(format!(
                "Selected ({}): {}  Recv {}  Sent {}",
                ranking_window_indicator(snapshot),
                format_rank_value(snapshot, selected.total()),
                format_rank_value(snapshot, selected.recv),
                format_rank_value(snapshot, selected.sent)
            )),
            Line::from(format!(
                "Rank ({}): {}  Recv {}  Sent {}",
                ranking_window_indicator(snapshot),
                format_rank_value(snapshot, process.rank.total()),
                format_rank_value(snapshot, process.rank.recv),
                format_rank_value(snapshot, process.rank.sent)
            )),
            Line::from("Shared traffic is included in Total and may appear in multiple processes."),
            Line::from(Span::styled(
                "Attr: E = exclusive only, M = mixed (includes shared)",
                Style::default().fg(palette::muted()),
            )),
        ];
        if paused.is_some() {
            summary_lines.push(Line::from(Span::styled(
                "Tracking paused",
                Style::default()
                    .fg(palette::warn())
                    .add_modifier(Modifier::BOLD),
            )));
        }
        f.render_widget(Paragraph::new(summary_lines), rows[3]);
    } else {
        let mut attr_lines = vec![Line::from(Span::styled(
            "Attribution (lifetime)",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ))];
        attr_lines.extend(process_attribution_detail_lines(&process, true));
        attr_lines.push(Line::from(format!(
            "Selected ({}): {}  Recv {}  Sent {}",
            ranking_window_indicator(snapshot),
            format_rank_value(snapshot, selected.total()),
            format_rank_value(snapshot, selected.recv),
            format_rank_value(snapshot, selected.sent)
        )));
        attr_lines.push(Line::from(format!(
            "Rank ({}): {}  Recv {}  Sent {}",
            ranking_window_indicator(snapshot),
            format_rank_value(snapshot, process.rank.total()),
            format_rank_value(snapshot, process.rank.recv),
            format_rank_value(snapshot, process.rank.sent)
        )));
        attr_lines.push(Line::from(
            "Shared traffic is included in Total and may appear in multiple processes.",
        ));
        attr_lines.push(Line::from(Span::styled(
            "Attr: E = exclusive only, M = mixed (includes shared)",
            Style::default().fg(palette::muted()),
        )));
        if paused.is_some() {
            attr_lines.push(Line::from(Span::styled(
                "Tracking paused",
                Style::default()
                    .fg(palette::warn())
                    .add_modifier(Modifier::BOLD),
            )));
        }
        f.render_widget(
            Paragraph::new(attr_lines).block(attr_block),
            attribution_area,
        );
    }

    // IP Statistics: a real table.
    let flow_block = panel_block(
        "ip",
        "IP Statistics (lifetime)",
        None,
        palette::accent(),
        palette::border(),
        None,
    );
    let len = process.flows.len();
    let max_scroll = len.saturating_sub(1);
    let scroll = state.proc_detail_scroll.min(max_scroll);
    state.proc_detail_scroll = scroll;
    state.proc_detail_view_height = (flow_area.height.saturating_sub(2) as usize).max(1);
    let tbl = flow_table(&process, flow_block, flow_area, compact);
    f.render_stateful_widget(tbl, flow_area, &mut ratatui_state(len, scroll));
}
pub(in crate::tui) fn flow_table(
    process: &ProcessSnapshot,
    block: Block<'static>,
    area: Rect,
    compact: bool,
) -> Table<'static> {
    let inner_width = area.width.saturating_sub(2) as usize;
    let spacing = 6usize;
    let (
        headers,
        port_src_width,
        endpoint_gap_width,
        port_dest_width,
        protocol_width,
        bytes_width,
        addr_min,
    ): ([&str; 7], usize, usize, usize, usize, usize, usize) = if compact {
        (
            ["Src", "Port", "", "Dest", "Port", "Proto", "Bytes"],
            5,
            0,
            5,
            5,
            9,
            8,
        )
    } else {
        (
            [
                "Address (Src)",
                "Port (Src)",
                "",
                "Address (Dest)",
                "Port (Dest)",
                "Protocol",
                "Bytes",
            ],
            10,
            2,
            11,
            8,
            11,
            14,
        )
    };
    let fixed_width = port_src_width
        + endpoint_gap_width
        + port_dest_width
        + protocol_width
        + bytes_width
        + spacing;
    let address_total = inner_width
        .saturating_sub(fixed_width)
        .max(addr_min.saturating_mul(2));
    let src_addr_width = address_total / 2;
    let dest_addr_width = address_total.saturating_sub(src_addr_width);

    let protocol_width = protocol_width.max(1);
    let rows = if process.flows.is_empty() {
        vec![
            Row::new(vec!["No traffic observed", "", "", "", "", "", ""])
                .style(Style::default().fg(palette::muted())),
        ]
    } else {
        process
            .flows
            .iter()
            .map(|flow| {
                let (protocol, protocol_color) = match flow.protocol {
                    crate::capture::TransportProtocol::Tcp => ("TCP", palette::outbound()),
                    crate::capture::TransportProtocol::Udp => ("UDP", palette::violet()),
                };
                Row::new(vec![
                    Cell::from(truncate(
                        &flow.local_ip.to_string(),
                        src_addr_width.saturating_sub(1),
                    )),
                    Cell::from(format!(
                        "{:>width$}",
                        flow.local_port,
                        width = port_src_width
                    ))
                    .style(Style::default().fg(palette::muted())),
                    Cell::from(""),
                    Cell::from(truncate(
                        &flow.remote_ip.to_string(),
                        dest_addr_width.saturating_sub(1),
                    )),
                    Cell::from(format!(
                        "{:>width$}",
                        flow.remote_port,
                        width = port_dest_width
                    ))
                    .style(Style::default().fg(palette::muted())),
                    Cell::from(format!("{protocol:^protocol_width$}"))
                        .style(Style::default().fg(protocol_color)),
                    Cell::from(format!(
                        "{:>width$}",
                        human_bytes(flow.total()),
                        width = bytes_width
                    ))
                    .style(Style::default().fg(palette::warn())),
                ])
            })
            .collect()
    };
    Table::new(
        rows,
        [
            Constraint::Length(src_addr_width as u16),
            Constraint::Length(port_src_width as u16),
            Constraint::Length(endpoint_gap_width as u16),
            Constraint::Length(dest_addr_width as u16),
            Constraint::Length(port_dest_width as u16),
            Constraint::Length(protocol_width as u16),
            Constraint::Length(bytes_width as u16),
        ],
    )
    .header(Row::new(headers).style(Style::default().fg(palette::muted())))
    .column_spacing(1)
    .block(block)
}
pub(in crate::tui) fn relative_last_seen(
    last_seen: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let seconds = now.signed_duration_since(last_seen).num_seconds().max(0);
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 60 * 60 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h ago", seconds / (60 * 60))
    } else {
        format!("{}d ago", seconds / (24 * 60 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::TransportProtocol;
    use crate::stats::ProcFlowSnapshot;
    use crate::tui::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn process_details_show_empty_connection_table() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
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
        assert!(rendered.contains("IP Statistics (lifetime)"));
        assert!(rendered.contains("No traffic observed"));
        assert!(!rendered.contains("IP Statistics (lifetime) 0"));
        assert!(!rendered.contains("IP Statistics (lifetime) 1"));
    }

    #[test]
    fn process_details_render_connection_rows_with_grouped_columns_and_protocol_colors() {
        let mut process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        process.flows = vec![
            ProcFlowSnapshot {
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                local_port: 49_152,
                remote_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                remote_port: 443,
                protocol: TransportProtocol::Tcp,
                recv: 0,
                sent: 40,
                last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
            },
            ProcFlowSnapshot {
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                local_port: 53_535,
                remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
                remote_port: 53,
                protocol: TransportProtocol::Udp,
                recv: 60,
                sent: 0,
                last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
            },
        ]
        .into();
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![process].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
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
        let lines = rendered_lines(&terminal);
        let rendered = lines.join("\n");
        assert!(rendered.contains("IP Statistics (lifetime)"));
        for header in [
            "Address (Src)",
            "Port (Src)",
            "Address (Dest)",
            "Port (Dest)",
            "Protocol",
            "Bytes",
        ] {
            assert!(rendered.contains(header), "missing flow header: {header}");
        }
        assert!(!rendered.contains("Port ( Address"));
        assert!(!rendered.contains("Port ( Protocol"));
        let header_line = lines
            .iter()
            .find(|line| line.contains("Port (Src)"))
            .expect("flow table header");
        let src_port_end = header_line.find("Port (Src)").unwrap() + "Port (Src)".len();
        let dest_address_start = header_line.find("Address (Dest)").unwrap();
        assert_eq!(
            &header_line[src_port_end..dest_address_start],
            "    ",
            "source and destination endpoint groups should have a four-column gap"
        );
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("198.51.100.5"));
        assert!(rendered.contains("203.0.113.8"));
        assert!(rendered.contains("TCP"));
        assert!(rendered.contains("UDP"));
        assert!(rendered.contains("40 B"));
        assert!(!rendered.contains("40 B/s"));
        assert!(!rendered.contains("No traffic observed"));

        let position = |needle: &str| {
            let (y, line) = lines
                .iter()
                .enumerate()
                .find(|(_, line)| line.contains(needle))
                .unwrap_or_else(|| panic!("missing rendered text: {needle}"));
            let byte_x = line.find(needle).unwrap();
            (line[..byte_x].chars().count() as u16, y as u16)
        };
        let buffer = terminal.backend().buffer();
        let tcp = buffer[position("TCP")].fg;
        let udp = buffer[position("UDP")].fg;
        let bytes = buffer[position("40 B")].fg;
        assert_eq!(tcp, palette::outbound());
        assert_eq!(udp, palette::violet());
        assert_ne!(tcp, udp);
        assert_ne!(tcp, bytes);
        assert_ne!(udp, bytes);
    }

    #[test]
    fn processes_page_shows_pending_attribution_in_the_border() {
        let terminal = render_processes_with_pending(1536);

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("proc Processes 0"));
        assert!(rendered.contains("?    1.50 KB"));
        assert_pending_indicator_color(&terminal, palette::warn());
    }

    #[test]
    fn processes_page_shows_zero_pending_attribution_in_muted_fixed_width_text() {
        let terminal = render_processes_with_pending(0);

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("?    0.00  B"));
        assert_pending_indicator_color(&terminal, palette::muted());
    }

    #[test]
    fn processes_page_promotes_pending_attribution_unit_after_rounding() {
        let terminal = render_processes_with_pending(1024 * 1024 - 1);

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("?    1.00 MB"));
        assert!(!rendered.contains("1024.00 KB"));
    }

    #[test]
    fn processes_page_keeps_pending_attribution_value_in_seven_columns() {
        let terminal = render_processes_with_pending(1023 * 1024);

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("? 1023.00 KB"));
    }

    #[test]
    fn processes_page_degrades_pending_attribution_beyond_tb_capacity() {
        let terminal = render_processes_with_pending(1024_u64.pow(5));

        let lines = rendered_lines(&terminal);
        let process_border = lines
            .iter()
            .find(|line| line.contains("proc Processes"))
            .expect("process panel border");
        assert!(process_border.contains("           ?"));
        assert!(!process_border.contains("TB"));
    }

    #[test]
    fn overview_does_not_show_pending_attribution_indicator() {
        let snapshot = TrafficSnapshot {
            pending_attribution_bytes: 1536,
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(!rendered.contains("?    1.50 KB"));
    }

    #[test]
    fn pending_status_title_keeps_a_fixed_slot_and_degrades_when_narrow() {
        let full = pending_status_title(1536, 80);
        let empty = pending_status_title(0, 80);
        let narrow = pending_status_title(1536, 40);

        assert_eq!(full.width(), PENDING_STATUS_SLOT_WIDTH);
        assert_eq!(empty.width(), PENDING_STATUS_SLOT_WIDTH);
        assert_eq!(narrow.width(), 1);
        assert_eq!(narrow.to_string(), "?");
    }

    #[test]
    fn processes_page_renders_attribution_summary_and_attr_column() {
        let snapshot = TrafficSnapshot {
            attribution: crate::stats::AttributionSummary {
                exclusive: crate::stats::ProcTraffic {
                    recv: 900,
                    sent: 800,
                },
                shared: crate::stats::ProcTraffic {
                    recv: 100,
                    sent: 50,
                },
                system: crate::stats::ProcTraffic { recv: 20, sent: 10 },
                unattributed: crate::stats::ProcTraffic { recv: 40, sent: 60 },
            },
            processes: vec![
                {
                    let mut process = ProcessSnapshot::attributed(
                        7,
                        Some(Arc::from("solo")),
                        None,
                        chrono::Utc::now(),
                        900,
                        800,
                    );
                    process.window = crate::stats::ProcTraffic { recv: 90, sent: 80 };
                    process
                },
                {
                    let mut process = ProcessSnapshot::attributed_with_shared(
                        8,
                        Some(Arc::from("mix")),
                        None,
                        chrono::Utc::now(),
                        crate::stats::ProcTraffic::default(),
                        crate::stats::ProcTraffic {
                            recv: 100,
                            sent: 50,
                        },
                        vec![Arc::from("solo")],
                    );
                    process.window = crate::stats::ProcTraffic { recv: 10, sent: 5 };
                    process
                },
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();

        terminal
            .draw(|frame| {
                draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now());
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        // The conservation summary uses lifetime totals, not the 5-minute window.
        assert!(rendered.contains("Total 1.93 KB"));
        assert!(rendered.contains("Exclusive 1.66 KB"));
        assert!(rendered.contains("Shared 150 B"));
        assert!(rendered.contains("System 30 B"));
        assert!(rendered.contains("Unattributed 100 B"));
        assert!(rendered.contains("1.66 KB"));
        assert!(rendered.contains("150 B"));
        // Attr column: worded header, single-letter values (E = exclusive-only, M = mixed)
        assert!(rendered.contains("Attr"));
        assert!(rendered.contains(" E "));
        assert!(rendered.contains(" M "));
    }

    #[test]
    fn selected_process_opens_in_details_and_escape_returns_to_list() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![
                ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl")),
                    Some(Arc::from("/usr/bin/curl")),
                    "2026-07-15T08:00:00Z".parse().unwrap(),
                    40,
                    60,
                ),
                ProcessSnapshot::attributed(
                    8,
                    Some(Arc::from("ssh")),
                    Some(Arc::from("/usr/bin/ssh")),
                    "2026-07-15T08:01:00Z".parse().unwrap(),
                    10,
                    20,
                ),
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        state.proc_scroll = 1;

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );

        assert!(matches!(outcome, KeyOutcome::Changed));
        assert_eq!(
            state.process_detail.as_ref().unwrap().process.pid(),
            Some(8)
        );

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &snapshot,
        );

        assert!(matches!(outcome, KeyOutcome::Changed));
        assert!(state.process_detail.is_none());

        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &snapshot,
            ),
            KeyOutcome::Changed
        ));
        assert!(state.quit_confirm);
        assert!(state.process_detail.is_some());
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &snapshot,
            ),
            KeyOutcome::Quit
        ));
    }

    #[test]
    fn process_attribution_total_line_keeps_equation_values_tight() {
        let process = ProcessSnapshot::attributed_with_shared(
            7,
            Some(Arc::from("app")),
            None,
            chrono::Utc::now(),
            crate::stats::ProcTraffic {
                recv: 556_564,
                sent: 508_365,
            },
            crate::stats::ProcTraffic::default(),
            Vec::new(),
        );
        let lines = process_attribution_detail_lines(&process, true);
        let text: Vec<String> = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        assert!(
            text.last()
                .unwrap()
                .contains("= Exclusive 1.02 MB + Shared 0 B"),
            "total equation should not inherit Recv/Sent padding: {}",
            text.last().unwrap()
        );
        assert!(
            !text[2].contains("Shared      0 B") && !text[2].contains("Shared       0 B"),
            "shared addend should not be right-padded: {}",
            text[2]
        );
    }

    #[test]

    fn process_details_render_all_fields_at_eighty_columns() {
        let path = "/opt/services/payments/releases/2026-07-15/production/workers/payment-processing/payment-worker";
        let mut process = ProcessSnapshot::attributed_with_shared(
            7,
            Some(Arc::from("payment-worker")),
            Some(Arc::from(path)),
            "2026-07-15T08:00:00Z".parse().unwrap(),
            crate::stats::ProcTraffic {
                recv: 1024,
                sent: 2048,
            },
            crate::stats::ProcTraffic {
                recv: 512,
                sent: 1024,
            },
            Vec::new(),
        );
        process.window = crate::stats::ProcTraffic {
            recv: 256,
            sent: 512,
        };
        process.selected = process.window;
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![process].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 32)).unwrap();

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

        let lines = rendered_lines(&terminal);
        let rendered = lines.join("\n");
        assert!(rendered.contains("Process Details"));
        assert!(rendered.contains("payment-worker"));
        assert!(rendered.contains("PID: 7"));
        assert!(rendered.contains("Recv: 1.50 KB"));
        assert!(rendered.contains("Sent: 3.00 KB"));
        assert!(rendered.contains("Total: 4.50 KB"));
        assert!(rendered.contains("Attribution (lifetime)"));
        assert!(rendered.contains("Exclusive:") && rendered.contains("3.00 KB"));
        assert!(rendered.contains("Recv: 1.00 KB"));
        assert!(rendered.contains("Sent: 2.00 KB"));
        assert!(rendered.contains("Selected (total): 768 B  Recv 256 B  Sent 512 B"));
        assert!(
            rendered.contains(
                "Shared traffic is included in Total and may appear in multiple processes."
            )
        );
        assert!(rendered.contains("Last seen: 2m ago"));
        assert!(rendered.contains("Esc:back"));
        let inner_lines = lines
            .iter()
            .map(|line| line.chars().skip(2).take(76).collect::<String>())
            .collect::<Vec<_>>();
        let path_line = inner_lines
            .iter()
            .position(|line| line.starts_with("Path: "))
            .unwrap();
        let displayed_path = inner_lines[path_line]
            .trim_end()
            .strip_prefix("Path:")
            .unwrap()
            .trim_start()
            .to_string();
        assert!(
            displayed_path.contains("/opt/"),
            "path shown: {displayed_path}"
        );
        let path_pos = rendered.find("Path:").expect("path field");
        let last_seen_pos = rendered.find("Last seen:").expect("last seen field");
        let recv_pos = rendered.find("Recv: ").expect("recv field");
        assert!(recv_pos < last_seen_pos, "Recv should precede Last seen");
        assert!(last_seen_pos < path_pos, "Last seen should precede Path");
        for line in lines {
            let field_count = [
                "Name:",
                "PID:",
                "Path:",
                "Recv:",
                "Sent:",
                "Total:",
                "Last seen:",
            ]
            .iter()
            .filter(|field| line.contains(**field))
            .count();
            assert!(field_count <= 2, "detail fields overlap: {line}");
        }
    }

    #[test]
    fn details_update_when_the_same_identity_arrives() {
        let selected = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            None,
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        let latest = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("renamed-curl")),
            None,
            "2026-07-15T08:01:00Z".parse().unwrap(),
            140,
            160,
        );
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![selected].into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    processes: vec![latest.clone()].into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = &state.process_detail.as_ref().unwrap().process;
        assert_eq!((detail.recv, detail.sent), (140, 160));
        assert_eq!(detail.name(), Some("renamed-curl"));
        assert!(detail.path().is_none());
        assert_eq!(
            detail.last_seen(),
            "2026-07-15T08:01:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
    }

    #[test]
    fn same_pid_with_a_different_path_does_not_update_details() {
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("old-curl")),
                Some(Arc::from("/opt/old/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    processes: vec![ProcessSnapshot::attributed(
                        7,
                        Some(Arc::from("new-curl")),
                        Some(Arc::from("/opt/new/curl")),
                        "2026-07-15T08:01:00Z".parse().unwrap(),
                        140,
                        160,
                    )]
                    .into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = state.process_detail.as_ref().unwrap();
        assert_eq!(detail.process.path(), Some("/opt/old/curl"));
        assert_eq!((detail.process.recv, detail.process.sent), (40, 60));
        assert_eq!(detail.paused, Some(TrackingPause::OutsideTopN));
    }

    #[test]
    fn top_n_pause_notice_is_drawn_once_while_paused_details_persist() {
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let now = "2026-07-15T08:05:00Z".parse().unwrap();

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |state, snapshot| {
                terminal
                    .draw(|frame| {
                        draw_at(frame, state, snapshot, "eth0", "host", Instant::now(), now);
                    })
                    .map(|_| ())
            },
            || {
                Ok::<_, std::convert::Infallible>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let first_draw = rendered_lines(&terminal).join("\n");
        assert!(first_draw.contains("Tracking paused: process is no longer in Top-N."));
        assert!(first_draw.contains("Total: 100 B"));
        assert!(first_draw.contains("Last seen: 5m ago"));

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |state, snapshot| {
                terminal
                    .draw(|frame| {
                        draw_at(frame, state, snapshot, "eth0", "host", Instant::now(), now);
                    })
                    .map(|_| ())
            },
            || {
                Ok::<_, std::convert::Infallible>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let second_draw = rendered_lines(&terminal).join("\n");
        assert!(!second_draw.contains("process is no longer in Top-N"));
        assert!(second_draw.contains("Tracking paused"));
        assert!(second_draw.contains("Total: 100 B"));
        assert!(second_draw.contains("Last seen: 5m ago"));
    }

    #[test]
    fn stale_process_data_pauses_details_without_claiming_process_exit() {
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        });
        let stale_process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:01:00Z".parse().unwrap(),
            140,
            160,
        );
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |state, snapshot| {
                terminal
                    .draw(|frame| {
                        draw_at(
                            frame,
                            state,
                            snapshot,
                            "eth0",
                            "host",
                            Instant::now(),
                            "2026-07-15T08:02:00Z".parse().unwrap(),
                        );
                    })
                    .map(|_| ())
            },
            || {
                Ok::<_, std::convert::Infallible>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: false,
                    processes: vec![stale_process.clone()].into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = state.process_detail.as_ref().unwrap();
        assert_eq!(detail.paused, Some(TrackingPause::Stale));
        assert_eq!((detail.process.recv, detail.process.sent), (140, 160));
        assert_eq!(
            detail.process.last_seen(),
            "2026-07-15T08:01:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Tracking paused: process data is stale."));
        assert!(rendered.contains("Total: 300 B"));
        assert!(rendered.contains("Last seen: 1m ago"));
        assert!(!rendered.contains("exited"));
    }

    #[test]
    fn details_resume_when_the_same_identity_returns_to_top_n() {
        let selected = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        let mut snapshot = Arc::new(TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![selected].into(),
            ..TrafficSnapshot::default()
        });
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();
        assert_eq!(
            state.process_detail.as_ref().unwrap().paused,
            Some(TrackingPause::OutsideTopN)
        );

        let resumed = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:03:00Z".parse().unwrap(),
            140,
            160,
        );
        process_iteration(
            &mut state,
            &mut snapshot,
            None,
            |_, _| Ok::<_, ()>(()),
            || {
                Ok::<_, ()>(Some(Arc::new(TrafficSnapshot {
                    process_data_fresh: true,
                    processes: vec![resumed.clone()].into(),
                    ..TrafficSnapshot::default()
                })))
            },
        )
        .unwrap();

        let detail = state.process_detail.as_ref().unwrap();
        assert_eq!(detail.paused, None);
        assert_eq!(detail.pause_notice, None);
        assert_eq!((detail.process.recv, detail.process.sent), (140, 160));
    }

    #[test]
    fn process_detail_scroll_does_not_move_process_list_scroll() {
        let mut process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            None,
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        process.flows = (0..20u16)
            .map(|port| ProcFlowSnapshot {
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                local_port: 49_152,
                remote_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                remote_port: port + 1,
                protocol: TransportProtocol::Tcp,
                recv: 0,
                sent: 10,
                last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
            })
            .collect::<Vec<_>>()
            .into();
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![process].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let list_scroll = state.proc_scroll;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
            &snapshot,
        );
        assert_eq!(state.proc_scroll, list_scroll);
        assert_eq!(state.proc_detail_scroll, 1);
        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
            &snapshot,
        );
        assert!(matches!(outcome, KeyOutcome::Ignored));
        assert_eq!(state.page, Page::Processes);
        assert!(state.process_detail.is_some());
    }
}
