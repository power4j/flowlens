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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectionalFlowRow {
    src_ip: std::net::IpAddr,
    src_port: u16,
    dest_ip: std::net::IpAddr,
    dest_port: u16,
    protocol: crate::capture::TransportProtocol,
    bytes: u64,
    direction: FlowDirection,
}

struct FormattedDirectionalFlowRow {
    src_ip: String,
    src_port: String,
    dest_ip: String,
    dest_port: String,
    protocol: &'static str,
    protocol_color: ratatui::style::Color,
    bytes: String,
    local_is_src: bool,
}

impl DirectionalFlowRow {
    fn local_is_src(&self) -> bool {
        matches!(self.direction, FlowDirection::Outbound)
    }
}

fn directional_flow_parts(
    flow: &crate::stats::ProcFlowSnapshot,
) -> impl Iterator<Item = (FlowDirection, u64)> + '_ {
    [
        (FlowDirection::Outbound, flow.sent),
        (FlowDirection::Inbound, flow.recv),
    ]
    .into_iter()
    .filter(|(_, bytes)| *bytes > 0)
}

fn directional_flow_rows(process: &ProcessSnapshot) -> Vec<DirectionalFlowRow> {
    let mut rows = Vec::with_capacity(process.flows.len().saturating_mul(2));
    for flow in process.flows.iter() {
        rows.extend(directional_flow_parts(flow).map(|(direction, bytes)| {
            let (src_ip, src_port, dest_ip, dest_port) = match direction {
                FlowDirection::Outbound => (
                    flow.local_ip,
                    flow.local_port,
                    flow.remote_ip,
                    flow.remote_port,
                ),
                FlowDirection::Inbound => (
                    flow.remote_ip,
                    flow.remote_port,
                    flow.local_ip,
                    flow.local_port,
                ),
            };
            DirectionalFlowRow {
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                protocol: flow.protocol,
                bytes,
                direction,
            }
        }));
    }
    rows.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.src_ip.cmp(&right.src_ip))
            .then_with(|| left.src_port.cmp(&right.src_port))
            .then_with(|| left.dest_ip.cmp(&right.dest_ip))
            .then_with(|| left.dest_port.cmp(&right.dest_port))
            .then_with(|| protocol_sort_key(left.protocol).cmp(&protocol_sort_key(right.protocol)))
            .then_with(|| {
                direction_sort_key(left.direction).cmp(&direction_sort_key(right.direction))
            })
    });
    rows
}

pub(in crate::tui) fn directional_flow_row_count(process: &ProcessSnapshot) -> usize {
    process
        .flows
        .iter()
        .map(|flow| directional_flow_parts(flow).count())
        .sum()
}

fn protocol_sort_key(protocol: crate::capture::TransportProtocol) -> u8 {
    match protocol {
        crate::capture::TransportProtocol::Tcp => 0,
        crate::capture::TransportProtocol::Udp => 1,
    }
}

fn direction_sort_key(direction: FlowDirection) -> u8 {
    match direction {
        FlowDirection::Outbound => 0,
        FlowDirection::Inbound => 1,
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
            Constraint::Length(if compact || paused.is_some() { 12 } else { 11 }),
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
    let len = directional_flow_row_count(&process);
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
    // Reserve the border and current-row marker, then keep the members of each
    // endpoint group close together. Any remaining width becomes separation
    // between endpoint/protocol/traffic groups instead of padding IP columns.
    let inner_width = area.width.saturating_sub(4) as usize;
    let spacing = 8usize;
    let (
        headers,
        port_src_width,
        port_dest_width,
        protocol_width,
        bytes_width,
        addr_min,
        group_gap_min,
    ): ([&str; 9], usize, usize, usize, usize, usize, usize) = if compact {
        (
            ["Src", "Port", "", "Dest", "Port", "", "Proto", "", "Bytes"],
            5,
            5,
            5,
            9,
            8,
            0,
        )
    } else {
        (
            [
                "Address (Src)",
                "Port (Src)",
                "",
                "Address (Dest)",
                "Port (Dest)",
                "",
                "Protocol",
                "",
                "Bytes",
            ],
            10,
            11,
            8,
            11,
            10,
            2,
        )
    };
    let directional_rows: Vec<_> = directional_flow_rows(process)
        .into_iter()
        .map(|row| {
            let (protocol, protocol_color) = match row.protocol {
                crate::capture::TransportProtocol::Tcp => ("TCP", palette::outbound()),
                crate::capture::TransportProtocol::Udp => ("UDP", palette::violet()),
            };
            FormattedDirectionalFlowRow {
                src_ip: row.src_ip.to_string(),
                src_port: row.src_port.to_string(),
                dest_ip: row.dest_ip.to_string(),
                dest_port: row.dest_port.to_string(),
                protocol,
                protocol_color,
                bytes: human_bytes(row.bytes),
                local_is_src: row.local_is_src(),
            }
        })
        .collect();
    let desired_src_width = directional_rows
        .iter()
        .map(|row| row.src_ip.chars().count())
        .max()
        .unwrap_or(0)
        .max(headers[0].chars().count())
        .max(if directional_rows.is_empty() {
            "No traffic observed".chars().count()
        } else {
            0
        })
        .max(addr_min);
    let desired_dest_width = directional_rows
        .iter()
        .map(|row| row.dest_ip.chars().count())
        .max()
        .unwrap_or(0)
        .max(headers[3].chars().count())
        .max(addr_min);
    let fixed_width = port_src_width
        + port_dest_width
        + protocol_width
        + bytes_width
        + spacing
        + group_gap_min * 3;
    let address_total = inner_width
        .saturating_sub(fixed_width)
        .max(addr_min.saturating_mul(2));
    let desired_total = desired_src_width + desired_dest_width;
    let (src_addr_width, dest_addr_width, extra_gap_width) = if address_total >= desired_total {
        (
            desired_src_width,
            desired_dest_width,
            address_total - desired_total,
        )
    } else {
        let src = (address_total / 2).max(addr_min);
        (src, address_total.saturating_sub(src).max(addr_min), 0)
    };
    let endpoint_gap_width = group_gap_min + extra_gap_width / 3;
    let protocol_gap_width = group_gap_min + (extra_gap_width + 1) / 3;
    let traffic_gap_width = group_gap_min + extra_gap_width.div_ceil(3);

    let rows = if directional_rows.is_empty() {
        vec![
            Row::new(vec!["No traffic observed", "", "", "", "", "", "", "", ""])
                .style(Style::default().fg(palette::muted())),
        ]
    } else {
        directional_rows
            .into_iter()
            .map(|row| {
                let local_style = Style::default()
                    .fg(palette::accent())
                    .add_modifier(Modifier::BOLD);
                Row::new(vec![
                    Cell::from(truncate(&row.src_ip, src_addr_width)).style(if row.local_is_src {
                        local_style
                    } else {
                        Style::default()
                    }),
                    Cell::from(row.src_port).style(Style::default().fg(palette::muted())),
                    Cell::from(""),
                    Cell::from(truncate(&row.dest_ip, dest_addr_width)).style(
                        if row.local_is_src {
                            Style::default()
                        } else {
                            local_style
                        },
                    ),
                    Cell::from(row.dest_port).style(Style::default().fg(palette::muted())),
                    Cell::from(""),
                    Cell::from(Line::from(row.protocol).alignment(Alignment::Center))
                        .style(Style::default().fg(row.protocol_color)),
                    Cell::from(""),
                    Cell::from(Line::from(row.bytes).alignment(Alignment::Right))
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
            Constraint::Length(protocol_gap_width as u16),
            Constraint::Length(protocol_width as u16),
            Constraint::Length(traffic_gap_width as u16),
            Constraint::Length(bytes_width as u16),
        ],
    )
    .header(
        Row::new(headers.into_iter().enumerate().map(|(index, header)| {
            if index == 8 {
                Cell::from(Line::from(header).alignment(Alignment::Right))
            } else {
                Cell::from(header)
            }
        }))
        .style(Style::default().fg(palette::muted())),
    )
    .column_spacing(1)
    .block(block)
    .row_highlight_style(
        Style::default()
            .patch(palette::selection_style())
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ")
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn flow(
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        protocol: TransportProtocol,
        recv: u64,
        sent: u64,
    ) -> ProcFlowSnapshot {
        ProcFlowSnapshot {
            local_ip: IpAddr::V4(Ipv4Addr::from(local_ip)),
            local_port,
            remote_ip: IpAddr::V4(Ipv4Addr::from(remote_ip)),
            remote_port,
            protocol,
            recv,
            sent,
            last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
        }
    }

    fn process_with_flows(flows: Vec<ProcFlowSnapshot>) -> ProcessSnapshot {
        let mut process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            60,
        );
        process.flows = flows.into();
        process
    }

    fn render_flow_table(process: &ProcessSnapshot) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(100, 8)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let table =
                    flow_table(process, Block::default().borders(Borders::ALL), area, false);
                frame.render_stateful_widget(
                    table,
                    area,
                    &mut ratatui_state(directional_flow_row_count(process), 0),
                );
            })
            .unwrap();
        terminal
    }

    fn rendered_cell_color(
        terminal: &Terminal<TestBackend>,
        row_marker: &str,
        cell_text: &str,
    ) -> ratatui::style::Color {
        let lines = rendered_lines(terminal);
        let (y, line) = lines
            .iter()
            .enumerate()
            .find(|(_, line)| line.contains(row_marker))
            .unwrap_or_else(|| panic!("missing rendered row: {row_marker}"));
        let byte_x = line.find(cell_text).unwrap();
        terminal.backend().buffer()[(line[..byte_x].chars().count() as u16, y as u16)].fg
    }

    #[test]
    fn directional_flow_rows_project_sent_traffic_from_local_to_remote() {
        let process = process_with_flows(vec![flow(
            [192, 0, 2, 10],
            49_152,
            [198, 51, 100, 5],
            443,
            TransportProtocol::Tcp,
            0,
            40,
        )]);

        let rows = directional_flow_rows(&process);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(rows[0].src_port, 49_152);
        assert_eq!(rows[0].dest_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)));
        assert_eq!(rows[0].dest_port, 443);
        assert_eq!(rows[0].bytes, 40);
        assert!(rows[0].local_is_src());
    }

    #[test]
    fn directional_flow_rows_project_received_traffic_from_remote_to_local() {
        let process = process_with_flows(vec![flow(
            [192, 0, 2, 10],
            49_152,
            [198, 51, 100, 5],
            443,
            TransportProtocol::Tcp,
            60,
            0,
        )]);

        let rows = directional_flow_rows(&process);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].src_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)));
        assert_eq!(rows[0].src_port, 443);
        assert_eq!(rows[0].dest_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(rows[0].dest_port, 49_152);
        assert_eq!(rows[0].bytes, 60);
        assert!(!rows[0].local_is_src());
    }

    #[test]
    fn directional_flow_rows_split_bidirectional_traffic_and_sort_by_bytes() {
        let process = process_with_flows(vec![flow(
            [192, 0, 2, 10],
            49_152,
            [198, 51, 100, 5],
            443,
            TransportProtocol::Tcp,
            60,
            40,
        )]);

        let rows = directional_flow_rows(&process);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bytes, 60);
        assert_eq!(rows[0].src_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)));
        assert!(!rows[0].local_is_src());
        assert_eq!(rows[1].bytes, 40);
        assert_eq!(rows[1].src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert!(rows[1].local_is_src());
    }

    #[test]
    fn directional_flow_rows_use_every_deterministic_tie_break_field() {
        let rows = directional_flow_rows(&process_with_flows(vec![
            flow(
                [192, 0, 2, 2],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
        ]));
        assert_eq!(rows[0].src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

        let rows = directional_flow_rows(&process_with_flows(vec![
            flow(
                [192, 0, 2, 1],
                49_153,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
        ]));
        assert_eq!(rows[0].src_port, 49_152);

        let rows = directional_flow_rows(&process_with_flows(vec![
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 2],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
        ]));
        assert_eq!(rows[0].dest_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));

        let rows = directional_flow_rows(&process_with_flows(vec![
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                444,
                TransportProtocol::Tcp,
                0,
                10,
            ),
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
        ]));
        assert_eq!(rows[0].dest_port, 443);

        let rows = directional_flow_rows(&process_with_flows(vec![
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Udp,
                0,
                10,
            ),
            flow(
                [192, 0, 2, 1],
                49_152,
                [203, 0, 113, 1],
                443,
                TransportProtocol::Tcp,
                0,
                10,
            ),
        ]));
        assert_eq!(rows[0].protocol, TransportProtocol::Tcp);

        let rows = directional_flow_rows(&process_with_flows(vec![flow(
            [127, 0, 0, 1],
            8080,
            [127, 0, 0, 1],
            8080,
            TransportProtocol::Tcp,
            10,
            10,
        )]));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].direction, FlowDirection::Outbound);
        assert_eq!(rows[1].direction, FlowDirection::Inbound);
    }

    #[test]
    fn directional_flow_row_count_matches_projected_rows_for_all_inclusion_shapes() {
        let cases = [
            Vec::new(),
            vec![flow(
                [192, 0, 2, 1],
                1,
                [198, 51, 100, 1],
                2,
                TransportProtocol::Tcp,
                0,
                0,
            )],
            vec![flow(
                [192, 0, 2, 1],
                1,
                [198, 51, 100, 1],
                2,
                TransportProtocol::Tcp,
                0,
                10,
            )],
            vec![flow(
                [192, 0, 2, 1],
                1,
                [198, 51, 100, 1],
                2,
                TransportProtocol::Tcp,
                20,
                10,
            )],
            vec![
                flow(
                    [192, 0, 2, 1],
                    1,
                    [198, 51, 100, 1],
                    2,
                    TransportProtocol::Tcp,
                    20,
                    10,
                ),
                flow(
                    [192, 0, 2, 2],
                    3,
                    [198, 51, 100, 2],
                    4,
                    TransportProtocol::Udp,
                    0,
                    0,
                ),
                flow(
                    [192, 0, 2, 3],
                    5,
                    [198, 51, 100, 3],
                    6,
                    TransportProtocol::Udp,
                    30,
                    0,
                ),
            ],
        ];

        for flows in cases {
            let process = process_with_flows(flows);
            assert_eq!(
                directional_flow_row_count(&process),
                directional_flow_rows(&process).len()
            );
        }
    }

    fn benchmark_process(
        flow_count: usize,
        bidirectional: bool,
        ipv6: bool,
        equal_bytes: bool,
    ) -> ProcessSnapshot {
        let flows = (0..flow_count)
            .map(|index| {
                let local_ip = if ipv6 {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, index as u16))
                } else {
                    IpAddr::V4(Ipv4Addr::new(10, 0, (index / 256) as u8, index as u8))
                };
                let remote_ip = if ipv6 {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, index as u16))
                } else {
                    IpAddr::V4(Ipv4Addr::new(198, 51, (index / 256) as u8, index as u8))
                };
                let bytes = if equal_bytes { 1_024 } else { index as u64 + 1 };
                ProcFlowSnapshot {
                    local_ip,
                    local_port: 10_000 + index as u16,
                    remote_ip,
                    remote_port: 20_000 + index as u16,
                    protocol: if index % 2 == 0 {
                        TransportProtocol::Tcp
                    } else {
                        TransportProtocol::Udp
                    },
                    recv: if bidirectional { bytes } else { 0 },
                    sent: bytes,
                    last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
                }
            })
            .collect();
        process_with_flows(flows)
    }

    fn benchmark_distribution(
        label: &str,
        warmup_iterations: usize,
        measured_iterations: usize,
        mut operation: impl FnMut(),
    ) {
        for _ in 0..warmup_iterations {
            operation();
        }
        let mut samples = Vec::with_capacity(measured_iterations);
        for _ in 0..measured_iterations {
            let started = std::time::Instant::now();
            operation();
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let percentile = |percent: usize| {
            let index = samples
                .len()
                .saturating_mul(percent)
                .div_ceil(100)
                .saturating_sub(1);
            samples[index.min(samples.len().saturating_sub(1))]
        };
        println!(
            "{label}: median={:?}, p95={:?}, max={:?}",
            percentile(50),
            percentile(95),
            samples.last().copied().unwrap_or_default()
        );
    }

    #[test]
    #[ignore = "manual release performance measurement"]
    fn directional_flow_benchmark() {
        const WARMUP: usize = 100;
        const ITERATIONS: usize = 1_000;
        let single_ipv4 = benchmark_process(256, false, false, false);
        let bidirectional_ipv4 = benchmark_process(256, true, false, false);
        let bidirectional_ipv6 = benchmark_process(256, true, true, false);
        let equal_bytes = benchmark_process(256, true, false, true);
        let large_bidirectional = benchmark_process(4_096, true, false, false);

        for (label, process) in [
            ("projection 256 single-direction IPv4", &single_ipv4),
            ("projection 256 bidirectional IPv4", &bidirectional_ipv4),
            ("projection 256 bidirectional IPv6", &bidirectional_ipv6),
            ("projection 256 bidirectional equal-byte ties", &equal_bytes),
            ("projection 4096 bidirectional IPv4", &large_bidirectional),
        ] {
            benchmark_distribution(label, WARMUP, ITERATIONS, || {
                std::hint::black_box(directional_flow_rows(std::hint::black_box(process)));
            });
        }

        let area = Rect::new(0, 0, 200, 60);
        benchmark_distribution(
            "flow_table 512 directional rows at 200x60",
            WARMUP,
            ITERATIONS,
            || {
                std::hint::black_box(flow_table(
                    std::hint::black_box(&bidirectional_ipv4),
                    Block::default().borders(Borders::ALL),
                    area,
                    false,
                ));
            },
        );
        benchmark_distribution(
            "flow_table 8192 directional rows at 200x60",
            WARMUP,
            ITERATIONS,
            || {
                std::hint::black_box(flow_table(
                    std::hint::black_box(&large_bidirectional),
                    Block::default().borders(Borders::ALL),
                    area,
                    false,
                ));
            },
        );

        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![bidirectional_ipv4.clone()].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &snapshot,
        );
        let mut terminal = Terminal::new(TestBackend::new(200, 60)).unwrap();
        let now: chrono::DateTime<chrono::Utc> = "2026-07-15T08:02:00Z".parse().unwrap();
        benchmark_distribution(
            "full process detail draw 512 rows at 200x60",
            WARMUP,
            ITERATIONS,
            || {
                terminal
                    .draw(|frame| {
                        draw_at(
                            frame,
                            &mut state,
                            &snapshot,
                            "eth0",
                            "host",
                            Instant::now(),
                            now,
                        )
                    })
                    .unwrap();
            },
        );

        let rows = directional_flow_rows(&bidirectional_ipv4);
        println!(
            "DirectionalFlowRow size={} bytes, default rows len={}, capacity={}",
            std::mem::size_of::<DirectionalFlowRow>(),
            rows.len(),
            rows.capacity()
        );
    }

    #[test]
    #[ignore = "manual release peak working-set measurement"]
    fn directional_flow_memory_harness() {
        const WARMUP: usize = 100;
        const DRAWS: usize = 5_000;
        let process = benchmark_process(256, true, false, false);
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
        let mut terminal = Terminal::new(TestBackend::new(200, 60)).unwrap();
        let now: chrono::DateTime<chrono::Utc> = "2026-07-15T08:02:00Z".parse().unwrap();
        for _ in 0..WARMUP + DRAWS {
            terminal
                .draw(|frame| {
                    draw_at(
                        frame,
                        &mut state,
                        &snapshot,
                        "eth0",
                        "host",
                        Instant::now(),
                        now,
                    )
                })
                .unwrap();
        }
        println!(
            "memory harness: connections=256, directional_rows=512, terminal=200x60, warmup={WARMUP}, draws={DRAWS}"
        );
    }

    #[test]
    fn all_zero_flows_render_the_same_empty_state_without_reserving_address_width() {
        let empty = process_with_flows(Vec::new());
        let mut zero = process_with_flows(Vec::new());
        zero.flows = vec![ProcFlowSnapshot {
            local_ip: IpAddr::V6(
                "2001:db8:1111:2222:3333:4444:5555:6666"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            ),
            local_port: 49_152,
            remote_ip: IpAddr::V6(
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            ),
            remote_port: 443,
            protocol: TransportProtocol::Tcp,
            recv: 0,
            sent: 0,
            last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
        }]
        .into();

        let empty_lines = rendered_lines(&render_flow_table(&empty));
        let zero_lines = rendered_lines(&render_flow_table(&zero));

        assert_eq!(zero_lines, empty_lines);
        assert!(zero_lines.join("\n").contains("No traffic observed"));
    }

    #[test]
    fn loopback_received_traffic_highlights_only_the_normalized_local_side() {
        let process = process_with_flows(vec![flow(
            [127, 0, 0, 1],
            49_152,
            [127, 0, 0, 2],
            443,
            TransportProtocol::Tcp,
            20,
            0,
        )]);
        let terminal = render_flow_table(&process);

        assert_ne!(
            rendered_cell_color(&terminal, "20 B", "127.0.0.2"),
            palette::accent()
        );
        assert_eq!(
            rendered_cell_color(&terminal, "20 B", "127.0.0.1"),
            palette::accent()
        );
    }

    #[test]
    fn shared_attribution_still_highlights_only_the_normalized_local_endpoint() {
        let mut process = ProcessSnapshot::attributed_with_shared(
            7,
            Some(Arc::from("shared-client")),
            None,
            "2026-07-15T08:00:00Z".parse().unwrap(),
            crate::stats::ProcTraffic::default(),
            crate::stats::ProcTraffic { recv: 30, sent: 0 },
            Vec::new(),
        );
        process.flows = vec![flow(
            [10, 11, 12, 31],
            22_010,
            [95, 25, 28, 161],
            33_718,
            TransportProtocol::Udp,
            30,
            0,
        )]
        .into();
        let terminal = render_flow_table(&process);

        assert_ne!(
            rendered_cell_color(&terminal, "30 B", "95.25.28.161"),
            palette::accent()
        );
        assert_eq!(
            rendered_cell_color(&terminal, "30 B", "10.11.12.31"),
            palette::accent()
        );
    }

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
        let outbound_row = lines
            .iter()
            .find(|line| {
                line.contains("192.0.2.10")
                    && line.contains("198.51.100.5")
                    && line.contains("40 B")
            })
            .expect("outbound flow table row");
        let inbound_row = lines
            .iter()
            .find(|line| {
                line.contains("203.0.113.8") && line.contains("192.0.2.10") && line.contains("60 B")
            })
            .expect("inbound flow table row");
        assert!(
            outbound_row.find("192.0.2.10").unwrap() < outbound_row.find("198.51.100.5").unwrap(),
            "sent traffic should render local to remote: {outbound_row}"
        );
        assert!(
            inbound_row.find("203.0.113.8").unwrap() < inbound_row.find("192.0.2.10").unwrap(),
            "received traffic should render remote to local: {inbound_row}"
        );
        let local_address_end = outbound_row.find("192.0.2.10").unwrap() + "192.0.2.10".len();
        let local_port_start = outbound_row.find("49152").unwrap();
        assert!(
            local_port_start.saturating_sub(local_address_end) <= 4,
            "source address and port should stay visually grouped: {outbound_row}"
        );
        let src_port_end = outbound_row.find("49152").unwrap() + "49152".len();
        let dest_address_start = outbound_row.find("198.51.100.5").unwrap();
        assert!(
            dest_address_start.saturating_sub(src_port_end) >= 4,
            "source and destination endpoint groups should remain separated: {outbound_row}"
        );
        let selected_prefix = &inbound_row[..inbound_row.find("203.0.113.8").unwrap()];
        assert!(
            selected_prefix.ends_with("> "),
            "the largest directional row should have a current-row marker: {inbound_row}"
        );
        let bytes_header_end = header_line.find("Bytes").unwrap() + "Bytes".len();
        let bytes_value_end = outbound_row.find("40 B").unwrap() + "40 B".len();
        assert_eq!(
            bytes_header_end, bytes_value_end,
            "Bytes header and values should share a right edge"
        );
        assert!(rendered.contains("TCP"));
        assert!(rendered.contains("UDP"));
        assert!(!rendered.contains("40 B/s"));
        assert!(!rendered.contains("No traffic observed"));

        let position_in = |line: &str, needle: &str| {
            let y = lines
                .iter()
                .position(|candidate| candidate == line)
                .unwrap();
            let byte_x = line.find(needle).unwrap();
            (line[..byte_x].chars().count() as u16, y as u16)
        };
        let buffer = terminal.backend().buffer();
        assert_eq!(
            buffer[position_in(outbound_row, "192.0.2.10")].fg,
            palette::accent()
        );
        assert_ne!(
            buffer[position_in(outbound_row, "198.51.100.5")].fg,
            palette::accent()
        );
        assert_ne!(
            buffer[position_in(inbound_row, "203.0.113.8")].fg,
            palette::accent()
        );
        assert_eq!(
            buffer[position_in(inbound_row, "192.0.2.10")].fg,
            palette::accent()
        );
        let tcp = buffer[position_in(outbound_row, "TCP")].fg;
        let udp = buffer[position_in(inbound_row, "UDP")].fg;
        let bytes = buffer[position_in(outbound_row, "40 B")].fg;
        assert_eq!(tcp, palette::outbound());
        assert_eq!(udp, palette::violet());
        assert_ne!(tcp, udp);
        assert_ne!(tcp, bytes);
        assert_ne!(udp, bytes);
    }

    #[test]
    fn narrow_process_details_render_directional_ipv6_rows_with_visible_selection() {
        let mut process = process_with_flows(Vec::new());
        process.flows = vec![ProcFlowSnapshot {
            local_ip: IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()),
            local_port: 49_152,
            remote_ip: IpAddr::V6(
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            ),
            remote_port: 443,
            protocol: TransportProtocol::Tcp,
            recv: 60,
            sent: 40,
            last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
        }]
        .into();

        for width in [68, 80] {
            let snapshot = TrafficSnapshot {
                process_data_fresh: true,
                processes: vec![process.clone()].into(),
                ..TrafficSnapshot::default()
            };
            let mut state = AppState::new();
            state.page = Page::Processes;
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                &snapshot,
            );
            let mut terminal = Terminal::new(TestBackend::new(width, 36)).unwrap();
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
            let selected_row = lines
                .iter()
                .find(|line| line.contains("60 B") && line.contains("TCP"))
                .unwrap_or_else(|| panic!("missing selected IPv6 row at width {width}"));
            let unselected_row = lines
                .iter()
                .find(|line| line.contains("40 B") && line.contains("TCP"))
                .unwrap_or_else(|| panic!("missing unselected IPv6 row at width {width}"));
            for row in [selected_row, unselected_row] {
                assert!(
                    row.contains("fd00::1"),
                    "missing local IPv6 at width {width}: {row}"
                );
                assert!(
                    row.contains("2001:db8"),
                    "missing truncated remote IPv6 at width {width}: {row}"
                );
                assert!(
                    row.contains("49152"),
                    "missing local port at width {width}: {row}"
                );
                assert!(
                    row.contains("443"),
                    "missing remote port at width {width}: {row}"
                );
                assert!(
                    row.contains("TCP"),
                    "missing protocol at width {width}: {row}"
                );
            }
            let selected_prefix = &selected_row[..selected_row.find("2001:db8").unwrap()];
            assert!(
                selected_prefix.ends_with("> "),
                "selected IPv6 row should retain its marker at width {width}: {selected_row}"
            );

            let position = |line: &str, needle: &str| {
                let y = lines
                    .iter()
                    .position(|candidate| candidate == line)
                    .unwrap();
                let byte_x = line.find(needle).unwrap();
                (line[..byte_x].chars().count() as u16, y as u16)
            };
            let buffer = terminal.backend().buffer();
            let selected_style = buffer[position(selected_row, "fd00::1")].style();
            let unselected_style = buffer[position(unselected_row, "fd00::1")].style();
            assert_ne!(
                selected_style, unselected_style,
                "selected IPv6 row should have a distinct background or reverse style at width {width}"
            );
        }
    }

    #[test]
    fn compact_process_details_right_align_bytes_header_with_values() {
        let mut process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            Some(Arc::from("/usr/bin/curl")),
            "2026-07-15T08:00:00Z".parse().unwrap(),
            40,
            0,
        );
        process.flows = vec![ProcFlowSnapshot {
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            local_port: 49_152,
            remote_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            remote_port: 443,
            protocol: TransportProtocol::Tcp,
            recv: 0,
            sent: 40,
            last_seen: "2026-07-15T08:00:00Z".parse().unwrap(),
        }]
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
        let mut terminal = Terminal::new(TestBackend::new(71, 32)).unwrap();
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
        let header_line = lines
            .iter()
            .find(|line| line.contains("Proto") && line.contains("Bytes"))
            .expect("compact flow table header");
        let bytes_row = lines
            .iter()
            .find(|line| line.contains("198.51.100.5") && line.contains("40 B"))
            .expect("compact flow table row");
        let bytes_header_end = header_line.find("Bytes").unwrap() + "Bytes".len();
        let bytes_value_end = bytes_row.find("40 B").unwrap() + "40 B".len();
        assert_eq!(
            bytes_header_end, bytes_value_end,
            "compact Bytes header and values should share a right edge"
        );
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
    fn settings_overlay_preserves_process_details_and_scroll_when_closed() {
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
        state.proc_detail_scroll = 7;
        state.proc_detail_view_height = 3;

        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(state.settings_open);
        assert_eq!(
            state.process_detail.as_ref().unwrap().process.pid(),
            Some(7)
        );
        assert_eq!(state.proc_detail_scroll, 7);
        assert_eq!(state.proc_detail_view_height, 3);

        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(!state.settings_open);
        assert_eq!(
            state.process_detail.as_ref().unwrap().process.pid(),
            Some(7)
        );
        assert_eq!(state.proc_detail_scroll, 7);
        assert_eq!(state.proc_detail_view_height, 3);
    }

    #[test]
    fn settings_overlay_does_not_consume_a_hidden_process_pause_notice() {
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
        state
            .process_detail
            .as_mut()
            .unwrap()
            .pause(TrackingPause::OutsideTopN);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        send_key(&mut state, KeyCode::Char('o'));
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        assert_eq!(
            state.process_detail.as_ref().unwrap().pause_notice,
            Some(TrackingPause::OutsideTopN)
        );

        send_key(&mut state, KeyCode::Char('o'));
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        assert!(
            rendered_lines(&terminal)
                .join("\n")
                .contains("Tracking paused: process is no longer in Top-N.")
        );
        assert_eq!(state.process_detail.as_ref().unwrap().pause_notice, None);
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
        assert!(rendered.contains("o:settings"));
        let attr_legend_line = lines
            .iter()
            .position(|line| line.contains("Attr: E = exclusive only"))
            .expect("attribution legend");
        let flow_title_line = lines
            .iter()
            .position(|line| line.contains("IP Statistics (lifetime)"))
            .expect("IP Statistics title");
        assert_eq!(
            flow_title_line,
            attr_legend_line + 2,
            "the IP Statistics panel should immediately follow the attribution panel"
        );
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
        process.flows = (0..10u16)
            .map(|port| ProcFlowSnapshot {
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                local_port: 49_152,
                remote_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                remote_port: port + 1,
                protocol: TransportProtocol::Tcp,
                recv: 5,
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
        state.proc_detail_view_height = 5;
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
            &snapshot,
        );
        assert_eq!(state.proc_detail_scroll, 6);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
            &snapshot,
        );
        assert_eq!(state.proc_detail_scroll, 1);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
            &snapshot,
        );
        assert_eq!(state.proc_detail_scroll, 19);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &snapshot,
        );
        assert_eq!(
            state.proc_detail_scroll, 19,
            "selection should remain on the final flow instead of entering a dead range"
        );

        state.process_detail.as_mut().unwrap().process.flows = vec![flow(
            [192, 0, 2, 10],
            49_152,
            [198, 51, 100, 5],
            443,
            TransportProtocol::Tcp,
            0,
            10,
        )]
        .into();
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        terminal
            .draw(|frame| {
                draw_process_detail(
                    frame,
                    frame.area(),
                    &mut state,
                    &snapshot,
                    "2026-07-15T08:02:00Z".parse().unwrap(),
                );
            })
            .unwrap();
        assert_eq!(
            state.proc_detail_scroll, 0,
            "a shorter refreshed snapshot should clamp selection to its new final row"
        );

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
