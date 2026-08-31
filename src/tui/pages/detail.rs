//! Process detail page: attribution breakdown.

use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::palette;
use crate::report::human_bytes;
use crate::stats::{ProcessSnapshot, RankWindow, TrafficSnapshot};

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
    vec![
        Line::from(format!(
            "  {label:<label_width$} {total}  Recv {recv}  Sent {sent}",
            label = "Exclusive:",
            total = value(exclusive.total()),
            recv = value(exclusive.recv),
            sent = value(exclusive.sent),
        )),
        Line::from(format!(
            "  {label:<label_width$} {total}  Recv {recv}  Sent {sent}",
            label = "Shared:",
            total = value(shared.total()),
            recv = value(shared.recv),
            sent = value(shared.sent),
        )),
        Line::from(format!(
            "  {label:<label_width$} {total} = Exclusive {exclusive} + Shared {shared}",
            label = "Total:",
            total = value(process.total()),
            exclusive = human_bytes(exclusive.total()),
            shared = human_bytes(shared.total()),
        )),
    ]
}

pub(in crate::tui) fn draw_process_detail(
    f: &mut ratatui::Frame,
    area: Rect,
    detail: &ProcessDetail,
    snapshot: &TrafficSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) {
    let process = &detail.process;
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Name: "),
            process_name_span(process, usize::MAX),
        ]),
        Line::from(format!(
            "PID: {}",
            process
                .pid()
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string())
        )),
        Line::from(format!("Path: {}", process.path().unwrap_or("-"))),
        Line::from(format!(
            "Last seen: {}",
            relative_last_seen(process.last_seen(), now)
        )),
        Line::from(""),
        Line::from(format!("Recv: {}", human_bytes(process.recv))),
        Line::from(format!("Sent: {}", human_bytes(process.sent))),
        Line::from(format!("Total: {}", human_bytes(process.total()))),
        Line::from(""),
        Line::from(Span::styled(
            "Attribution (lifetime)",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        )),
    ];
    lines.extend(process_attribution_detail_lines(process));
    let selected = if snapshot.ranking.window == RankWindow::Cumulative {
        process.selected
    } else {
        process.rank
    };
    lines.push(Line::from(format!(
        "Selected ({}): {}  Recv {}  Sent {}",
        ranking_window_indicator(snapshot),
        format_rank_value(snapshot, selected.total()),
        format_rank_value(snapshot, selected.recv),
        format_rank_value(snapshot, selected.sent)
    )));
    if snapshot.ranking.window == RankWindow::Cumulative {
        lines.push(Line::from(format!(
            "Rank (total): {}  Recv {}  Sent {}",
            human_bytes(process.total()),
            human_bytes(process.recv),
            human_bytes(process.sent)
        )));
    } else {
        lines.push(Line::from(format!(
            "Rank ({}): {}  Recv {}  Sent {}",
            ranking_window_indicator(snapshot),
            format_rank_value(snapshot, process.rank.total()),
            format_rank_value(snapshot, process.rank.recv),
            format_rank_value(snapshot, process.rank.sent)
        )));
    }
    if !process.attribution.shared_with.is_empty() {
        lines.push(Line::from(format!(
            "  Shared with: {}",
            process.attribution.shared_with.join(", ")
        )));
    }
    lines.push(Line::from(
        "Shared traffic is included in Total and may appear in multiple processes.",
    ));
    // ADR 0013: the list's Attr column legend lives in the detail page's
    // Attribution area.
    lines.push(Line::from(Span::styled(
        "  Attr: E = exclusive only, M = mixed (includes shared)",
        Style::default().fg(palette::muted()),
    )));
    if detail.paused.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Tracking paused",
            Style::default()
                .fg(palette::warn())
                .add_modifier(Modifier::BOLD),
        )));
    }
    let block = panel_block(
        "proc",
        "Process Details",
        None,
        palette::coral(),
        palette::border(),
        None,
    );
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
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
