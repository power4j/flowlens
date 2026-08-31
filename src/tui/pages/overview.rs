//! Overview page: traffic summary panels.

use ratatui::layout::{Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::palette;
use crate::report::human_bytes;
use crate::stats::TrafficSnapshot;

use super::domains::draw_domain_preview;
use super::ips::draw_ip_preview;
use super::processes::draw_process_preview;
use crate::tui::layout::*;
use crate::tui::state::*;

pub(in crate::tui) fn draw_overview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    // Row-based layout: every row is either a full-width panel or two
    // equal 50/50 columns. Wide/Standard use three rows; Compact stacks five rows.
    //
    // Height allocation:
    //   * Wide/Standard — Traffic fixed at top; the Process|Domain row gets
    //     Fill(2) and the IP row gets Fill(1) so the previews of processes and
    //     domains (the primary diagnostic dimensions) take the larger share.
    //   * Compact — Traffic fixed at top; the four preview panels split the
    //     remaining space evenly (Fill(1) each) since vertical space is scarce.
    match mode {
        LayoutMode::Wide | LayoutMode::Standard => {
            let rows = Layout::default()
                .direction(LayoutDir::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(1),
                    Constraint::Fill(2),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .split(area);
            draw_traffic(f, rows[0], snapshot);

            // Force compact tables in the half-width preview columns so the
            // full five-column layout does not cramp at 50% width.
            let preview_mode = LayoutMode::Compact;
            let mid = Layout::default()
                .direction(LayoutDir::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(1),
                    Constraint::Percentage(50),
                ])
                .split(rows[2]);
            draw_process_preview(f, mid[0], snapshot, preview_mode, now);
            draw_domain_preview(f, mid[2], snapshot, preview_mode, now);

            let bottom = Layout::default()
                .direction(LayoutDir::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(1),
                    Constraint::Percentage(50),
                ])
                .split(rows[4]);
            draw_ip_preview(f, bottom[0], snapshot, true, now);
            draw_ip_preview(f, bottom[2], snapshot, false, now);
        }
        LayoutMode::Compact => {
            let rows = Layout::default()
                .direction(LayoutDir::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .split(area);
            draw_traffic(f, rows[0], snapshot);
            draw_process_preview(f, rows[2], snapshot, mode, now);
            draw_domain_preview(f, rows[4], snapshot, mode, now);
            draw_ip_preview(f, rows[6], snapshot, true, now);
            draw_ip_preview(f, rows[8], snapshot, false, now);
        }
    }
}

pub(in crate::tui) fn draw_traffic(f: &mut ratatui::Frame, area: Rect, snapshot: &TrafficSnapshot) {
    let block = panel_block(
        "net",
        "Traffic",
        None,
        palette::violet(),
        palette::border(),
        None,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);

    let total = snapshot.in_bytes.saturating_add(snapshot.out_bytes);
    let lines = vec![
        traffic_line(
            "IN total",
            palette::inbound(),
            ratio(snapshot.in_bytes, total),
            &human_bytes(snapshot.in_bytes),
            inner.width,
        ),
        traffic_line(
            "OUT total",
            palette::outbound(),
            ratio(snapshot.out_bytes, total),
            &human_bytes(snapshot.out_bytes),
            inner.width,
        ),
        traffic_line(
            "Combined",
            palette::accent_dim(),
            if total > 0 { 1.0 } else { 0.0 },
            &human_bytes(total),
            inner.width,
        ),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

pub(in crate::tui) fn ratio(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64
    }
}

pub(in crate::tui) fn traffic_line(
    label: &str,
    color: Color,
    ratio: f64,
    value: &str,
    width: u16,
) -> Line<'static> {
    pub(in crate::tui) const LABEL_WIDTH: usize = 10;
    let value_width = value.chars().count();
    let bar_width = (width as usize).saturating_sub(LABEL_WIDTH + value_width + 2);
    let filled = ((bar_width as f64 * ratio).round() as usize).min(bar_width);
    Line::from(vec![
        Span::styled(format!("{label:<LABEL_WIDTH$}"), Style::default().fg(color)),
        Span::styled("█".repeat(filled), Style::default().fg(color)),
        Span::styled(
            "─".repeat(bar_width.saturating_sub(filled)),
            Style::default().fg(palette::border()),
        ),
        Span::styled(format!("  {value}"), Style::default().fg(palette::strong())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn wide_overview_uses_row_layout_with_equal_columns() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let lines = rendered_lines(&terminal);
        let position = |label: &str| {
            lines
                .iter()
                .enumerate()
                .find_map(|(y, line)| {
                    line.find(label)
                        .map(|byte_offset| (line[..byte_offset].chars().count(), y))
                })
                .unwrap_or_else(|| panic!("missing panel label: {label}"))
        };
        let traffic = position("Traffic");
        let inbound = position("Inbound IPs");
        let outbound = position("Outbound IPs");
        let processes = position("Top Processes");
        let domains = position("Top Domains");

        // Row 1: Traffic spans the full width at the top.
        assert!(traffic.1 < processes.1);
        assert!(traffic.1 < inbound.1);

        // Row 2: Process (left) and Domain (right) share the same band.
        assert_eq!(processes.1, domains.1);
        assert!(processes.0 < 50);
        assert!(domains.0 >= 50);

        // Row 3: Inbound (left) and Outbound (right) share a lower band.
        assert_eq!(inbound.1, outbound.1);
        assert!(inbound.1 > processes.1);
        assert!(inbound.0 < 50);
        assert!(outbound.0 >= 50);

        // Two equal columns: the right column sits ~half the body width to the
        // right of the left column.
        let body_width: usize = 120 - 4; // 2-char margin each side
        let half_width = body_width / 2;
        assert!((domains.0 - processes.0) >= half_width.saturating_sub(2));
        assert!((domains.0 - processes.0) <= half_width + 2);
        assert!((outbound.0 - inbound.0) >= half_width.saturating_sub(2));
        assert!((outbound.0 - inbound.0) <= half_width + 2);

        // Palette: the "n" prefix of the Traffic panel keeps the violet tint.
        let net_cell = &terminal.backend().buffer()[(traffic.0 as u16 - 4, traffic.1 as u16)];
        assert_eq!(net_cell.symbol(), "n");
        assert_eq!(net_cell.fg, Color::Rgb(167, 139, 250));
        assert_eq!(net_cell.bg, Color::Rgb(9, 13, 20));
    }

    #[test]
    fn standard_overview_uses_row_layout_with_equal_columns() {
        // 80-column terminal lands in Standard mode (80..120). The Overview
        // still arranges its panels in the row-based layout: Traffic at top,
        // then Process|Domain on the same band, then Inbound|Outbound IPs on
        // the next.
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let lines = rendered_lines(&terminal);
        let position = |label: &str| {
            lines
                .iter()
                .enumerate()
                .find_map(|(y, line)| {
                    line.find(label)
                        .map(|byte_offset| (line[..byte_offset].chars().count(), y))
                })
                .unwrap_or_else(|| panic!("missing panel label: {label}"))
        };
        let traffic = position("Traffic");
        let processes = position("Top Processes");
        let domains = position("Top Domains");
        let inbound = position("Inbound IPs");
        let outbound = position("Outbound IPs");

        assert!(traffic.1 < processes.1);
        assert!(traffic.1 < inbound.1);

        assert_eq!(processes.1, domains.1);
        assert!(processes.0 < domains.0);

        assert_eq!(inbound.1, outbound.1);
        assert!(inbound.1 > processes.1);
        assert!(inbound.0 < outbound.0);
    }

    #[test]
    fn compact_overview_stacks_five_rows_without_side_by_side_panels() {
        // <80 columns triggers Compact mode. Overview stacks Traffic / Process
        // / Domain / Inbound / Outbound IP vertically — no side-by-side panels.
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(72, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let lines = rendered_lines(&terminal);
        let position = |label: &str| {
            lines
                .iter()
                .enumerate()
                .find_map(|(y, line)| {
                    line.find(label)
                        .map(|byte_offset| (line[..byte_offset].chars().count(), y))
                })
                .unwrap_or_else(|| panic!("missing panel label: {label}"))
        };
        let traffic = position("Traffic");
        let processes = position("Top Processes");
        let domains = position("Top Domains");
        let inbound = position("Inbound IPs");
        let outbound = position("Outbound IPs");

        // Vertical order: Traffic < Process < Domain < Inbound IP < Outbound IP.
        assert!(traffic.1 < processes.1);
        assert!(processes.1 < domains.1);
        assert!(domains.1 < inbound.1);
        assert!(inbound.1 < outbound.1);
    }

    #[test]
    fn overview_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
            attribution: Default::default(),
            ranking: Default::default(),
            in_bytes: 1024,
            out_bytes: 2048,
            pending_attribution_bytes: 0,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl --silent")),
                Some(Arc::from("/usr/bin/curl")),
                chrono::Utc::now(),
                1024,
                2048,
            )]
            .into(),
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
            outbound_domains: vec![OutboundDomainSnapshot::new(
                Arc::from("example.com"),
                1024,
                2048,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
            process_data_fresh: false,
            diagnostics: None,
        };
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("curl --silent"));
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("198.51.100.20"));
        assert!(rendered.contains("Top Processes"));
        assert!(rendered.contains("Top Domains"));
        assert!(rendered.contains("example.com"));
        assert!(!rendered.contains("/usr/bin/curl"));
    }
}
