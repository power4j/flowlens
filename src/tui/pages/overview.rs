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
