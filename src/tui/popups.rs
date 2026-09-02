//! Modal overlays that interrupt normal page rendering.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::capture::InterfaceInfo;

use crate::palette;

use super::layout::centered_rect;

pub(super) fn draw_quit_confirm(f: &mut ratatui::Frame, area: Rect) {
    let popup = centered_rect(area, 50, 7);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette::warn()))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "Confirm",
                Style::default()
                    .fg(palette::warn())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]));
    let inner = block.inner(popup);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Quit FlowLens?",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "q/y/Enter quit   n/Esc cancel",
            Style::default().fg(palette::muted()),
        )),
    ];
    f.render_widget(Clear, popup);
    f.render_widget(
        Block::default().style(Style::default().bg(palette::bg())),
        popup,
    );
    f.render_widget(block, popup);
    f.render_widget(Paragraph::new(lines), inner);
}

pub(super) fn draw_interface_ip_popup(
    f: &mut ratatui::Frame,
    area: Rect,
    interface: &InterfaceInfo,
    scroll: usize,
) {
    let popup_height = area.height.saturating_sub(4).clamp(8, 18);
    let popup = centered_rect(area, 80, popup_height);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette::border()))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "IP addresses",
                Style::default()
                    .fg(palette::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]));

    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        interface.name.clone(),
        Style::default()
            .fg(palette::strong())
            .add_modifier(Modifier::BOLD),
    )));
    if interface.addresses.is_empty() {
        lines.push(Line::from(Span::styled(
            "No IP addresses",
            Style::default().fg(palette::muted()),
        )));
    } else {
        let mut has_v4 = false;
        let mut has_v6 = false;
        for address in &interface.addresses {
            if address.is_ipv4() && !has_v4 {
                lines.push(Line::from(Span::styled(
                    "IPv4",
                    Style::default().fg(palette::accent()),
                )));
                has_v4 = true;
            } else if address.is_ipv6() && !has_v6 {
                lines.push(Line::from(Span::styled(
                    "IPv6",
                    Style::default().fg(palette::accent()),
                )));
                has_v6 = true;
            }
            lines.push(Line::from(format!("  {address}")));
        }
    }

    let inner = block.inner(popup);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);
    f.render_widget(Clear, popup);
    f.render_widget(
        Block::default().style(Style::default().bg(palette::bg())),
        popup,
    );
    f.render_widget(block, popup);
    let max_scroll = lines.len().saturating_sub(chunks[0].height as usize);
    f.render_widget(
        Paragraph::new(lines)
            .scroll((scroll.min(max_scroll).min(u16::MAX as usize) as u16, 0))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new("j/k or ↑/↓:scroll  PgUp/PgDn:page  Home/End:jump  Esc/i:close")
            .style(Style::default().fg(palette::muted())),
        chunks[1],
    );
}
