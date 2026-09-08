//! Modal overlays that interrupt normal page rendering.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};

use crate::capture::InterfaceInfo;

use crate::palette;

use super::layout::{centered_rect, ratatui_state};

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
    selected: usize,
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

    let inner = block.inner(popup);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);
    f.render_widget(Clear, popup);
    f.render_widget(
        Block::default().style(Style::default().bg(palette::bg())),
        popup,
    );
    f.render_widget(block, popup);
    f.render_widget(
        Paragraph::new(Span::styled(
            interface.name.clone(),
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        )),
        chunks[0],
    );
    if interface.addresses.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "No IP addresses",
                Style::default().fg(palette::muted()),
            )),
            chunks[1],
        );
    } else {
        let rows = interface.addresses.iter().map(|address| {
            let family = if address.is_ipv4() { "IPv4" } else { "IPv6" };
            Row::new([Cell::from(Line::from(vec![
                Span::styled(family, Style::default().fg(palette::accent())),
                Span::raw("  "),
                Span::raw(address.to_string()),
            ]))])
        });
        let table = Table::new(rows, [Constraint::Min(1)])
            .row_highlight_style(
                Style::default()
                    .patch(palette::selection_style())
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        f.render_stateful_widget(
            table,
            chunks[1],
            &mut ratatui_state(interface.addresses.len(), selected),
        );
    }
    f.render_widget(
        Paragraph::new("j/k or ↑/↓:select  PgUp/PgDn:page  Home/End:jump  Esc/i:close")
            .style(Style::default().fg(palette::muted())),
        chunks[2],
    );
}
