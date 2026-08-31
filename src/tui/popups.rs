//! Modal overlays that interrupt normal page rendering.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

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
