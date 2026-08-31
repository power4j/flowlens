//! About page.

use ratatui::layout::{Alignment, Constraint, Direction as LayoutDir, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::palette;

pub(in crate::tui) fn draw_about(f: &mut ratatui::Frame, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let repository = env!("CARGO_PKG_REPOSITORY");
    let commit = env!("FLOWLENS_BUILD_COMMIT");
    let frame_width = area.width.saturating_sub(4).min(62);
    let horizontal = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(frame_width),
            Constraint::Fill(1),
        ])
        .split(area)[1];
    let frame_area = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(9),
            Constraint::Fill(1),
        ])
        .split(horizontal)[1];
    let frame = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .border_style(Style::default().fg(palette::border()));
    let content_area = frame.inner(frame_area);
    f.render_widget(frame, frame_area);

    let lines = vec![
        Line::from(Span::styled(
            "flowlens",
            Style::default()
                .fg(palette::accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Network Traffic Analyzer",
            Style::default().fg(palette::strong()),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("Version {version} ({commit})"),
            Style::default().fg(palette::muted()),
        )),
        Line::from(""),
        Line::from(Span::styled(
            repository,
            Style::default().fg(palette::muted()),
        )),
    ];
    let para = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(para, content_area);
}

#[cfg(test)]
mod tests {

    use crate::tui::*;

    #[test]
    fn about_page_frames_identity_and_hides_capture_context() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.page = Page::About;
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| {
                draw(
                    frame,
                    &mut state,
                    &snapshot,
                    "private-interface",
                    "private-host",
                    Instant::now(),
                )
            })
            .unwrap();

        let lines = rendered_lines(&terminal);
        let identity_row = lines
            .iter()
            .rposition(|line| line.contains("flowlens"))
            .expect("about identity");
        assert!(
            lines[..identity_row]
                .iter()
                .any(|line| line.contains("────────"))
        );
        assert!(
            lines[identity_row + 1..]
                .iter()
                .any(|line| line.contains("────────"))
        );
        let rendered = lines.join("\n");
        assert!(rendered.contains("Network Traffic Analyzer"));
        assert!(rendered.contains("Version"));
        assert!(rendered.contains(env!("FLOWLENS_BUILD_COMMIT")));
        assert!(rendered.contains(env!("CARGO_PKG_REPOSITORY")));
        assert!(!rendered.contains("private-interface"));
        assert!(!rendered.contains("private-host"));
    }
}
