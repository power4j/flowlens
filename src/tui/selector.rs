//! Interface selector overlay and activation hand-off.

use std::sync::Arc;

use ratatui::layout::{Constraint, Direction as LayoutDir, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use crate::capture::InterfaceInfo;
use crate::palette;
use crate::session::Activation;
use crate::stats::TrafficSnapshot;

use super::layout::ratatui_state;
use super::state::*;

pub(super) struct InterfaceSelector {
    pub(super) selected: usize,
    pub(super) can_cancel: bool,
    pub(super) activating: Option<String>,
    pub(super) error: Option<String>,
}

pub(super) fn finish_tui_activation(
    state: &mut AppState,
    snapshot: &mut Arc<TrafficSnapshot>,
    result: anyhow::Result<Activation>,
) {
    let interface = state
        .interface_selector
        .as_mut()
        .and_then(|selector| selector.activating.take())
        .unwrap_or_else(|| "interface".to_string());
    match result {
        Ok(Activation::Activated) => {
            state.reset_after_interface_switch();
            *snapshot = Arc::new(TrafficSnapshot::default());
        }
        Ok(Activation::Unchanged) => state.interface_selector = None,
        Ok(Activation::Pending) => {}
        Err(error) => {
            if let Some(selector) = state.interface_selector.as_mut() {
                selector.error = Some(format!("Failed to activate {interface}: {error}"));
            }
        }
    }
}

pub(super) fn interface_display_label(
    interface: Option<&str>,
    interfaces: &[InterfaceInfo],
) -> String {
    let interface_name = interface.unwrap_or("No interface");
    interfaces
        .iter()
        .find(|candidate| candidate.name == interface_name)
        .map(|candidate| candidate.description.as_str())
        .filter(|description| !description.is_empty() && *description != "No description")
        .map(str::to_string)
        .unwrap_or_else(|| interface_name.to_string())
}

pub(super) fn draw_interface_selector(
    f: &mut ratatui::Frame,
    area: Rect,
    selector: &InterfaceSelector,
    interfaces: &[InterfaceInfo],
    active: Option<&str>,
) {
    let content = area.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(content);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " flowlens ",
                Style::default()
                    .fg(palette::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Select an interface",
                Style::default()
                    .fg(palette::strong())
                    .add_modifier(Modifier::BOLD),
            ),
        ])),
        chunks[0],
    );

    let compact = area.width < 100;
    let rows = if interfaces.is_empty() {
        vec![
            Row::new(vec![Cell::from(""), Cell::from("No interfaces available")])
                .style(Style::default().fg(palette::muted())),
        ]
    } else {
        interfaces
            .iter()
            .enumerate()
            .map(|(index, interface)| {
                let mut markers = Vec::new();
                if active == Some(interface.name.as_str()) {
                    markers.push("current");
                }
                if interface.is_default_route {
                    markers.push("default route");
                }
                let marker = if markers.is_empty() {
                    String::new()
                } else {
                    format!("[{}]", markers.join(", "))
                };
                let (primary, secondary) = interface.display_labels();
                if compact {
                    let secondary = secondary.unwrap_or("");
                    Row::new(vec![
                        Cell::from(format!("{}.", index + 1)),
                        Cell::from(format!("{primary}\n{secondary}  {marker}")),
                    ])
                    .height(2)
                } else {
                    Row::new(vec![
                        Cell::from(format!("{}.", index + 1)),
                        Cell::from(primary),
                        Cell::from(secondary.unwrap_or("")),
                        Cell::from(marker),
                    ])
                }
            })
            .collect()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette::border()));
    let table = if compact {
        Table::new(rows, [Constraint::Length(3), Constraint::Min(1)])
    } else {
        Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Min(18),
                Constraint::Min(50),
                Constraint::Length(24),
            ],
        )
    }
    .column_spacing(1)
    .block(block)
    .row_highlight_style(
        Style::default()
            .fg(palette::strong())
            .patch(palette::selection_style())
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");
    f.render_stateful_widget(
        table,
        chunks[1],
        &mut ratatui_state(interfaces.len(), selector.selected),
    );

    let activation_hint = selector
        .activating
        .as_ref()
        .map(|interface| format!("Activating {interface}...  q:quit"));
    let hint = selector
        .error
        .as_deref()
        .or(activation_hint.as_deref())
        .unwrap_or(if selector.can_cancel {
            "j/k:select  Enter:activate  Esc:cancel  q:quit"
        } else {
            "j/k:select  Enter:activate  q:quit"
        });
    f.render_widget(
        Paragraph::new(hint)
            .style(Style::default().fg(if selector.error.is_some() {
                palette::coral()
            } else {
                palette::muted()
            }))
            .wrap(Wrap { trim: true }),
        chunks[2],
    );
}
