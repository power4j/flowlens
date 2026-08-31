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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn startup_selector_renders_structured_interfaces_and_cannot_cancel() {
        let interfaces = interfaces();
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::startup(&interfaces);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_with_interfaces(
                    frame,
                    &mut state,
                    &snapshot,
                    None,
                    &interfaces,
                    "host",
                    Instant::now(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Select an interface"));
        assert!(rendered.contains("eth0"));
        assert!(rendered.contains("Wired Ethernet"));
        assert!(rendered.contains("default route"));
        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                &mut Arc::new(TrafficSnapshot::default()),
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Ignored
        );
        assert!(state.interface_selector.is_some());
        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut Arc::new(TrafficSnapshot::default()),
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Changed
        );
        assert!(state.quit_confirm);
        assert!(state.interface_selector.is_some());
        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut Arc::new(TrafficSnapshot::default()),
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Quit
        );
    }

    #[test]
    fn selector_ignores_releases_and_handles_press_and_repeat() {
        let mut interfaces = interfaces();
        interfaces.push(crate::capture::InterfaceInfo {
            name: "lo".to_string(),
            description: "Loopback".to_string(),
            is_default_route: false,
        });
        let mut state = AppState::startup(&interfaces);
        let mut snapshot = Arc::new(TrafficSnapshot::default());

        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new_with_kind(
                    KeyCode::Down,
                    KeyModifiers::NONE,
                    crossterm::event::KeyEventKind::Release,
                ),
                &mut snapshot,
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Ignored
        );
        assert_eq!(state.interface_selector.as_ref().unwrap().selected, 0);

        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                &mut snapshot,
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Changed
        );
        assert_eq!(state.interface_selector.as_ref().unwrap().selected, 1);

        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new_with_kind(
                    KeyCode::Down,
                    KeyModifiers::NONE,
                    crossterm::event::KeyEventKind::Repeat,
                ),
                &mut snapshot,
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Changed
        );
        assert_eq!(state.interface_selector.as_ref().unwrap().selected, 2);

        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new_with_kind(
                    KeyCode::Enter,
                    KeyModifiers::NONE,
                    crossterm::event::KeyEventKind::Release,
                ),
                &mut snapshot,
                &interfaces,
                None,
                |_| unreachable!(),
            ),
            KeyOutcome::Ignored
        );
        assert!(state.interface_selector.is_some());
    }

    #[test]
    fn header_uses_interface_description_instead_of_pcap_device_name() {
        let interfaces = vec![crate::capture::InterfaceInfo {
            name: r"\Device\NPF_{A1B2C3D4}".to_string(),
            description: "Intel Ethernet Controller".to_string(),
            is_default_route: true,
        }];
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_with_interfaces(
                    frame,
                    &mut state,
                    &snapshot,
                    Some(r"\Device\NPF_{A1B2C3D4}"),
                    &interfaces,
                    "host",
                    Instant::now(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Intel Ethernet Controller"));
        assert!(!rendered.contains(r"\Device\NPF_{A1B2C3D4}"));
    }

    #[test]
    fn interface_label_falls_back_to_pcap_name_without_a_description() {
        let name = r"\Device\NPF_{A1B2C3D4}";
        for description in ["", "No description"] {
            let interfaces = vec![crate::capture::InterfaceInfo {
                name: name.to_string(),
                description: description.to_string(),
                is_default_route: true,
            }];

            assert_eq!(interface_display_label(Some(name), &interfaces), name);
        }
    }

    #[test]
    fn active_interface_selector_cancels_and_successful_switch_resets_view() {
        let interfaces = interfaces();
        let mut state = AppState::new();
        state.page = Page::About;
        let mut snapshot = Arc::new(TrafficSnapshot {
            in_bytes: 99,
            ..TrafficSnapshot::default()
        });

        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
                &mut snapshot,
                &interfaces,
                Some("eth0"),
                |_| unreachable!(),
            ),
            KeyOutcome::Changed
        );
        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                &mut snapshot,
                &interfaces,
                Some("eth0"),
                |_| unreachable!(),
            ),
            KeyOutcome::Changed
        );
        assert!(state.interface_selector.is_none());

        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| unreachable!(),
        );
        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| unreachable!(),
        );
        let outcome = handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| Ok(crate::session::Activation::Activated),
        );

        assert_eq!(outcome, KeyOutcome::Changed);
        assert_eq!(state.page, Page::Overview);
        assert!(state.interface_selector.is_none());
        assert_eq!(snapshot.in_bytes, 0);
    }

    #[test]
    fn selector_error_keeps_current_view_and_traffic() {
        let interfaces = interfaces();
        let mut state = AppState::new();
        state.page = Page::About;
        let mut snapshot = Arc::new(TrafficSnapshot {
            in_bytes: 99,
            ..TrafficSnapshot::default()
        });
        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| unreachable!(),
        );
        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| unreachable!(),
        );

        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| Err(anyhow::anyhow!("permission denied")),
        );

        assert_eq!(state.page, Page::About);
        assert_eq!(snapshot.in_bytes, 99);
        assert_eq!(
            state.interface_selector.as_ref().unwrap().error.as_deref(),
            Some("Failed to activate wlan0: permission denied")
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                draw_with_interfaces(
                    frame,
                    &mut state,
                    &snapshot,
                    Some("eth0"),
                    &interfaces,
                    "host",
                    Instant::now(),
                );
            })
            .unwrap();
        assert!(
            rendered_lines(&terminal)
                .join("\n")
                .contains("Failed to activate wlan0: permission denied")
        );
    }

    #[test]
    fn pending_interface_activation_keeps_the_tui_responsive_until_completion() {
        let interfaces = interfaces();
        let mut state = AppState::new();
        state.page = Page::About;
        let mut snapshot = Arc::new(TrafficSnapshot {
            in_bytes: 99,
            ..TrafficSnapshot::default()
        });
        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| unreachable!(),
        );
        handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| unreachable!(),
        );

        let outcome = handle_tui_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut snapshot,
            &interfaces,
            Some("eth0"),
            |_| Ok(Activation::Pending),
        );

        assert_eq!(outcome, KeyOutcome::Changed);
        assert_eq!(state.page, Page::About);
        assert_eq!(snapshot.in_bytes, 99);
        assert_eq!(
            state
                .interface_selector
                .as_ref()
                .unwrap()
                .activating
                .as_deref(),
            Some("wlan0")
        );
        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut snapshot,
                &interfaces,
                Some("eth0"),
                |_| unreachable!(),
            ),
            KeyOutcome::Changed
        );
        assert!(state.quit_confirm);
        assert_eq!(
            handle_tui_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
                &mut snapshot,
                &interfaces,
                Some("eth0"),
                |_| unreachable!(),
            ),
            KeyOutcome::Quit
        );

        finish_tui_activation(&mut state, &mut snapshot, Ok(Activation::Activated));

        assert_eq!(state.page, Page::Overview);
        assert!(state.interface_selector.is_none());
        assert_eq!(snapshot.in_bytes, 0);
    }

    #[test]
    fn interface_selector_is_usable_at_compact_minimum_size() {
        let interfaces = interfaces();
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::startup(&interfaces);
        let mut terminal = Terminal::new(TestBackend::new(60, 16)).unwrap();

        terminal
            .draw(|frame| {
                draw_with_interfaces(
                    frame,
                    &mut state,
                    &snapshot,
                    None,
                    &interfaces,
                    "host",
                    Instant::now(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Select an interface"));
        assert!(rendered.contains("eth0"));
        assert!(rendered.contains("Wired Ethernet"));
        assert!(rendered.contains("Enter:activate"));
    }

    #[test]
    fn compact_selector_keeps_a_long_pcap_name_visible() {
        let pcap_name = r"\Device\NPF_{12345678-1234-1234-1234-123456789ABC}";
        let interfaces = vec![crate::capture::InterfaceInfo {
            name: pcap_name.to_string(),
            description: "Npcap Adapter".to_string(),
            is_default_route: false,
        }];
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::startup(&interfaces);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_with_interfaces(
                    frame,
                    &mut state,
                    &snapshot,
                    None,
                    &interfaces,
                    "host",
                    Instant::now(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains(pcap_name));
        let pcap_position = rendered.find(pcap_name).unwrap();
        let description_position = rendered.find("Npcap Adapter").unwrap();
        if cfg!(windows) {
            assert!(description_position < pcap_position);
        } else {
            assert!(pcap_position < description_position);
        }
    }

    #[test]
    fn selector_renders_platform_primary_label_first() {
        let (interface_name, description) = if cfg!(windows) {
            (
                r"\Device\NPF_{12345678-1234-1234-1234-123456789ABC}",
                "Intel Ethernet Controller",
            )
        } else {
            ("eth0", "Wired Ethernet")
        };
        let interfaces = vec![crate::capture::InterfaceInfo {
            name: interface_name.to_string(),
            description: description.to_string(),
            is_default_route: false,
        }];
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::startup(&interfaces);
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw_with_interfaces(
                    frame,
                    &mut state,
                    &snapshot,
                    None,
                    &interfaces,
                    "host",
                    Instant::now(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        let interface_position = rendered.find(interface_name).unwrap();
        let description_position = rendered.find(description).unwrap();
        if cfg!(windows) {
            assert!(description_position < interface_position);
        } else {
            assert!(interface_position < description_position);
        }
    }
}
