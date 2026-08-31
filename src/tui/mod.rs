//! Terminal UI: tabbed pages with scrollable tables.
//!
//! The TUI owns only interaction state and the latest immutable traffic snapshot.
//! Capture and aggregation run in the traffic pipeline.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::diagnostics::DiagnosticsWriter;
use crate::palette;
use crate::report::hostname;
use crate::session::TrafficSession;
use crate::stats::{RankWindow, TrafficSnapshot};

#[cfg(test)]
use crate::session::Activation;
#[cfg(test)]
use crossterm::event::KeyEvent;
#[cfg(test)]
use pages::*;
#[cfg(test)]
use ratatui::layout::Rect;
#[cfg(test)]
use ratatui::style::{Color, Modifier};
#[cfg(test)]
use ratatui::widgets::Paragraph;

mod keys;
mod layout;
mod pages;
mod popups;
mod selector;
mod state;

use keys::*;
use layout::*;
use selector::*;
use state::*;

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Run the TUI until the user quits.
pub fn run(
    session: &mut TrafficSession,
    diagnostics_writer: Option<DiagnosticsWriter>,
    diagnostics_enabled: Arc<AtomicBool>,
    rank_window: Arc<AtomicU8>,
) -> io::Result<()> {
    palette::set_active_tier(palette::detect_tier());
    let started_at = Instant::now();
    let host = hostname();
    let mut snapshot = session
        .try_latest()
        .map_err(io::Error::other)?
        .unwrap_or_else(|| Arc::new(TrafficSnapshot::default()));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = if session.active_interface().is_some() {
        AppState::new()
    } else {
        AppState::startup(session.interfaces())
    };
    state.rank_window = RankWindow::from_u8(rank_window.load(Ordering::Acquire));
    state.rank_window_draft = state.rank_window;
    if let Some(writer) = diagnostics_writer.as_ref() {
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = writer.file_name();
    }
    let result = tui_loop(
        &mut terminal,
        &mut state,
        &mut snapshot,
        &host,
        started_at,
        session,
        DiagnosticsRuntime::new_with_rank(diagnostics_writer, diagnostics_enabled, rank_window),
    );

    // Restore terminal regardless of how the event loop exited.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

#[allow(clippy::too_many_arguments)]
fn tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
    snapshot: &mut Arc<TrafficSnapshot>,
    host: &str,
    started_at: Instant,
    session: &mut TrafficSession,
    mut diagnostics: DiagnosticsRuntime,
) -> io::Result<()> {
    terminal.draw(|f| {
        draw_with_interfaces(
            f,
            state,
            snapshot,
            session.active_interface(),
            session.interfaces(),
            host,
            started_at,
        )
    })?;

    loop {
        let event = if event::poll(EVENT_POLL_INTERVAL)? {
            Some(event::read()?)
        } else {
            None
        };

        let mut changed = event.as_ref().is_some_and(event_requires_redraw);
        if let Some(Event::Key(key)) = event {
            let interfaces = session.interfaces().to_vec();
            let active = session.active_interface().map(str::to_string);
            match handle_tui_key(
                state,
                key,
                snapshot,
                &interfaces,
                active.as_deref(),
                |name| session.begin_activate(name),
            ) {
                KeyOutcome::Quit => return Ok(()),
                KeyOutcome::Changed => changed = true,
                KeyOutcome::Ignored => {}
            }
        }

        if diagnostics.reconcile(state) {
            changed = true;
        }

        if let Some(result) = session.poll_activation() {
            finish_tui_activation(state, snapshot, result);
            changed = true;
        }

        if let Some(result) = session.poll_capture_readiness()
            && let Err(error) = result
        {
            state.open_interface_selector(session.interfaces(), session.active_interface(), true);
            if let Some(selector) = state.interface_selector.as_mut() {
                selector.error = Some(format!(
                    "Capture failed; restored the previous interface: {error}"
                ));
            }
            changed = true;
        }

        if let Some(latest) = session.try_latest().map_err(io::Error::other)? {
            if let Some(writer) = diagnostics.writer.as_mut()
                && let Some(diag) = latest.diagnostics.as_ref()
            {
                let interface = session.active_interface().unwrap_or("<none>");
                if let Err(error) = writer.write(interface, diag) {
                    diagnostics.note_write_failure(state, error);
                }
            }
            *snapshot = latest;
            state.update_process_detail(snapshot);
            changed = true;
        }

        if changed {
            terminal.draw(|f| {
                draw_with_interfaces(
                    f,
                    state,
                    snapshot,
                    session.active_interface(),
                    session.interfaces(),
                    host,
                    started_at,
                )
            })?;
        }
    }
}

fn event_requires_redraw(event: &Event) -> bool {
    matches!(event, Event::Resize(_, _))
}

#[cfg(test)]
fn process_iteration<D, L, E>(
    state: &mut AppState,
    snapshot: &mut Arc<TrafficSnapshot>,
    key: Option<KeyEvent>,
    mut draw: D,
    mut try_latest: L,
) -> Result<bool, E>
where
    D: FnMut(&mut AppState, &TrafficSnapshot) -> Result<(), E>,
    L: FnMut() -> Result<Option<Arc<TrafficSnapshot>>, E>,
{
    if let Some(key) = key {
        match handle_key(state, key, snapshot) {
            KeyOutcome::Quit => return Ok(true),
            KeyOutcome::Changed => draw(state, snapshot)?,
            KeyOutcome::Ignored => {}
        }
    }

    if let Some(latest) = try_latest()? {
        *snapshot = latest;
        state.update_process_detail(snapshot);
        draw(state, snapshot)?;
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use std::path::PathBuf;

    use crate::stats::{IpSnapshot, OutboundDomainSnapshot, ProcessSnapshot, TrafficSnapshot};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn interfaces() -> Vec<crate::capture::InterfaceInfo> {
        vec![
            crate::capture::InterfaceInfo {
                name: "eth0".to_string(),
                description: "Wired Ethernet".to_string(),
                is_default_route: true,
            },
            crate::capture::InterfaceInfo {
                name: "wlan0".to_string(),
                description: "Wireless Adapter".to_string(),
                is_default_route: false,
            },
        ]
    }

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

    #[test]
    fn resize_event_requests_a_redraw() {
        assert!(event_requires_redraw(&Event::Resize(80, 24)));
        assert!(!event_requires_redraw(&Event::FocusGained));
    }

    fn rendered_lines(terminal: &Terminal<TestBackend>) -> Vec<String> {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn render_processes_with_pending(bytes: u64) -> Terminal<TestBackend> {
        let snapshot = TrafficSnapshot {
            pending_attribution_bytes: bytes,
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        terminal
    }

    fn assert_pending_indicator_color(terminal: &Terminal<TestBackend>, expected: Color) {
        let indicator = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "?")
            .expect("pending attribution indicator");
        assert_eq!(indicator.fg, expected);
    }

    #[test]
    fn top_navigation_renders_page_tabs_with_the_active_page_selected() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let first_line = rendered_lines(&terminal)[0].clone();
        assert!(
            first_line.contains("flowlens  1 Overview  2 Processes  3 IPs  4 Domains  5 About")
        );
        let overview_cell = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "O")
            .expect("Overview tab cell");
        assert_eq!(overview_cell.bg, Color::Rgb(43, 37, 15));
        assert!(overview_cell.modifier.contains(Modifier::BOLD));
    }

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
    fn overview_domain_preview_lists_top_domains_and_empty_state() {
        let populated = TrafficSnapshot {
            outbound_domains: vec![OutboundDomainSnapshot::new(
                Arc::from("example.com"),
                100,
                240,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal
            .draw(|frame| {
                draw(
                    frame,
                    &mut state,
                    &populated,
                    "eth0",
                    "host",
                    Instant::now(),
                )
            })
            .unwrap();
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Top Domains"));
        assert!(rendered.contains("example.com"));
        assert!(rendered.contains("340 B"));
        assert!(!rendered.contains("No outbound domains observed"));

        let empty = TrafficSnapshot::default();
        let mut terminal2 = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal2
            .draw(|frame| draw(frame, &mut state, &empty, "eth0", "host", Instant::now()))
            .unwrap();
        let rendered2 = rendered_lines(&terminal2).join("\n");
        assert!(rendered2.contains("Top Domains"));
        assert!(rendered2.contains("No outbound domains observed"));
        assert!(rendered2.contains("0/0"));

        let window_empty = TrafficSnapshot {
            ranking: crate::stats::RankingSnapshot {
                window: RankWindow::TEN_SECONDS,
                metric: crate::stats::RankingMetric::AverageThroughput,
                coverage_seconds: Some(10),
            },
            ..TrafficSnapshot::default()
        };
        let mut terminal3 = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal3
            .draw(|frame| {
                draw(
                    frame,
                    &mut state,
                    &window_empty,
                    "eth0",
                    "host",
                    Instant::now(),
                )
            })
            .unwrap();
        let rendered3 = rendered_lines(&terminal3).join("\n");
        assert!(rendered3.contains("No domains in window"));
        assert!(!rendered3.contains("No outbound domains observed"));
    }

    #[test]
    fn ranking_values_keep_rate_suffix_visible_in_tables() {
        let mut process = ProcessSnapshot::attributed(
            7,
            Some(Arc::from("curl")),
            None,
            chrono::Utc::now(),
            100 * 1024,
            100 * 1024,
        );
        process.rank = crate::stats::ProcTraffic {
            recv: 100 * 1024,
            sent: 100 * 1024,
        };
        let snapshot = TrafficSnapshot {
            ranking: crate::stats::RankingSnapshot {
                window: RankWindow::TEN_SECONDS,
                metric: crate::stats::RankingMetric::AverageThroughput,
                coverage_seconds: Some(10),
            },
            processes: vec![process].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("100.00 KB/s"));
    }

    #[test]
    fn eighty_column_processes_keep_full_columns_and_a_visible_selection() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                chrono::Utc::now(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("proc Processes 1"));
        assert!(rendered.contains("Process"));
        assert!(rendered.contains("PID"));
        assert!(rendered.contains("Recv"));
        assert!(rendered.contains("Sent"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("1/1"));
        let selected = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "c" && cell.bg == Color::Rgb(23, 43, 60))
            .expect("selected process row");
        assert!(selected.modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn undersized_terminal_shows_only_the_minimum_size_message() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(59, 15)).unwrap();

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

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Terminal too small (minimum 60x16)"));
        assert!(!rendered.contains("private-interface"));
        assert!(!rendered.contains("private-host"));
        assert!(!rendered.contains("Traffic"));
    }

    #[test]
    fn compact_ips_stack_themed_panels_vertically() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.page = Page::Ips;
        let mut terminal = Terminal::new(TestBackend::new(72, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let lines = rendered_lines(&terminal);
        let inbound_y = lines
            .iter()
            .position(|line| line.contains("in Inbound IPs"))
            .expect("inbound panel");
        let outbound_y = lines
            .iter()
            .position(|line| line.contains("out Outbound IPs"))
            .expect("outbound panel");
        assert!(inbound_y < outbound_y);
        assert!(outbound_y - inbound_y >= 8);
    }

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

    #[test]
    fn processes_page_renders_from_snapshot() {
        let observed_at = "2026-07-15T08:00:00Z".parse().unwrap();
        let snapshot = TrafficSnapshot {
            in_bytes: 40,
            out_bytes: 60,
            processes: vec![{
                let mut process = ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl --silent")),
                    None,
                    observed_at,
                    40,
                    60,
                );
                process.window = crate::stats::ProcTraffic { recv: 40, sent: 60 };
                process
            }]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

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

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("curl --silent"));
        assert!(rendered.contains("100 B"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("2m ago"));
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
    fn processes_page_marks_the_selected_row() {
        let snapshot = TrafficSnapshot {
            processes: vec![
                ProcessSnapshot::attributed(
                    7,
                    Some(Arc::from("curl")),
                    Some(Arc::from("/usr/bin/curl")),
                    chrono::Utc::now(),
                    40,
                    60,
                ),
                ProcessSnapshot::attributed(
                    8,
                    Some(Arc::from("ssh")),
                    Some(Arc::from("/usr/bin/ssh")),
                    chrono::Utc::now(),
                    10,
                    20,
                ),
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                &snapshot,
            ),
            KeyOutcome::Changed
        ));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

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
        assert!(rendered.contains("> ssh"));
        assert!(rendered.contains("Process"));
        assert!(rendered.contains("PID"));
        assert!(rendered.contains("Recv"));
        assert!(rendered.contains("Sent"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("Enter:details"));
        assert!(rendered.contains("q:quit"));
        assert!(!rendered.contains("/usr/bin/ssh"));
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

    #[test]
    fn process_preview_has_no_selection_cursor() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl")),
                Some(Arc::from("/usr/bin/curl")),
                chrono::Utc::now(),
                40,
                60,
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();

        terminal
            .draw(|frame| {
                draw_process_preview(
                    frame,
                    frame.area(),
                    &snapshot,
                    LayoutMode::Standard,
                    chrono::Utc::now(),
                );
            })
            .unwrap();

        let process_line = rendered_lines(&terminal)
            .into_iter()
            .find(|line| line.contains("curl"))
            .expect("process row");
        assert!(!process_line.contains("> "));
    }

    #[test]
    fn ips_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
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
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Ips;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

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
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("1.00 KB"));
        assert!(rendered.contains("198.51.100.20"));
        assert!(rendered.contains("2.00 KB"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("2m ago"));
    }

    #[test]
    fn domains_page_renders_columns_and_rows_from_snapshot() {
        let snapshot = TrafficSnapshot {
            outbound_domains: vec![OutboundDomainSnapshot::new(
                Arc::from("example.com"),
                240,
                100,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Domains;
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| {
                draw_at(
                    frame,
                    &mut state,
                    &snapshot,
                    "eth0",
                    "host",
                    Instant::now(),
                    "2026-07-15T08:02:30Z".parse().unwrap(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Host"));
        assert!(rendered.contains("In"));
        assert!(rendered.contains("Out"));
        assert!(rendered.contains("Total"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("example.com"));
        assert!(rendered.contains("240 B"));
        assert!(rendered.contains("100 B"));
        assert!(rendered.contains("340 B"));
        assert!(rendered.contains("2m ago"));
        assert!(rendered.contains("j/k scroll"));
        assert!(rendered.contains("1/1"));
    }

    #[test]
    fn domains_page_renders_empty_state_when_no_domains() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.page = Page::Domains;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("No outbound domains observed"));
        assert!(rendered.contains("Host"));
        assert!(rendered.contains("Last seen"));
        assert!(rendered.contains("0/0"));
    }

    #[test]
    fn domains_page_relative_last_seen_uses_the_same_format_as_process_details() {
        let snapshot = TrafficSnapshot {
            outbound_domains: vec![
                OutboundDomainSnapshot::new(
                    Arc::from("seconds.example"),
                    10,
                    20,
                    "2026-07-15T08:00:00Z".parse().unwrap(),
                ),
                OutboundDomainSnapshot::new(
                    Arc::from("minutes.example"),
                    30,
                    40,
                    "2026-07-15T07:00:00Z".parse().unwrap(),
                ),
                OutboundDomainSnapshot::new(
                    Arc::from("hours.example"),
                    50,
                    60,
                    "2026-07-14T06:00:00Z".parse().unwrap(),
                ),
            ]
            .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Domains;
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| {
                draw_at(
                    frame,
                    &mut state,
                    &snapshot,
                    "eth0",
                    "host",
                    Instant::now(),
                    "2026-07-15T08:00:30Z".parse().unwrap(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("seconds.example"));
        assert!(rendered.contains("30s ago"));
        assert!(rendered.contains("minutes.example"));
        assert!(rendered.contains("1h ago"));
        assert!(rendered.contains("hours.example"));
        assert!(rendered.contains("1d ago"));
    }

    #[test]
    fn domains_page_scrolls_through_entries() {
        let snapshot = TrafficSnapshot {
            outbound_domains: (0..30)
                .map(|index| {
                    OutboundDomainSnapshot::new(
                        Arc::from(format!("host-{index}.example").into_boxed_str()),
                        100 + index as u64,
                        50,
                        "2026-07-15T08:00:00Z".parse().unwrap(),
                    )
                })
                .collect::<Vec<_>>()
                .into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Domains;

        assert!(matches!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                &snapshot,
            ),
            KeyOutcome::Changed
        ));
        assert_eq!(state.domain_scroll, 1);

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("host-1.example"));
        assert!(rendered.contains("> host-1.example"));
        assert!(rendered.contains("2/30"));
    }

    #[test]
    fn page_key_reports_changed() {
        let mut state = AppState::new();
        let snapshot = TrafficSnapshot::default();

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
            &snapshot,
        );

        assert!(matches!(outcome, KeyOutcome::Changed));
        assert!(state.page == Page::Processes);
    }

    #[test]
    fn page_key_four_opens_domains_and_five_opens_about() {
        let mut state = AppState::new();
        let snapshot = TrafficSnapshot::default();

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE),
            &snapshot,
        );
        assert!(matches!(outcome, KeyOutcome::Changed));
        assert!(state.page == Page::Domains);

        let outcome = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE),
            &snapshot,
        );
        assert!(matches!(outcome, KeyOutcome::Changed));
        assert!(state.page == Page::About);
    }

    #[test]
    fn page_key_draws_before_checking_for_snapshot_update() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let draw_calls = calls.clone();
        let latest_calls = calls.clone();
        let mut state = AppState::new();
        let mut snapshot = Arc::new(TrafficSnapshot::default());

        let quit = process_iteration(
            &mut state,
            &mut snapshot,
            Some(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE)),
            |_, _| {
                draw_calls.borrow_mut().push("draw");
                Ok::<_, ()>(())
            },
            || {
                latest_calls.borrow_mut().push("latest");
                Ok::<_, ()>(None)
            },
        )
        .unwrap();

        assert!(!quit);
        assert_eq!(*calls.borrow(), vec!["draw", "latest"]);
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
        let lines = process_attribution_detail_lines(&process);
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
            text[2].contains("= Exclusive 1.02 MB + Shared 0 B"),
            "total equation should not inherit Recv/Sent padding: {}",
            text[2]
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
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

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
        assert!(rendered.contains("Name: payment-worker"));
        assert!(rendered.contains("PID: 7"));
        assert!(rendered.contains("Recv: 1.50 KB"));
        assert!(rendered.contains("Sent: 3.00 KB"));
        assert!(rendered.contains("Total: 4.50 KB"));
        assert!(rendered.contains("Attribution (lifetime)"));
        assert!(rendered.contains("Exclusive: 3.00 KB  Recv 1.00 KB  Sent 2.00 KB"));
        assert!(rendered.contains("Shared:    1.50 KB  Recv   512 B  Sent 1.00 KB"));
        assert!(rendered.contains("Total:     4.50 KB = Exclusive 3.00 KB + Shared 1.50 KB"));
        let exclusive = lines
            .iter()
            .find(|line| line.contains("Exclusive:") && line.contains("Recv"))
            .expect("exclusive attribution row");
        let shared = lines
            .iter()
            .find(|line| line.contains("Shared:") && line.contains("Recv"))
            .expect("shared attribution row");
        let total = lines
            .iter()
            .find(|line| line.contains("Total:") && line.contains("= Exclusive"))
            .expect("total attribution row");
        let value_column = |line: &str| {
            line.find(|ch: char| ch.is_ascii_digit())
                .expect("attribution value")
        };
        assert_eq!(value_column(exclusive), value_column(shared));
        assert_eq!(value_column(shared), value_column(total));
        assert!(rendered.contains("Selected (total): 768 B  Recv 256 B  Sent 512 B"));
        assert!(
            rendered.contains(
                "Shared traffic is included in Total and may appear in multiple processes."
            )
        );
        assert!(rendered.contains("Last seen: 2m ago"));
        assert!(rendered.contains("Esc:back"));
        let inner_lines = lines
            .iter()
            .map(|line| line.chars().skip(2).take(76).collect::<String>())
            .collect::<Vec<_>>();
        let path_line = inner_lines
            .iter()
            .position(|line| line.starts_with("Path: "))
            .unwrap();
        let mut displayed_path = inner_lines[path_line]
            .trim_end()
            .strip_prefix("Path:")
            .unwrap()
            .trim_start()
            .to_string();
        for continuation in &inner_lines[path_line + 1..] {
            if continuation.trim().is_empty() || continuation.trim_start().starts_with("Last seen:")
            {
                break;
            }
            displayed_path.push_str(continuation.trim_end());
        }
        assert_eq!(displayed_path, path);
        let path_pos = rendered.find("Path:").expect("path field");
        let last_seen_pos = rendered.find("Last seen:").expect("last seen field");
        let recv_pos = rendered.find("Recv: ").expect("recv field");
        assert!(path_pos < last_seen_pos, "Last seen should follow Path");
        assert!(last_seen_pos < recv_pos, "Last seen should precede Recv");
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
            assert!(field_count <= 1, "detail fields overlap: {line}");
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

    // --- settings overlay ---

    fn send_key(state: &mut AppState, key: KeyCode) -> KeyOutcome {
        handle_tui_key(
            state,
            KeyEvent::new(key, KeyModifiers::NONE),
            &mut Arc::new(TrafficSnapshot::default()),
            &interfaces(),
            Some("eth0"),
            |_| unreachable!(),
        )
    }

    #[test]
    fn o_key_opens_and_closes_the_settings_overlay() {
        let mut state = AppState::new();
        assert!(!state.settings_open);

        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(state.settings_open);

        // 'o' toggles back off.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(!state.settings_open);

        // Open again, then Esc closes.
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.settings_open);
    }

    #[test]
    fn settings_overlay_renders_palette_row_and_hint() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.settings_open = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Settings"));
        assert!(rendered.contains("Palette:"));
        assert!(rendered.contains("j/k select  h/l change  o or Esc close"));
    }

    #[test]
    fn settings_jk_moves_selection_and_clamps() {
        let mut state = AppState::new();
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert_eq!(state.settings_selection, 0);

        // Down/j moves to Diagnostics and clamps at the bottom.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('j')),
            KeyOutcome::Changed
        );
        assert_eq!(state.settings_selection, 1);
        assert_eq!(send_key(&mut state, KeyCode::Down), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 2);

        // Up/k moves back through Diagnostics to Palette and clamps at the top.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('k')),
            KeyOutcome::Changed
        );
        assert_eq!(state.settings_selection, 1);
        assert_eq!(send_key(&mut state, KeyCode::Up), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 0);
        assert_eq!(send_key(&mut state, KeyCode::Up), KeyOutcome::Changed);
        assert_eq!(state.settings_selection, 0);
    }

    #[test]
    fn settings_hl_changes_the_selected_item_only() {
        let mut state = AppState::new();
        state.detected_tier = palette::ColorTier::Truecolor;
        state.palette_choice = palette::PaletteChoice::Auto;
        send_key(&mut state, KeyCode::Char('o'));

        // Palette row selected by default: h/l cycle the palette.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert_eq!(state.palette_choice, palette::PaletteChoice::Truecolor);
        assert!(!state.diagnostics_draft);

        // Select Diagnostics: h/l toggle only the draft; the actual state
        // (writer + shared flag) is committed when the overlay closes.
        send_key(&mut state, KeyCode::Char('j'));
        assert_eq!(state.settings_selection, 1);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert!(state.diagnostics_draft);
        assert!(!state.diagnostics_enabled);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert!(!state.diagnostics_draft);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('h')),
            KeyOutcome::Changed
        );
        assert!(state.diagnostics_draft);
        assert!(!state.diagnostics_enabled);
    }

    #[test]
    fn settings_enter_is_ignored() {
        let mut state = AppState::new();
        state.detected_tier = palette::ColorTier::Truecolor;
        state.palette_choice = palette::PaletteChoice::Auto;
        send_key(&mut state, KeyCode::Char('o'));

        // Enter has no action in the settings overlay: it neither closes the
        // overlay nor commits the diagnostics draft.
        assert_eq!(send_key(&mut state, KeyCode::Enter), KeyOutcome::Ignored);
        assert!(state.settings_open, "Enter must not close the overlay");
        assert_eq!(state.palette_choice, palette::PaletteChoice::Auto);
    }

    #[test]
    fn settings_overlay_renders_diagnostics_state_and_file() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        state.settings_open = true;
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = Some("flowlens-42.log".to_string());
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Diagnostics: ON"));
        assert!(rendered.contains("flowlens-42.log"));
    }

    /// Unique path for a real diagnostics writer under the temp dir, so the
    /// deferred-commit tests never touch the working directory.
    fn diagnostics_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "flowlens-tui-{label}-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn settings_overlay_renders_pending_and_stop_on_close_file_markers() {
        let snapshot = TrafficSnapshot::default();
        let render = |state: &mut AppState| {
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| draw(frame, state, &snapshot, "eth0", "host", Instant::now()))
                .unwrap();
            rendered_lines(&terminal).join("\n")
        };

        // Actual OFF + draft ON: pending path marked (pending).
        let mut state = AppState::new();
        state.settings_open = true;
        state.diagnostics_draft = true;
        state.diagnostics_pending_path = Some(PathBuf::from("flowlens-pending-1.log"));
        let rendered = render(&mut state);
        assert!(rendered.contains("Diagnostics: ON"));
        assert!(rendered.contains("flowlens-pending-1.log (pending)"));

        // Actual ON + draft OFF: live file marked as stopping on close.
        let mut state = AppState::new();
        state.settings_open = true;
        state.diagnostics_enabled = true;
        state.diagnostics_draft = false;
        state.diagnostics_file = Some("flowlens-42.log".to_string());
        let rendered = render(&mut state);
        assert!(rendered.contains("Diagnostics: OFF"));
        assert!(rendered.contains("flowlens-42.log (stops on close)"));

        // Actual OFF + draft OFF: no file.
        let mut state = AppState::new();
        state.settings_open = true;
        let rendered = render(&mut state);
        assert!(rendered.contains("File: (none)"));
    }

    #[test]
    fn long_file_label_is_truncated_with_a_middle_ellipsis() {
        assert_eq!(truncate_with_ellipsis("short.log", 20), "short.log");
        assert_eq!(truncate_with_ellipsis("x", 1), "x");
        let long = "flowlens-20260811T053335Z194489942-23262.log (pending)";
        let out = truncate_with_ellipsis(long, 30);
        assert_eq!(out.chars().count(), 30);
        assert!(out.starts_with("flowlens-2026"));
        assert!(out.ends_with("(pending)"));
        assert!(out.contains('…'));
    }

    #[test]
    fn diagnostics_toggles_in_settings_only_change_the_draft() {
        // While the overlay is open, h/l flips only the draft: neither the
        // writer nor the shared flag moves, and the pending path is not
        // regenerated.
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();

        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert!(!state.diagnostics_enabled);
        assert!(!state.diagnostics_draft);
        let pending = state.diagnostics_pending_path.clone();
        assert!(pending.is_some());

        send_key(&mut state, KeyCode::Char('j')); // select the Diagnostics row
        for _ in 0..4 {
            send_key(&mut state, KeyCode::Char('l')); // draft ON
            assert!(state.diagnostics_draft);
            assert_eq!(state.diagnostics_pending_path, pending);
            assert!(
                !runtime.reconcile(&mut state),
                "overlay toggles must not touch the runtime"
            );
            assert!(runtime.writer.is_none());
            assert!(!enabled.load(Ordering::Relaxed));
            assert!(!state.diagnostics_enabled);

            send_key(&mut state, KeyCode::Char('l')); // draft OFF
            assert!(!state.diagnostics_draft);
            assert_eq!(state.diagnostics_pending_path, pending);
            assert!(!runtime.reconcile(&mut state));
            assert!(runtime.writer.is_none());
            assert!(!state.diagnostics_enabled);
        }
    }

    #[test]
    fn diagnostics_pending_path_is_generated_once_per_overlay_open() {
        let mut state = AppState::new();
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);
        assert!(state.diagnostics_pending_path.is_some());
        let pending = state.diagnostics_pending_path.clone().unwrap();

        send_key(&mut state, KeyCode::Char('j'));
        for _ in 0..6 {
            send_key(&mut state, KeyCode::Char('l'));
            assert_eq!(
                state.diagnostics_pending_path.as_deref(),
                Some(pending.as_path())
            );
            send_key(&mut state, KeyCode::Char('l'));
            assert_eq!(
                state.diagnostics_pending_path.as_deref(),
                Some(pending.as_path())
            );
        }
    }

    #[test]
    fn diagnostics_final_on_commits_a_single_writer_at_the_pending_path() {
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();
        let pending = diagnostics_temp_path("final-on");
        assert!(!pending.exists());
        state.diagnostics_pending_path = Some(pending.clone());

        send_key(&mut state, KeyCode::Char('o'));
        send_key(&mut state, KeyCode::Char('j'));
        send_key(&mut state, KeyCode::Char('l')); // draft ON
        send_key(&mut state, KeyCode::Char('l')); // draft OFF
        send_key(&mut state, KeyCode::Char('l')); // draft ON again
        assert!(state.diagnostics_draft);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('o')),
            KeyOutcome::Changed
        );
        assert!(!state.settings_open);

        // Commit happens on the next reconcile (same loop iteration in the TUI).
        assert!(runtime.reconcile(&mut state));
        assert!(runtime.writer.is_some());
        assert!(enabled.load(Ordering::Relaxed));
        assert!(state.diagnostics_enabled);
        assert_eq!(state.diagnostics_error, None);
        assert!(state.diagnostics_pending_path.is_none());
        let committed = state.diagnostics_file.clone().unwrap();
        assert_eq!(
            Some(committed.as_str()),
            pending
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .as_deref()
        );
        assert!(pending.is_file(), "the committed file must exist");

        // A follow-up reconcile is quiescent: no second writer or file.
        assert!(!runtime.reconcile(&mut state));

        runtime.writer = None;
        std::fs::remove_file(&pending).unwrap();
    }

    #[test]
    fn diagnostics_final_off_creates_no_file_and_discards_the_pending_path() {
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();
        let pending = diagnostics_temp_path("final-off");
        state.diagnostics_pending_path = Some(pending.clone());
        assert!(!pending.exists());

        send_key(&mut state, KeyCode::Char('o')); // draft := actual (OFF)
        send_key(&mut state, KeyCode::Char('j'));
        send_key(&mut state, KeyCode::Char('l')); // draft ON
        send_key(&mut state, KeyCode::Char('l')); // draft OFF
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.settings_open);

        assert!(!runtime.reconcile(&mut state));
        assert!(runtime.writer.is_none());
        assert!(!enabled.load(Ordering::Relaxed));
        assert!(!state.diagnostics_enabled);
        assert!(
            state.diagnostics_pending_path.is_none(),
            "an OFF draft discards the pending path"
        );
        assert!(
            !pending.exists(),
            "no file may be created for a final OFF state"
        );
    }

    #[test]
    fn diagnostics_actual_on_keeps_writer_and_file_when_draft_returns_on() {
        let pending = diagnostics_temp_path("keep-on");
        let writer = DiagnosticsWriter::create(&pending).unwrap();
        let file_name = writer.file_name().unwrap();
        let enabled = Arc::new(AtomicBool::new(true));
        let mut runtime = DiagnosticsRuntime::new(Some(writer), Arc::clone(&enabled));

        let mut state = AppState::new();
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = Some(file_name.clone());

        send_key(&mut state, KeyCode::Char('o')); // draft := actual (ON)
        assert!(
            state.diagnostics_pending_path.is_none(),
            "no pending path is reserved while diagnostics are actually on"
        );
        send_key(&mut state, KeyCode::Char('j'));
        send_key(&mut state, KeyCode::Char('l')); // draft OFF
        assert!(!state.diagnostics_draft);
        send_key(&mut state, KeyCode::Char('l')); // draft ON again
        assert!(state.diagnostics_draft);
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.settings_open);

        assert!(
            !runtime.reconcile(&mut state),
            "draft matches actual: no change"
        );
        assert!(runtime.writer.is_some());
        assert_eq!(
            runtime.writer.as_ref().unwrap().file_name().as_deref(),
            Some(file_name.as_str())
        );
        assert!(enabled.load(Ordering::Relaxed));
        assert_eq!(state.diagnostics_file.as_deref(), Some(file_name.as_str()));
        assert!(pending.is_file());

        runtime.writer = None;
        std::fs::remove_file(&pending).unwrap();
    }

    #[test]
    fn diagnostics_unchanged_close_does_nothing() {
        // Actual OFF + draft OFF: closing without toggling must not create a
        // writer, and the pending path is discarded.
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();
        send_key(&mut state, KeyCode::Char('o'));
        let pending = state.diagnostics_pending_path.clone().unwrap();
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.settings_open);

        assert!(!runtime.reconcile(&mut state));
        assert!(runtime.writer.is_none());
        assert!(!enabled.load(Ordering::Relaxed));
        assert!(!state.diagnostics_enabled);
        assert!(state.diagnostics_pending_path.is_none());
        assert!(!pending.exists());
    }

    #[test]
    fn diagnostics_commit_failure_keeps_actual_state_and_reports_error() {
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();
        // Point the pending path at an existing file so create_new fails.
        let blocking = diagnostics_temp_path("block");
        std::fs::write(&blocking, "occupied").unwrap();
        state.diagnostics_enabled = false;
        state.diagnostics_draft = true; // final intent ON
        state.diagnostics_pending_path = Some(blocking.clone());

        assert!(runtime.reconcile(&mut state));
        assert!(runtime.writer.is_none(), "no half-baked writer on failure");
        assert!(!enabled.load(Ordering::Relaxed));
        assert!(!state.diagnostics_enabled, "actual state stays OFF");
        assert!(!state.diagnostics_draft, "failed intent is reverted");
        assert!(
            state.diagnostics_pending_path.is_none(),
            "failed path is consumed"
        );
        assert!(
            state
                .diagnostics_error
                .as_deref()
                .is_some_and(|e| e.starts_with("Diagnostics unavailable:"))
        );
        // The failed intent must not be retried on every loop iteration.
        assert!(!runtime.reconcile(&mut state));

        std::fs::remove_file(&blocking).unwrap();
    }

    #[test]
    fn write_failure_forces_draft_and_pending_off_without_retry() {
        // A runtime write failure must shut diagnostics down completely: the
        // actual state, the settings draft, the writer and the shared flag
        // all go OFF, the reserved path is cleared, and the next reconcile
        // does not re-open the writer. The error stays visible.
        let file = diagnostics_temp_path("write-fail");
        let writer = DiagnosticsWriter::create(&file).unwrap();
        let enabled = Arc::new(AtomicBool::new(true));
        let mut runtime = DiagnosticsRuntime::new(Some(writer), Arc::clone(&enabled));

        let mut state = AppState::new();
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = Some("flowlens-42.log".to_string());
        state.diagnostics_pending_path = Some(PathBuf::from("stale-pending.log"));

        runtime.note_write_failure(&mut state, io::Error::other("disk full"));

        assert!(runtime.writer.is_none());
        assert!(!enabled.load(Ordering::Relaxed));
        assert!(!state.diagnostics_enabled);
        assert!(
            !state.diagnostics_draft,
            "the draft is forced off together with the actual state"
        );
        assert!(state.diagnostics_file.is_none());
        assert!(
            state.diagnostics_pending_path.is_none(),
            "the stale pending path is cleared"
        );
        assert!(
            state
                .diagnostics_error
                .as_deref()
                .is_some_and(|e| e.starts_with("Diagnostics disabled:"))
        );

        // The next reconcile must not re-create the writer or re-enable
        // diagnostics, and the error must survive it.
        assert!(!runtime.reconcile(&mut state));
        assert!(runtime.writer.is_none());
        assert!(!enabled.load(Ordering::Relaxed));
        assert!(!state.diagnostics_enabled);
        assert!(
            state
                .diagnostics_error
                .as_deref()
                .is_some_and(|e| e.starts_with("Diagnostics disabled:"))
        );

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn write_failure_then_manual_reopen_commits_a_fresh_writer() {
        // After a forced shutdown the user can re-open the settings overlay,
        // toggle the draft ON manually and commit a fresh writer.
        let enabled = Arc::new(AtomicBool::new(false));
        let mut runtime = DiagnosticsRuntime::new(None, Arc::clone(&enabled));
        let mut state = AppState::new();
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        runtime.note_write_failure(&mut state, io::Error::other("disk full"));
        assert!(!state.diagnostics_draft);

        let pending = diagnostics_temp_path("reopen");
        state.diagnostics_pending_path = Some(pending.clone());
        send_key(&mut state, KeyCode::Char('o')); // draft := actual (OFF)
        assert!(state.settings_open);
        assert!(!state.diagnostics_draft);
        assert_eq!(
            state.diagnostics_pending_path.as_deref(),
            Some(pending.as_path())
        );
        send_key(&mut state, KeyCode::Char('j'));
        send_key(&mut state, KeyCode::Char('l')); // draft ON
        assert!(state.diagnostics_draft);
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.settings_open);

        assert!(runtime.reconcile(&mut state));
        assert!(runtime.writer.is_some());
        assert!(enabled.load(Ordering::Relaxed));
        assert!(state.diagnostics_enabled);
        assert_eq!(
            state.diagnostics_error, None,
            "a successful manual commit clears the stale error"
        );
        assert!(pending.is_file());

        runtime.writer = None;
        std::fs::remove_file(&pending).unwrap();
    }

    #[test]
    fn interface_switch_keeps_diagnostics_enabled_and_file() {
        let interfaces = interfaces();
        let mut state = AppState::new();
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = Some("flowlens-42.log".to_string());
        let mut snapshot = Arc::new(TrafficSnapshot::default());

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
            |_| Ok(Activation::Activated),
        );

        assert_eq!(outcome, KeyOutcome::Changed);
        assert!(state.interface_selector.is_none());
        assert!(
            state.diagnostics_enabled,
            "a successful interface switch must not disable diagnostics"
        );
        assert_eq!(state.diagnostics_file.as_deref(), Some("flowlens-42.log"));
    }

    #[test]
    fn interface_switch_preserves_writer_flag_and_file_name() {
        // The runtime side of the switch: after the view reset, reconcile must
        // not see a state mismatch and silently close an open writer.
        let pending = diagnostics_temp_path("switch");
        let writer = DiagnosticsWriter::create(&pending).unwrap();
        let file_name = writer.file_name().unwrap();
        let enabled = Arc::new(AtomicBool::new(true));
        let mut runtime = DiagnosticsRuntime::new(Some(writer), Arc::clone(&enabled));

        let mut state = AppState::new();
        state.diagnostics_enabled = true;
        state.diagnostics_draft = true;
        state.diagnostics_file = Some(file_name.clone());

        state.reset_after_interface_switch();

        assert!(state.diagnostics_enabled);
        assert!(state.diagnostics_draft);
        assert_eq!(state.diagnostics_file.as_deref(), Some(file_name.as_str()));
        assert!(
            !runtime.reconcile(&mut state),
            "no reconcile churn after the switch"
        );
        assert!(runtime.writer.is_some());
        assert_eq!(
            runtime.writer.as_ref().unwrap().file_name().as_deref(),
            Some(file_name.as_str())
        );
        assert!(enabled.load(Ordering::Relaxed));

        runtime.writer = None;
        std::fs::remove_file(&pending).unwrap();
    }

    #[test]
    fn settings_overlay_highlights_the_selected_row() {
        let snapshot = TrafficSnapshot::default();
        let area = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        };
        let popup = centered_rect(area, 70, 11);
        let render_styles = |selection: usize| {
            let mut state = AppState::new();
            state.settings_open = true;
            state.settings_selection = selection;
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
                .unwrap();
            let buffer = terminal.backend().buffer();
            (
                buffer[(popup.x + 1, popup.y + 2)].style(),
                buffer[(popup.x + 1, popup.y + 3)].style(),
            )
        };
        let (palette_top, diagnostics_top) = render_styles(0);
        let (palette_bottom, diagnostics_bottom) = render_styles(1);
        assert_ne!(
            palette_top, palette_bottom,
            "palette row highlight should follow selection"
        );
        assert_ne!(
            diagnostics_top, diagnostics_bottom,
            "diagnostics row highlight should follow selection"
        );
    }

    #[test]
    fn settings_marker_prefix_is_color_independent() {
        // The `> ` prefix is deliberately independent of the palette: 16-color
        // and monochrome tiers may not render the highlight style (covered by
        // palette::tests::selection_style_reverses_below_truecolor), so the
        // selection must stay identifiable from the marker alone.
        assert_eq!(settings_selection_prefix(true), "> ");
        assert_eq!(settings_selection_prefix(false), "  ");
    }

    #[test]
    fn settings_marker_and_padding_keep_rows_aligned() {
        let snapshot = TrafficSnapshot::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut state = AppState::new();
        state.settings_open = true;
        state.settings_selection = 0;
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("> Palette:"));
        assert!(rendered.contains("  Diagnostics:"));

        state.settings_selection = 1;
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("> Diagnostics:"));
        assert!(rendered.contains("  Palette:"));
    }

    #[test]
    fn settings_overlay_clears_underlying_cells() {
        let state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let area = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        };
        let popup = centered_rect(area, 70, 11);

        terminal
            .draw(|frame| {
                frame.render_widget(
                    Paragraph::new("underlay"),
                    Rect {
                        x: popup.x + 2,
                        y: popup.y + 1,
                        width: 8,
                        height: 1,
                    },
                );
                draw_settings(frame, area, &state);
            })
            .unwrap();

        assert_eq!(
            terminal.backend().buffer()[(popup.x + 2, popup.y + 1)].symbol(),
            " "
        );
    }

    #[test]
    fn settings_overlay_is_not_rendered_when_closed() {
        let snapshot = TrafficSnapshot::default();
        let mut state = AppState::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(!rendered.contains("Settings"));
    }

    #[test]
    fn overlay_h_and_l_cycle_palette_choice_in_opposite_directions() {
        let mut state = AppState::new();
        // Pin detected_tier to Truecolor so resolve(Auto, Truecolor) stays at
        // Truecolor; the one-step cycle exercised here (Auto -> Truecolor)
        // therefore leaves the global ACTIVE tier unchanged, avoiding
        // interference with parallel tests. The full 4-step cycle (including
        // SixteenColor/Monochrome) is covered by the pure-function test
        // next_palette_choice_cycles_through_all_four_with_wraparound.
        state.detected_tier = palette::ColorTier::Truecolor;
        state.palette_choice = palette::PaletteChoice::Auto;

        // Open the overlay; the default choice is Auto.
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);

        // 'l' advances Auto -> Truecolor (no tier change since detected=Truecolor).
        assert_eq!(
            send_key(&mut state, KeyCode::Char('l')),
            KeyOutcome::Changed
        );
        assert_eq!(state.palette_choice, palette::PaletteChoice::Truecolor);

        // 'h' cycles backward. Start from Truecolor so the step stays
        // side-effect-free: prev(Truecolor) == Auto and resolve(Auto,
        // Truecolor) == Truecolor leaves the global ACTIVE tier untouched.
        state.palette_choice = palette::PaletteChoice::Truecolor;
        assert_eq!(
            send_key(&mut state, KeyCode::Char('h')),
            KeyOutcome::Changed
        );
        assert_eq!(state.palette_choice, palette::PaletteChoice::Auto);

        // Enter is a no-op under the unified select/change model.
        state.palette_choice = palette::PaletteChoice::Auto;
        assert_eq!(send_key(&mut state, KeyCode::Enter), KeyOutcome::Ignored);
        assert_eq!(state.palette_choice, palette::PaletteChoice::Auto);
    }

    #[test]
    fn overlay_swallows_page_keys_but_q_still_quits() {
        let mut state = AppState::new();
        send_key(&mut state, KeyCode::Char('o'));
        assert!(state.settings_open);

        // Tab/1-5 get swallowed by the overlay.
        assert_eq!(send_key(&mut state, KeyCode::Tab), KeyOutcome::Ignored,);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('1')),
            KeyOutcome::Ignored,
        );
        assert_eq!(state.page, Page::Overview);

        // q still requests a global quit even with the overlay open.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('q')),
            KeyOutcome::Changed
        );
        assert!(state.quit_confirm);
        assert!(state.settings_open);
        assert_eq!(send_key(&mut state, KeyCode::Char('q')), KeyOutcome::Quit);
    }

    #[test]
    fn quit_requires_confirmation_and_can_be_cancelled() {
        let mut state = AppState::new();
        assert_eq!(
            send_key(&mut state, KeyCode::Char('q')),
            KeyOutcome::Changed
        );
        assert!(state.quit_confirm);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('n')),
            KeyOutcome::Changed
        );
        assert!(!state.quit_confirm);

        assert_eq!(
            send_key(&mut state, KeyCode::Char('q')),
            KeyOutcome::Changed
        );
        assert_eq!(send_key(&mut state, KeyCode::Esc), KeyOutcome::Changed);
        assert!(!state.quit_confirm);
        assert_eq!(
            send_key(&mut state, KeyCode::Char('q')),
            KeyOutcome::Changed
        );
        assert_eq!(send_key(&mut state, KeyCode::Enter), KeyOutcome::Quit);
    }

    #[test]
    fn quit_confirm_overlay_renders_prompt() {
        let mut state = AppState::new();
        state.quit_confirm = true;
        let snapshot = TrafficSnapshot::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now()))
            .unwrap();
        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Confirm"));
        assert!(rendered.contains("Quit FlowLens?"));
        assert!(rendered.contains("q/y/Enter quit"));
        assert!(rendered.contains("n/Esc cancel"));
    }

    #[test]
    fn palette_choice_and_tier_labels_match_the_adr_wording() {
        assert_eq!(palette_choice_label(palette::PaletteChoice::Auto), "Auto");
        assert_eq!(
            palette_choice_label(palette::PaletteChoice::Truecolor),
            "truecolor",
        );
        assert_eq!(
            palette_choice_label(palette::PaletteChoice::SixteenColor),
            "16-color",
        );
        assert_eq!(
            palette_choice_label(palette::PaletteChoice::Monochrome),
            "monochrome",
        );

        assert_eq!(color_tier_label(palette::ColorTier::Truecolor), "truecolor");
        assert_eq!(color_tier_label(palette::ColorTier::Sixteen), "16-color");
        assert_eq!(
            color_tier_label(palette::ColorTier::Monochrome),
            "monochrome",
        );
    }

    #[test]
    fn next_palette_choice_cycles_through_all_four_with_wraparound() {
        use palette::PaletteChoice;
        assert_eq!(
            next_palette_choice(PaletteChoice::Auto),
            PaletteChoice::Truecolor,
        );
        assert_eq!(
            next_palette_choice(PaletteChoice::Truecolor),
            PaletteChoice::SixteenColor,
        );
        assert_eq!(
            next_palette_choice(PaletteChoice::SixteenColor),
            PaletteChoice::Monochrome,
        );
        assert_eq!(
            next_palette_choice(PaletteChoice::Monochrome),
            PaletteChoice::Auto,
        );
    }

    #[test]
    fn prev_palette_choice_cycles_backward_through_all_four_with_wraparound() {
        use palette::PaletteChoice;
        assert_eq!(
            prev_palette_choice(PaletteChoice::Auto),
            PaletteChoice::Monochrome,
        );
        assert_eq!(
            prev_palette_choice(PaletteChoice::Truecolor),
            PaletteChoice::Auto,
        );
        assert_eq!(
            prev_palette_choice(PaletteChoice::SixteenColor),
            PaletteChoice::Truecolor,
        );
        assert_eq!(
            prev_palette_choice(PaletteChoice::Monochrome),
            PaletteChoice::SixteenColor,
        );
    }
}
