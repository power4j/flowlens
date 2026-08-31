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
use ratatui::style::Color;

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
use std::cell::RefCell;

#[cfg(test)]
use std::rc::Rc;

#[cfg(test)]
use ratatui::backend::TestBackend;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use crate::stats::{IpSnapshot, OutboundDomainSnapshot, ProcessSnapshot};

#[cfg(test)]
use crossterm::event::{KeyCode, KeyModifiers};

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_event_requests_a_redraw() {
        assert!(event_requires_redraw(&Event::Resize(80, 24)));
        assert!(!event_requires_redraw(&Event::FocusGained));
    }
}
