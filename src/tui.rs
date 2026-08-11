//! Terminal UI: tabbed pages with scrollable tables.
//!
//! The TUI owns only interaction state and the latest immutable traffic snapshot.
//! Capture and aggregation run in the traffic pipeline.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction as LayoutDir, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::capture::InterfaceInfo;
use crate::diagnostics::DiagnosticsWriter;
use crate::palette;
use crate::report::{fmt_elapsed, hostname, human_bytes, truncate};
use crate::session::{Activation, TrafficSession};
use crate::stats::{IpSnapshot, ProcessSnapshot, TrafficSnapshot};

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Number of selectable rows in the settings overlay.
const SETTINGS_SELECTABLE_ROWS: usize = 2;
/// Settings row index for the palette choice.
const PALETTE_ROW: usize = 0;
/// Settings row index for the diagnostics toggle.
const DIAGNOSTICS_ROW: usize = 1;

/// Which page is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Overview,
    Processes,
    Ips,
    Domains,
    About,
}

impl Page {
    const ALL: [Page; 5] = [
        Page::Overview,
        Page::Processes,
        Page::Ips,
        Page::Domains,
        Page::About,
    ];

    fn index(self) -> usize {
        match self {
            Page::Overview => 0,
            Page::Processes => 1,
            Page::Ips => 2,
            Page::Domains => 3,
            Page::About => 4,
        }
    }
}

/// Focus within the IPs page (left/right split).
#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFocus {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyOutcome {
    Quit,
    Changed,
    Ignored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LayoutMode {
    Compact,
    Standard,
    Wide,
}

impl LayoutMode {
    fn from_area(area: Rect) -> Self {
        match area.width {
            120.. => Self::Wide,
            80.. => Self::Standard,
            _ => Self::Compact,
        }
    }
}

const MIN_TERMINAL_WIDTH: u16 = 60;
const MIN_TERMINAL_HEIGHT: u16 = 16;
const PENDING_STATUS_SLOT_WIDTH: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrackingPause {
    OutsideTopN,
    Stale,
}

impl TrackingPause {
    fn message(self) -> &'static str {
        match self {
            Self::OutsideTopN => "Tracking paused: process is no longer in Top-N.",
            Self::Stale => "Tracking paused: process data is stale.",
        }
    }
}

struct ProcessDetail {
    process: ProcessSnapshot,
    paused: Option<TrackingPause>,
    pause_notice: Option<TrackingPause>,
}

struct InterfaceSelector {
    selected: usize,
    can_cancel: bool,
    activating: Option<String>,
    error: Option<String>,
}

impl ProcessDetail {
    fn pause(&mut self, reason: TrackingPause) {
        if self.paused != Some(reason) {
            self.pause_notice = Some(reason);
        }
        self.paused = Some(reason);
    }
}

/// Persistent UI state across refreshes.
struct AppState {
    page: Page,
    proc_scroll: usize,
    process_detail: Option<ProcessDetail>,
    ip_in_scroll: usize,
    ip_out_scroll: usize,
    ip_focus: IpFocus,
    domain_scroll: usize,
    /// Monotonic view height, updated each draw for clamping scrolls.
    proc_view_height: usize,
    ip_in_view_height: usize,
    ip_out_view_height: usize,
    domain_view_height: usize,
    interface_selector: Option<InterfaceSelector>,
    /// Whether the settings overlay is open.
    settings_open: bool,
    /// User-facing palette selection, adjusted in the settings overlay.
    palette_choice: palette::PaletteChoice,
    /// Terminal color tier detected at startup; `Auto` follows this.
    detected_tier: palette::ColorTier,
    diagnostics_error: Option<String>,
    /// Actual diagnostics state: true while a writer is open. Kept in sync
    /// with `DiagnosticsRuntime::writer` and the shared enable flag.
    diagnostics_enabled: bool,
    /// Draft diagnostics state edited in the settings overlay. Copied from
    /// the actual state when the overlay opens and committed only when it
    /// closes, so h/l toggling never touches the writer mid-edit.
    diagnostics_draft: bool,
    /// Basename of the currently open diagnostics output file.
    diagnostics_file: Option<String>,
    /// Path reserved for a future writer while the overlay is open, when the
    /// actual state is OFF. Never turned into a real file except by a final
    /// ON commit; discarded when the final state is OFF.
    diagnostics_pending_path: Option<PathBuf>,
    /// Selected settings row (0 = Palette, 1 = Diagnostics).
    settings_selection: usize,
}

impl AppState {
    fn new() -> Self {
        Self {
            page: Page::Overview,
            proc_scroll: 0,
            process_detail: None,
            ip_in_scroll: 0,
            ip_out_scroll: 0,
            ip_focus: IpFocus::Inbound,
            domain_scroll: 0,
            proc_view_height: 1,
            ip_in_view_height: 1,
            ip_out_view_height: 1,
            domain_view_height: 1,
            interface_selector: None,
            settings_open: false,
            palette_choice: palette::PaletteChoice::Auto,
            detected_tier: palette::detect_tier(),
            diagnostics_error: None,
            diagnostics_enabled: false,
            diagnostics_draft: false,
            diagnostics_file: None,
            diagnostics_pending_path: None,
            settings_selection: 0,
        }
    }

    fn startup(interfaces: &[InterfaceInfo]) -> Self {
        let mut state = Self::new();
        state.open_interface_selector(interfaces, None, false);
        state
    }

    fn open_interface_selector(
        &mut self,
        interfaces: &[InterfaceInfo],
        active: Option<&str>,
        can_cancel: bool,
    ) {
        let selected = active
            .and_then(|active| {
                interfaces
                    .iter()
                    .position(|interface| interface.name == active)
            })
            .or_else(|| {
                interfaces
                    .iter()
                    .position(|interface| interface.is_default_route)
            })
            .unwrap_or(0);
        self.interface_selector = Some(InterfaceSelector {
            selected,
            can_cancel,
            activating: None,
            error: None,
        });
    }

    /// Reset the view after a successful interface switch while preserving the
    /// actual diagnostics state, so an open writer, its file name and any
    /// pending error survive the reset instead of being silently disabled.
    fn reset_after_interface_switch(&mut self) {
        let diagnostics_enabled = self.diagnostics_enabled;
        let diagnostics_draft = self.diagnostics_draft;
        let diagnostics_file = self.diagnostics_file.clone();
        let diagnostics_error = self.diagnostics_error.clone();
        *self = AppState::new();
        self.diagnostics_enabled = diagnostics_enabled;
        self.diagnostics_draft = diagnostics_draft;
        self.diagnostics_file = diagnostics_file;
        self.diagnostics_error = diagnostics_error;
    }

    fn update_process_detail(&mut self, snapshot: &TrafficSnapshot) {
        let Some(detail) = self.process_detail.as_mut() else {
            return;
        };
        let matching_process = snapshot
            .processes
            .iter()
            .find(|process| process.same_identity_as(&detail.process));
        if let Some(process) = matching_process {
            detail.process = process.clone();
        }
        if !snapshot.process_data_fresh {
            detail.pause(TrackingPause::Stale);
        } else if matching_process.is_some() {
            detail.paused = None;
            detail.pause_notice = None;
        } else {
            detail.pause(TrackingPause::OutsideTopN);
        }
    }
}

fn handle_tui_key<F>(
    state: &mut AppState,
    key: KeyEvent,
    snapshot: &mut Arc<TrafficSnapshot>,
    interfaces: &[InterfaceInfo],
    active: Option<&str>,
    mut activate: F,
) -> KeyOutcome
where
    F: FnMut(&str) -> anyhow::Result<Activation>,
{
    if key.kind == KeyEventKind::Release {
        return KeyOutcome::Ignored;
    }

    if matches!(key.code, KeyCode::Char('q'))
        || matches!(key.code, KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL))
    {
        return KeyOutcome::Quit;
    }

    if let Some(selector) = state.interface_selector.as_mut() {
        if selector.activating.is_some() {
            return KeyOutcome::Ignored;
        }
        match key.code {
            KeyCode::Esc if selector.can_cancel => {
                state.interface_selector = None;
                KeyOutcome::Changed
            }
            KeyCode::Esc => KeyOutcome::Ignored,
            KeyCode::Down | KeyCode::Char('j') => {
                selector.selected = (selector.selected + 1).min(interfaces.len().saturating_sub(1));
                selector.error = None;
                KeyOutcome::Changed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                selector.selected = selector.selected.saturating_sub(1);
                selector.error = None;
                KeyOutcome::Changed
            }
            KeyCode::Enter => {
                let Some(interface) = interfaces.get(selector.selected) else {
                    return KeyOutcome::Ignored;
                };
                let interface_name = interface.name.clone();
                match activate(&interface_name) {
                    Ok(Activation::Activated) => {
                        state.reset_after_interface_switch();
                        *snapshot = Arc::new(TrafficSnapshot::default());
                    }
                    Ok(Activation::Pending) => {
                        selector.activating = Some(interface_name);
                    }
                    Ok(Activation::Unchanged) => state.interface_selector = None,
                    Err(error) => {
                        selector.error =
                            Some(format!("Failed to activate {interface_name}: {error}"));
                    }
                }
                KeyOutcome::Changed
            }
            _ => KeyOutcome::Ignored,
        }
    } else if state.settings_open {
        match key.code {
            // `o` and Esc close the overlay; the draft is committed by
            // `DiagnosticsRuntime::reconcile` on the next loop iteration.
            KeyCode::Esc | KeyCode::Char('o') => {
                state.settings_open = false;
                KeyOutcome::Changed
            }
            KeyCode::Up | KeyCode::Char('k') => {
                state.settings_selection = state.settings_selection.saturating_sub(1);
                KeyOutcome::Changed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                state.settings_selection =
                    (state.settings_selection + 1).min(SETTINGS_SELECTABLE_ROWS - 1);
                KeyOutcome::Changed
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Right | KeyCode::Char('l') => {
                if state.settings_selection == PALETTE_ROW {
                    let forward = matches!(key.code, KeyCode::Right | KeyCode::Char('l'));
                    state.palette_choice = if forward {
                        next_palette_choice(state.palette_choice)
                    } else {
                        prev_palette_choice(state.palette_choice)
                    };
                    palette::set_active_tier(palette::resolve(
                        state.palette_choice,
                        state.detected_tier,
                    ));
                } else if state.settings_selection == DIAGNOSTICS_ROW {
                    // Only the draft changes here; the writer and the shared
                    // enable flag are touched once, when the overlay closes
                    // (see `DiagnosticsRuntime::reconcile`).
                    state.diagnostics_draft = !state.diagnostics_draft;
                    // After a write failure forced diagnostics off mid-edit,
                    // the reserved path was cleared; re-reserve one when the
                    // draft moves back ON so the overlay keeps showing it.
                    if state.diagnostics_draft {
                        state
                            .diagnostics_pending_path
                            .get_or_insert_with(crate::diagnostics::default_output_path);
                    }
                } else {
                    return KeyOutcome::Ignored;
                }
                KeyOutcome::Changed
            }
            // Enter has no action in the settings overlay.
            KeyCode::Enter => KeyOutcome::Ignored,
            // The overlay swallows all other keys so page shortcuts do not
            // leak through while it is open.
            _ => KeyOutcome::Ignored,
        }
    } else if key.code == KeyCode::Char('o') {
        state.settings_open = true;
        state.settings_selection = 0;
        // Start editing from the actual diagnostics state, and reserve one
        // pending output path up front when diagnostics are currently off.
        // Repeated in-overlay toggles reuse it; no file is created here.
        state.diagnostics_draft = state.diagnostics_enabled;
        if !state.diagnostics_enabled {
            state
                .diagnostics_pending_path
                .get_or_insert_with(crate::diagnostics::default_output_path);
        }
        KeyOutcome::Changed
    } else if key.code == KeyCode::Char('i') {
        state.open_interface_selector(interfaces, active, true);
        KeyOutcome::Changed
    } else {
        handle_key(state, key, snapshot)
    }
}

fn finish_tui_activation(
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

/// Runtime side of the diagnostics toggle: the open writer plus the shared
/// enable flag that gates pipeline-side collection.
struct DiagnosticsRuntime {
    writer: Option<DiagnosticsWriter>,
    enabled: Arc<AtomicBool>,
}

impl DiagnosticsRuntime {
    fn new(writer: Option<DiagnosticsWriter>, enabled: Arc<AtomicBool>) -> Self {
        Self { writer, enabled }
    }

    /// Apply the settings-overlay draft to the actual diagnostics state once
    /// the overlay is closed. While the overlay is open the draft lives only
    /// in `state`, so rapid h/l toggling never opens or closes the writer.
    /// Returns true when a redraw is required.
    fn reconcile(&mut self, state: &mut AppState) -> bool {
        if state.settings_open {
            return false;
        }
        if state.diagnostics_draft == state.diagnostics_enabled {
            // No runtime change (final state matches the actual one). Discard
            // any path reserved while the overlay was open, e.g. a final OFF
            // state; it is only ever materialized by an ON commit below.
            state.diagnostics_pending_path.take();
            return false;
        }
        if state.diagnostics_draft {
            // Actual OFF -> draft ON: create the writer exactly once, at the
            // path reserved when the overlay opened.
            let path = state
                .diagnostics_pending_path
                .take()
                .unwrap_or_else(crate::diagnostics::default_output_path);
            match DiagnosticsWriter::create(&path) {
                Ok(writer) => {
                    state.diagnostics_file = writer.file_name();
                    state.diagnostics_error = None;
                    state.diagnostics_enabled = true;
                    self.writer = Some(writer);
                    self.enabled.store(true, Ordering::Relaxed);
                }
                Err(error) => {
                    // The actual state stays OFF; revert the draft so the
                    // failed intent is not retried every loop iteration.
                    state.diagnostics_draft = false;
                    state.diagnostics_error = Some(format!("Diagnostics unavailable: {error}"));
                }
            }
        } else {
            // Actual ON -> draft OFF: stop writing and clear the file name.
            self.writer = None;
            state.diagnostics_file = None;
            state.diagnostics_enabled = false;
            self.enabled.store(false, Ordering::Relaxed);
        }
        true
    }

    /// Disable diagnostics after a write failure. The actual state, the
    /// settings draft and the shared flag are all turned off together, and
    /// any reserved path is cleared, so the next `reconcile` has nothing to
    /// commit and never re-opens the writer. The error stays visible in the
    /// status bar; the user can re-open the settings overlay and manually
    /// turn diagnostics back on.
    fn note_write_failure(&mut self, state: &mut AppState, error: io::Error) {
        self.writer = None;
        state.diagnostics_enabled = false;
        state.diagnostics_draft = false;
        state.diagnostics_file = None;
        state.diagnostics_pending_path = None;
        self.enabled.store(false, Ordering::Relaxed);
        state.diagnostics_error = Some(format!("Diagnostics disabled: {error}"));
    }
}

/// Run the TUI until the user quits.
pub fn run(
    session: &mut TrafficSession,
    diagnostics_writer: Option<DiagnosticsWriter>,
    diagnostics_enabled: Arc<AtomicBool>,
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
        DiagnosticsRuntime::new(diagnostics_writer, diagnostics_enabled),
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

fn handle_key(state: &mut AppState, key: KeyEvent, snapshot: &TrafficSnapshot) -> KeyOutcome {
    match key.code {
        KeyCode::Char('q') => KeyOutcome::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyOutcome::Quit,
        KeyCode::Esc if state.process_detail.is_some() => {
            state.process_detail = None;
            KeyOutcome::Changed
        }
        KeyCode::Esc => KeyOutcome::Quit,
        KeyCode::Enter if state.page == Page::Processes && state.process_detail.is_none() => {
            let Some(process) = snapshot.processes.get(state.proc_scroll) else {
                return KeyOutcome::Ignored;
            };
            let mut detail = ProcessDetail {
                process: process.clone(),
                paused: None,
                pause_notice: None,
            };
            if !snapshot.process_data_fresh {
                detail.pause(TrackingPause::Stale);
            }
            state.process_detail = Some(detail);
            KeyOutcome::Changed
        }
        _ if state.process_detail.is_some() => KeyOutcome::Ignored,
        KeyCode::Char('1') => {
            state.page = Page::Overview;
            KeyOutcome::Changed
        }
        KeyCode::Char('2') => {
            state.page = Page::Processes;
            KeyOutcome::Changed
        }
        KeyCode::Char('3') => {
            state.page = Page::Ips;
            KeyOutcome::Changed
        }
        KeyCode::Char('4') => {
            state.page = Page::Domains;
            KeyOutcome::Changed
        }
        KeyCode::Char('5') => {
            state.page = Page::About;
            KeyOutcome::Changed
        }
        KeyCode::Tab => {
            if state.page == Page::Ips {
                state.ip_focus = match state.ip_focus {
                    IpFocus::Inbound => IpFocus::Outbound,
                    IpFocus::Outbound => IpFocus::Inbound,
                };
                KeyOutcome::Changed
            } else {
                KeyOutcome::Ignored
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            state.page = prev_page(state.page);
            KeyOutcome::Changed
        }
        KeyCode::Right | KeyCode::Char('l') => {
            state.page = next_page(state.page);
            KeyOutcome::Changed
        }
        KeyCode::Down | KeyCode::Char('j') => {
            scroll(state, 1);
            KeyOutcome::Changed
        }
        KeyCode::Up | KeyCode::Char('k') => {
            scroll(state, -1);
            KeyOutcome::Changed
        }
        KeyCode::PageDown => {
            scroll(state, state.current_view_height() as isize);
            KeyOutcome::Changed
        }
        KeyCode::PageUp => {
            scroll(state, -(state.current_view_height() as isize));
            KeyOutcome::Changed
        }
        KeyCode::Home => {
            scroll_to_top(state);
            KeyOutcome::Changed
        }
        KeyCode::End => {
            scroll_to_bottom(state, snapshot);
            KeyOutcome::Changed
        }
        _ => KeyOutcome::Ignored,
    }
}

fn prev_page(p: Page) -> Page {
    let idx = p.index();
    Page::ALL[(idx + Page::ALL.len() - 1) % Page::ALL.len()]
}

fn next_page(p: Page) -> Page {
    let idx = p.index();
    Page::ALL[(idx + 1) % Page::ALL.len()]
}

/// Palette choices in the order the settings overlay cycles through them.
const PALETTE_CHOICES: [palette::PaletteChoice; 4] = [
    palette::PaletteChoice::Auto,
    palette::PaletteChoice::Truecolor,
    palette::PaletteChoice::SixteenColor,
    palette::PaletteChoice::Monochrome,
];

fn next_palette_choice(choice: palette::PaletteChoice) -> palette::PaletteChoice {
    let idx = PALETTE_CHOICES
        .iter()
        .position(|candidate| *candidate == choice)
        .unwrap_or(0);
    PALETTE_CHOICES[(idx + 1) % PALETTE_CHOICES.len()]
}

fn prev_palette_choice(choice: palette::PaletteChoice) -> palette::PaletteChoice {
    let idx = PALETTE_CHOICES
        .iter()
        .position(|candidate| *candidate == choice)
        .unwrap_or(0);
    let len = PALETTE_CHOICES.len();
    PALETTE_CHOICES[(idx + len - 1) % len]
}

/// User-visible label for a palette choice, as shown in the settings overlay.
fn palette_choice_label(choice: palette::PaletteChoice) -> &'static str {
    match choice {
        palette::PaletteChoice::Auto => "Auto",
        palette::PaletteChoice::Truecolor => "truecolor",
        palette::PaletteChoice::SixteenColor => "16-color",
        palette::PaletteChoice::Monochrome => "monochrome",
    }
}

/// User-visible label for a detected color tier.
fn color_tier_label(tier: palette::ColorTier) -> &'static str {
    match tier {
        palette::ColorTier::Truecolor => "truecolor",
        palette::ColorTier::Sixteen => "16-color",
        palette::ColorTier::Monochrome => "monochrome",
    }
}

impl AppState {
    fn current_view_height(&self) -> usize {
        match self.page {
            Page::Processes => self.proc_view_height,
            Page::Ips => match self.ip_focus {
                IpFocus::Inbound => self.ip_in_view_height,
                IpFocus::Outbound => self.ip_out_view_height,
            },
            Page::Domains => self.domain_view_height,
            _ => 1,
        }
    }
}

fn scroll(state: &mut AppState, delta: isize) {
    match state.page {
        Page::Processes => {
            state.proc_scroll = (state.proc_scroll as isize + delta).max(0) as usize;
        }
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => {
                state.ip_in_scroll = (state.ip_in_scroll as isize + delta).max(0) as usize;
            }
            IpFocus::Outbound => {
                state.ip_out_scroll = (state.ip_out_scroll as isize + delta).max(0) as usize;
            }
        },
        Page::Domains => {
            state.domain_scroll = (state.domain_scroll as isize + delta).max(0) as usize;
        }
        _ => {}
    }
}

fn scroll_to_top(state: &mut AppState) {
    match state.page {
        Page::Processes => state.proc_scroll = 0,
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => state.ip_in_scroll = 0,
            IpFocus::Outbound => state.ip_out_scroll = 0,
        },
        Page::Domains => state.domain_scroll = 0,
        _ => {}
    }
}

fn scroll_to_bottom(state: &mut AppState, snapshot: &TrafficSnapshot) {
    match state.page {
        Page::Processes => {
            let len = snapshot.processes.len();
            state.proc_scroll = len.saturating_sub(state.proc_view_height);
        }
        Page::Ips => match state.ip_focus {
            IpFocus::Inbound => {
                let len = snapshot.inbound_ips.len();
                state.ip_in_scroll = len.saturating_sub(state.ip_in_view_height);
            }
            IpFocus::Outbound => {
                let len = snapshot.outbound_ips.len();
                state.ip_out_scroll = len.saturating_sub(state.ip_out_view_height);
            }
        },
        Page::Domains => {
            let len = snapshot.outbound_domains.len();
            state.domain_scroll = len.saturating_sub(state.domain_view_height);
        }
        _ => {}
    }
}

// ── drawing ──

#[cfg(test)]
fn draw(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
) {
    draw_with_interfaces(f, state, snapshot, Some(interface), &[], host, started_at);
}

fn draw_with_interfaces(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: Option<&str>,
    interfaces: &[InterfaceInfo],
    host: &str,
    started_at: Instant,
) {
    draw_with_interfaces_at(
        f,
        state,
        snapshot,
        interface,
        interfaces,
        host,
        started_at,
        chrono::Utc::now(),
    );
}

#[cfg(test)]
fn draw_at(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: &str,
    host: &str,
    started_at: Instant,
    now: chrono::DateTime<chrono::Utc>,
) {
    draw_with_interfaces_at(
        f,
        state,
        snapshot,
        Some(interface),
        &[],
        host,
        started_at,
        now,
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_with_interfaces_at(
    f: &mut ratatui::Frame,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    interface: Option<&str>,
    interfaces: &[InterfaceInfo],
    host: &str,
    started_at: Instant,
    now: chrono::DateTime<chrono::Utc>,
) {
    let area = f.area();
    f.render_widget(
        Block::default().style(Style::default().fg(palette::text()).bg(palette::bg())),
        area,
    );

    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        draw_too_small(f, area);
        return;
    }

    if let Some(selector) = state.interface_selector.as_ref() {
        draw_interface_selector(f, area, selector, interfaces, interface);
        return;
    }

    let mode = LayoutMode::from_area(area);
    let chunks = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let interface_label = interface_display_label(interface, interfaces);
    draw_header(
        f,
        chunks[0],
        state.page,
        &interface_label,
        host,
        started_at,
        mode,
    );
    let body = chunks[1].inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    match state.page {
        Page::Overview => draw_overview(f, body, snapshot, mode, now),
        Page::Processes => match state.process_detail.as_ref() {
            Some(detail) => draw_process_detail(f, body, detail, now),
            None => draw_processes(f, body, state, snapshot, mode, now),
        },
        Page::Ips => draw_ips(f, body, state, snapshot, mode, now),
        Page::Domains => draw_domains(f, body, state, snapshot, mode, now),
        Page::About => draw_about(f, body),
    }
    draw_status_bar(f, chunks[2], state, mode);

    if state.settings_open {
        draw_settings(f, area, state);
    }
}

fn interface_display_label(interface: Option<&str>, interfaces: &[InterfaceInfo]) -> String {
    let interface_name = interface.unwrap_or("No interface");
    interfaces
        .iter()
        .find(|candidate| candidate.name == interface_name)
        .map(|candidate| candidate.description.as_str())
        .filter(|description| !description.is_empty() && *description != "No description")
        .map(str::to_string)
        .unwrap_or_else(|| interface_name.to_string())
}

fn draw_interface_selector(
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

fn draw_too_small(f: &mut ratatui::Frame, area: Rect) {
    let message_area = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(area)[1];
    let lines = vec![
        Line::from(Span::styled(
            "flowlens",
            Style::default()
                .fg(palette::accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("Terminal too small (minimum {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT})"),
            Style::default().fg(palette::muted()),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        message_area,
    );
}

fn draw_header(
    f: &mut ratatui::Frame,
    area: Rect,
    page: Page,
    interface: &str,
    host: &str,
    started_at: Instant,
    mode: LayoutMode,
) {
    let navigation = navigation_line(page, mode);
    if page == Page::About {
        f.render_widget(Paragraph::new(navigation), area);
        return;
    }

    let runtime = runtime_line(interface, host, started_at, mode);
    let runtime_width = (runtime.width() as u16).min(area.width / 2);
    let chunks = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(runtime_width)])
        .split(area);
    f.render_widget(Paragraph::new(navigation), chunks[0]);
    f.render_widget(
        Paragraph::new(runtime).alignment(Alignment::Right),
        chunks[1],
    );
}

fn navigation_line(page: Page, mode: LayoutMode) -> Line<'static> {
    let mut spans = vec![Span::styled(
        " flowlens ",
        Style::default()
            .fg(palette::accent())
            .add_modifier(Modifier::BOLD),
    )];
    for candidate in Page::ALL {
        let label = match (candidate, mode) {
            (Page::Overview, LayoutMode::Compact) => " 1 ".to_string(),
            (Page::Processes, LayoutMode::Compact) => " 2 ".to_string(),
            (Page::Ips, LayoutMode::Compact) => " 3 ".to_string(),
            (Page::Domains, LayoutMode::Compact) => " 4 ".to_string(),
            (Page::About, LayoutMode::Compact) => " 5 ".to_string(),
            (Page::Overview, _) => " 1 Overview ".to_string(),
            (Page::Processes, _) => " 2 Processes ".to_string(),
            (Page::Ips, _) => " 3 IPs ".to_string(),
            (Page::Domains, _) => " 4 Domains ".to_string(),
            (Page::About, _) => " 5 About ".to_string(),
        };
        let style = if candidate == page {
            Style::default()
                .fg(palette::strong())
                .bg(palette::overview_highlight())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(palette::muted())
        };
        spans.push(Span::styled(label, style));
    }
    Line::from(spans)
}

fn runtime_line(
    interface: &str,
    host: &str,
    started_at: Instant,
    mode: LayoutMode,
) -> Line<'static> {
    let mut spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            interface.to_string(),
            Style::default().fg(palette::strong()),
        ),
    ];
    if mode == LayoutMode::Wide {
        spans.push(Span::styled("  ", Style::default()));
        spans.push(Span::styled(
            host.to_string(),
            Style::default().fg(palette::strong()),
        ));
    }
    spans.push(Span::styled("  up ", Style::default().fg(palette::muted())));
    spans.push(Span::styled(
        fmt_elapsed(started_at.elapsed()),
        Style::default().fg(palette::strong()),
    ));
    if mode != LayoutMode::Compact {
        spans.push(Span::styled(
            format!("  {}", chrono::Local::now().format("%H:%M:%S")),
            Style::default().fg(palette::muted()),
        ));
    }
    Line::from(spans)
}

fn draw_overview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    // Row-based layout (ticket 07): every row is either a full-width panel or two
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

fn draw_traffic(f: &mut ratatui::Frame, area: Rect, snapshot: &TrafficSnapshot) {
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

fn ratio(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64
    }
}

fn traffic_line(label: &str, color: Color, ratio: f64, value: &str, width: u16) -> Line<'static> {
    const LABEL_WIDTH: usize = 10;
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

fn panel_block(
    prefix: &str,
    title: &str,
    count: Option<usize>,
    prefix_color: Color,
    border_color: Color,
    footer: Option<String>,
) -> Block<'static> {
    let mut title_spans = vec![
        Span::styled(
            format!(" {prefix} "),
            Style::default()
                .fg(prefix_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            title.to_string(),
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(count) = count {
        title_spans.push(Span::styled(
            format!(" {count} "),
            Style::default().fg(palette::muted()),
        ));
    } else {
        title_spans.push(Span::raw(" "));
    }

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Line::from(title_spans));
    if let Some(footer) = footer {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" {footer} "),
                Style::default().fg(palette::muted()),
            ))
            .alignment(Alignment::Right),
        );
    }
    block
}

fn process_name_span(process: &ProcessSnapshot, max_chars: usize) -> Span<'static> {
    let name = if process.is_unattributed() {
        process.display_name().to_string()
    } else {
        truncate(process.display_name(), max_chars)
    };
    if process.is_unattributed() {
        Span::styled(
            name,
            Style::default()
                .fg(palette::warn())
                .add_modifier(Modifier::ITALIC),
        )
    } else {
        Span::raw(name)
    }
}

fn draw_process_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let footer = preview_position(snapshot.processes.len(), area.height);
    let block = panel_block(
        "proc",
        "Top Processes",
        Some(snapshot.processes.len()),
        palette::coral(),
        palette::border(),
        Some(footer),
    );
    // The overview preview is informational, so it must not select a row.
    f.render_widget(process_table(snapshot, mode, block, now), area);
}

fn process_table(
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    block: Block<'static>,
    now: chrono::DateTime<chrono::Utc>,
) -> Table<'static> {
    let compact = mode == LayoutMode::Compact;
    let rows = process_rows(snapshot, compact, now);
    let header_style = Style::default().fg(palette::muted());
    let table = if compact {
        Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Process", "Total", "Last seen"]).style(header_style))
    } else {
        Table::new(
            rows,
            [
                Constraint::Min(22),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(11),
            ],
        )
        .header(
            Row::new(vec!["Process", "PID", "Recv", "Sent", "Total", "Last seen"])
                .style(header_style),
        )
    };
    table.column_spacing(1).block(block)
}

fn process_rows(
    snapshot: &TrafficSnapshot,
    compact: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Row<'static>> {
    if snapshot.processes.is_empty() {
        let cells = if compact {
            vec![
                Cell::from("No traffic observed"),
                Cell::from(""),
                Cell::from(""),
            ]
        } else {
            vec![
                Cell::from("No traffic observed"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]
        };
        return vec![Row::new(cells).style(Style::default().fg(palette::muted()))];
    }

    snapshot
        .processes
        .iter()
        .map(|process| {
            let name = Cell::from(process_name_span(process, 40));
            if compact {
                Row::new(vec![
                    name,
                    Cell::from(human_bytes(process.total()))
                        .style(Style::default().fg(palette::strong())),
                    Cell::from(relative_last_seen(process.last_seen(), now)),
                ])
            } else {
                Row::new(vec![
                    name,
                    Cell::from(
                        process
                            .pid()
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(human_bytes(process.recv))
                        .style(Style::default().fg(palette::inbound())),
                    Cell::from(human_bytes(process.sent))
                        .style(Style::default().fg(palette::outbound())),
                    Cell::from(human_bytes(process.total()))
                        .style(Style::default().fg(palette::strong())),
                    Cell::from(relative_last_seen(process.last_seen(), now)),
                ])
            }
        })
        .collect()
}

fn selected_position(selected: usize, len: usize) -> String {
    if len == 0 {
        "0/0".to_string()
    } else {
        format!("{}/{}", selected.min(len - 1) + 1, len)
    }
}

fn preview_position(len: usize, height: u16) -> String {
    if len == 0 {
        return "0/0".to_string();
    }
    let shown = len.min(height.saturating_sub(3) as usize);
    format!("1-{shown}/{len}")
}

fn draw_processes(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let view_h = area.height.saturating_sub(3) as usize;
    state.proc_view_height = view_h.max(1);
    state.proc_scroll = state
        .proc_scroll
        .min(snapshot.processes.len().saturating_sub(1));

    let footer = selected_position(state.proc_scroll, snapshot.processes.len());
    let block = panel_block(
        "proc",
        "Processes",
        Some(snapshot.processes.len()),
        palette::coral(),
        palette::border(),
        Some(footer),
    )
    .title(pending_status_title(
        snapshot.pending_attribution_bytes,
        area.width,
    ));
    let table = process_table(snapshot, mode, block, now)
        .row_highlight_style(
            Style::default()
                .patch(palette::selection_style())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(
        table,
        area,
        &mut ratatui_state(snapshot.processes.len(), state.proc_scroll),
    );
}

fn pending_status_title(bytes: u64, area_width: u16) -> Line<'static> {
    let slot_width = if area_width < 44 {
        1
    } else {
        PENDING_STATUS_SLOT_WIDTH
    };
    let label = if slot_width == 1 {
        if bytes == 0 {
            String::new()
        } else {
            "?".to_string()
        }
    } else {
        const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut value = bytes as f64;
        let mut unit_index = 0;
        while unit_index < UNITS.len() - 1 && (value * 100.0).round() / 100.0 >= 1024.0 {
            value /= 1024.0;
            unit_index += 1;
        }
        let unit = UNITS[unit_index];
        let rounded_value = (value * 100.0).round() / 100.0;
        let full = if unit_index == UNITS.len() - 1 && rounded_value >= 1024.0 {
            "?".to_string()
        } else {
            format!("? {value:>7.2} {unit:>2}")
        };
        if full.chars().count() <= PENDING_STATUS_SLOT_WIDTH {
            full
        } else {
            "?".to_string()
        }
    };
    let padding = slot_width.saturating_sub(label.chars().count());
    Line::from(Span::styled(
        format!("{}{}", " ".repeat(padding), label),
        Style::default().fg(if bytes == 0 {
            palette::muted()
        } else {
            palette::warn()
        }),
    ))
    .alignment(Alignment::Right)
}

fn draw_process_detail(
    f: &mut ratatui::Frame,
    area: Rect,
    detail: &ProcessDetail,
    now: chrono::DateTime<chrono::Utc>,
) {
    let process = &detail.process;
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Name: "),
            process_name_span(process, usize::MAX),
        ]),
        Line::from(format!(
            "PID: {}",
            process
                .pid()
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string())
        )),
        Line::from(format!("Path: {}", process.path().unwrap_or("-"))),
        Line::from(""),
        Line::from(format!("Recv: {}", human_bytes(process.recv))),
        Line::from(format!("Sent: {}", human_bytes(process.sent))),
        Line::from(format!("Total: {}", human_bytes(process.total()))),
        Line::from(format!(
            "Last seen: {}",
            relative_last_seen(process.last_seen(), now)
        )),
    ];
    if detail.paused.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Tracking paused",
            Style::default()
                .fg(palette::warn())
                .add_modifier(Modifier::BOLD),
        )));
    }
    let block = panel_block(
        "proc",
        "Process Details",
        None,
        palette::coral(),
        palette::border(),
        None,
    );
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn relative_last_seen(
    last_seen: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let seconds = now.signed_duration_since(last_seen).num_seconds().max(0);
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 60 * 60 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h ago", seconds / (60 * 60))
    } else {
        format!("{}d ago", seconds / (24 * 60 * 60))
    }
}

fn draw_ip_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    inbound: bool,
    now: chrono::DateTime<chrono::Utc>,
) {
    let entries = if inbound {
        snapshot.inbound_ips.as_ref()
    } else {
        snapshot.outbound_ips.as_ref()
    };
    let (prefix, title, color) = ip_theme(inbound);
    let block = panel_block(
        prefix,
        title,
        Some(entries.len()),
        color,
        palette::border(),
        Some(preview_position(entries.len(), area.height)),
    );
    let table = ip_table(entries, color, block, now);
    f.render_widget(table, area);
}

fn ip_theme(inbound: bool) -> (&'static str, &'static str, Color) {
    if inbound {
        ("in", "Inbound IPs", palette::inbound())
    } else {
        ("out", "Outbound IPs", palette::outbound())
    }
}

fn ip_table(
    entries: &[IpSnapshot],
    color: Color,
    block: Block<'static>,
    now: chrono::DateTime<chrono::Utc>,
) -> Table<'static> {
    let rows = if entries.is_empty() {
        vec![
            Row::new(vec!["No traffic observed", "", ""])
                .style(Style::default().fg(palette::muted())),
        ]
    } else {
        entries
            .iter()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.ip.to_string()),
                    Cell::from(human_bytes(entry.bytes)).style(Style::default().fg(color)),
                    Cell::from(relative_last_seen(entry.last_seen(), now)),
                ])
            })
            .collect()
    };
    Table::new(
        rows,
        [
            Constraint::Min(14),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["Remote address", "Total", "Last seen"])
            .style(Style::default().fg(palette::muted())),
    )
    .column_spacing(1)
    .block(block)
}

fn draw_ips(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let panes = if mode == LayoutMode::Compact {
        Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(50),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(50),
            ])
            .split(area)
    };

    let inbound_area = panes[0];
    let outbound_area = panes[2];
    state.ip_in_view_height = (inbound_area.height.saturating_sub(3) as usize).max(1);
    state.ip_out_view_height = (outbound_area.height.saturating_sub(3) as usize).max(1);
    state.ip_in_scroll = state
        .ip_in_scroll
        .min(snapshot.inbound_ips.len().saturating_sub(1));
    state.ip_out_scroll = state
        .ip_out_scroll
        .min(snapshot.outbound_ips.len().saturating_sub(1));

    draw_ip_table(
        f,
        inbound_area,
        snapshot.inbound_ips.as_ref(),
        true,
        state.ip_focus == IpFocus::Inbound,
        state.ip_in_scroll,
        now,
    );
    draw_ip_table(
        f,
        outbound_area,
        snapshot.outbound_ips.as_ref(),
        false,
        state.ip_focus == IpFocus::Outbound,
        state.ip_out_scroll,
        now,
    );
}

fn draw_ip_table(
    f: &mut ratatui::Frame,
    area: Rect,
    entries: &[IpSnapshot],
    inbound: bool,
    focused: bool,
    selected: usize,
    now: chrono::DateTime<chrono::Utc>,
) {
    let (prefix, title, color) = ip_theme(inbound);
    let block = panel_block(
        prefix,
        title,
        Some(entries.len()),
        color,
        palette::border(),
        Some(selected_position(selected, entries.len())),
    );
    let table = ip_table(entries, color, block, now)
        .row_highlight_style(if focused {
            Style::default()
                .fg(palette::strong())
                .patch(palette::selection_style())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        })
        .highlight_symbol(if focused { "> " } else { "  " });
    f.render_stateful_widget(table, area, &mut ratatui_state(entries.len(), selected));
}

/// Overview preview of top outbound domains. Mirrors `draw_ip_preview` and
/// `draw_process_preview`: panel prefix `dom`, title `Top Domains`, rows
/// clipped by height, `preview_position` footer.
fn draw_domain_preview(
    f: &mut ratatui::Frame,
    area: Rect,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let footer = preview_position(snapshot.outbound_domains.len(), area.height);
    let block = panel_block(
        "dom",
        "Top Domains",
        Some(snapshot.outbound_domains.len()),
        palette::violet(),
        palette::border(),
        Some(footer),
    );
    let table = domain_table(snapshot, mode, block, now);
    f.render_widget(table, area);
}

fn draw_domains(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &mut AppState,
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    now: chrono::DateTime<chrono::Utc>,
) {
    let view_h = area.height.saturating_sub(3) as usize;
    state.domain_view_height = view_h.max(1);
    state.domain_scroll = state
        .domain_scroll
        .min(snapshot.outbound_domains.len().saturating_sub(1));

    let footer = selected_position(state.domain_scroll, snapshot.outbound_domains.len());
    let block = panel_block(
        "dom",
        "Domains",
        Some(snapshot.outbound_domains.len()),
        palette::violet(),
        palette::border(),
        Some(footer),
    );
    let table = domain_table(snapshot, mode, block, now)
        .row_highlight_style(
            Style::default()
                .patch(palette::selection_style())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(
        table,
        area,
        &mut ratatui_state(snapshot.outbound_domains.len(), state.domain_scroll),
    );
}

fn domain_table(
    snapshot: &TrafficSnapshot,
    mode: LayoutMode,
    block: Block<'static>,
    now: chrono::DateTime<chrono::Utc>,
) -> Table<'static> {
    let compact = mode == LayoutMode::Compact;
    let rows = domain_rows(snapshot, compact, now);
    let header_style = Style::default().fg(palette::muted());
    let table = if compact {
        Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Host", "Total", "Last seen"]).style(header_style))
    } else {
        Table::new(
            rows,
            [
                Constraint::Min(20),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(vec!["Host", "In", "Out", "Total", "Last seen"]).style(header_style))
    };
    table.column_spacing(1).block(block)
}

fn domain_rows(
    snapshot: &TrafficSnapshot,
    compact: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Row<'static>> {
    if snapshot.outbound_domains.is_empty() {
        let cells = if compact {
            vec![
                Cell::from("No outbound domains observed"),
                Cell::from(""),
                Cell::from(""),
            ]
        } else {
            vec![
                Cell::from("No outbound domains observed"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]
        };
        return vec![Row::new(cells).style(Style::default().fg(palette::muted()))];
    }

    snapshot
        .outbound_domains
        .iter()
        .map(|domain| {
            let host = Cell::from(truncate(domain.host(), 40));
            let last_seen = Cell::from(relative_last_seen(domain.last_seen(), now));
            if compact {
                Row::new(vec![
                    host,
                    Cell::from(human_bytes(domain.total_bytes()))
                        .style(Style::default().fg(palette::strong())),
                    last_seen,
                ])
            } else {
                Row::new(vec![
                    host,
                    Cell::from(human_bytes(domain.in_bytes))
                        .style(Style::default().fg(palette::inbound())),
                    Cell::from(human_bytes(domain.out_bytes))
                        .style(Style::default().fg(palette::outbound())),
                    Cell::from(human_bytes(domain.total_bytes()))
                        .style(Style::default().fg(palette::strong())),
                    last_seen,
                ])
            }
        })
        .collect()
}

fn draw_about(f: &mut ratatui::Frame, area: Rect) {
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

/// Two-character selection marker column: `> ` for the selected row, two
/// spaces otherwise, so rows stay aligned even when the highlight style is not
/// visible (16-color/monochrome tiers).
fn settings_selection_prefix(selected: bool) -> &'static str {
    if selected { "> " } else { "  " }
}

/// Truncate a single-line label to at most `max` display columns, keeping the
/// start and end with a middle ellipsis. Used so long diagnostics basenames
/// cannot overflow the settings overlay.
fn truncate_with_ellipsis(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let keep_head = (max - 1) / 2;
    let keep_tail = (max - 1) - keep_head;
    let mut out: String = text.chars().take(keep_head).collect();
    out.push('…');
    out.extend(text.chars().skip(count - keep_tail));
    out
}

/// Centered settings overlay: lets the user pick the active palette tier for
/// the session. Drawn on top of the current page when `state.settings_open`.
fn draw_settings(f: &mut ratatui::Frame, area: Rect, state: &AppState) {
    let popup = centered_rect(area, 70, 9);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette::accent()))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "Settings",
                Style::default()
                    .fg(palette::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]));
    let detected_label = color_tier_label(state.detected_tier);
    let choice_label = palette_choice_label(state.palette_choice);
    let diagnostics_label = if state.diagnostics_draft { "ON" } else { "OFF" };
    let selection_style = palette::selection_style();
    let palette_selected = state.settings_selection == PALETTE_ROW;
    let mut palette_line = Line::from(vec![
        Span::raw(settings_selection_prefix(palette_selected)),
        Span::styled(
            "Palette: ",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            choice_label.to_string(),
            Style::default().fg(palette::accent()),
        ),
        Span::styled(
            format!("  (detected: {detected_label})"),
            Style::default().fg(palette::muted()),
        ),
    ]);
    let mut diagnostics_line = Line::from(vec![
        Span::raw(settings_selection_prefix(
            state.settings_selection == DIAGNOSTICS_ROW,
        )),
        Span::styled(
            "Diagnostics: ",
            Style::default()
                .fg(palette::strong())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(diagnostics_label, Style::default().fg(palette::accent())),
    ]);
    if palette_selected {
        palette_line.style = selection_style;
    } else {
        diagnostics_line.style = selection_style;
    }
    // File display follows the (actual, draft) matrix: the live file name is
    // shown while diagnostics are actually on (flagged when the draft would
    // stop them on close); a pending path is shown while actually off but
    // drafted on; otherwise "(none)".
    let file_text = match (state.diagnostics_enabled, state.diagnostics_draft) {
        (true, true) => state
            .diagnostics_file
            .as_deref()
            .unwrap_or("(none)")
            .to_string(),
        (true, false) => format!(
            "{} (stops on close)",
            state.diagnostics_file.as_deref().unwrap_or("(none)")
        ),
        (false, true) => {
            let name = state
                .diagnostics_pending_path
                .as_ref()
                .and_then(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "(none)".to_string());
            format!("{name} (pending)")
        }
        (false, false) => "(none)".to_string(),
    };
    let inner = block.inner(popup);
    // Budget for the label: "File: " prefix plus a small right margin, so a
    // long basename cannot overflow or misalign the overlay.
    let label_width = inner.width.saturating_sub(8) as usize;
    let file_label = truncate_with_ellipsis(&file_text, label_width.max(1));
    let lines = vec![
        Line::from(""),
        palette_line,
        diagnostics_line,
        Line::from(vec![
            Span::styled(
                "File: ",
                Style::default()
                    .fg(palette::strong())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(file_label, Style::default().fg(palette::muted())),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "j/k select  h/l change  o or Esc close",
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

/// Center a rect of `width_pct`% of `area`'s width and `height` rows, vertically
/// and horizontally. Used for overlay popups.
fn centered_rect(area: Rect, width_pct: u16, height: u16) -> Rect {
    let popup_layout = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(area);
    Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Percentage(width_pct),
            Constraint::Fill(1),
        ])
        .split(popup_layout[1])[1]
}

fn draw_status_bar(f: &mut ratatui::Frame, area: Rect, state: &mut AppState, mode: LayoutMode) {
    if let Some(error) = state.diagnostics_error.as_deref() {
        f.render_widget(
            Paragraph::new(format!(" {error} ")).style(Style::default().fg(palette::coral())),
            area,
        );
        return;
    }
    if let Some(detail) = state.process_detail.as_ref() {
        let hint = match (detail.pause_notice, detail.paused) {
            (Some(reason), _) => format!("{}  Esc:back  q:quit", reason.message()),
            (None, Some(_)) => "Tracking paused  Esc:back  q:quit".to_string(),
            (None, None) => "Esc:back  q:quit".to_string(),
        };
        f.render_widget(
            Paragraph::new(format!(" {hint} ")).style(Style::default().fg(palette::muted())),
            area,
        );
        if let Some(detail) = state.process_detail.as_mut() {
            detail.pause_notice = None;
        }
        return;
    }

    let mut spans = Vec::new();
    push_hint(&mut spans, "i", "interface");
    push_hint(&mut spans, "1-5", "page");
    push_hint(&mut spans, "h/l", "switch");
    push_hint(&mut spans, "o", ":settings");
    if state.page == Page::Ips {
        push_hint(&mut spans, "Tab", "panel");
    }
    if matches!(state.page, Page::Processes | Page::Ips | Page::Domains) {
        if state.page == Page::Processes {
            push_hint(&mut spans, "Enter", ":details");
        }
        push_hint(&mut spans, "j/k", "scroll");
        if mode != LayoutMode::Compact {
            push_hint(&mut spans, "PgUp/PgDn", "page");
            push_hint(&mut spans, "Home/End", "jump");
        }
    }

    let chunks = Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(area);
    f.render_widget(Paragraph::new(Line::from(spans)), chunks[0]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "q",
                Style::default()
                    .fg(palette::coral())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(":quit ", Style::default().fg(palette::muted())),
        ]))
        .alignment(Alignment::Right),
        chunks[1],
    );
}

fn push_hint(spans: &mut Vec<Span<'static>>, key: &str, action: &str) {
    if !spans.is_empty() {
        spans.push(Span::raw("  "));
    } else {
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        key.to_string(),
        Style::default()
            .fg(palette::accent())
            .add_modifier(Modifier::BOLD),
    ));
    let separator = if action.starts_with(':') { "" } else { " " };
    spans.push(Span::styled(
        format!("{separator}{action}"),
        Style::default().fg(palette::muted()),
    ));
}

/// Build a ratatui TableState at the given offset.
fn ratatui_state(len: usize, scroll: usize) -> ratatui::widgets::TableState {
    let mut s = ratatui::widgets::TableState::default();
    if len > 0 {
        s.select(Some(scroll.min(len - 1)));
    }
    s
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::stats::{IpSnapshot, OutboundDomainSnapshot, ProcessSnapshot, TrafficSnapshot};

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

    fn assert_unattributed_style(terminal: &Terminal<TestBackend>) {
        let rendered = rendered_lines(terminal).join("\n");
        assert!(rendered.contains("<unattributed traffic>"));
        let first_label_cell = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .find(|cell| cell.symbol() == "<")
            .expect("unattributed label cell");
        assert_eq!(first_label_cell.fg, Color::Yellow);
        assert!(first_label_cell.modifier.contains(Modifier::ITALIC));
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
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("curl --silent")),
                None,
                observed_at,
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
    fn unattributed_process_row_uses_special_label_and_style() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::unattributed(40, 60, chrono::Utc::now())].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        state.page = Page::Processes;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now());
            })
            .unwrap();

        assert_unattributed_style(&terminal);
    }

    #[test]
    fn overview_page_renders_from_snapshot() {
        let snapshot = TrafficSnapshot {
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
    fn overview_uses_special_style_for_unattributed_traffic() {
        let snapshot = TrafficSnapshot {
            processes: vec![ProcessSnapshot::unattributed(40, 60, chrono::Utc::now())].into(),
            ..TrafficSnapshot::default()
        };
        let mut state = AppState::new();
        // Use a 120-wide terminal so the half-width preview columns still have
        // enough room to render the `<unattributed traffic>` label in full.
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

        terminal
            .draw(|frame| {
                draw(frame, &mut state, &snapshot, "eth0", "host", Instant::now());
            })
            .unwrap();

        assert_unattributed_style(&terminal);
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
            KeyOutcome::Quit
        ));
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
    fn process_details_render_all_fields_at_eighty_columns() {
        let path = "/opt/services/payments/releases/2026-07-15/production/workers/payment-processing/payment-worker";
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::attributed(
                7,
                Some(Arc::from("payment-worker")),
                Some(Arc::from(path)),
                "2026-07-15T08:00:00Z".parse().unwrap(),
                1024,
                2048,
            )]
            .into(),
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
        assert!(rendered.contains("Recv: 1.00 KB"));
        assert!(rendered.contains("Sent: 2.00 KB"));
        assert!(rendered.contains("Total: 3.00 KB"));
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
            if continuation.trim().is_empty() {
                break;
            }
            displayed_path.push_str(continuation.trim_end());
        }
        assert_eq!(displayed_path, path);
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

    #[test]
    fn unattributed_traffic_details_keep_missing_fields_and_special_style() {
        let snapshot = TrafficSnapshot {
            process_data_fresh: true,
            processes: vec![ProcessSnapshot::unattributed(
                40,
                60,
                "2026-07-15T08:00:00Z".parse().unwrap(),
            )]
            .into(),
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
                    "2026-07-15T08:01:00Z".parse().unwrap(),
                );
            })
            .unwrap();

        let rendered = rendered_lines(&terminal).join("\n");
        assert!(rendered.contains("Name: <unattributed traffic>"));
        assert!(rendered.contains("PID: -"));
        assert!(rendered.contains("Path: -"));
        assert_unattributed_style(&terminal);
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
        assert_eq!(state.settings_selection, 1);

        // Up/k moves back to Palette and clamps at the top.
        assert_eq!(
            send_key(&mut state, KeyCode::Char('k')),
            KeyOutcome::Changed
        );
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
        let popup = centered_rect(area, 60, 9);
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
        let popup = centered_rect(area, 60, 9);

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

        // q still quits globally even with the overlay open.
        assert_eq!(send_key(&mut state, KeyCode::Char('q')), KeyOutcome::Quit);
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
