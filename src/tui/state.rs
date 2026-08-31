//! TUI interaction state: pages, focus, layout mode, and the shared application state.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use ratatui::layout::Rect;

use super::InterfaceSelector;
use crate::capture::InterfaceInfo;
use crate::diagnostics::DiagnosticsWriter;
use crate::palette;
use crate::stats::{ProcessSnapshot, RankWindow, TrafficSnapshot};

/// Which page is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Page {
    Overview,
    Processes,
    Ips,
    Domains,
    About,
}

impl Page {
    pub(super) const ALL: [Page; 5] = [
        Page::Overview,
        Page::Processes,
        Page::Ips,
        Page::Domains,
        Page::About,
    ];

    pub(super) fn index(self) -> usize {
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
pub(super) enum IpFocus {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LayoutMode {
    Compact,
    Standard,
    Wide,
}

impl LayoutMode {
    pub(super) fn from_area(area: Rect) -> Self {
        match area.width {
            120.. => Self::Wide,
            80.. => Self::Standard,
            _ => Self::Compact,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TrackingPause {
    OutsideTopN,
    Stale,
}

impl TrackingPause {
    pub(super) fn message(self) -> &'static str {
        match self {
            Self::OutsideTopN => "Tracking paused: process is no longer in Top-N.",
            Self::Stale => "Tracking paused: process data is stale.",
        }
    }
}

pub(super) struct ProcessDetail {
    pub(super) process: ProcessSnapshot,
    pub(super) paused: Option<TrackingPause>,
    pub(super) pause_notice: Option<TrackingPause>,
}

impl ProcessDetail {
    pub(super) fn pause(&mut self, reason: TrackingPause) {
        if self.paused != Some(reason) {
            self.pause_notice = Some(reason);
        }
        self.paused = Some(reason);
    }
}

/// Persistent UI state across refreshes.
pub(super) struct AppState {
    pub(super) page: Page,
    pub(super) proc_scroll: usize,
    pub(super) process_detail: Option<ProcessDetail>,
    pub(super) ip_in_scroll: usize,
    pub(super) ip_out_scroll: usize,
    pub(super) ip_focus: IpFocus,
    pub(super) domain_scroll: usize,
    /// Monotonic view height, updated each draw for clamping scrolls.
    pub(super) proc_view_height: usize,
    pub(super) ip_in_view_height: usize,
    pub(super) ip_out_view_height: usize,
    pub(super) domain_view_height: usize,
    pub(super) interface_selector: Option<InterfaceSelector>,
    /// Whether the settings overlay is open.
    pub(super) settings_open: bool,
    /// User-facing palette selection, adjusted in the settings overlay.
    pub(super) palette_choice: palette::PaletteChoice,
    /// Terminal color tier detected at startup; `Auto` follows this.
    pub(super) detected_tier: palette::ColorTier,
    pub(super) diagnostics_error: Option<String>,
    /// Actual diagnostics state: true while a writer is open. Kept in sync
    /// with `DiagnosticsRuntime::writer` and the shared enable flag.
    pub(super) diagnostics_enabled: bool,
    /// Draft diagnostics state edited in the settings overlay. Copied from
    /// the actual state when the overlay opens and committed only when it
    /// closes, so h/l toggling never touches the writer mid-edit.
    pub(super) diagnostics_draft: bool,
    /// Basename of the currently open diagnostics output file.
    pub(super) diagnostics_file: Option<String>,
    /// Path reserved for a future writer while the overlay is open, when the
    /// actual state is OFF. Never turned into a real file except by a final
    /// ON commit; discarded when the final state is OFF.
    pub(super) diagnostics_pending_path: Option<PathBuf>,
    /// Selected settings row (0 = Palette, 1 = Diagnostics, 2 = Rank window).
    pub(super) settings_selection: usize,
    /// Actual ranking window used by the pipeline.
    pub(super) rank_window: RankWindow,
    /// Draft ranking window committed when the settings overlay closes.
    pub(super) rank_window_draft: RankWindow,
    /// Waiting for a second confirmation before leaving the TUI.
    pub(super) quit_confirm: bool,
}

impl AppState {
    pub(super) fn new() -> Self {
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
            rank_window: RankWindow::Cumulative,
            rank_window_draft: RankWindow::Cumulative,
            quit_confirm: false,
        }
    }

    pub(super) fn startup(interfaces: &[InterfaceInfo]) -> Self {
        let mut state = Self::new();
        state.open_interface_selector(interfaces, None, false);
        state
    }

    pub(super) fn open_interface_selector(
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
    pub(super) fn reset_after_interface_switch(&mut self) {
        let diagnostics_enabled = self.diagnostics_enabled;
        let diagnostics_draft = self.diagnostics_draft;
        let diagnostics_file = self.diagnostics_file.clone();
        let diagnostics_error = self.diagnostics_error.clone();
        *self = AppState::new();
        self.diagnostics_enabled = diagnostics_enabled;
        self.diagnostics_draft = diagnostics_draft;
        self.diagnostics_file = diagnostics_file;
        self.diagnostics_error = diagnostics_error;
        self.rank_window = RankWindow::Cumulative;
        self.rank_window_draft = RankWindow::Cumulative;
    }

    pub(super) fn update_process_detail(&mut self, snapshot: &TrafficSnapshot) {
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

/// Runtime side of the diagnostics toggle: the open writer plus the shared
/// enable flag that gates pipeline-side collection.
pub(super) struct DiagnosticsRuntime {
    pub(super) writer: Option<DiagnosticsWriter>,
    pub(super) enabled: Arc<AtomicBool>,
    pub(super) rank_window: Arc<AtomicU8>,
}

impl DiagnosticsRuntime {
    #[cfg(test)]
    pub(super) fn new(writer: Option<DiagnosticsWriter>, enabled: Arc<AtomicBool>) -> Self {
        Self::new_with_rank(
            writer,
            enabled,
            Arc::new(AtomicU8::new(RankWindow::Cumulative.to_u8())),
        )
    }

    pub(super) fn new_with_rank(
        writer: Option<DiagnosticsWriter>,
        enabled: Arc<AtomicBool>,
        rank_window: Arc<AtomicU8>,
    ) -> Self {
        Self {
            writer,
            enabled,
            rank_window,
        }
    }

    /// Apply the settings-overlay draft to the actual diagnostics state once
    /// the overlay is closed. While the overlay is open the draft lives only
    /// in `state`, so rapid h/l toggling never opens or closes the writer.
    /// Returns true when a redraw is required.
    pub(super) fn reconcile(&mut self, state: &mut AppState) -> bool {
        if state.settings_open {
            return false;
        }
        if state.rank_window_draft != state.rank_window {
            state.rank_window = state.rank_window_draft;
            self.rank_window
                .store(state.rank_window.to_u8(), Ordering::Release);
            return true;
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
    pub(super) fn note_write_failure(&mut self, state: &mut AppState, error: io::Error) {
        self.writer = None;
        state.diagnostics_enabled = false;
        state.diagnostics_draft = false;
        state.diagnostics_file = None;
        state.diagnostics_pending_path = None;
        self.enabled.store(false, Ordering::Relaxed);
        state.diagnostics_error = Some(format!("Diagnostics disabled: {error}"));
    }
}

impl AppState {
    pub(super) fn current_view_height(&self) -> usize {
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
