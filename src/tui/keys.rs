//! Keyboard handling: key dispatch, quit confirmation, page navigation, palette cycling,
//! and scroll control.

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::pages::settings::{
    DIAGNOSTICS_ROW, PALETTE_CHOICES, PALETTE_ROW, RANK_WINDOW_ROW, SETTINGS_SELECTABLE_ROWS,
};
use super::state::*;
use crate::capture::InterfaceInfo;
use crate::palette;
use crate::session::Activation;
use crate::stats::TrafficSnapshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyOutcome {
    Quit,
    Changed,
    Ignored,
}

pub(super) fn handle_tui_key<F>(
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

    if state.quit_confirm {
        return handle_quit_confirm_key(state, key);
    }
    if is_quit_request(key) {
        return request_quit(state);
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
                } else if state.settings_selection == RANK_WINDOW_ROW {
                    let forward = matches!(key.code, KeyCode::Right | KeyCode::Char('l'));
                    state.rank_window_draft = if forward {
                        state.rank_window_draft.next()
                    } else {
                        state.rank_window_draft.prev()
                    };
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
        state.rank_window_draft = state.rank_window;
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

pub(super) fn is_quit_request(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
        || matches!(key.code, KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL))
}

pub(super) fn request_quit(state: &mut AppState) -> KeyOutcome {
    state.quit_confirm = true;
    KeyOutcome::Changed
}

pub(super) fn handle_quit_confirm_key(state: &mut AppState, key: KeyEvent) -> KeyOutcome {
    if is_quit_request(key)
        || matches!(
            key.code,
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter
        )
    {
        return KeyOutcome::Quit;
    }
    if matches!(
        key.code,
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N')
    ) {
        state.quit_confirm = false;
        return KeyOutcome::Changed;
    }
    KeyOutcome::Ignored
}

pub(super) fn handle_key(
    state: &mut AppState,
    key: KeyEvent,
    snapshot: &TrafficSnapshot,
) -> KeyOutcome {
    if state.quit_confirm {
        return handle_quit_confirm_key(state, key);
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => request_quit(state),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => request_quit(state),
        KeyCode::Esc if state.process_detail.is_some() => {
            state.process_detail = None;
            KeyOutcome::Changed
        }
        KeyCode::Esc => request_quit(state),
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

pub(super) fn prev_page(p: Page) -> Page {
    let idx = p.index();
    Page::ALL[(idx + Page::ALL.len() - 1) % Page::ALL.len()]
}

pub(super) fn next_page(p: Page) -> Page {
    let idx = p.index();
    Page::ALL[(idx + 1) % Page::ALL.len()]
}

pub(super) fn next_palette_choice(choice: palette::PaletteChoice) -> palette::PaletteChoice {
    let idx = PALETTE_CHOICES
        .iter()
        .position(|candidate| *candidate == choice)
        .unwrap_or(0);
    PALETTE_CHOICES[(idx + 1) % PALETTE_CHOICES.len()]
}

pub(super) fn prev_palette_choice(choice: palette::PaletteChoice) -> palette::PaletteChoice {
    let idx = PALETTE_CHOICES
        .iter()
        .position(|candidate| *candidate == choice)
        .unwrap_or(0);
    let len = PALETTE_CHOICES.len();
    PALETTE_CHOICES[(idx + len - 1) % len]
}

pub(super) fn scroll(state: &mut AppState, delta: isize) {
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

pub(super) fn scroll_to_top(state: &mut AppState) {
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

pub(super) fn scroll_to_bottom(state: &mut AppState, snapshot: &TrafficSnapshot) {
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
