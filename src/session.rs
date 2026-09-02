use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, sync_channel};
use std::thread;

use anyhow::{Result, anyhow};

use crate::capture::{CaptureSource, InterfaceInfo};
use crate::pipeline::{CaptureReadiness, PipelineError, TrafficPipeline};
use crate::proc_table::SharedProcTable;
use crate::stats::{RankWindow, TrafficSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activation {
    Activated,
    Pending,
    Unchanged,
}

struct ActiveCapture {
    interface: String,
    pipeline: TrafficPipeline,
}

struct PendingActivation {
    interface: String,
    result_rx: Receiver<Result<PreparedPipeline>>,
}

struct PreparedPipeline {
    pipeline: TrafficPipeline,
    readiness: CaptureReadiness,
}

pub struct TrafficSession {
    interfaces: Vec<InterfaceInfo>,
    proc_table: SharedProcTable,
    top_n: usize,
    flow_table_capacity: u64,
    read_mode: crate::capture::CaptureReadMode,
    diagnostics_enabled: Arc<AtomicBool>,
    rank_window: Arc<AtomicU8>,
    active: Option<ActiveCapture>,
    fallback: Option<ActiveCapture>,
    pending: Option<PendingActivation>,
}

impl TrafficSession {
    pub fn discover(
        proc_table: SharedProcTable,
        top_n: usize,
        flow_table_capacity: u64,
        diagnostics_enabled: bool,
        read_mode: crate::capture::CaptureReadMode,
    ) -> Result<Self> {
        Ok(Self {
            interfaces: crate::capture::interface_catalog()?,
            proc_table,
            top_n,
            flow_table_capacity,
            read_mode,
            diagnostics_enabled: Arc::new(AtomicBool::new(diagnostics_enabled)),
            rank_window: Arc::new(AtomicU8::new(RankWindow::Cumulative.to_u8())),
            active: None,
            fallback: None,
            pending: None,
        })
    }

    pub fn interfaces(&self) -> &[InterfaceInfo] {
        &self.interfaces
    }

    pub fn active_interface(&self) -> Option<&str> {
        self.active.as_ref().map(|active| active.interface.as_str())
    }

    pub fn diagnostics_enabled_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.diagnostics_enabled)
    }

    pub fn rank_window_handle(&self) -> Arc<AtomicU8> {
        Arc::clone(&self.rank_window)
    }

    pub fn activate(&mut self, selector: &str) -> Result<Activation> {
        let proc_table = self.proc_table.clone();
        let top_n = self.top_n;
        let capacity = self.flow_table_capacity;
        let read_mode = self.read_mode;
        let diagnostics_enabled = Arc::clone(&self.diagnostics_enabled);
        let rank_window = Arc::clone(&self.rank_window);
        self.activate_with(selector, move |name| {
            let source = CaptureSource::open_with_read_mode(name, capacity, read_mode)?;
            TrafficPipeline::spawn(source, proc_table, top_n, diagnostics_enabled, rank_window)
                .map_err(anyhow::Error::from)
        })
    }

    pub fn begin_activate(&mut self, selector: &str) -> Result<Activation> {
        let proc_table = self.proc_table.clone();
        let top_n = self.top_n;
        let capacity = self.flow_table_capacity;
        let read_mode = self.read_mode;
        let diagnostics_enabled = Arc::clone(&self.diagnostics_enabled);
        let rank_window = Arc::clone(&self.rank_window);
        self.begin_activate_with(selector, move |name| {
            let source = CaptureSource::open_with_read_mode(name, capacity, read_mode)?;
            TrafficPipeline::spawn(source, proc_table, top_n, diagnostics_enabled, rank_window)
                .map_err(anyhow::Error::from)
        })
    }

    pub fn poll_activation(&mut self) -> Option<Result<Activation>> {
        let result = match self.pending.as_ref()?.result_rx.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => {
                Err(anyhow!("interface activation worker stopped unexpectedly"))
            }
        };
        let pending = self.pending.take().expect("pending activation exists");
        Some(result.map(|prepared| {
            self.rank_window
                .store(RankWindow::Cumulative.to_u8(), Ordering::Release);
            let previous = self.active.replace(ActiveCapture {
                interface: pending.interface,
                pipeline: prepared.pipeline,
            });
            if prepared.readiness == CaptureReadiness::Waiting {
                self.fallback = previous;
            }
            Activation::Activated
        }))
    }

    pub fn poll_capture_readiness(&mut self) -> Option<Result<()>> {
        let active = self.active.as_ref()?;
        self.fallback.as_ref()?;
        match active.pipeline.poll_capture_readiness()? {
            Ok(CaptureReadiness::Ready) => {
                self.fallback = None;
                None
            }
            Ok(CaptureReadiness::Waiting) => None,
            Err(error) => {
                let fallback = self.fallback.take().expect("fallback exists");
                self.active.replace(fallback);
                Some(Err(anyhow::Error::from(error)))
            }
        }
    }

    pub fn try_latest(&self) -> Result<Option<Arc<TrafficSnapshot>>, PipelineError> {
        match self.active.as_ref() {
            Some(active) => active.pipeline.try_latest(),
            None => Ok(None),
        }
    }

    fn activate_with<F>(&mut self, selector: &str, start: F) -> Result<Activation>
    where
        F: FnOnce(&str) -> Result<TrafficPipeline>,
    {
        let interface = self.resolve_selector(selector)?.to_string();
        if self.active_interface() == Some(interface.as_str()) {
            return Ok(Activation::Unchanged);
        }

        let pipeline = start(&interface)?;
        let _readiness = pipeline
            .observe_early_capture_failure()
            .map_err(anyhow::Error::from)?;
        self.active.replace(ActiveCapture {
            interface,
            pipeline,
        });
        self.rank_window
            .store(RankWindow::Cumulative.to_u8(), Ordering::Release);
        Ok(Activation::Activated)
    }

    fn begin_activate_with<F>(&mut self, selector: &str, start: F) -> Result<Activation>
    where
        F: FnOnce(&str) -> Result<TrafficPipeline> + Send + 'static,
    {
        let interface = self.resolve_selector(selector)?.to_string();
        if self.active_interface() == Some(interface.as_str()) {
            return Ok(Activation::Unchanged);
        }
        if self.pending.is_some() {
            return Err(anyhow!("an interface activation is already in progress"));
        }

        let (result_tx, result_rx) = sync_channel(1);
        let worker_interface = interface.clone();
        thread::Builder::new()
            .name("flowlens-interface-open".to_string())
            .spawn(move || {
                let result = start(&worker_interface).and_then(|pipeline| {
                    let readiness = pipeline
                        .observe_early_capture_failure()
                        .map_err(anyhow::Error::from)?;
                    Ok(PreparedPipeline {
                        pipeline,
                        readiness,
                    })
                });
                let _ = result_tx.send(result);
            })?;
        self.fallback = None;
        self.pending = Some(PendingActivation {
            interface,
            result_rx,
        });
        Ok(Activation::Pending)
    }

    fn resolve_selector(&self, selector: &str) -> Result<&str> {
        if let Some(interface) = self
            .interfaces
            .iter()
            .find(|interface| interface.name == selector)
        {
            return Ok(&interface.name);
        }
        if !selector.is_empty() && selector.bytes().all(|byte| byte.is_ascii_digit()) {
            let index = selector
                .parse::<usize>()
                .ok()
                .and_then(|number| number.checked_sub(1));
            if let Some(interface) = index.and_then(|index| self.interfaces.get(index)) {
                return Ok(&interface.name);
            }
            if self.interfaces.is_empty() {
                return Err(anyhow!(
                    "Invalid interface number: {selector} (no interfaces available)"
                ));
            }
            return Err(anyhow!(
                "Invalid interface number: {selector} (choose 1-{})",
                self.interfaces.len()
            ));
        }
        Err(anyhow!("Interface not found: {selector}"))
    }

    #[cfg(test)]
    fn from_active_for_test(
        interfaces: Vec<InterfaceInfo>,
        proc_table: SharedProcTable,
        top_n: usize,
        interface: &str,
        pipeline: TrafficPipeline,
    ) -> Self {
        Self {
            interfaces,
            proc_table,
            top_n,
            flow_table_capacity: crate::flow_table::DEFAULT_FLOW_TABLE_CAPACITY,
            read_mode: crate::capture::CaptureReadMode::default(),
            diagnostics_enabled: Arc::new(AtomicBool::new(false)),
            rank_window: Arc::new(AtomicU8::new(RankWindow::Cumulative.to_u8())),
            active: Some(ActiveCapture {
                interface: interface.to_string(),
                pipeline,
            }),
            fallback: None,
            pending: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::capture::InterfaceInfo;
    use crate::pipeline::TrafficPipeline;
    use crate::proc_table::ProcTable;
    use crate::stats::TrafficSnapshot;
    use std::sync::RwLock;

    #[test]
    fn successful_switch_replaces_interface_with_a_fresh_snapshot_stream() {
        let mut session = session_with_active("eth0", 99);

        let outcome = session
            .activate_with("wlan0", |_| Ok(pipeline_with_snapshot(0)))
            .unwrap();

        assert_eq!(outcome, Activation::Activated);
        assert_eq!(session.active_interface(), Some("wlan0"));
        assert_eq!(session.try_latest().unwrap().unwrap().in_bytes, 0);
    }

    #[test]
    fn selecting_active_interface_is_a_no_op() {
        let mut session = session_with_active("eth0", 99);
        let mut starts = 0;

        let outcome = session
            .activate_with("1", |_| {
                starts += 1;
                Ok(pipeline_with_snapshot(0))
            })
            .unwrap();

        assert_eq!(outcome, Activation::Unchanged);
        assert_eq!(starts, 0);
        assert_eq!(session.try_latest().unwrap().unwrap().in_bytes, 99);
    }

    #[test]
    fn failed_switch_retains_current_interface_and_snapshot() {
        let mut session = session_with_active("eth0", 99);

        let error = session
            .activate_with("wlan0", |_| Err(anyhow::anyhow!("permission denied")))
            .unwrap_err();

        assert_eq!(error.to_string(), "permission denied");
        assert_eq!(session.active_interface(), Some("eth0"));
        assert_eq!(session.try_latest().unwrap().unwrap().in_bytes, 99);
    }

    #[test]
    fn beginning_a_switch_does_not_wait_for_slow_interface_open() {
        let mut session = session_with_active("eth0", 99);
        let started_at = std::time::Instant::now();

        let outcome = session
            .begin_activate_with("wlan0", |_| {
                std::thread::sleep(std::time::Duration::from_millis(250));
                Ok(pipeline_with_snapshot(0))
            })
            .unwrap();

        assert_eq!(outcome, Activation::Pending);
        assert!(started_at.elapsed() < std::time::Duration::from_millis(50));
        assert_eq!(session.active_interface(), Some("eth0"));

        loop {
            if let Some(outcome) = session.poll_activation() {
                assert_eq!(outcome.unwrap(), Activation::Activated);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.active_interface(), Some("wlan0"));
    }

    #[test]
    fn failed_first_capture_read_keeps_the_active_interface_and_snapshot() {
        let mut session = session_with_active("eth0", 99);
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::sync_channel(1);
        snapshot_tx
            .send(Arc::new(TrafficSnapshot::default()))
            .unwrap();
        let failure = Arc::new(std::sync::OnceLock::new());
        failure
            .set(crate::pipeline::PipelineError::Capture(
                "permission denied".to_string(),
            ))
            .unwrap();

        session
            .begin_activate_with("wlan0", move |_| {
                Ok(TrafficPipeline::from_parts(snapshot_rx, failure))
            })
            .unwrap();

        loop {
            if let Some(outcome) = session.poll_activation() {
                assert_eq!(
                    outcome.unwrap_err().to_string(),
                    "capture failed: permission denied"
                );
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.active_interface(), Some("eth0"));
        assert_eq!(session.try_latest().unwrap().unwrap().in_bytes, 99);
    }

    #[test]
    fn delayed_first_capture_failure_restores_the_previous_interface() {
        let mut session = session_with_active("eth0", 99);
        session
            .begin_activate_with("wlan0", |_| {
                Ok(TrafficPipeline::from_delayed_failure_for_test(
                    std::time::Duration::from_millis(500),
                    "pcap device closed",
                ))
            })
            .unwrap();

        loop {
            if let Some(outcome) = session.poll_activation() {
                assert_eq!(outcome.unwrap(), Activation::Activated);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.active_interface(), Some("wlan0"));

        loop {
            if let Some(outcome) = session.poll_capture_readiness() {
                assert_eq!(
                    outcome.unwrap_err().to_string(),
                    "capture failed: pcap device closed"
                );
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.active_interface(), Some("eth0"));
        assert_eq!(session.try_latest().unwrap().unwrap().in_bytes, 99);
    }

    #[test]
    fn beginning_a_new_switch_replaces_a_waiting_fallback_recovery() {
        let mut session = session_with_active("eth0", 99);
        session.interfaces.push(info("lo", false));

        session
            .begin_activate_with("wlan0", |_| {
                Ok(TrafficPipeline::from_delayed_failure_for_test(
                    std::time::Duration::from_secs(60),
                    "pcap device closed",
                ))
            })
            .unwrap();

        loop {
            if let Some(outcome) = session.poll_activation() {
                assert_eq!(outcome.unwrap(), Activation::Activated);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.active_interface(), Some("wlan0"));

        let outcome = session
            .begin_activate_with("lo", |_| Ok(pipeline_with_snapshot(7)))
            .unwrap();

        assert_eq!(outcome, Activation::Pending);

        loop {
            if let Some(outcome) = session.poll_activation() {
                assert_eq!(outcome.unwrap(), Activation::Activated);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.active_interface(), Some("lo"));
        assert_eq!(session.try_latest().unwrap().unwrap().in_bytes, 7);
    }

    fn session_with_active(interface: &str, in_bytes: u64) -> TrafficSession {
        let catalog = vec![info("eth0", true), info("wlan0", false)];
        TrafficSession::from_active_for_test(
            catalog,
            Arc::new(RwLock::new(ProcTable::default())),
            10,
            interface,
            pipeline_with_snapshot(in_bytes),
        )
    }

    fn pipeline_with_snapshot(in_bytes: u64) -> TrafficPipeline {
        TrafficPipeline::from_snapshot_for_test(Arc::new(TrafficSnapshot {
            in_bytes,
            ..TrafficSnapshot::default()
        }))
    }

    fn info(name: &str, is_default_route: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_string(),
            description: format!("{name} description"),
            is_default_route,
        }
    }
}
