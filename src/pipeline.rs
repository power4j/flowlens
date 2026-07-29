use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::attribution::{self, PendingAttributor};
use crate::capture::{CaptureSource, Flow};
use crate::diagnostics;
#[cfg(test)]
use crate::proc_table;
use crate::proc_table::SharedProcTable;
use crate::process_probe::ProcessProbe;
use crate::stats::{Stats, TrafficSnapshot};

const STOP_CHECK_INTERVAL: Duration = Duration::from_millis(100);
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);
const FLOW_CHANNEL_CAPACITY: usize = 8192;
const SNAPSHOT_CHANNEL_CAPACITY: usize = 2;
const CAPTURE_EARLY_FAILURE_WINDOW: Duration = Duration::from_millis(50);

type ThreadTask = Box<dyn FnOnce() + Send + 'static>;
type CaptureWakeup = Box<dyn Fn() + Send + Sync>;

fn spawn_named_thread(name: &'static str, task: ThreadTask) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().name(name.to_string()).spawn(task)
}

#[derive(Clone, Debug)]
pub enum PipelineError {
    Capture(String),
    WorkerStopped(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureReadiness {
    Ready,
    Waiting,
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(message) => write!(f, "capture failed: {message}"),
            Self::WorkerStopped(worker) => {
                write!(f, "traffic pipeline worker stopped unexpectedly: {worker}")
            }
        }
    }
}

impl std::error::Error for PipelineError {}

fn capture_loop<N, E>(
    mut next_flow: N,
    flow_tx: SyncSender<Flow>,
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<PipelineError>>,
    mut ready_tx: Option<SyncSender<Result<(), PipelineError>>>,
) where
    N: FnMut() -> Result<Option<Flow>, E>,
    E: fmt::Display,
{
    while !stop.load(Ordering::Acquire) {
        match next_flow() {
            Ok(flow) => {
                if let Some(ready_tx) = ready_tx.take() {
                    let _ = ready_tx.send(Ok(()));
                }
                let Some(flow) = flow else {
                    continue;
                };
                let mut pending = flow;
                loop {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    match flow_tx.try_send(pending) {
                        Ok(()) => break,
                        Err(TrySendError::Full(flow)) => {
                            pending = flow;
                            thread::sleep(STOP_CHECK_INTERVAL);
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
            }
            Err(error) => {
                let error = PipelineError::Capture(error.to_string());
                if let Some(ready_tx) = ready_tx.take() {
                    let _ = ready_tx.send(Err(error.clone()));
                }
                if !stop.load(Ordering::Acquire) {
                    let _ = failure.set(error);
                }
                return;
            }
        }
    }
}

fn aggregate_loop_with_probe(
    flow_rx: Receiver<Flow>,
    snapshot_tx: SyncSender<Arc<TrafficSnapshot>>,
    proc_table: SharedProcTable,
    top_n: usize,
    snapshot_interval: Duration,
    probe: Option<ProcessProbe>,
    flow_table_entries: Option<Arc<AtomicU64>>,
    diagnostics_enabled: bool,
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<PipelineError>>,
) {
    let mut stats = Stats::default();
    let mut attributor = match probe {
        Some(probe) => PendingAttributor::with_probe(
            attribution::PENDING_ATTRIBUTION_WINDOW,
            attribution::PENDING_ATTRIBUTION_CAPACITY,
            probe,
        ),
        None => PendingAttributor::default(),
    };
    let mut next_snapshot = Instant::now() + snapshot_interval;
    let mut last_published_pending_nonempty = false;

    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }

        let now = Instant::now();
        attributor.advance(&mut stats, &proc_table, now);
        let pending_bytes = attributor.snapshot().bytes;
        let has_pending = pending_bytes > 0;
        if has_pending != last_published_pending_nonempty {
            let snapshot = snapshot_for_publish(
                &stats,
                &proc_table,
                &attributor,
                top_n,
                pending_bytes,
                flow_table_entries.as_ref(),
                false,
            );
            let published = match snapshot_tx.try_send(Arc::new(snapshot)) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => false,
                Err(TrySendError::Disconnected(_)) => {
                    if !stop.load(Ordering::Acquire) {
                        let _ = failure.set(PipelineError::WorkerStopped("snapshot consumer"));
                    }
                    return;
                }
            };
            if published {
                last_published_pending_nonempty = has_pending;
            }
        }
        if now >= next_snapshot {
            let snapshot = snapshot_for_publish(
                &stats,
                &proc_table,
                &attributor,
                top_n,
                pending_bytes,
                flow_table_entries.as_ref(),
                diagnostics_enabled,
            );
            let snapshot = Arc::new(snapshot);
            match snapshot_tx.try_send(snapshot) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    if !stop.load(Ordering::Acquire) {
                        let _ = failure.set(PipelineError::WorkerStopped("snapshot consumer"));
                    }
                    return;
                }
            }
            next_snapshot = Instant::now() + snapshot_interval;
            continue;
        }

        let wait = next_snapshot
            .saturating_duration_since(now)
            .min(STOP_CHECK_INTERVAL);
        match flow_rx.recv_timeout(wait) {
            Ok(flow) => {
                attributor.record_flow(
                    &mut stats,
                    flow,
                    &proc_table,
                    Instant::now(),
                    chrono::Utc::now(),
                );
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if !stop.load(Ordering::Acquire) && failure.get().is_none() {
                    let _ = failure.set(PipelineError::WorkerStopped("capture"));
                }
                return;
            }
        }
    }
}

#[cfg(test)]
fn aggregate_loop(
    flow_rx: Receiver<Flow>,
    snapshot_tx: SyncSender<Arc<TrafficSnapshot>>,
    proc_table: SharedProcTable,
    top_n: usize,
    snapshot_interval: Duration,
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<PipelineError>>,
) {
    aggregate_loop_with_probe(
        flow_rx,
        snapshot_tx,
        proc_table,
        top_n,
        snapshot_interval,
        None,
        None,
        false,
        stop,
        failure,
    );
}

fn snapshot_for_publish(
    stats: &Stats,
    proc_table: &SharedProcTable,
    attributor: &PendingAttributor,
    top_n: usize,
    pending_attribution_bytes: u64,
    flow_table_entries: Option<&Arc<AtomicU64>>,
    diagnostics_enabled: bool,
) -> TrafficSnapshot {
    let mut snapshot = stats.snapshot(top_n);
    snapshot.pending_attribution_bytes = pending_attribution_bytes;
    snapshot.process_data_fresh = proc_table.read().is_ok_and(|table| table.is_fresh());
    snapshot.diagnostics = if diagnostics_enabled {
        diagnostics::collect(
            proc_table,
            attributor.snapshot(),
            stats.diagnostics_snapshot(),
            flow_table_entries.map_or(0, |entries| entries.load(Ordering::Relaxed)),
        )
        .map(Arc::new)
    } else {
        None
    };
    snapshot
}

pub struct TrafficPipeline {
    snapshot_rx: Receiver<Arc<TrafficSnapshot>>,
    capture_ready_rx: Receiver<Result<(), PipelineError>>,
    failure: Arc<OnceLock<PipelineError>>,
    stop: Arc<AtomicBool>,
    capture_wakeup: Option<CaptureWakeup>,
    workers: Vec<thread::JoinHandle<()>>,
    #[cfg(test)]
    _snapshot_keepalive: Option<SyncSender<Arc<TrafficSnapshot>>>,
}

impl TrafficPipeline {
    pub fn spawn(
        mut source: CaptureSource,
        proc_table: SharedProcTable,
        top_n: usize,
        diagnostics_enabled: bool,
    ) -> io::Result<Self> {
        let breakloop = source.breakloop_handle();
        let flow_table_entries = Arc::new(AtomicU64::new(0));
        let capture_flow_table_entries = flow_table_entries.clone();
        Self::spawn_with_next_using(
            move || {
                let result = source.next();
                capture_flow_table_entries
                    .store(source.flow_table_entry_count(), Ordering::Relaxed);
                result
            },
            proc_table,
            top_n,
            Some(flow_table_entries),
            diagnostics_enabled,
            Some(Box::new(move || breakloop.breakloop())),
            spawn_named_thread,
        )
    }

    #[cfg(test)]
    fn spawn_with_next<N, E>(
        next_flow: N,
        proc_table: SharedProcTable,
        top_n: usize,
    ) -> io::Result<Self>
    where
        N: FnMut() -> Result<Option<Flow>, E> + Send + 'static,
        E: fmt::Display + Send + 'static,
    {
        Self::spawn_with_next_using(
            next_flow,
            proc_table,
            top_n,
            None,
            false,
            None,
            spawn_named_thread,
        )
    }

    #[cfg(test)]
    fn spawn_with_next_and_wakeup<N, E, W>(
        next_flow: N,
        proc_table: SharedProcTable,
        top_n: usize,
        wake_capture: W,
    ) -> io::Result<Self>
    where
        N: FnMut() -> Result<Option<Flow>, E> + Send + 'static,
        E: fmt::Display + Send + 'static,
        W: Fn() + Send + Sync + 'static,
    {
        Self::spawn_with_next_using(
            next_flow,
            proc_table,
            top_n,
            None,
            false,
            Some(Box::new(wake_capture)),
            spawn_named_thread,
        )
    }

    fn spawn_with_next_using<N, E, S>(
        next_flow: N,
        proc_table: SharedProcTable,
        top_n: usize,
        flow_table_entries: Option<Arc<AtomicU64>>,
        diagnostics_enabled: bool,
        capture_wakeup: Option<CaptureWakeup>,
        mut spawn_thread: S,
    ) -> io::Result<Self>
    where
        N: FnMut() -> Result<Option<Flow>, E> + Send + 'static,
        E: fmt::Display + Send + 'static,
        S: FnMut(&'static str, ThreadTask) -> io::Result<thread::JoinHandle<()>>,
    {
        let (flow_tx, flow_rx) = std::sync::mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::sync_channel(SNAPSHOT_CHANNEL_CAPACITY);
        let (capture_ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel(1);
        snapshot_tx
            .try_send(Arc::new(TrafficSnapshot::default()))
            .expect("new snapshot channel has capacity");

        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let aggregate_stop = stop.clone();
        let aggregate_failure = failure.clone();
        let aggregate_thread = spawn_thread(
            "delray-aggregate",
            Box::new(move || {
                aggregate_loop_with_probe(
                    flow_rx,
                    snapshot_tx,
                    proc_table,
                    top_n,
                    SNAPSHOT_INTERVAL,
                    Some(ProcessProbe::spawn()),
                    flow_table_entries,
                    diagnostics_enabled,
                    aggregate_stop,
                    aggregate_failure,
                );
            }),
        )?;

        let capture_stop = stop.clone();
        let capture_failure = failure.clone();
        let capture_thread = match spawn_thread(
            "delray-capture",
            Box::new(move || {
                capture_loop(
                    next_flow,
                    flow_tx,
                    capture_stop,
                    capture_failure,
                    Some(capture_ready_tx),
                )
            }),
        ) {
            Ok(thread) => thread,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let _ = aggregate_thread.join();
                return Err(error);
            }
        };

        Ok(Self {
            snapshot_rx,
            capture_ready_rx,
            failure,
            stop,
            capture_wakeup,
            workers: vec![capture_thread, aggregate_thread],
            #[cfg(test)]
            _snapshot_keepalive: None,
        })
    }

    #[cfg(test)]
    pub fn stop(&mut self) {
        self.signal_stop();
        Self::join_workers(self.workers.drain(..));
    }

    fn signal_stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(wake_capture) = self.capture_wakeup.take() {
            wake_capture();
        }
        for worker in &self.workers {
            worker.thread().unpark();
        }
    }

    fn join_workers(workers: impl IntoIterator<Item = thread::JoinHandle<()>>) {
        for worker in workers {
            let _ = worker.join();
        }
    }

    fn stop_in_background(&mut self) {
        self.signal_stop();
        let workers: Vec<_> = self.workers.drain(..).collect();
        if workers.is_empty() {
            return;
        }
        let _ = thread::Builder::new()
            .name("delray-pipeline-reaper".to_string())
            .spawn(move || Self::join_workers(workers));
    }

    pub fn try_latest(&self) -> Result<Option<Arc<TrafficSnapshot>>, PipelineError> {
        let mut latest = None;
        loop {
            match self.snapshot_rx.try_recv() {
                Ok(snapshot) => latest = Some(snapshot),
                Err(TryRecvError::Empty) => {
                    return match self.failure.get() {
                        Some(failure) => Err(failure.clone()),
                        None => Ok(latest),
                    };
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(self
                        .failure
                        .get()
                        .cloned()
                        .unwrap_or(PipelineError::WorkerStopped("aggregate")));
                }
            }
        }
    }

    pub(crate) fn observe_early_capture_failure(&self) -> Result<CaptureReadiness, PipelineError> {
        match self
            .capture_ready_rx
            .recv_timeout(CAPTURE_EARLY_FAILURE_WINDOW)
        {
            Ok(Ok(())) => Ok(CaptureReadiness::Ready),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Ok(CaptureReadiness::Waiting),
            Err(RecvTimeoutError::Disconnected) => Err(self
                .failure
                .get()
                .cloned()
                .unwrap_or(PipelineError::WorkerStopped("capture"))),
        }
    }

    pub(crate) fn poll_capture_readiness(&self) -> Option<Result<CaptureReadiness, PipelineError>> {
        match self.capture_ready_rx.try_recv() {
            Ok(Ok(())) => Some(Ok(CaptureReadiness::Ready)),
            Ok(Err(error)) => Some(Err(error)),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(self
                .failure
                .get()
                .cloned()
                .unwrap_or(PipelineError::WorkerStopped("capture")))),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_snapshot_receiver(snapshot_rx: Receiver<Arc<TrafficSnapshot>>) -> Self {
        let (ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel(1);
        ready_tx.send(Ok(())).unwrap();
        Self {
            snapshot_rx,
            capture_ready_rx,
            failure: Arc::new(OnceLock::new()),
            stop: Arc::new(AtomicBool::new(false)),
            capture_wakeup: None,
            workers: Vec::new(),
            _snapshot_keepalive: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_snapshot_for_test(snapshot: Arc<TrafficSnapshot>) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let (ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel(1);
        tx.send(snapshot)
            .expect("new snapshot receiver is connected");
        ready_tx.send(Ok(())).unwrap();
        Self {
            snapshot_rx: rx,
            capture_ready_rx,
            failure: Arc::new(OnceLock::new()),
            stop: Arc::new(AtomicBool::new(false)),
            capture_wakeup: None,
            workers: Vec::new(),
            _snapshot_keepalive: Some(tx),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        snapshot_rx: Receiver<Arc<TrafficSnapshot>>,
        failure: Arc<OnceLock<PipelineError>>,
    ) -> Self {
        let (ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel(1);
        ready_tx
            .send(Err(failure
                .get()
                .cloned()
                .unwrap_or(PipelineError::WorkerStopped("capture"))))
            .unwrap();
        Self {
            snapshot_rx,
            capture_ready_rx,
            failure,
            stop: Arc::new(AtomicBool::new(false)),
            capture_wakeup: None,
            workers: Vec::new(),
            _snapshot_keepalive: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_delayed_failure_for_test(delay: Duration, message: &str) -> Self {
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::sync_channel(1);
        snapshot_tx
            .send(Arc::new(TrafficSnapshot::default()))
            .unwrap();
        let (ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel(1);
        let message = message.to_string();
        thread::spawn(move || {
            thread::sleep(delay);
            let _ = ready_tx.send(Err(PipelineError::Capture(message)));
        });
        Self {
            snapshot_rx,
            capture_ready_rx,
            failure: Arc::new(OnceLock::new()),
            stop: Arc::new(AtomicBool::new(false)),
            capture_wakeup: None,
            workers: Vec::new(),
            _snapshot_keepalive: Some(snapshot_tx),
        }
    }
}

impl Drop for TrafficPipeline {
    fn drop(&mut self) {
        self.stop_in_background();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::sync_channel;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::capture::Flow;
    use crate::proc_table::ProcTable;
    use crate::stats::{Direction, TrafficSnapshot};

    #[test]
    fn try_latest_returns_newest_queued_snapshot() {
        let (tx, rx) = sync_channel(2);
        tx.send(snapshot(1)).unwrap();
        tx.send(snapshot(2)).unwrap();
        let pipeline = TrafficPipeline::from_snapshot_receiver(rx);

        let latest = pipeline.try_latest().unwrap().unwrap();

        assert_eq!(latest.in_bytes, 2);
        assert!(pipeline.try_latest().unwrap().is_none());
    }

    #[test]
    fn disconnected_snapshot_worker_takes_priority_over_queued_snapshot() {
        let (tx, rx) = sync_channel(2);
        tx.send(snapshot(3)).unwrap();
        drop(tx);
        let pipeline = TrafficPipeline::from_snapshot_receiver(rx);

        let error = match pipeline.try_latest() {
            Err(error) => error,
            Ok(_) => panic!("worker disconnect should take priority"),
        };

        assert!(matches!(error, PipelineError::WorkerStopped("aggregate")));
    }

    #[test]
    fn terminal_failure_takes_priority_over_queued_snapshot() {
        let (tx, rx) = sync_channel(2);
        tx.send(snapshot(7)).unwrap();
        let failure = Arc::new(OnceLock::new());
        failure
            .set(PipelineError::Capture("pcap failed".to_string()))
            .unwrap();
        let pipeline = TrafficPipeline::from_parts(rx, failure);

        let error = match pipeline.try_latest() {
            Err(error) => error,
            Ok(_) => panic!("terminal failure should take priority"),
        };

        assert!(matches!(error, PipelineError::Capture(message) if message == "pcap failed"));
    }

    #[test]
    fn capture_loop_continues_after_no_flow() {
        let (tx, rx) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_from_source = stop.clone();
        let failure = Arc::new(OnceLock::new());
        let mut calls = 0;

        capture_loop(
            || -> anyhow::Result<Option<Flow>> {
                calls += 1;
                match calls {
                    1 => Ok(None),
                    2 => Ok(Some(flow(99))),
                    _ => {
                        stop_from_source.store(true, Ordering::Release);
                        Ok(None)
                    }
                }
            },
            tx,
            stop,
            failure,
            None,
        );

        assert_eq!(calls, 3);
        assert_eq!(rx.recv().unwrap().bytes, 99);
    }

    #[test]
    fn aggregate_loop_publishes_snapshot_without_flow() {
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(2);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        assert_eq!(snapshot.in_bytes, 0);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn aggregate_snapshot_marks_uninitialized_process_data_stale() {
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        assert!(!snapshot.process_data_fresh);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn aggregate_snapshot_treats_a_poisoned_process_table_as_stale() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let poisoned = proc_table.clone();
        let _ = thread::spawn(move || {
            let _guard = poisoned.write().unwrap();
            panic!("poison process table for test");
        })
        .join();
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        assert!(!snapshot.process_data_fresh);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn aggregate_loop_publishes_pending_state_transitions_without_waiting_for_regular_snapshot() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(2);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_secs(5),
                worker_stop,
                worker_failure,
            );
        });

        flow_tx
            .send(Flow {
                direction: Direction::Outbound,
                peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                peer_port: Some(443),
                bytes: 120,
                local_socket: Some(crate::capture::LocalSocket {
                    ip: local_ip,
                    port: 49_152,
                    protocol: crate::capture::TransportProtocol::Tcp,
                }),
                peer_local_socket: None,
                domain: None,
            })
            .unwrap();

        let pending = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("pending transition should publish immediately");
        assert_eq!(pending.pending_attribution_bytes, 120);

        let finalized = snapshot_rx
            .recv_timeout(crate::attribution::PENDING_ATTRIBUTION_WINDOW * 2)
            .expect("pending completion should publish immediately");
        assert_eq!(finalized.pending_attribution_bytes, 0);

        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn aggregate_loop_does_not_block_when_snapshot_channel_is_full() {
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(1);
        snapshot_tx
            .send(Arc::new(TrafficSnapshot::default()))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let (done_tx, done_rx) = sync_channel(1);
        thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
            done_tx.send(()).unwrap();
        });

        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Release);
        drop(flow_tx);

        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_ok());
        drop(snapshot_rx);
    }

    #[test]
    fn aggregate_loop_resolves_process_before_snapshot() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            443,
            crate::capture::TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            Some(Arc::from("/usr/bin/curl")),
        );
        let proc_table = Arc::new(RwLock::new(table));
        let diagnostics_table = proc_table.clone();
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(2);
        flow_tx
            .send(Flow {
                direction: Direction::Outbound,
                peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                peer_port: Some(443),
                bytes: 120,
                local_socket: Some(crate::capture::LocalSocket {
                    ip: local_ip,
                    port: 443,
                    protocol: crate::capture::TransportProtocol::Tcp,
                }),
                peer_local_socket: None,
                domain: None,
            })
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].name(), Some("curl"));
        assert_eq!(snapshot.processes[0].path(), Some("/usr/bin/curl"));
        assert_eq!(snapshot.processes[0].sent, 120);
        assert!(snapshot.process_data_fresh);
        let diagnostics = proc_table::diagnostics_snapshot(&diagnostics_table).unwrap();
        assert_eq!(diagnostics.lookup_hits, 1);
        assert_eq!(diagnostics.lookup_misses, 0);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn aggregate_loop_resolves_both_local_endpoints_for_loopback_flow() {
        let local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            18_765,
            crate::capture::TransportProtocol::Tcp,
            18765,
            Arc::from("python"),
            Some(Arc::from("/usr/bin/python")),
        );
        table.insert_for_test(
            local_ip,
            49_152,
            crate::capture::TransportProtocol::Tcp,
            49152,
            Arc::from("curl"),
            Some(Arc::from("/usr/bin/curl")),
        );
        let proc_table = Arc::new(RwLock::new(table));
        let diagnostics_table = proc_table.clone();
        let (flow_tx, flow_rx) = sync_channel(1);
        let (snapshot_tx, snapshot_rx) = sync_channel(2);
        flow_tx
            .send(Flow {
                direction: Direction::Outbound,
                peer: local_ip,
                peer_port: Some(49_152),
                bytes: 120,
                local_socket: Some(crate::capture::LocalSocket {
                    ip: local_ip,
                    port: 18_765,
                    protocol: crate::capture::TransportProtocol::Tcp,
                }),
                peer_local_socket: Some(crate::capture::LocalSocket {
                    ip: local_ip,
                    port: 49_152,
                    protocol: crate::capture::TransportProtocol::Tcp,
                }),
                domain: None,
            })
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = thread::spawn(move || {
            aggregate_loop(
                flow_rx,
                snapshot_tx,
                proc_table,
                10,
                Duration::from_millis(10),
                worker_stop,
                worker_failure,
            );
        });

        let snapshot = snapshot_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();
        let server = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(18765))
            .unwrap();
        let client = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(49152))
            .unwrap();

        assert_eq!(snapshot.in_bytes, 120);
        assert_eq!(snapshot.out_bytes, 120);
        assert_eq!((server.recv, server.sent), (0, 120));
        assert_eq!((client.recv, client.sent), (120, 0));
        let diagnostics = proc_table::diagnostics_snapshot(&diagnostics_table).unwrap();
        assert_eq!(diagnostics.lookup_hits, 2);
        assert_eq!(diagnostics.lookup_misses, 0);
        stop.store(true, Ordering::Release);
        drop(flow_tx);
        worker.join().unwrap();
    }

    #[test]
    fn spawn_makes_initial_snapshot_available_immediately() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let pipeline = TrafficPipeline::spawn_with_next(
            || -> anyhow::Result<Option<Flow>> {
                thread::sleep(Duration::from_millis(10));
                Ok(None)
            },
            proc_table,
            10,
        )
        .unwrap();

        let snapshot = pipeline.try_latest().unwrap().unwrap();

        assert_eq!(snapshot.in_bytes, 0);
        assert_eq!(snapshot.out_bytes, 0);
    }

    #[test]
    fn stop_joins_capture_and_aggregate_workers() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let source_calls = calls.clone();
        let (started_tx, started_rx) = sync_channel(1);
        let mut pipeline = TrafficPipeline::spawn_with_next(
            move || -> anyhow::Result<Option<Flow>> {
                source_calls.fetch_add(1, Ordering::Relaxed);
                let _ = started_tx.try_send(());
                thread::sleep(Duration::from_millis(5));
                Ok(None)
            },
            proc_table,
            10,
        )
        .unwrap();

        started_rx.recv_timeout(Duration::from_millis(100)).unwrap();
        pipeline.stop();
        let calls_after_stop = calls.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(20));

        assert!(calls_after_stop > 0);
        assert_eq!(calls.load(Ordering::Relaxed), calls_after_stop);
    }

    #[test]
    fn stop_interrupts_a_blocked_capture_before_joining_workers() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let (started_tx, started_rx) = sync_channel(1);
        let (wake_tx, wake_rx) = sync_channel(1);
        let mut pipeline = TrafficPipeline::spawn_with_next_and_wakeup(
            move || -> anyhow::Result<Option<Flow>> {
                started_tx.send(()).unwrap();
                wake_rx.recv().unwrap();
                Ok(None)
            },
            proc_table,
            10,
            move || wake_tx.send(()).unwrap(),
        )
        .unwrap();

        started_rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let stopped_at = Instant::now();
        pipeline.stop();

        assert!(stopped_at.elapsed() < STOP_CHECK_INTERVAL);
    }

    #[test]
    fn dropping_a_pipeline_does_not_join_blocked_workers_on_the_caller_thread() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let (started_tx, started_rx) = sync_channel(1);
        let pipeline = TrafficPipeline::spawn_with_next(
            move || -> anyhow::Result<Option<Flow>> {
                let _ = started_tx.try_send(());
                thread::sleep(Duration::from_millis(250));
                Ok(None)
            },
            proc_table,
            10,
        )
        .unwrap();

        started_rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let dropped_at = Instant::now();
        drop(pipeline);

        assert!(dropped_at.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn capture_spawn_failure_stops_started_aggregate_worker() {
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let (aggregate_stopped_tx, aggregate_stopped_rx) = sync_channel(1);

        let result = TrafficPipeline::spawn_with_next_using(
            || Ok::<_, io::Error>(None),
            proc_table,
            10,
            None,
            false,
            None,
            move |name, task| {
                if name == "delray-capture" {
                    return Err(io::Error::other("capture thread refused"));
                }

                let aggregate_stopped_tx = aggregate_stopped_tx.clone();
                thread::Builder::new()
                    .name(name.to_string())
                    .spawn(move || {
                        task();
                        aggregate_stopped_tx.send(()).unwrap();
                    })
            },
        );

        let error = result.err().expect("capture thread spawn should fail");
        assert_eq!(error.to_string(), "capture thread refused");
        assert!(
            aggregate_stopped_rx
                .recv_timeout(STOP_CHECK_INTERVAL * 2)
                .is_ok()
        );
    }

    fn snapshot(in_bytes: u64) -> Arc<TrafficSnapshot> {
        Arc::new(TrafficSnapshot {
            in_bytes,
            ..TrafficSnapshot::default()
        })
    }

    fn flow(bytes: u64) -> Flow {
        Flow {
            direction: Direction::Inbound,
            peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
            peer_port: None,
            bytes,
            local_socket: None,
            peer_local_socket: None,
            domain: None,
        }
    }
}
