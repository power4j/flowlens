use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{LocalSocket, TransportProtocol};

pub(crate) type SocketKey = (IpAddr, u16, TransportProtocol);
const LOOKUP_MISS_SAMPLE_LIMIT: usize = 8;

/// Process association table rebuilt periodically by a background thread.
#[derive(Default)]
pub struct ProcTable {
    entries: HashMap<SocketKey, HashMap<u32, ProcInfo>>,
    v4_mapped_aliases: HashSet<SocketKey>,
    record_count: u64,
    v4_mapped_record_count: u64,
    refreshed_at: Option<Instant>,
    generation: u64,
    max_age: Duration,
    refresh_tx: Option<SyncSender<RefreshRequest>>,
    diagnostics: Arc<ProcDiagnostics>,
}

pub struct ProcInfo {
    pub pid: u32,
    pub name: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
}

struct ListenerRecord {
    socket: SocketAddr,
    protocol: TransportProtocol,
    pid: u32,
    name: String,
    path: String,
}

pub type SharedProcTable = Arc<RwLock<ProcTable>>;
type ThreadTask = Box<dyn FnOnce() + Send + 'static>;
type RefreshRequest = ();

#[derive(Default)]
struct ProcDiagnostics {
    lookup_hits: AtomicU64,
    lookup_misses: AtomicU64,
    lookup_no_candidate: AtomicU64,
    lookup_ambiguous: AtomicU64,
    lookup_stale: AtomicU64,
    lookup_no_candidate_bytes: AtomicU64,
    lookup_ambiguous_bytes: AtomicU64,
    lookup_stale_bytes: AtomicU64,
    lookup_v4_mapped_hits: AtomicU64,
    no_local_socket: AtomicU64,
    refresh_requests: AtomicU64,
    refresh_actual: AtomicU64,
    refresh_success: AtomicU64,
    refresh_failure: AtomicU64,
    refresh_records: AtomicU64,
    refresh_v4_mapped_records: AtomicU64,
    refresh_duration_nanos: AtomicU64,
    last_refresh_duration_nanos: AtomicU64,
    lookup_miss_samples: Mutex<Vec<LookupMissSample>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LookupMissSample {
    pub reason: LookupMissReason,
    pub local_socket: LocalSocket,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProcDiagnosticsSnapshot {
    pub lookup_hits: u64,
    pub lookup_misses: u64,
    pub lookup_no_candidate: u64,
    pub lookup_ambiguous: u64,
    pub lookup_stale: u64,
    pub lookup_no_candidate_bytes: u64,
    pub lookup_ambiguous_bytes: u64,
    pub lookup_stale_bytes: u64,
    pub lookup_v4_mapped_hits: u64,
    pub no_local_socket: u64,
    pub refresh_requests: u64,
    pub refresh_actual: u64,
    pub refresh_success: u64,
    pub refresh_failure: u64,
    pub refresh_records: u64,
    pub refresh_v4_mapped_records: u64,
    pub refresh_duration: Duration,
    pub last_refresh_duration: Duration,
    pub lookup_miss_samples: Vec<LookupMissSample>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RefreshWake {
    Periodic,
    Requested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LookupMissReason {
    NoCandidate,
    Ambiguous,
    Stale,
}

pub(crate) enum LookupOutcome<'a> {
    Hit {
        process: &'a ProcInfo,
        v4_mapped: bool,
    },
    /// Multiple candidate processes for the same (ip, port, protocol); the
    /// candidate set feeds shared attribution (ADR 0013).
    Ambiguous {
        processes: Vec<&'a ProcInfo>,
    },
    Miss(LookupMissReason),
}

impl ProcTable {
    pub(crate) fn is_fresh(&self) -> bool {
        self.is_fresh_at(Instant::now())
    }

    fn is_fresh_at(&self, now: Instant) -> bool {
        self.refreshed_at
            .is_some_and(|refreshed_at| now.saturating_duration_since(refreshed_at) <= self.max_age)
    }

    #[cfg(test)]
    pub(crate) fn lookup(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
    ) -> Option<&ProcInfo> {
        self.lookup_at(ip, port, protocol, Instant::now())
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Data source for the history interval log (ADR 0013 history engine):
    /// all socket→PID mappings of the current generation.
    pub(crate) fn iter_entries(&self) -> impl Iterator<Item = (SocketKey, &ProcInfo)> {
        self.entries
            .iter()
            .flat_map(|(socket, by_pid)| by_pid.values().map(move |info| (*socket, info)))
    }

    #[cfg(test)]
    fn lookup_at(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        now: Instant,
    ) -> Option<&ProcInfo> {
        match self.lookup_outcome_at(ip, port, protocol, now) {
            LookupOutcome::Hit { process, .. } => Some(process),
            LookupOutcome::Ambiguous { .. } | LookupOutcome::Miss(_) => None,
        }
    }

    pub(crate) fn lookup_outcome(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
    ) -> LookupOutcome<'_> {
        self.lookup_outcome_at(ip, port, protocol, Instant::now())
    }

    fn lookup_outcome_at(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        now: Instant,
    ) -> LookupOutcome<'_> {
        if self
            .refreshed_at
            .is_some_and(|refreshed_at| now.saturating_duration_since(refreshed_at) > self.max_age)
        {
            return LookupOutcome::Miss(LookupMissReason::Stale);
        }

        let key = (ip, port, protocol);
        let wildcard_key = (wildcard_for(ip), port, protocol);
        let Some((lookup_key, candidates)) = self
            .entries
            .get_key_value(&key)
            .or_else(|| self.entries.get_key_value(&wildcard_key))
            .map(|(key, candidates)| (*key, candidates))
        else {
            return LookupOutcome::Miss(LookupMissReason::NoCandidate);
        };
        if candidates.len() != 1 {
            return LookupOutcome::Ambiguous {
                processes: candidates.values().collect(),
            };
        }
        let process = candidates
            .values()
            .next()
            .expect("one candidate exists after length check");
        LookupOutcome::Hit {
            process,
            v4_mapped: self.v4_mapped_aliases.contains(&lookup_key),
        }
    }

    pub(crate) fn record_lookup_hit(&self) {
        self.diagnostics.lookup_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_v4_mapped_lookup_hit(&self) {
        self.diagnostics
            .lookup_v4_mapped_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_lookup_miss_bytes(&self, reason: LookupMissReason, bytes: u64) {
        self.diagnostics
            .lookup_misses
            .fetch_add(1, Ordering::Relaxed);
        match reason {
            LookupMissReason::NoCandidate => {
                self.diagnostics
                    .lookup_no_candidate
                    .fetch_add(1, Ordering::Relaxed);
                self.diagnostics
                    .lookup_no_candidate_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            LookupMissReason::Ambiguous => {
                self.diagnostics
                    .lookup_ambiguous
                    .fetch_add(1, Ordering::Relaxed);
                self.diagnostics
                    .lookup_ambiguous_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            LookupMissReason::Stale => {
                self.diagnostics
                    .lookup_stale
                    .fetch_add(1, Ordering::Relaxed);
                self.diagnostics
                    .lookup_stale_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
            }
        };
    }

    pub(crate) fn record_lookup_miss_sample(
        &self,
        reason: LookupMissReason,
        local_socket: LocalSocket,
        peer_ip: IpAddr,
        peer_port: u16,
    ) {
        let Ok(mut samples) = self.diagnostics.lookup_miss_samples.lock() else {
            return;
        };
        if samples.len() >= LOOKUP_MISS_SAMPLE_LIMIT {
            return;
        }
        let sample = LookupMissSample {
            reason,
            local_socket,
            peer_ip,
            peer_port,
        };
        if !samples.contains(&sample) {
            samples.push(sample);
        }
    }

    fn record_no_local_socket(&self) {
        self.diagnostics
            .no_local_socket
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_refresh_request(&self) {
        self.diagnostics
            .refresh_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_refresh_start(&self) {
        self.diagnostics
            .refresh_actual
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_refresh_result(&self, success: bool, duration: Duration) {
        if success {
            self.diagnostics
                .refresh_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.diagnostics
                .refresh_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        let nanos = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
        self.diagnostics
            .refresh_duration_nanos
            .fetch_add(nanos, Ordering::Relaxed);
        self.diagnostics
            .last_refresh_duration_nanos
            .store(nanos, Ordering::Relaxed);
    }

    fn record_refresh_table_shape(&self) {
        self.diagnostics
            .refresh_records
            .store(self.record_count, Ordering::Relaxed);
        self.diagnostics
            .refresh_v4_mapped_records
            .store(self.v4_mapped_record_count, Ordering::Relaxed);
    }

    fn diagnostics_snapshot(&self) -> ProcDiagnosticsSnapshot {
        let lookup_miss_samples = self
            .diagnostics
            .lookup_miss_samples
            .lock()
            .map(|mut samples| std::mem::take(&mut *samples))
            .unwrap_or_default();
        ProcDiagnosticsSnapshot {
            lookup_hits: self.diagnostics.lookup_hits.load(Ordering::Relaxed),
            lookup_misses: self.diagnostics.lookup_misses.load(Ordering::Relaxed),
            lookup_no_candidate: self.diagnostics.lookup_no_candidate.load(Ordering::Relaxed),
            lookup_ambiguous: self.diagnostics.lookup_ambiguous.load(Ordering::Relaxed),
            lookup_stale: self.diagnostics.lookup_stale.load(Ordering::Relaxed),
            lookup_no_candidate_bytes: self
                .diagnostics
                .lookup_no_candidate_bytes
                .load(Ordering::Relaxed),
            lookup_ambiguous_bytes: self
                .diagnostics
                .lookup_ambiguous_bytes
                .load(Ordering::Relaxed),
            lookup_stale_bytes: self.diagnostics.lookup_stale_bytes.load(Ordering::Relaxed),
            lookup_v4_mapped_hits: self
                .diagnostics
                .lookup_v4_mapped_hits
                .load(Ordering::Relaxed),
            no_local_socket: self.diagnostics.no_local_socket.load(Ordering::Relaxed),
            refresh_requests: self.diagnostics.refresh_requests.load(Ordering::Relaxed),
            refresh_actual: self.diagnostics.refresh_actual.load(Ordering::Relaxed),
            refresh_success: self.diagnostics.refresh_success.load(Ordering::Relaxed),
            refresh_failure: self.diagnostics.refresh_failure.load(Ordering::Relaxed),
            refresh_records: self.diagnostics.refresh_records.load(Ordering::Relaxed),
            refresh_v4_mapped_records: self
                .diagnostics
                .refresh_v4_mapped_records
                .load(Ordering::Relaxed),
            refresh_duration: Duration::from_nanos(
                self.diagnostics
                    .refresh_duration_nanos
                    .load(Ordering::Relaxed),
            ),
            last_refresh_duration: Duration::from_nanos(
                self.diagnostics
                    .last_refresh_duration_nanos
                    .load(Ordering::Relaxed),
            ),
            lookup_miss_samples,
        }
    }

    fn from_records(records: impl IntoIterator<Item = ListenerRecord>) -> Self {
        let mut entries: HashMap<SocketKey, HashMap<u32, ProcInfo>> = HashMap::new();
        let mut v4_mapped_aliases = HashSet::new();
        let mut record_count = 0;
        let mut v4_mapped_record_count = 0;
        for record in records {
            record_count += 1;
            let ip = record.socket.ip();
            let port = record.socket.port();
            let is_v4_mapped = is_ipv4_mapped(ip);
            if is_v4_mapped {
                v4_mapped_record_count += 1;
            }
            let name = executable_name(&record.path)
                .map(Arc::from)
                .or_else(|| (!record.name.is_empty()).then(|| Arc::from(record.name)));
            let path = (!record.path.is_empty()).then(|| Arc::from(record.path));
            for (key, is_alias) in socket_keys(ip, port, record.protocol) {
                if is_alias {
                    v4_mapped_aliases.insert(key);
                }
                entries
                    .entry(key)
                    .or_default()
                    .entry(record.pid)
                    .or_insert_with(|| ProcInfo {
                        pid: record.pid,
                        name: name.clone(),
                        path: path.clone(),
                    });
            }
        }
        Self {
            entries,
            v4_mapped_aliases,
            record_count,
            v4_mapped_record_count,
            refreshed_at: None,
            generation: 0,
            max_age: Duration::ZERO,
            refresh_tx: None,
            diagnostics: Arc::new(ProcDiagnostics::default()),
        }
    }

    fn refresh_at(
        &mut self,
        result: Result<Vec<ListenerRecord>, String>,
        refreshed_at: Instant,
        refresh: Duration,
    ) -> Result<(), String> {
        let refresh_tx = self.refresh_tx.clone();
        let diagnostics = self.diagnostics.clone();
        let records = result?;
        let mut next = Self::from_records(records);
        next.refreshed_at = Some(refreshed_at);
        next.generation = self.generation.wrapping_add(1);
        next.max_age = refresh.saturating_mul(2);
        next.refresh_tx = refresh_tx;
        next.diagnostics = diagnostics;
        *self = next;
        self.record_refresh_table_shape();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &mut self,
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        name: Arc<str>,
        path: Option<Arc<str>>,
    ) {
        self.refreshed_at = Some(Instant::now());
        self.generation = self.generation.wrapping_add(1);
        self.max_age = Duration::MAX;
        self.record_count += 1;
        self.entries
            .entry((ip, port, protocol))
            .or_default()
            .insert(
                pid,
                ProcInfo {
                    pid,
                    name: Some(name),
                    path,
                },
            );
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.max_age = Duration::ZERO;
        self.refreshed_at = Some(Instant::now() - Duration::from_nanos(1));
    }

    #[cfg(test)]
    pub(crate) fn fail_refresh_for_test(&mut self) {
        let _ = self.refresh_at(
            Err("listeners unavailable".to_string()),
            Instant::now(),
            Duration::from_secs(1),
        );
    }
}

pub(crate) fn record_no_local_socket(table: &SharedProcTable) {
    if let Ok(table) = table.read() {
        table.record_no_local_socket();
    }
}

pub(crate) fn request_refresh(table: &SharedProcTable) -> bool {
    let (refresh_tx, requested) = match table.read() {
        Ok(table) => {
            table.record_refresh_request();
            (table.refresh_tx.clone(), true)
        }
        Err(error) => {
            eprintln!("Failed to request process table refresh: {error}");
            (None, false)
        }
    };
    if !requested {
        return false;
    }
    let Some(refresh_tx) = refresh_tx else {
        return false;
    };
    match refresh_tx.try_send(()) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => false,
        Err(TrySendError::Disconnected(_)) => false,
    }
}

pub(crate) fn diagnostics_snapshot(table: &SharedProcTable) -> Option<ProcDiagnosticsSnapshot> {
    table.read().ok().map(|table| table.diagnostics_snapshot())
}

fn wildcard_for(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn is_ipv4_mapped(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ipv6) if ipv6.to_ipv4_mapped().is_some())
}

fn socket_keys(ip: IpAddr, port: u16, protocol: TransportProtocol) -> Vec<(SocketKey, bool)> {
    let key = (ip, port, protocol);
    let IpAddr::V6(ipv6) = ip else {
        return vec![(key, false)];
    };
    match ipv6.to_ipv4_mapped() {
        Some(ipv4) => vec![(key, false), ((IpAddr::V4(ipv4), port, protocol), true)],
        None => vec![(key, false)],
    }
}

impl From<listeners::Listener> for ListenerRecord {
    fn from(listener: listeners::Listener) -> Self {
        Self {
            socket: listener.socket,
            protocol: listener.protocol.into(),
            pid: listener.process.pid,
            name: listener.process.name,
            path: listener.process.path,
        }
    }
}

impl From<listeners::Protocol> for TransportProtocol {
    fn from(protocol: listeners::Protocol) -> Self {
        match protocol {
            listeners::Protocol::TCP => Self::Tcp,
            listeners::Protocol::UDP => Self::Udp,
        }
    }
}

fn executable_name(path: &str) -> Option<&str> {
    Path::new(path)
        .file_name()?
        .to_str()
        .filter(|name| !name.is_empty())
}

/// Build the initial process table synchronously, then refresh it in the background.
pub fn spawn(refresh: Duration) -> SharedProcTable {
    let min_request_interval = request_refresh_min_interval(refresh);
    spawn_using(
        refresh,
        min_request_interval,
        query,
        wait_for_refresh,
        |task| {
            thread::spawn(task);
        },
    )
}

fn spawn_using<Q, W, S>(
    refresh: Duration,
    min_request_interval: Duration,
    mut query: Q,
    mut wait: W,
    spawn_thread: S,
) -> SharedProcTable
where
    Q: FnMut() -> Result<Vec<ListenerRecord>, String> + Send + 'static,
    W: FnMut(Duration, &Receiver<RefreshRequest>) -> Option<RefreshWake> + Send + 'static,
    S: FnOnce(ThreadTask),
{
    let table: SharedProcTable = Arc::new(RwLock::new(ProcTable::default()));
    let (refresh_tx, refresh_rx) = std::sync::mpsc::sync_channel(1);
    if let Ok(mut table) = table.write() {
        table.refresh_tx = Some(refresh_tx);
    }
    run_refresh(&table, &mut query, refresh);

    let handle = table.clone();
    spawn_thread(Box::new(move || {
        let mut last_requested_refresh = None;
        loop {
            let Some(wake) = wait(refresh, &refresh_rx) else {
                return;
            };
            if wake == RefreshWake::Requested {
                let now = Instant::now();
                if last_requested_refresh
                    .is_some_and(|last| now.saturating_duration_since(last) < min_request_interval)
                {
                    drain_refresh_requests(&refresh_rx);
                    continue;
                }
                last_requested_refresh = Some(now);
            }
            run_refresh(&handle, &mut query, refresh);
            drain_refresh_requests(&refresh_rx);
        }
    }));
    table
}

fn wait_for_refresh(
    duration: Duration,
    refresh_rx: &Receiver<RefreshRequest>,
) -> Option<RefreshWake> {
    match refresh_rx.recv_timeout(duration) {
        Ok(()) => Some(RefreshWake::Requested),
        Err(RecvTimeoutError::Timeout) => Some(RefreshWake::Periodic),
        Err(RecvTimeoutError::Disconnected) => None,
    }
}

fn request_refresh_min_interval(refresh: Duration) -> Duration {
    refresh.min(Duration::from_secs(1))
}

fn drain_refresh_requests(refresh_rx: &Receiver<RefreshRequest>) {
    loop {
        match refresh_rx.try_recv() {
            Ok(()) => {}
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

fn run_refresh<Q>(table: &SharedProcTable, query: &mut Q, refresh: Duration)
where
    Q: FnMut() -> Result<Vec<ListenerRecord>, String>,
{
    if let Ok(table) = table.read() {
        table.record_refresh_start();
    }
    let started_at = Instant::now();
    let result = query();
    let duration = started_at.elapsed();
    let success = result.is_ok();
    refresh_table(table, result, refresh, duration);
    if let Ok(table) = table.read() {
        table.record_refresh_result(success, duration);
    }
}

fn refresh_table(
    table: &SharedProcTable,
    result: Result<Vec<ListenerRecord>, String>,
    refresh: Duration,
    duration: Duration,
) {
    if let Err(error) = &result {
        eprintln!("Failed to refresh process table after {duration:?}: {error}");
    }
    match table.write() {
        Ok(mut table) => {
            let _ = table.refresh_at(result, Instant::now(), refresh);
        }
        Err(error) => {
            eprintln!("Failed to update process table: {error}");
        }
    }
}

fn query() -> Result<Vec<ListenerRecord>, String> {
    listeners::get_all()
        .map(|listeners| listeners.into_iter().map(ListenerRecord::from).collect())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::sync_channel;
    use std::time::Instant;

    use super::*;

    fn record(
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        path: &str,
    ) -> ListenerRecord {
        record_with_name(ip, port, protocol, pid, "", path)
    }

    fn record_with_name(
        ip: IpAddr,
        port: u16,
        protocol: TransportProtocol,
        pid: u32,
        name: &str,
        path: &str,
    ) -> ListenerRecord {
        ListenerRecord {
            socket: SocketAddr::new(ip, port),
            protocol,
            pid,
            name: name.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn initial_success_is_visible_when_startup_returns() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (task_tx, task_rx) = sync_channel(1);

        let table = spawn_using(
            Duration::from_secs(5),
            Duration::from_secs(1),
            move || {
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    7,
                    "/usr/bin/curl",
                )])
            },
            |_, _| None,
            move |task| task_tx.send(task).unwrap(),
        );

        assert_eq!(
            table
                .read()
                .unwrap()
                .lookup(ip, 443, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
        drop(task_rx.recv().unwrap());
    }

    #[test]
    fn startup_queries_once_before_the_first_refresh_interval() {
        let queries = Arc::new(AtomicUsize::new(0));
        let query_count = queries.clone();
        let (task_tx, task_rx) = sync_channel(1);

        let _table = spawn_using(
            Duration::from_secs(5),
            Duration::from_secs(1),
            move || {
                query_count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
            |_, _| None,
            move |task| task_tx.send(task).unwrap(),
        );
        task_rx.recv().unwrap()();

        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn initial_failure_allows_background_recovery() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut results = vec![
            Err("listeners unavailable".to_string()),
            Ok(vec![record(
                ip,
                443,
                TransportProtocol::Tcp,
                7,
                "/usr/bin/curl",
            )]),
        ]
        .into_iter();
        let mut first_wait = true;
        let (task_tx, task_rx) = sync_channel(1);

        let table = spawn_using(
            Duration::from_secs(5),
            Duration::from_secs(1),
            move || results.next().expect("only two queries are expected"),
            move |_, _| std::mem::replace(&mut first_wait, false).then_some(RefreshWake::Periodic),
            move |task| task_tx.send(task).unwrap(),
        );

        {
            let table = table.read().unwrap();
            assert!(!table.is_fresh());
            assert!(table.lookup(ip, 443, TransportProtocol::Tcp).is_none());
        }

        task_rx.recv().unwrap()();

        let table = table.read().unwrap();
        assert!(table.is_fresh());
        assert_eq!(
            table
                .lookup(ip, 443, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
    }

    #[test]
    fn refresh_request_triggers_one_background_refresh() {
        let queries = Arc::new(AtomicUsize::new(0));
        let query_count = queries.clone();
        let (task_tx, task_rx) = sync_channel(1);
        let table = spawn_using(
            Duration::from_secs(60),
            Duration::from_secs(1),
            move || {
                query_count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
            |_, refresh_rx| match refresh_rx.try_recv() {
                Ok(()) => Some(RefreshWake::Requested),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => None,
            },
            move |task| task_tx.send(task).unwrap(),
        );

        assert!(request_refresh(&table));
        task_rx.recv().unwrap()();

        assert_eq!(queries.load(Ordering::SeqCst), 2);
        let diagnostics = diagnostics_snapshot(&table).unwrap();
        assert_eq!(diagnostics.refresh_requests, 1);
        assert_eq!(diagnostics.refresh_actual, 2);
        assert_eq!(diagnostics.refresh_success, 2);
        assert_eq!(diagnostics.refresh_failure, 0);
    }

    #[test]
    fn burst_refresh_requests_are_coalesced() {
        let queries = Arc::new(AtomicUsize::new(0));
        let query_count = queries.clone();
        let (task_tx, task_rx) = sync_channel(1);
        let table = spawn_using(
            Duration::from_secs(60),
            Duration::from_secs(1),
            move || {
                query_count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
            |_, refresh_rx| match refresh_rx.try_recv() {
                Ok(()) => Some(RefreshWake::Requested),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => None,
            },
            move |task| task_tx.send(task).unwrap(),
        );

        assert!(request_refresh(&table));
        assert!(!request_refresh(&table));
        task_rx.recv().unwrap()();

        assert_eq!(queries.load(Ordering::SeqCst), 2);
        let diagnostics = diagnostics_snapshot(&table).unwrap();
        assert_eq!(diagnostics.refresh_requests, 2);
        assert_eq!(diagnostics.refresh_actual, 2);
    }

    #[test]
    fn requested_refreshes_are_rate_limited() {
        let queries = Arc::new(AtomicUsize::new(0));
        let query_count = queries.clone();
        let mut wakes = vec![
            Some(RefreshWake::Requested),
            Some(RefreshWake::Requested),
            None,
        ]
        .into_iter();
        let (task_tx, task_rx) = sync_channel(1);
        let _table = spawn_using(
            Duration::from_secs(60),
            Duration::from_secs(1),
            move || {
                query_count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
            move |_, _| wakes.next().unwrap(),
            move |task| task_tx.send(task).unwrap(),
        );
        task_rx.recv().unwrap()();

        assert_eq!(queries.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn periodic_refresh_continues_after_requested_refresh() {
        let queries = Arc::new(AtomicUsize::new(0));
        let query_count = queries.clone();
        let mut wakes = vec![
            Some(RefreshWake::Requested),
            Some(RefreshWake::Periodic),
            None,
        ]
        .into_iter();
        let (task_tx, task_rx) = sync_channel(1);
        let _table = spawn_using(
            Duration::from_secs(60),
            Duration::from_secs(1),
            move || {
                query_count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
            move |_, _| wakes.next().unwrap(),
            move |task| task_tx.send(task).unwrap(),
        );
        task_rx.recv().unwrap()();

        assert_eq!(queries.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn refresh_failure_keeps_snapshot_and_records_failure_duration() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut results = vec![
            Ok(vec![record(
                ip,
                443,
                TransportProtocol::Tcp,
                7,
                "/usr/bin/curl",
            )]),
            Err("listeners unavailable".to_string()),
        ]
        .into_iter();
        let (task_tx, task_rx) = sync_channel(1);
        let table = spawn_using(
            Duration::from_secs(60),
            Duration::from_secs(1),
            move || {
                std::thread::sleep(Duration::from_millis(1));
                results.next().expect("only two queries are expected")
            },
            |_, refresh_rx| match refresh_rx.try_recv() {
                Ok(()) => Some(RefreshWake::Requested),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => None,
            },
            move |task| task_tx.send(task).unwrap(),
        );

        assert!(request_refresh(&table));
        task_rx.recv().unwrap()();

        let table_read = table.read().unwrap();
        assert_eq!(
            table_read
                .lookup(ip, 443, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
        let diagnostics = table_read.diagnostics_snapshot();
        assert_eq!(diagnostics.refresh_actual, 2);
        assert_eq!(diagnostics.refresh_success, 1);
        assert_eq!(diagnostics.refresh_failure, 1);
        assert!(diagnostics.refresh_duration >= diagnostics.last_refresh_duration);
        assert!(diagnostics.last_refresh_duration > Duration::ZERO);
    }

    #[test]
    fn injected_records_match_address_port_and_protocol() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let table = ProcTable::from_records([
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl"),
            record(ip, 443, TransportProtocol::Udp, 8, "/usr/bin/quiche"),
        ]);

        assert_eq!(
            table.lookup(ip, 443, TransportProtocol::Tcp).map(|p| p.pid),
            Some(7)
        );
        assert_eq!(
            table.lookup(ip, 443, TransportProtocol::Udp).map(|p| p.pid),
            Some(8)
        );
        assert!(table.lookup(ip, 80, TransportProtocol::Tcp).is_none());
    }

    #[test]
    fn injected_records_support_ipv4_and_ipv6() {
        let ipv4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let table = ProcTable::from_records([
            record(ipv4, 8080, TransportProtocol::Tcp, 10, "/opt/server4"),
            record(ipv6, 5353, TransportProtocol::Udp, 11, "/opt/server6"),
        ]);

        assert_eq!(
            table
                .lookup(ipv4, 8080, TransportProtocol::Tcp)
                .map(|p| p.pid),
            Some(10)
        );
        assert_eq!(
            table
                .lookup(ipv6, 5353, TransportProtocol::Udp)
                .map(|p| p.pid),
            Some(11)
        );
    }

    #[test]
    fn ipv4_wildcard_listener_matches_concrete_address() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let table = ProcTable::from_records([record(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            8080,
            TransportProtocol::Tcp,
            7,
            "/opt/server",
        )]);

        assert_eq!(
            table
                .lookup(local_ip, 8080, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
    }

    #[test]
    fn ipv6_wildcard_listener_matches_concrete_address() {
        let local_ip = IpAddr::V6("2001:db8::10".parse().unwrap());
        let table = ProcTable::from_records([record(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            8080,
            TransportProtocol::Tcp,
            7,
            "/opt/server",
        )]);

        assert_eq!(
            table
                .lookup(local_ip, 8080, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(7)
        );
    }

    #[test]
    fn ipv4_lookup_matches_ipv4_mapped_ipv6_socket() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(186, 241, 106, 205));
        let mapped_ip = IpAddr::V6(Ipv4Addr::new(186, 241, 106, 205).to_ipv6_mapped());
        let table = ProcTable::from_records([record(
            mapped_ip,
            51102,
            TransportProtocol::Tcp,
            2027468,
            "/app/sui",
        )]);

        assert_eq!(
            table
                .lookup(local_ip, 51102, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(2027468)
        );
    }

    #[test]
    fn ipv4_mapped_records_and_hits_are_counted() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(186, 241, 106, 205));
        let mapped_ip = IpAddr::V6(Ipv4Addr::new(186, 241, 106, 205).to_ipv6_mapped());
        let mut table = ProcTable::default();
        table
            .refresh_at(
                Ok(vec![record(
                    mapped_ip,
                    51102,
                    TransportProtocol::Tcp,
                    2027468,
                    "/app/sui",
                )]),
                Instant::now(),
                Duration::from_secs(1),
            )
            .unwrap();

        let diagnostics = table.diagnostics_snapshot();
        assert_eq!(diagnostics.refresh_records, 1);
        assert_eq!(diagnostics.refresh_v4_mapped_records, 1);

        match table.lookup_outcome(local_ip, 51102, TransportProtocol::Tcp) {
            LookupOutcome::Hit { process, v4_mapped } => {
                assert_eq!(process.pid, 2027468);
                assert!(v4_mapped);
            }
            LookupOutcome::Ambiguous { .. } => panic!("expected hit, got ambiguous"),
            LookupOutcome::Miss(reason) => panic!("expected hit, got {reason:?}"),
        }
        table.record_lookup_hit();
        table.record_v4_mapped_lookup_hit();

        let diagnostics = table.diagnostics_snapshot();
        assert_eq!(diagnostics.lookup_hits, 1);
        assert_eq!(diagnostics.lookup_v4_mapped_hits, 1);
    }

    #[test]
    fn lookup_miss_reasons_are_counted_separately() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut table = ProcTable::default();
        table
            .refresh_at(Ok(Vec::new()), Instant::now(), Duration::from_secs(1))
            .unwrap();

        match table.lookup_outcome(ip, 443, TransportProtocol::Tcp) {
            LookupOutcome::Miss(reason) => table.record_lookup_miss_bytes(reason, 10),
            LookupOutcome::Ambiguous { .. } => panic!("empty table should not be ambiguous"),
            LookupOutcome::Hit { .. } => panic!("empty table should not match"),
        }

        table
            .refresh_at(
                Ok(vec![
                    record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/server-a"),
                    record(ip, 443, TransportProtocol::Tcp, 8, "/usr/bin/server-b"),
                ]),
                Instant::now(),
                Duration::from_secs(1),
            )
            .unwrap();
        match table.lookup_outcome(ip, 443, TransportProtocol::Tcp) {
            // Ambiguity is a distinct variant (ADR 0013); the counting basis
            // matches attribution.rs.
            LookupOutcome::Ambiguous { .. } => {
                table.record_lookup_miss_bytes(LookupMissReason::Ambiguous, 20)
            }
            LookupOutcome::Miss(reason) => table.record_lookup_miss_bytes(reason, 20),
            LookupOutcome::Hit { .. } => panic!("ambiguous table should not match"),
        }

        table.expire_for_test();
        match table.lookup_outcome(ip, 443, TransportProtocol::Tcp) {
            LookupOutcome::Ambiguous { .. } => {
                panic!("expired table should be stale, not ambiguous")
            }
            LookupOutcome::Miss(reason) => table.record_lookup_miss_bytes(reason, 30),
            LookupOutcome::Hit { .. } => panic!("stale table should not match"),
        }

        let diagnostics = table.diagnostics_snapshot();
        assert_eq!(diagnostics.lookup_misses, 3);
        assert_eq!(diagnostics.lookup_no_candidate, 1);
        assert_eq!(diagnostics.lookup_ambiguous, 1);
        assert_eq!(diagnostics.lookup_stale, 1);
        assert_eq!(diagnostics.lookup_no_candidate_bytes, 10);
        assert_eq!(diagnostics.lookup_ambiguous_bytes, 20);
        assert_eq!(diagnostics.lookup_stale_bytes, 30);
    }

    #[test]
    fn lookup_miss_samples_are_bounded_deduplicated_and_drained() {
        let table = ProcTable::default();
        let local_ip = IpAddr::V4(Ipv4Addr::new(186, 241, 106, 205));
        let peer_ip = IpAddr::V4(Ipv4Addr::new(101, 204, 221, 33));
        let local_socket = crate::capture::LocalSocket {
            ip: local_ip,
            port: 51102,
            protocol: TransportProtocol::Tcp,
        };

        table.record_lookup_miss_sample(LookupMissReason::NoCandidate, local_socket, peer_ip, 6041);
        table.record_lookup_miss_sample(LookupMissReason::NoCandidate, local_socket, peer_ip, 6041);
        for peer_port in 6042..6055 {
            table.record_lookup_miss_sample(
                LookupMissReason::NoCandidate,
                crate::capture::LocalSocket {
                    port: peer_port,
                    ..local_socket
                },
                peer_ip,
                peer_port,
            );
        }

        let diagnostics = table.diagnostics_snapshot();
        assert_eq!(
            diagnostics.lookup_miss_samples.len(),
            LOOKUP_MISS_SAMPLE_LIMIT
        );
        assert_eq!(
            diagnostics.lookup_miss_samples[0],
            LookupMissSample {
                reason: LookupMissReason::NoCandidate,
                local_socket,
                peer_ip,
                peer_port: 6041,
            }
        );

        let diagnostics = table.diagnostics_snapshot();
        assert!(diagnostics.lookup_miss_samples.is_empty());
    }

    #[test]
    fn concrete_address_takes_priority_over_wildcard_listener() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let table = ProcTable::from_records([
            record(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080,
                TransportProtocol::Tcp,
                7,
                "/opt/wildcard-server",
            ),
            record(
                local_ip,
                8080,
                TransportProtocol::Tcp,
                8,
                "/opt/specific-server",
            ),
        ]);

        assert_eq!(
            table
                .lookup(local_ip, 8080, TransportProtocol::Tcp)
                .map(|process| process.pid),
            Some(8)
        );
    }

    #[test]
    fn duplicate_candidates_for_one_pid_are_attributed() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl"),
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl"),
        ]);

        assert_eq!(
            table.lookup(ip, 443, TransportProtocol::Tcp).map(|p| p.pid),
            Some(7)
        );
    }

    #[test]
    fn candidates_for_different_pids_are_ambiguous() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([
            record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/server-a"),
            record(ip, 443, TransportProtocol::Tcp, 8, "/usr/bin/server-b"),
        ]);

        assert!(table.lookup(ip, 443, TransportProtocol::Tcp).is_none());
    }

    #[test]
    fn process_display_name_uses_executable_file_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record_with_name(
            ip,
            443,
            TransportProtocol::Tcp,
            7,
            "backend-name",
            "/usr/bin/curl",
        )]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("injected listener should match");
        assert_eq!(process.name.as_deref(), Some("curl"));
    }

    #[test]
    fn process_observation_includes_executable_path() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table =
            ProcTable::from_records([record(ip, 443, TransportProtocol::Tcp, 7, "/usr/bin/curl")]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("injected listener should match");

        assert_eq!(process.path.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn missing_process_name_uses_executable_file_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record_with_name(
            ip,
            443,
            TransportProtocol::Tcp,
            7,
            "",
            "/usr/bin/curl",
        )]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing process name");
        assert_eq!(process.name.as_deref(), Some("curl"));
    }

    #[test]
    fn missing_executable_path_uses_listener_process_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record_with_name(
            ip,
            443,
            TransportProtocol::Tcp,
            7,
            "curl",
            "",
        )]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing executable path");
        assert_eq!(process.name.as_deref(), Some("curl"));
    }

    #[test]
    fn missing_executable_path_has_no_display_name() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let table = ProcTable::from_records([record(ip, 443, TransportProtocol::Tcp, 7, "")]);

        let process = table
            .lookup(ip, 443, TransportProtocol::Tcp)
            .expect("PID attribution should survive a missing path");
        assert!(process.name.is_none());
        assert!(process.path.is_none());
    }

    #[test]
    fn failed_refresh_keeps_last_success_until_snapshot_expires() {
        let started_at = Instant::now();
        let refresh = Duration::from_secs(5);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut table = ProcTable::default();
        table
            .refresh_at(
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    7,
                    "/usr/bin/curl",
                )]),
                started_at,
                refresh,
            )
            .unwrap();

        let error = table
            .refresh_at(
                Err("listeners unavailable".to_string()),
                started_at + refresh,
                refresh,
            )
            .unwrap_err();
        table
            .refresh_at(
                Err("listeners still unavailable".to_string()),
                started_at + refresh * 2,
                refresh,
            )
            .unwrap_err();

        assert_eq!(error, "listeners unavailable");
        assert_eq!(
            table
                .lookup_at(ip, 443, TransportProtocol::Tcp, started_at + refresh * 2,)
                .map(|process| process.pid),
            Some(7)
        );
        assert!(
            table
                .lookup_at(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    started_at + refresh * 2 + Duration::from_nanos(1),
                )
                .is_none()
        );
    }

    #[test]
    fn process_data_freshness_uses_the_last_successful_refresh() {
        let started_at = Instant::now();
        let refresh = Duration::from_secs(5);
        let mut table = ProcTable::default();
        table
            .refresh_at(Ok(Vec::new()), started_at, refresh)
            .unwrap();

        assert!(table.is_fresh_at(started_at + refresh * 2));
        assert!(!table.is_fresh_at(started_at + refresh * 2 + Duration::from_nanos(1)));
    }

    #[test]
    fn successful_refresh_replaces_expired_snapshot() {
        let started_at = Instant::now();
        let refresh = Duration::from_secs(5);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut table = ProcTable::default();
        table
            .refresh_at(
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    7,
                    "/usr/bin/old-server",
                )]),
                started_at,
                refresh,
            )
            .unwrap();
        let recovered_at = started_at + refresh * 3;

        assert!(
            table
                .lookup_at(ip, 443, TransportProtocol::Tcp, recovered_at)
                .is_none()
        );

        table
            .refresh_at(
                Ok(vec![record(
                    ip,
                    443,
                    TransportProtocol::Tcp,
                    8,
                    "/usr/bin/new-server",
                )]),
                recovered_at,
                refresh,
            )
            .unwrap();

        assert_eq!(
            table
                .lookup_at(ip, 443, TransportProtocol::Tcp, recovered_at)
                .map(|process| process.pid),
            Some(8)
        );
    }
}
