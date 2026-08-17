use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::capture::{Flow, LocalSocket};
use crate::proc_table::{self, LookupMissReason, LookupOutcome, SharedProcTable};
use crate::process_probe::{
    ConnectionMatch, ProbeProcess, ProbeRequestId, ProbeRequestOutcome, ProbeResult, ProcessProbe,
};
use crate::stats::{Direction, ObservedProcess, Stats};

pub(crate) const PENDING_ATTRIBUTION_WINDOW: Duration = Duration::from_secs(1);
pub(crate) const PENDING_ATTRIBUTION_CAPACITY: usize = 1_024;
pub(crate) const PENDING_ATTRIBUTION_MAX_PROBE_ATTEMPTS: u8 = 3;
pub(crate) const PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PendingAttributionSnapshot {
    pub records: usize,
    pub bytes: u64,
    pub probe_request_queued: u64,
    pub probe_result_unique: u64,
    pub probe_result_not_found: u64,
    pub probe_result_ambiguous: u64,
    pub probe_result_unavailable: u64,
    pub probe_result_dropped: u64,
    pub probe_result_late: u64,
    pub probe_query_count: u64,
    pub probe_query_ms: u128,
    pub probe_last_query_ms: u128,
    pub pending_expired_bytes: u64,
    pub pending_capacity_bytes: u64,
    pub probe_unique_pending_bytes: u64,
    pub probe_not_found_pending_bytes: u64,
    pub probe_ambiguous_pending_bytes: u64,
    pub probe_unavailable_pending_bytes: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    local_socket: LocalSocket,
    peer_ip: IpAddr,
    peer_port: u16,
    direction: Direction,
}

struct PendingAttribution {
    connection: ConnectionKey,
    socket: LocalSocket,
    direction: Direction,
    bytes: u64,
    observed_at: DateTime<Utc>,
    /// 歧义候选（ADR 0013 共享归属）：push 时从歧义 lookup 捕获；终结时 >= 2 即共享归属。
    candidates: Vec<ObservedProcess>,
    pending_since: Instant,
}

struct EndpointObservation {
    socket: Option<LocalSocket>,
    direction: Direction,
    peer_ip: IpAddr,
    peer_port: Option<u16>,
    bytes: u64,
    observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
struct ProbeState {
    active_request: Option<ProbeRequestId>,
    attempts: u8,
    next_retry_at: Instant,
    exhausted: bool,
    accept_results: bool,
}

pub(crate) struct PendingAttributor {
    pending: VecDeque<PendingAttribution>,
    window: Duration,
    capacity: usize,
    last_generation: Option<u64>,
    probe: Option<ProcessProbe>,
    probe_state: HashMap<LocalSocket, ProbeState>,
    probe_request_queued: u64,
    probe_result_unique: u64,
    probe_result_not_found: u64,
    probe_result_ambiguous: u64,
    probe_result_unavailable: u64,
    probe_result_dropped: u64,
    probe_result_late: u64,
    pending_expired_bytes: u64,
    pending_capacity_bytes: u64,
    probe_unique_pending_bytes: u64,
    probe_not_found_pending_bytes: u64,
    probe_ambiguous_pending_bytes: u64,
    probe_unavailable_pending_bytes: u64,
}

impl Default for PendingAttributor {
    fn default() -> Self {
        Self::new(PENDING_ATTRIBUTION_WINDOW, PENDING_ATTRIBUTION_CAPACITY)
    }
}

impl PendingAttributor {
    pub(crate) fn new(window: Duration, capacity: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            window,
            capacity,
            last_generation: None,
            probe: None,
            probe_state: HashMap::new(),
            probe_request_queued: 0,
            probe_result_unique: 0,
            probe_result_not_found: 0,
            probe_result_ambiguous: 0,
            probe_result_unavailable: 0,
            probe_result_dropped: 0,
            probe_result_late: 0,
            pending_expired_bytes: 0,
            pending_capacity_bytes: 0,
            probe_unique_pending_bytes: 0,
            probe_not_found_pending_bytes: 0,
            probe_ambiguous_pending_bytes: 0,
            probe_unavailable_pending_bytes: 0,
        }
    }

    pub(crate) fn with_probe(window: Duration, capacity: usize, probe: ProcessProbe) -> Self {
        let mut attributor = Self::new(window, capacity);
        attributor.probe = Some(probe);
        attributor
    }

    pub(crate) fn record_flow(
        &mut self,
        stats: &mut Stats,
        flow: Flow,
        proc_table: &SharedProcTable,
        now: Instant,
        observed_at: DateTime<Utc>,
    ) {
        self.advance(stats, proc_table, now);
        stats.record_interface_flow(&flow, observed_at);
        stats.record_outbound_domain(
            flow.domain.as_ref(),
            flow.direction,
            flow.bytes,
            observed_at,
        );

        self.record_endpoint(
            stats,
            EndpointObservation {
                socket: flow.local_socket,
                direction: flow.direction,
                peer_ip: flow.peer,
                peer_port: flow.peer_port,
                bytes: flow.bytes,
                observed_at,
            },
            proc_table,
            now,
        );

        if let (Some(peer_socket), Some(local_socket)) = (flow.peer_local_socket, flow.local_socket)
        {
            self.record_endpoint(
                stats,
                EndpointObservation {
                    socket: Some(peer_socket),
                    direction: Direction::Inbound,
                    peer_ip: local_socket.ip,
                    peer_port: Some(local_socket.port),
                    bytes: flow.bytes,
                    observed_at,
                },
                proc_table,
                now,
            );
        }
    }

    pub(crate) fn advance(
        &mut self,
        stats: &mut Stats,
        proc_table: &SharedProcTable,
        now: Instant,
    ) {
        self.drain_and_apply_probe_results(stats, now);
        self.finalize_expired(stats, now);
        self.resolve_pending_on_generation_change(stats, proc_table);
        self.cleanup_idle_probe_state();
        self.retry_due_probes(now);
    }

    fn drain_and_apply_probe_results(&mut self, stats: &mut Stats, now: Instant) {
        let results = match self.probe.as_ref() {
            Some(probe) => probe.drain_results(),
            None => Vec::new(),
        };
        for result in results {
            self.apply_probe_result(stats, result, now);
        }
    }

    pub(crate) fn apply_probe_result(
        &mut self,
        stats: &mut Stats,
        result: ProbeResult,
        now: Instant,
    ) {
        match result {
            ProbeResult::Unique {
                request_id,
                socket,
                process,
            } => {
                self.probe_result_unique += 1;
                self.probe_unique_pending_bytes += self.pending_bytes_for_socket(socket);
                let Some(state) = self.probe_state.get(&socket) else {
                    self.probe_result_dropped += 1;
                    return;
                };
                if state.active_request != Some(request_id) {
                    self.probe_result_dropped += 1;
                    return;
                }
                let accept_results = state.accept_results;
                let mut retained = VecDeque::new();
                if accept_results {
                    while let Some(pending) = self.pending.pop_front() {
                        if pending.socket == socket {
                            stats.record_process(
                                Some(ObservedProcess::from(process.clone())),
                                pending.direction,
                                pending.bytes,
                                pending.observed_at,
                            );
                        } else {
                            retained.push_back(pending);
                        }
                    }
                    self.pending = retained;
                    self.probe_state.remove(&socket);
                } else {
                    self.reactivate_probe_for_pending(socket, now);
                }
            }
            ProbeResult::ConnectionMatches {
                request_id,
                socket,
                matches,
            } => {
                let Some(state) = self.probe_state.get(&socket) else {
                    self.probe_result_dropped += 1;
                    return;
                };
                if state.active_request != Some(request_id) {
                    self.probe_result_dropped += 1;
                    return;
                }
                if !state.accept_results {
                    self.reactivate_probe_for_pending(socket, now);
                    return;
                }

                let matched_bytes = self.pending_bytes_for_matches(socket, &matches);
                self.probe_result_unique += matches.len() as u64;
                self.probe_unique_pending_bytes += matched_bytes;
                let mut retained = VecDeque::new();
                while let Some(pending) = self.pending.pop_front() {
                    if pending.socket == socket
                        && let Some(process) = connection_process(&pending, &matches)
                    {
                        stats.record_process(
                            Some(ObservedProcess::from(process)),
                            pending.direction,
                            pending.bytes,
                            pending.observed_at,
                        );
                        continue;
                    }
                    retained.push_back(pending);
                }
                self.pending = retained;

                if self.pending.iter().any(|pending| pending.socket == socket) {
                    if let Some(state) = self.probe_state.get_mut(&socket) {
                        state.active_request = None;
                        if state.attempts >= PENDING_ATTRIBUTION_MAX_PROBE_ATTEMPTS {
                            state.exhausted = true;
                        } else {
                            state.next_retry_at = now + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL;
                        }
                    }
                } else {
                    self.probe_state.remove(&socket);
                }
            }
            ProbeResult::Ambiguous {
                request_id, socket, ..
            } => {
                self.probe_result_ambiguous += 1;
                self.probe_ambiguous_pending_bytes += self.pending_bytes_for_socket(socket);
                let Some(state) = self.probe_state.get_mut(&socket) else {
                    self.probe_result_dropped += 1;
                    return;
                };
                if state.active_request != Some(request_id) {
                    self.probe_result_dropped += 1;
                    return;
                }
                state.active_request = None;
                if state.accept_results {
                    state.exhausted = true;
                } else {
                    self.probe_result_late += 1;
                    self.probe_result_dropped += 1;
                    self.probe_state.remove(&socket);
                }
            }
            ProbeResult::NotFound { request_id, socket } => {
                self.probe_result_not_found += 1;
                self.probe_not_found_pending_bytes += self.pending_bytes_for_socket(socket);
                let Some(state) = self.probe_state.get_mut(&socket) else {
                    self.probe_result_dropped += 1;
                    return;
                };
                if state.active_request != Some(request_id) {
                    self.probe_result_dropped += 1;
                    return;
                }
                state.active_request = None;
                if state.accept_results {
                    state.attempts = state.attempts.saturating_add(1);
                    if state.attempts >= PENDING_ATTRIBUTION_MAX_PROBE_ATTEMPTS {
                        state.exhausted = true;
                    } else {
                        state.next_retry_at = now + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL;
                    }
                } else {
                    self.probe_result_late += 1;
                    self.probe_result_dropped += 1;
                    self.probe_state.remove(&socket);
                }
            }
            ProbeResult::Unavailable {
                request_id, socket, ..
            } => {
                self.probe_result_unavailable += 1;
                self.probe_unavailable_pending_bytes += self.pending_bytes_for_socket(socket);
                let Some(state) = self.probe_state.get_mut(&socket) else {
                    self.probe_result_dropped += 1;
                    return;
                };
                if state.active_request != Some(request_id) {
                    self.probe_result_dropped += 1;
                    return;
                }
                state.active_request = None;
                if state.accept_results {
                    state.attempts = state.attempts.saturating_add(1);
                    if state.attempts >= PENDING_ATTRIBUTION_MAX_PROBE_ATTEMPTS {
                        state.exhausted = true;
                    } else {
                        state.next_retry_at = now + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL;
                    }
                } else {
                    self.probe_result_late += 1;
                    self.probe_result_dropped += 1;
                    self.probe_state.remove(&socket);
                }
            }
        }
    }

    fn ensure_probe(&mut self, socket: LocalSocket, now: Instant) {
        {
            let state = self.probe_state.entry(socket).or_insert(ProbeState {
                active_request: None,
                attempts: 0,
                next_retry_at: now,
                exhausted: false,
                accept_results: true,
            });
            if state.active_request.is_some() || state.exhausted || now < state.next_retry_at {
                return;
            }
            if state.attempts >= PENDING_ATTRIBUTION_MAX_PROBE_ATTEMPTS {
                state.exhausted = true;
                return;
            }
        }

        let peers = self.pending_peers_for_socket(socket);
        let outcome = match self.probe.as_ref() {
            Some(probe) if peers.is_empty() => probe.request(socket),
            Some(probe) => probe.request_for_peers(socket, peers),
            None => return,
        };
        let state = self
            .probe_state
            .get_mut(&socket)
            .expect("probe state was inserted before requesting");
        match outcome {
            ProbeRequestOutcome::Queued(request_id) => {
                self.probe_request_queued += 1;
                state.active_request = Some(request_id);
                state.attempts = state.attempts.saturating_add(1);
                state.next_retry_at = now + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL;
                state.accept_results = true;
            }
            ProbeRequestOutcome::InFlight(request_id) => {
                state.active_request = Some(request_id);
                state.next_retry_at = now + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL;
                state.accept_results = false;
            }
            ProbeRequestOutcome::Unavailable => {
                state.attempts = state.attempts.saturating_add(1);
                if state.attempts >= PENDING_ATTRIBUTION_MAX_PROBE_ATTEMPTS {
                    state.exhausted = true;
                } else {
                    state.next_retry_at = now + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL;
                }
            }
        }
    }

    fn retry_due_probes(&mut self, now: Instant) {
        let due: Vec<LocalSocket> = self
            .probe_state
            .iter()
            .filter(|(_, state)| {
                state.active_request.is_none() && !state.exhausted && now >= state.next_retry_at
            })
            .map(|(&socket, _)| socket)
            .collect();
        for socket in due {
            self.ensure_probe(socket, now);
        }
    }

    fn cleanup_idle_probe_state(&mut self) {
        let active: HashSet<LocalSocket> =
            self.pending.iter().map(|pending| pending.socket).collect();
        self.probe_state.retain(|socket, state| {
            if active.contains(socket) {
                true
            } else if state.active_request.is_some() {
                state.accept_results = false;
                true
            } else {
                false
            }
        });
    }

    fn resolve_pending_on_generation_change(
        &mut self,
        stats: &mut Stats,
        proc_table: &SharedProcTable,
    ) {
        let generation = proc_table.read().ok().map(|table| table.generation());
        if generation.is_none() || generation == self.last_generation {
            return;
        }
        self.last_generation = generation;

        let mut retained = VecDeque::new();
        while let Some(mut pending) = self.pending.pop_front() {
            match lookup_process(proc_table, pending.socket, None, false, pending.bytes) {
                Some(LookupResolved::Exclusive(process)) => {
                    stats.record_process(
                        Some(process),
                        pending.direction,
                        pending.bytes,
                        pending.observed_at,
                    );
                }
                Some(LookupResolved::Ambiguous(candidates)) => {
                    merge_candidates(&mut pending.candidates, candidates);
                    retained.push_back(pending);
                }
                Some(LookupResolved::Miss) | None => retained.push_back(pending),
            }
        }
        self.pending = retained;
    }

    #[cfg(test)]
    fn pending_bytes(&self) -> u64 {
        self.snapshot().bytes
    }

    pub(crate) fn snapshot(&self) -> PendingAttributionSnapshot {
        let probe = self
            .probe
            .as_ref()
            .map(ProcessProbe::diagnostics_snapshot)
            .unwrap_or_default();
        PendingAttributionSnapshot {
            records: self.pending.len(),
            bytes: self.pending.iter().map(|pending| pending.bytes).sum(),
            probe_request_queued: self.probe_request_queued,
            probe_result_unique: self.probe_result_unique,
            probe_result_not_found: self.probe_result_not_found,
            probe_result_ambiguous: self.probe_result_ambiguous,
            probe_result_unavailable: self.probe_result_unavailable,
            probe_result_dropped: self.probe_result_dropped,
            probe_result_late: self.probe_result_late,
            probe_query_count: probe.query_count,
            probe_query_ms: probe.query_duration.as_millis(),
            probe_last_query_ms: probe.last_query_duration.as_millis(),
            pending_expired_bytes: self.pending_expired_bytes,
            pending_capacity_bytes: self.pending_capacity_bytes,
            probe_unique_pending_bytes: self.probe_unique_pending_bytes,
            probe_not_found_pending_bytes: self.probe_not_found_pending_bytes,
            probe_ambiguous_pending_bytes: self.probe_ambiguous_pending_bytes,
            probe_unavailable_pending_bytes: self.probe_unavailable_pending_bytes,
        }
    }

    fn pending_bytes_for_socket(&self, socket: LocalSocket) -> u64 {
        self.pending
            .iter()
            .filter(|pending| pending.socket == socket)
            .map(|pending| pending.bytes)
            .sum()
    }

    fn reactivate_probe_for_pending(&mut self, socket: LocalSocket, now: Instant) {
        if self.pending.iter().any(|pending| pending.socket == socket) {
            if let Some(state) = self.probe_state.get_mut(&socket) {
                state.active_request = None;
                state.attempts = 0;
                state.next_retry_at = now;
                state.exhausted = false;
                state.accept_results = true;
            }
        } else {
            self.probe_result_late += 1;
            self.probe_result_dropped += 1;
            self.probe_state.remove(&socket);
        }
    }

    fn pending_bytes_for_matches(&self, socket: LocalSocket, matches: &[ConnectionMatch]) -> u64 {
        self.pending
            .iter()
            .filter(|pending| {
                pending.socket == socket && connection_process(pending, matches).is_some()
            })
            .map(|pending| pending.bytes)
            .sum()
    }

    fn pending_peers_for_socket(&self, socket: LocalSocket) -> Vec<std::net::SocketAddr> {
        let mut peers = Vec::new();
        for pending in &self.pending {
            if pending.socket != socket {
                continue;
            }
            let peer =
                std::net::SocketAddr::new(pending.connection.peer_ip, pending.connection.peer_port);
            if !peers.contains(&peer) {
                peers.push(peer);
            }
        }
        peers
    }

    fn record_endpoint(
        &mut self,
        stats: &mut Stats,
        observation: EndpointObservation,
        proc_table: &SharedProcTable,
        now: Instant,
    ) {
        let EndpointObservation {
            socket,
            direction,
            peer_ip,
            peer_port,
            bytes,
            observed_at,
        } = observation;
        let Some(socket) = socket else {
            proc_table::record_no_local_socket(proc_table);
            // 无本地套接字 = 系统流量（ADR 0013），不再混入未归属。
            stats.record_system(direction, bytes);
            return;
        };
        let Some(peer_port) = peer_port else {
            stats.record_process(None, direction, bytes, observed_at);
            return;
        };

        let mut candidates = Vec::new();
        match lookup_process(proc_table, socket, Some((peer_ip, peer_port)), true, bytes) {
            Some(LookupResolved::Exclusive(process)) => {
                stats.record_process(Some(process), direction, bytes, observed_at);
                return;
            }
            Some(LookupResolved::Ambiguous(found)) => candidates = found,
            Some(LookupResolved::Miss) | None => {}
        }

        if self.push_pending(
            stats,
            PendingAttribution {
                connection: ConnectionKey {
                    local_socket: socket,
                    peer_ip,
                    peer_port,
                    direction,
                },
                socket,
                direction,
                bytes,
                observed_at,
                candidates,
                pending_since: now,
            },
        ) {
            self.ensure_probe(socket, now);
        }
    }

    fn finalize_expired(&mut self, stats: &mut Stats, now: Instant) {
        while self.pending.front().is_some_and(|pending| {
            now.saturating_duration_since(pending.pending_since) >= self.window
        }) {
            self.finalize_oldest(stats, false);
        }
    }

    fn push_pending(&mut self, stats: &mut Stats, pending: PendingAttribution) -> bool {
        debug_assert_eq!(pending.connection.local_socket, pending.socket);
        debug_assert_eq!(pending.connection.direction, pending.direction);
        debug_assert!(matches!(
            pending.connection.peer_ip,
            IpAddr::V4(_) | IpAddr::V6(_)
        ));
        debug_assert_ne!(pending.connection.peer_port, 0);
        if self.capacity == 0 {
            self.pending_capacity_bytes += pending.bytes;
            stats.record_process(None, pending.direction, pending.bytes, pending.observed_at);
            return false;
        }
        if let Some(existing) = self
            .pending
            .iter_mut()
            .find(|existing| existing.connection == pending.connection)
        {
            existing.bytes += pending.bytes;
            existing.observed_at = pending.observed_at;
            merge_candidates(&mut existing.candidates, pending.candidates);
            return true;
        }
        if self.pending.len() == self.capacity {
            self.finalize_oldest(stats, true);
        }
        self.pending.push_back(pending);
        true
    }

    fn finalize_oldest(&mut self, stats: &mut Stats, capacity: bool) {
        if let Some(pending) = self.pending.pop_front() {
            let socket = pending.socket;
            if capacity {
                self.pending_capacity_bytes += pending.bytes;
            } else {
                self.pending_expired_bytes += pending.bytes;
            }
            if pending.candidates.len() >= 2 {
                // 终局歧义 → 共享归属：每个候选全额计入（ADR 0013）。
                stats.record_shared(
                    &pending.candidates,
                    pending.direction,
                    pending.bytes,
                    pending.observed_at,
                );
            } else {
                stats.record_process(None, pending.direction, pending.bytes, pending.observed_at);
            }
            if !self.pending.iter().any(|pending| pending.socket == socket)
                && let Some(state) = self.probe_state.get_mut(&socket)
            {
                state.accept_results = false;
            }
        }
    }
}

impl From<ProbeProcess> for ObservedProcess {
    fn from(process: ProbeProcess) -> Self {
        Self {
            pid: process.pid,
            name: process.name,
            path: process.path,
        }
    }
}

/// lookup 三态（ADR 0013）：唯一命中 / 歧义候选集 / 未命中。
enum LookupResolved {
    Exclusive(ObservedProcess),
    Ambiguous(Vec<ObservedProcess>),
    Miss,
}

/// 按 (pid, path) 去重合并歧义候选。
fn merge_candidates(current: &mut Vec<ObservedProcess>, extra: Vec<ObservedProcess>) {
    for candidate in extra {
        if !current
            .iter()
            .any(|existing| existing.pid == candidate.pid && existing.path == candidate.path)
        {
            current.push(candidate);
        }
    }
}

fn lookup_process(
    proc_table: &SharedProcTable,
    socket: LocalSocket,
    peer: Option<(IpAddr, u16)>,
    request_refresh: bool,
    bytes: u64,
) -> Option<LookupResolved> {
    let table = proc_table.read().ok()?;
    match table.lookup_outcome(socket.ip, socket.port, socket.protocol) {
        LookupOutcome::Hit { process, v4_mapped } => {
            table.record_lookup_hit();
            if v4_mapped {
                table.record_v4_mapped_lookup_hit();
            }
            Some(LookupResolved::Exclusive(ObservedProcess {
                pid: process.pid,
                name: process.name.clone(),
                path: process.path.clone(),
            }))
        }
        LookupOutcome::Ambiguous { processes } => {
            // 先把借用收紧为 owned，再 drop(table)（candidates 借用自 table）。
            let candidates = processes
                .iter()
                .map(|process| ObservedProcess {
                    pid: process.pid,
                    name: process.name.clone(),
                    path: process.path.clone(),
                })
                .collect::<Vec<_>>();
            table.record_lookup_miss_bytes(LookupMissReason::Ambiguous, bytes);
            if let Some((peer_ip, peer_port)) = peer {
                table.record_lookup_miss_sample(
                    LookupMissReason::Ambiguous,
                    socket,
                    peer_ip,
                    peer_port,
                );
            }
            drop(table);
            if request_refresh {
                proc_table::request_refresh(proc_table);
            }
            Some(LookupResolved::Ambiguous(candidates))
        }
        LookupOutcome::Miss(reason) => {
            table.record_lookup_miss_bytes(reason, bytes);
            if let Some((peer_ip, peer_port)) = peer {
                table.record_lookup_miss_sample(reason, socket, peer_ip, peer_port);
            }
            drop(table);
            if request_refresh {
                proc_table::request_refresh(proc_table);
            }
            Some(LookupResolved::Miss)
        }
    }
}

fn connection_process(
    pending: &PendingAttribution,
    matches: &[ConnectionMatch],
) -> Option<ProbeProcess> {
    let peer = std::net::SocketAddr::new(pending.connection.peer_ip, pending.connection.peer_port);
    matches
        .iter()
        .find(|connection| connection.peer == peer)
        .map(|connection| connection.process.clone())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock, mpsc};
    use std::thread;

    use super::*;
    use crate::capture::TransportProtocol;
    use crate::proc_table::ProcTable;
    use crate::stats::ProcessSnapshot;

    fn socket_flow(local_ip: IpAddr, local_port: u16, peer_port: u16, bytes: u64) -> Flow {
        Flow {
            direction: Direction::Outbound,
            peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            peer_port: Some(peer_port),
            bytes,
            local_socket: Some(LocalSocket {
                ip: local_ip,
                port: local_port,
                protocol: TransportProtocol::Tcp,
            }),
            peer_local_socket: None,
            domain: None,
        }
    }

    fn observed_at() -> DateTime<Utc> {
        "2026-07-17T08:00:00Z".parse().unwrap()
    }

    #[test]
    fn probe_cooldown_does_not_queue_a_request() {
        let query_count = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = mpsc::channel();
        let probe = ProcessProbe::spawn_blocked_for_test(query_count.clone(), release_rx);
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let socket = LocalSocket {
            ip: local_ip,
            port: 49_152,
            protocol: TransportProtocol::Tcp,
        };
        let mut attributor = PendingAttributor::with_probe(Duration::from_secs(1), 8, probe);
        let started = Instant::now();

        attributor.ensure_probe(socket, started);
        while query_count.load(Ordering::Acquire) != 1 {
            thread::yield_now();
        }
        let request_id = attributor.probe_state[&socket]
            .active_request
            .expect("initial request is active");
        let mut stats = Stats::default();
        attributor.apply_probe_result(
            &mut stats,
            ProbeResult::NotFound { request_id, socket },
            started,
        );

        release_tx.send(()).unwrap();
        while attributor
            .probe
            .as_ref()
            .expect("probe exists")
            .in_flight_count_for_test()
            != 0
        {
            thread::yield_now();
        }
        attributor
            .probe
            .as_ref()
            .expect("probe exists")
            .drain_results();

        attributor.ensure_probe(
            socket,
            started + PENDING_ATTRIBUTION_PROBE_RETRY_INTERVAL / 2,
        );
        assert_eq!(query_count.load(Ordering::Acquire), 1);
        assert_eq!(attributor.snapshot().probe_request_queued, 1);
    }

    #[test]
    fn late_probe_result_is_counted_when_pending_was_finalized() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let socket = LocalSocket {
            ip: local_ip,
            port: 49_152,
            protocol: TransportProtocol::Tcp,
        };
        let (release_tx, release_rx) = mpsc::channel();
        let probe = ProcessProbe::spawn_blocked_for_test(Arc::new(AtomicUsize::new(0)), release_rx);
        let request_id = match probe.request(socket) {
            ProbeRequestOutcome::Queued(request_id) => request_id,
            outcome => panic!("unexpected probe request outcome: {outcome:?}"),
        };
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 8);
        attributor.probe = Some(probe);
        attributor.probe_state.insert(
            socket,
            ProbeState {
                active_request: Some(request_id),
                attempts: 1,
                next_retry_at: Instant::now(),
                exhausted: false,
                accept_results: false,
            },
        );

        attributor.apply_probe_result(
            &mut Stats::default(),
            ProbeResult::Unique {
                request_id,
                socket,
                process: ProbeProcess {
                    pid: 7,
                    name: None,
                    path: None,
                },
            },
            Instant::now(),
        );

        let snapshot = attributor.snapshot();
        assert_eq!(snapshot.probe_result_unique, 1);
        assert_eq!(snapshot.probe_result_late, 1);
        assert_eq!(snapshot.probe_result_dropped, 1);
        release_tx.send(()).unwrap();
    }

    #[test]
    fn connection_matches_only_attribute_matching_pending_peers() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let first_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), 443);
        let second_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 6)), 443);
        let socket = LocalSocket {
            ip: local,
            port: 49_152,
            protocol: TransportProtocol::Tcp,
        };
        let observed_at = observed_at();
        let (release_tx, release_rx) = mpsc::channel();
        let probe = ProcessProbe::spawn_blocked_for_test(Arc::new(AtomicUsize::new(0)), release_rx);
        let request_id = match probe.request_for_peers(socket, vec![first_peer, second_peer]) {
            ProbeRequestOutcome::Queued(request_id) => request_id,
            outcome => panic!("unexpected probe request outcome: {outcome:?}"),
        };
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 8);
        attributor.probe = Some(probe);
        for (peer, bytes) in [(first_peer, 40), (second_peer, 60)] {
            attributor.pending.push_back(PendingAttribution {
                candidates: Vec::new(),
                connection: ConnectionKey {
                    local_socket: socket,
                    peer_ip: peer.ip(),
                    peer_port: peer.port(),
                    direction: Direction::Outbound,
                },
                socket,
                direction: Direction::Outbound,
                bytes,
                observed_at,
                pending_since: Instant::now(),
            });
        }
        attributor.probe_state.insert(
            socket,
            ProbeState {
                active_request: Some(request_id),
                attempts: 1,
                next_retry_at: Instant::now(),
                exhausted: false,
                accept_results: true,
            },
        );

        attributor.apply_probe_result(
            &mut Stats::default(),
            ProbeResult::ConnectionMatches {
                request_id,
                socket,
                matches: vec![ConnectionMatch {
                    peer: first_peer,
                    process: ProbeProcess {
                        pid: 7,
                        name: Some(Arc::from("curl")),
                        path: None,
                    },
                }],
            },
            Instant::now(),
        );

        assert_eq!(attributor.pending_bytes(), 60);
        assert_eq!(attributor.pending.len(), 1);
        assert_eq!(
            attributor.pending.front().unwrap().connection.peer_ip,
            second_peer.ip()
        );
        assert_eq!(attributor.snapshot().probe_result_unique, 1);
        release_tx.send(()).unwrap();
    }

    #[test]
    fn continued_flow_is_pending_then_attributed_after_a_new_proc_table() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        assert_eq!(stats.snapshot(10).out_bytes, 40);
        assert!(stats.snapshot(10).processes.is_empty());
        assert_eq!(attributor.pending_bytes(), 40);

        proc_table.write().unwrap().insert_for_test(
            local_ip,
            49_152,
            TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            Some(Arc::from("/usr/bin/curl")),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 60),
            &proc_table,
            started + Duration::from_millis(10),
            observed_at() + chrono::Duration::milliseconds(10),
        );

        let snapshot = stats.snapshot(10);
        let process = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(7))
            .unwrap();
        assert_eq!(snapshot.out_bytes, 100);
        assert_eq!(process.sent, 100);
        assert_eq!(
            process.last_seen(),
            observed_at() + chrono::Duration::milliseconds(10)
        );
        assert_eq!(attributor.pending_bytes(), 0);
    }

    #[test]
    fn short_flow_times_out_to_unattributed() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 40);
        assert!(snapshot.processes.is_empty());
        assert_eq!(snapshot.attribution.unattributed.sent, 40);
        assert_eq!(attributor.snapshot().pending_expired_bytes, 40);
    }

    #[test]
    fn delayed_attribution_uses_the_original_observation_time_for_last_seen() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        proc_table.write().unwrap().insert_for_test(
            local_ip,
            49_152,
            TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            None,
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + Duration::from_millis(500),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].last_seen(), observed_at());
    }

    #[test]
    fn ambiguous_same_port_becomes_shared_when_pending_expires() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        for (pid, name) in [(7, "server-a"), (8, "server-b")] {
            table.insert_for_test(
                local_ip,
                443,
                TransportProtocol::Tcp,
                pid,
                Arc::from(name),
                None,
            );
        }
        let proc_table = Arc::new(RwLock::new(table));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 443, 49_152, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        // 终局歧义 → 共享归属：两个候选各全额计入 40 B（inclusive 投影），
        // 记录层 shared 只计 40 B 一次，未归属为 0（ADR 0013）。
        assert_eq!(snapshot.processes.len(), 2);
        for process in snapshot.processes.iter() {
            assert_eq!(process.attribution.shared.sent, 40);
            assert_eq!(process.attribution.exclusive.sent, 0);
            assert_eq!(process.sent, 40);
            assert!(process.is_mixed());
            assert_eq!(process.attribution.shared_with.len(), 1);
        }
        let summary = snapshot.attribution;
        assert_eq!(summary.shared.sent, 40);
        assert_eq!(summary.unattributed.total(), 0);
        assert_eq!(summary.total(), snapshot.in_bytes + snapshot.out_bytes);
    }

    /// ADR 0013 记录层守恒：总计 = 独占 + 共享 + 系统 + 未归属（非环回流量，
    /// 每条 flow 恰好一个 endpoint 记录，通道总和不重不漏）。
    #[test]
    fn conservation_identity_holds_across_all_channels() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            8443,
            TransportProtocol::Tcp,
            7,
            Arc::from("solo"),
            None,
        );
        for (pid, name) in [(9, "alpha"), (10, "beta")] {
            table.insert_for_test(
                local_ip,
                9443,
                TransportProtocol::Tcp,
                pid,
                Arc::from(name),
                None,
            );
        }
        let proc_table = Arc::new(RwLock::new(table));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        // 独占：唯一命中。
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 8443, 5001, 100),
            &proc_table,
            started,
            observed_at(),
        );
        // 共享：歧义候选，窗口耗尽后共享归属。
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 9443, 5002, 40),
            &proc_table,
            started,
            observed_at(),
        );
        // 系统：无本地套接字（ICMP 类）。
        attributor.record_flow(
            &mut stats,
            Flow {
                direction: Direction::Outbound,
                peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                peer_port: None,
                bytes: 10,
                local_socket: None,
                peer_local_socket: None,
                domain: None,
            },
            &proc_table,
            started,
            observed_at(),
        );
        // 未归属：无候选且超时。
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 10443, 5003, 5),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        let summary = snapshot.attribution;
        assert_eq!(summary.exclusive.sent, 100);
        assert_eq!(summary.shared.sent, 40);
        assert_eq!(summary.system.sent, 10);
        assert_eq!(summary.unattributed.sent, 5);
        // 守恒：四通道记录层总和 == 接口字节（无环回双 endpoint）。
        assert_eq!(summary.total(), 155);
        assert_eq!(summary.total(), snapshot.in_bytes + snapshot.out_bytes);
        // 共享字节投影：两个候选各 +40，但记录层只计 40 一次。
        let shared_procs: Vec<&ProcessSnapshot> = snapshot
            .processes
            .iter()
            .filter(|process| process.is_mixed())
            .collect();
        assert_eq!(shared_procs.len(), 2);
        assert!(
            shared_procs
                .iter()
                .all(|process| process.attribution.shared.sent == 40)
        );
    }

    #[test]
    fn failed_refresh_and_stale_proc_table_do_not_falsely_attribute_pending_traffic() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut table = ProcTable::default();
        table.insert_for_test(
            local_ip,
            49_152,
            TransportProtocol::Tcp,
            7,
            Arc::from("curl"),
            None,
        );
        table.expire_for_test();
        table.fail_refresh_for_test();
        let proc_table = Arc::new(RwLock::new(table));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::default();
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.advance(
            &mut stats,
            &proc_table,
            started + PENDING_ATTRIBUTION_WINDOW,
        );

        let snapshot = stats.snapshot(10);
        assert!(snapshot.processes.is_empty());
        assert_eq!(snapshot.attribution.unattributed.sent, 40);
    }

    #[test]
    fn pending_capacity_overflow_finalizes_oldest_traffic_without_losing_totals() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 1);
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_153, 443, 60),
            &proc_table,
            started + Duration::from_millis(1),
            observed_at() + chrono::Duration::milliseconds(1),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 100);
        assert_eq!(snapshot.attribution.unattributed.sent, 40);
        assert_eq!(attributor.pending_bytes(), 60);
        assert_eq!(attributor.snapshot().pending_capacity_bytes, 40);
        attributor.advance(
            &mut stats,
            &proc_table,
            started + Duration::from_secs(1) + Duration::from_millis(1),
        );
        assert_eq!(stats.snapshot(10).attribution.unattributed.sent, 100);
    }

    #[test]
    fn same_connection_merges_pending_records_without_consuming_capacity() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 1);
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 60),
            &proc_table,
            started + Duration::from_millis(1),
            observed_at() + chrono::Duration::milliseconds(1),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 100);
        assert!(snapshot.processes.is_empty());
        assert_eq!(attributor.pending_bytes(), 100);
    }

    #[test]
    fn reused_local_port_with_a_different_peer_port_keeps_distinct_pending_records() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let proc_table = Arc::new(RwLock::new(ProcTable::default()));
        let mut stats = Stats::default();
        let mut attributor = PendingAttributor::new(Duration::from_secs(1), 1);
        let started = Instant::now();

        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 443, 40),
            &proc_table,
            started,
            observed_at(),
        );
        attributor.record_flow(
            &mut stats,
            socket_flow(local_ip, 49_152, 444, 60),
            &proc_table,
            started + Duration::from_millis(1),
            observed_at() + chrono::Duration::milliseconds(1),
        );

        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.out_bytes, 100);
        assert!(snapshot.processes.is_empty());
        assert_eq!(snapshot.attribution.unattributed.sent, 40);
        assert_eq!(attributor.pending_bytes(), 60);
    }
}
