use crate::capture::Flow;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

mod ranking;
mod snapshot;

pub use ranking::*;
pub use snapshot::*;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

pub type RankWindow = RankingWindow;

pub const DEFAULT_PROC_FLOWS: usize = 256;

#[derive(Clone, Copy)]
struct ProcFlowLimit(usize);

impl Default for ProcFlowLimit {
    fn default() -> Self {
        Self(DEFAULT_PROC_FLOWS)
    }
}

/// Cumulative stats since start.
#[derive(Default)]
pub struct Stats {
    /// Total inbound bytes.
    pub in_bytes: u64,
    /// Total outbound bytes.
    pub out_bytes: u64,
    in_by_ip: HashMap<IpAddr, u64>,
    out_by_ip: HashMap<IpAddr, u64>,
    in_ip_last_seen: HashMap<IpAddr, DateTime<Utc>>,
    out_ip_last_seen: HashMap<IpAddr, DateTime<Utc>>,
    in_ip_windows: HashMap<IpAddr, IpWindowState>,
    out_ip_windows: HashMap<IpAddr, IpWindowState>,
    ip_window_epoch: Option<i64>,
    ip_diagnostics: IpDiagnosticsCounters,
    by_proc: HashMap<ProcessKey, ProcTraffic>,
    proc_last_seen: HashMap<ProcessKey, DateTime<Utc>>,
    unattributed: ProcTraffic,
    unattributed_last_seen: Option<DateTime<Utc>>,
    /// Shared-attribution channel (ADR 0013): per-process inclusive
    /// projection; the record-layer total lives in `shared_total`.
    shared_by_proc: HashMap<ProcessKey, ProcTraffic>,
    /// Record-layer shared-byte total (each byte counted once); used by the
    /// conservation identity.
    shared_total: ProcTraffic,
    /// Shared partners (process statistics identity); data source of the
    /// detail page's shared_with.
    shared_partners: HashMap<ProcessKey, Vec<ProcessKey>>,
    /// Evidence sources of the exclusive channel (ADR 0013 history engine).
    evidence_by_proc: HashMap<ProcessKey, Evidence>,
    /// System traffic (no local socket, ADR 0013), separate from
    /// unattributed.
    system: ProcTraffic,
    /// Per-process rolling window (ADR 0013 process windowing): per-process
    /// inclusive bytes.
    proc_windows: HashMap<ProcessKey, DirectionalWindows>,
    /// Record-layer four-channel rolling window (the conservation summary's
    /// window basis).
    exclusive_window: DirectionalWindows,
    shared_window: DirectionalWindows,
    system_window: DirectionalWindows,
    unattributed_window: DirectionalWindows,
    /// Reference epoch of the process window (the bucket epoch of the most
    /// recent record).
    proc_window_epoch: Option<i64>,
    proc_names: HashMap<ProcessKey, Arc<str>>,
    by_domain: HashMap<Arc<str>, DomainTraffic>,
    domain_last_seen: HashMap<Arc<str>, DateTime<Utc>>,
    rank_proc: HashMap<ProcessKey, RankingEntityWindow>,
    rank_in_ip: HashMap<IpAddr, RankingEntityWindow>,
    rank_out_ip: HashMap<IpAddr, RankingEntityWindow>,
    rank_domain: HashMap<Arc<str>, RankingEntityWindow>,
    rank_epoch: Option<i64>,
    rank_start_epoch: Option<i64>,
    rank_window_evictions: u64,
    proc_flows: HashMap<ProcessKey, HashMap<ProcFlowKey, ProcFlowTraffic>>,
    proc_flow_limit: ProcFlowLimit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StatsDiagnostics {
    pub inbound_ip_entries: usize,
    pub outbound_ip_entries: usize,
    pub process_entries: usize,
    pub domain_entries: usize,
    pub inbound_heavy_ip_entries: usize,
    pub inbound_rising_ip_entries: usize,
    pub inbound_observation_ip_entries: usize,
    pub outbound_heavy_ip_entries: usize,
    pub outbound_rising_ip_entries: usize,
    pub outbound_observation_ip_entries: usize,
    pub ip_promotions: u64,
    pub ip_demotions: u64,
    pub ip_evictions_heavy: u64,
    pub ip_evictions_rising: u64,
    pub ip_evictions_observation: u64,
}

/// Per-domain bidirectional byte counters, following ProcTraffic's
/// recv/sent split.
#[derive(Default, Clone, Copy)]
struct DomainTraffic {
    /// Recv (inbound) bytes — peer replies accumulate here.
    recv: u64,
    /// Sent (outbound) bytes — locally originated packets accumulate here.
    sent: u64,
}

impl Stats {
    pub(crate) fn new_at(created_at: DateTime<Utc>) -> Self {
        Self {
            rank_start_epoch: Some(created_at.timestamp()),
            ..Self::default()
        }
    }
    fn rank_epoch(&mut self, observed_at: DateTime<Utc>) -> i64 {
        let observed_epoch = observed_at.timestamp();
        let epoch = self
            .rank_epoch
            .map_or(observed_epoch, |old| old.max(observed_epoch));
        self.rank_epoch = Some(epoch);
        if self.rank_start_epoch.is_none() {
            self.rank_start_epoch = Some(epoch);
        }
        epoch
    }
    fn record_rank_proc(
        &mut self,
        key: ProcessKey,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let epoch = self.rank_epoch(observed_at);
        let is_new = !self.rank_proc.contains_key(&key);
        if is_new
            && self.rank_proc.len() >= MAX_RANKING_PROCESS_ENTRIES
            && evict_oldest_ranking_entity(&mut self.rank_proc)
        {
            self.rank_window_evictions = self.rank_window_evictions.saturating_add(1);
        }
        let window = self.rank_proc.entry(key).or_default();
        window.record(direction, epoch, bytes);
        window.prune(epoch);
    }
    fn record_rank_ip(
        &mut self,
        inbound: bool,
        ip: IpAddr,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let epoch = self.rank_epoch(observed_at);
        let store = if inbound {
            &mut self.rank_in_ip
        } else {
            &mut self.rank_out_ip
        };
        let is_new = !store.contains_key(&ip);
        if is_new && store.len() >= MAX_RANKING_IP_ENTRIES && evict_oldest_ranking_entity(store) {
            self.rank_window_evictions = self.rank_window_evictions.saturating_add(1);
        }
        let window = store.entry(ip).or_default();
        window.record(Direction::Outbound, epoch, bytes);
        window.prune(epoch);
    }
    fn record_rank_domain(
        &mut self,
        host: Arc<str>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let epoch = self.rank_epoch(observed_at);
        let is_new = !self.rank_domain.contains_key(&host);
        if is_new
            && self.rank_domain.len() >= MAX_RANKING_DOMAIN_ENTRIES
            && evict_oldest_ranking_entity(&mut self.rank_domain)
        {
            self.rank_window_evictions = self.rank_window_evictions.saturating_add(1);
        }
        let window = self.rank_domain.entry(host).or_default();
        window.record(direction, epoch, bytes);
        window.prune(epoch);
    }
    pub(crate) fn diagnostics_snapshot(&self) -> StatsDiagnostics {
        let inbound_tiers = ip_tier_counts(&self.in_ip_windows);
        let outbound_tiers = ip_tier_counts(&self.out_ip_windows);
        StatsDiagnostics {
            inbound_ip_entries: self.in_by_ip.len(),
            outbound_ip_entries: self.out_by_ip.len(),
            process_entries: self.by_proc.len(),
            domain_entries: self.by_domain.len(),
            inbound_heavy_ip_entries: inbound_tiers.0,
            inbound_rising_ip_entries: inbound_tiers.1,
            inbound_observation_ip_entries: inbound_tiers.2,
            outbound_heavy_ip_entries: outbound_tiers.0,
            outbound_rising_ip_entries: outbound_tiers.1,
            outbound_observation_ip_entries: outbound_tiers.2,
            ip_promotions: self.ip_diagnostics.promotions,
            ip_demotions: self.ip_diagnostics.demotions,
            ip_evictions_heavy: self.ip_diagnostics.evictions_heavy,
            ip_evictions_rising: self.ip_diagnostics.evictions_rising,
            ip_evictions_observation: self.ip_diagnostics.evictions_observation,
        }
    }
    fn advance_ip_window(&mut self, epoch: i64) {
        if self.ip_window_epoch == Some(epoch) {
            return;
        }
        self.ip_window_epoch = Some(epoch);
        rebalance_ip_dimension(
            &mut self.in_by_ip,
            &mut self.in_ip_last_seen,
            &mut self.in_ip_windows,
            epoch,
            &mut self.ip_diagnostics,
            true,
        );
        rebalance_ip_dimension(
            &mut self.out_by_ip,
            &mut self.out_ip_last_seen,
            &mut self.out_ip_windows,
            epoch,
            &mut self.ip_diagnostics,
            true,
        );
    }
    fn add_in(&mut self, source: IpAddr, bytes: u64, observed_at: DateTime<Utc>) {
        self.in_bytes += bytes;
        self.record_rank_ip(true, source, bytes, observed_at);
        let epoch = bucket_epoch(observed_at);
        self.advance_ip_window(epoch);
        *self.in_by_ip.entry(source).or_default() += bytes;
        self.in_ip_last_seen.insert(source, observed_at);
        self.in_ip_windows
            .entry(source)
            .and_modify(|state| state.record(epoch, bytes))
            .or_insert_with(|| IpWindowState::new(epoch, bytes));
        if self.in_by_ip.len() > MAX_IP_DIMENSION_ENTRIES {
            rebalance_ip_dimension(
                &mut self.in_by_ip,
                &mut self.in_ip_last_seen,
                &mut self.in_ip_windows,
                epoch,
                &mut self.ip_diagnostics,
                false,
            );
        }
    }
    fn add_out(&mut self, destination: IpAddr, bytes: u64, observed_at: DateTime<Utc>) {
        self.out_bytes += bytes;
        self.record_rank_ip(false, destination, bytes, observed_at);
        let epoch = bucket_epoch(observed_at);
        self.advance_ip_window(epoch);
        *self.out_by_ip.entry(destination).or_default() += bytes;
        self.out_ip_last_seen.insert(destination, observed_at);
        self.out_ip_windows
            .entry(destination)
            .and_modify(|state| state.record(epoch, bytes))
            .or_insert_with(|| IpWindowState::new(epoch, bytes));
        if self.out_by_ip.len() > MAX_IP_DIMENSION_ENTRIES {
            rebalance_ip_dimension(
                &mut self.out_by_ip,
                &mut self.out_ip_last_seen,
                &mut self.out_ip_windows,
                epoch,
                &mut self.ip_diagnostics,
                false,
            );
        }
    }
    fn add_proc(
        &mut self,
        process: ObservedProcess,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let key = ProcessKey {
            pid: process.pid,
            path: process.path,
        };
        self.record_rank_proc(key.clone(), direction, bytes, observed_at);
        let epoch = self.advance_proc_window_epoch(observed_at);
        self.proc_windows
            .entry(key.clone())
            .or_default()
            .record(direction, epoch, bytes);
        self.exclusive_window.record(direction, epoch, bytes);
        let entry = self.by_proc.entry(key.clone()).or_default();
        match direction {
            Direction::Inbound => entry.recv += bytes,
            Direction::Outbound => entry.sent += bytes,
        }
        if let Some(name) = process.name {
            self.proc_names.entry(key.clone()).or_insert(name);
        }
        self.proc_last_seen.insert(key, observed_at);
    }
    #[cfg(test)]
    pub fn record_flow(&mut self, flow: Flow, process: Option<ObservedProcess>) {
        self.record_flow_at(flow, process, Utc::now());
    }
    #[cfg(test)]
    pub(crate) fn record_flow_at(
        &mut self,
        flow: Flow,
        process: Option<ObservedProcess>,
        observed_at: DateTime<Utc>,
    ) {
        self.record_flow_processes_at(flow, process, None, observed_at);
    }
    #[cfg(test)]
    pub(crate) fn record_flow_processes_at(
        &mut self,
        flow: Flow,
        process: Option<ObservedProcess>,
        peer_process: Option<ObservedProcess>,
        observed_at: DateTime<Utc>,
    ) {
        self.record_interface_flow(&flow, observed_at);
        self.record_outbound_domain(
            flow.domain.as_ref(),
            flow.direction,
            flow.bytes,
            observed_at,
        );
        if let Some(peer_local) = flow.peer_local_socket {
            self.record_process(
                process.clone(),
                Direction::Outbound,
                flow.bytes,
                observed_at,
            );
            if let (Some(process), Some(local), Some(peer_port)) =
                (process, flow.local_socket, flow.peer_port)
            {
                self.record_proc_flow(
                    ProcessKey {
                        pid: process.pid,
                        path: process.path.clone(),
                    },
                    ProcFlowKey::from_endpoint(local, flow.peer, peer_port),
                    Direction::Outbound,
                    flow.bytes,
                    observed_at,
                );
            }
            self.record_process(
                peer_process.clone(),
                Direction::Inbound,
                flow.bytes,
                observed_at,
            );
            if let Some(peer_process) = peer_process
                && let Some(local) = flow.local_socket
            {
                self.record_proc_flow(
                    ProcessKey {
                        pid: peer_process.pid,
                        path: peer_process.path.clone(),
                    },
                    ProcFlowKey::from_endpoint(peer_local, local.ip, local.port),
                    Direction::Inbound,
                    flow.bytes,
                    observed_at,
                );
            }
            return;
        }
        self.record_process(process.clone(), flow.direction, flow.bytes, observed_at);
        if let (Some(process), Some(local), Some(peer_port)) =
            (process, flow.local_socket, flow.peer_port)
        {
            self.record_proc_flow(
                ProcessKey {
                    pid: process.pid,
                    path: process.path.clone(),
                },
                ProcFlowKey::from_endpoint(local, flow.peer, peer_port),
                flow.direction,
                flow.bytes,
                observed_at,
            );
        }
    }
    pub(crate) fn record_interface_flow(&mut self, flow: &Flow, observed_at: DateTime<Utc>) {
        if flow.peer_local_socket.is_some() {
            self.add_out(flow.peer, flow.bytes, observed_at);
            self.add_in(
                flow.local_socket
                    .map(|socket| socket.ip)
                    .unwrap_or(flow.peer),
                flow.bytes,
                observed_at,
            );
            return;
        }
        match flow.direction {
            Direction::Inbound => self.add_in(flow.peer, flow.bytes, observed_at),
            Direction::Outbound => self.add_out(flow.peer, flow.bytes, observed_at),
        }
    }
    fn record_proc_flow(
        &mut self,
        process: ProcessKey,
        conn: ProcFlowKey,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let traffic = self
            .proc_flows
            .entry(process)
            .or_default()
            .entry(conn)
            .or_default();
        match direction {
            Direction::Inbound => traffic.recv = traffic.recv.saturating_add(bytes),
            Direction::Outbound => traffic.sent = traffic.sent.saturating_add(bytes),
        }
        traffic.last_seen_epoch = observed_at.timestamp();
    }

    pub(crate) fn record_process(
        &mut self,
        process: Option<ObservedProcess>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        self.add_process_or_unattributed(process, direction, bytes, observed_at);
    }
    /// Attribution record carrying evidence sources (snapshot / probe /
    /// history; ADR 0013 history engine).
    pub(crate) fn record_process_evidence(
        &mut self,
        process: ObservedProcess,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
        evidence: Evidence,
        conn: Option<ProcFlowKey>,
    ) {
        let key = ProcessKey {
            pid: process.pid,
            path: process.path.clone(),
        };
        let merged = self
            .evidence_by_proc
            .get(&key)
            .copied()
            .unwrap_or_default()
            .merge(evidence);
        self.evidence_by_proc.insert(key.clone(), merged);
        if let Some(conn) = conn {
            self.record_proc_flow(key, conn, direction, bytes, observed_at);
        }
        self.record_process(Some(process), direction, bytes, observed_at);
    }
    /// Flows of identified connections (domain=Some) accumulate into that
    /// domain per direction and update the domain's last_seen; unidentified
    /// flows (domain=None) do not enter this dimension.
    ///
    /// Last-seen rule matches the process dimension: updated only when
    /// record_*_domain actually runs; snapshot() reads but never updates.
    pub(crate) fn record_outbound_domain(
        &mut self,
        domain: Option<&Arc<str>>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let Some(host) = domain else {
            return;
        };
        let entry = self.by_domain.entry(host.clone()).or_default();
        match direction {
            Direction::Inbound => entry.recv += bytes,
            Direction::Outbound => entry.sent += bytes,
        }
        self.record_rank_domain(host.clone(), direction, bytes, observed_at);
        self.domain_last_seen.insert(host.clone(), observed_at);
    }
    fn add_process_or_unattributed(
        &mut self,
        process: Option<ObservedProcess>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        match process {
            Some(process) => {
                self.add_proc(process, direction, bytes, observed_at);
            }
            None => {
                let epoch = self.advance_proc_window_epoch(observed_at);
                self.unattributed_window.record(direction, epoch, bytes);
                match direction {
                    Direction::Inbound => self.unattributed.recv += bytes,
                    Direction::Outbound => self.unattributed.sent += bytes,
                }
                self.unattributed_last_seen = Some(observed_at);
            }
        }
    }
    /// ADR 0013 shared attribution: the same bytes count in full for every
    /// candidate process (inclusive projection); the record layer counts
    /// them once in shared_total. Fewer than 2 candidates is not shared —
    /// fall back to unattributed.
    pub(crate) fn record_shared(
        &mut self,
        candidates: &[ObservedProcess],
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
        conn: Option<ProcFlowKey>,
    ) {
        if candidates.len() < 2 {
            self.record_process(None, direction, bytes, observed_at);
            return;
        }
        let epoch = self.advance_proc_window_epoch(observed_at);
        self.shared_window.record(direction, epoch, bytes);
        match direction {
            Direction::Inbound => self.shared_total.recv += bytes,
            Direction::Outbound => self.shared_total.sent += bytes,
        }
        let keys: Vec<ProcessKey> = candidates
            .iter()
            .map(|candidate| ProcessKey {
                pid: candidate.pid,
                path: candidate.path.clone(),
            })
            .collect();
        for (candidate, key) in candidates.iter().zip(keys.iter()) {
            if let Some(conn) = conn {
                self.record_proc_flow(key.clone(), conn, direction, bytes, observed_at);
            }
            self.record_rank_proc(key.clone(), direction, bytes, observed_at);
            self.proc_windows
                .entry(key.clone())
                .or_default()
                .record(direction, epoch, bytes);
            let entry = self.shared_by_proc.entry(key.clone()).or_default();
            match direction {
                Direction::Inbound => entry.recv += bytes,
                Direction::Outbound => entry.sent += bytes,
            }
            if let Some(name) = candidate.name.clone() {
                self.proc_names.entry(key.clone()).or_insert(name);
            }
            let last_seen = self
                .proc_last_seen
                .entry(key.clone())
                .or_insert(observed_at);
            if *last_seen < observed_at {
                *last_seen = observed_at;
            }
            let partners = self.shared_partners.entry(key.clone()).or_default();
            for other in &keys {
                if other != key && !partners.contains(other) {
                    partners.push(other.clone());
                }
            }
        }
    }
    /// ADR 0013 system traffic: protocol traffic with no local socket (ICMP
    /// etc.), not part of process attribution.
    pub(crate) fn record_system(
        &mut self,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        let epoch = self.advance_proc_window_epoch(observed_at);
        self.system_window.record(direction, epoch, bytes);
        match direction {
            Direction::Inbound => self.system.recv += bytes,
            Direction::Outbound => self.system.sent += bytes,
        }
    }
    /// Advance the process-window reference epoch (monotonically the
    /// latest); returns the epoch for window accounting.
    fn advance_proc_window_epoch(&mut self, observed_at: DateTime<Utc>) -> i64 {
        let epoch = bucket_epoch(observed_at);
        self.proc_window_epoch = Some(self.proc_window_epoch.map_or(epoch, |prev| prev.max(epoch)));
        epoch
    }
    #[cfg(test)]
    fn attribution_window_summary(&self) -> AttributionSummary {
        let epoch = self.proc_window_epoch.unwrap_or(0);
        AttributionSummary {
            exclusive: self.exclusive_window.window(epoch),
            shared: self.shared_window.window(epoch),
            system: self.system_window.window(epoch),
            unattributed: self.unattributed_window.window(epoch),
        }
    }
    /// Record-layer conservation summary: total = exclusive + shared +
    /// system + unattributed (ADR 0013).
    pub(crate) fn attribution_summary(&self) -> AttributionSummary {
        let mut exclusive = ProcTraffic::default();
        for traffic in self.by_proc.values() {
            exclusive.recv += traffic.recv;
            exclusive.sent += traffic.sent;
        }
        AttributionSummary {
            exclusive,
            shared: self.shared_total,
            system: self.system,
            unattributed: self.unattributed,
        }
    }
    #[cfg(test)]
    pub fn snapshot(&self, top_n: usize) -> TrafficSnapshot {
        self.snapshot_at(top_n, Utc::now(), RankWindow::Cumulative)
    }
    pub fn snapshot_at(
        &self,
        top_n: usize,
        now: DateTime<Utc>,
        rank_window: RankWindow,
    ) -> TrafficSnapshot {
        let proc_epoch = self.proc_window_epoch.unwrap_or(0);
        let rank_epoch = self
            .rank_epoch
            .map_or(now.timestamp(), |epoch| epoch.max(now.timestamp()));
        let coverage_secs = rank_window.seconds().map_or(0, |seconds| {
            if self.rank_epoch.is_none() {
                0
            } else {
                self.rank_start_epoch.map_or(0, |start| {
                    rank_epoch.saturating_sub(start).min(i64::from(seconds)) as u64
                })
            }
        });
        let processes = self
            .ranked_processes(top_n, rank_epoch, rank_window)
            .into_iter()
            .map(|(key, rank)| {
                let last_seen = self.proc_last_seen[&key];
                let exclusive = self.by_proc.get(&key).copied().unwrap_or_default();
                let shared = self.shared_by_proc.get(&key).copied().unwrap_or_default();
                let lifetime = ProcTraffic {
                    recv: exclusive.recv.saturating_add(shared.recv),
                    sent: exclusive.sent.saturating_add(shared.sent),
                };
                let shared_with = self
                    .shared_partners
                    .get(&key)
                    .map(|partners| {
                        partners
                            .iter()
                            .map(|partner| {
                                self.proc_names
                                    .get(partner)
                                    .cloned()
                                    .unwrap_or_else(|| Arc::from("?"))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let evidence = self.evidence_by_proc.get(&key).copied();
                let window = self
                    .proc_windows
                    .get(&key)
                    .map_or_else(ProcTraffic::default, |windows| windows.window(proc_epoch));
                let mut process = ProcessSnapshot::attributed_with_shared(
                    key.pid,
                    self.proc_names.get(&key).cloned(),
                    key.path.clone(),
                    last_seen,
                    exclusive,
                    shared,
                    shared_with,
                );
                if let Some(evidence) = evidence {
                    process.attribution.evidence = evidence;
                }
                debug_assert_eq!(process.recv, lifetime.recv);
                debug_assert_eq!(process.sent, lifetime.sent);
                let mut flows = self
                    .proc_flows
                    .get(&key)
                    .map(|table| {
                        table
                            .iter()
                            .map(|(flow_key, traffic)| ProcFlowSnapshot {
                                local_ip: flow_key.local_ip,
                                local_port: flow_key.local_port,
                                remote_ip: flow_key.remote_ip,
                                remote_port: flow_key.remote_port,
                                protocol: flow_key.protocol,
                                recv: traffic.recv,
                                sent: traffic.sent,
                                last_seen: DateTime::from_timestamp(traffic.last_seen_epoch, 0)
                                    .unwrap_or(last_seen),
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                flows.sort_by_key(|flow| std::cmp::Reverse(flow.total()));
                let limit = self.proc_flow_limit.0;
                if flows.len() > limit {
                    flows.truncate(limit);
                }
                process.flows = flows.into();
                process.window = window;
                process.selected = rank;
                process.rank = average_rank_traffic(rank, rank_window, coverage_secs);
                process
            })
            .collect::<Vec<_>>();
        let inbound_ips = self
            .ranked_ips(top_n, true, rank_epoch, rank_window)
            .into_iter()
            .map(|(ip, rank_bytes)| {
                IpSnapshot::with_rank_and_selected(
                    ip,
                    self.in_by_ip[&ip],
                    rank_bytes,
                    average_rank_bytes(rank_bytes, rank_window, coverage_secs),
                    self.in_ip_last_seen[&ip],
                )
            })
            .collect::<Vec<_>>()
            .into();
        let outbound_ips = self
            .ranked_ips(top_n, false, rank_epoch, rank_window)
            .into_iter()
            .map(|(ip, rank_bytes)| {
                IpSnapshot::with_rank_and_selected(
                    ip,
                    self.out_by_ip[&ip],
                    rank_bytes,
                    average_rank_bytes(rank_bytes, rank_window, coverage_secs),
                    self.out_ip_last_seen[&ip],
                )
            })
            .collect::<Vec<_>>()
            .into();
        let outbound_domains = self
            .ranked_domains(top_n, rank_epoch, rank_window)
            .into_iter()
            .map(|(host, rank)| {
                let lifetime = self.by_domain[&host];
                let last_seen = self.domain_last_seen[&host];
                let selected = rank;
                let average = average_rank_traffic(selected, rank_window, coverage_secs);
                OutboundDomainSnapshot::with_rank_and_selected(
                    host,
                    lifetime.recv,
                    lifetime.sent,
                    selected.recv,
                    selected.sent,
                    average.recv,
                    average.sent,
                    last_seen,
                )
            })
            .collect::<Vec<_>>()
            .into();
        TrafficSnapshot {
            attribution: self.attribution_summary(),
            ranking: RankingSnapshot {
                window: rank_window,
                metric: if rank_window == RankWindow::Cumulative {
                    RankingMetric::TotalBytes
                } else {
                    RankingMetric::AverageThroughput
                },
                coverage_seconds: rank_window.seconds().map(|_| coverage_secs as u32),
            },
            in_bytes: self.in_bytes,
            out_bytes: self.out_bytes,
            process_data_fresh: false,
            pending_attribution_bytes: 0,
            processes: processes.into(),
            inbound_ips,
            outbound_ips,
            outbound_domains,
            diagnostics: None,
        }
    }
    fn ranked_processes(
        &self,
        n: usize,
        epoch: i64,
        window: RankWindow,
    ) -> Vec<(ProcessKey, ProcTraffic)> {
        let mut keys: HashSet<ProcessKey> = self.by_proc.keys().cloned().collect();
        keys.extend(self.shared_by_proc.keys().cloned());
        let mut entries = keys
            .into_iter()
            .filter_map(|key| {
                let traffic = if window == RankWindow::Cumulative {
                    let exclusive = self.by_proc.get(&key).copied().unwrap_or_default();
                    let shared = self.shared_by_proc.get(&key).copied().unwrap_or_default();
                    ProcTraffic {
                        recv: exclusive.recv.saturating_add(shared.recv),
                        sent: exclusive.sent.saturating_add(shared.sent),
                    }
                } else {
                    self.rank_proc.get(&key)?.traffic(epoch, window.seconds()?)
                };
                (traffic.total() > 0).then_some((key, traffic))
            })
            .collect::<Vec<_>>();
        entries.sort_by(|(left_key, left), (right_key, right)| {
            right
                .total()
                .cmp(&left.total())
                .then_with(|| left_key.pid.cmp(&right_key.pid))
                .then_with(|| left_key.path.as_deref().cmp(&right_key.path.as_deref()))
        });
        entries.truncate(n);
        entries
    }
    fn ranked_ips(
        &self,
        n: usize,
        inbound: bool,
        epoch: i64,
        window: RankWindow,
    ) -> Vec<(IpAddr, u64)> {
        let lifetime = if inbound {
            &self.in_by_ip
        } else {
            &self.out_by_ip
        };
        let recent = if inbound {
            &self.rank_in_ip
        } else {
            &self.rank_out_ip
        };
        let mut entries = lifetime
            .keys()
            .filter_map(|ip| {
                let bytes = if window == RankWindow::Cumulative {
                    lifetime[ip]
                } else {
                    recent.get(ip)?.traffic(epoch, window.seconds()?).total()
                };
                (bytes > 0).then_some((*ip, bytes))
            })
            .collect::<Vec<_>>();
        entries.sort_by(|(left_ip, left), (right_ip, right)| {
            right
                .cmp(left)
                .then_with(|| ip_sort_key(*left_ip).cmp(&ip_sort_key(*right_ip)))
        });
        entries.truncate(n);
        entries
    }
    fn ranked_domains(
        &self,
        n: usize,
        epoch: i64,
        window: RankWindow,
    ) -> Vec<(Arc<str>, ProcTraffic)> {
        let mut entries = self
            .by_domain
            .keys()
            .filter_map(|host| {
                let traffic = if window == RankWindow::Cumulative {
                    let lifetime = self.by_domain[host];
                    ProcTraffic {
                        recv: lifetime.recv,
                        sent: lifetime.sent,
                    }
                } else {
                    self.rank_domain
                        .get(host)?
                        .traffic(epoch, window.seconds()?)
                };
                (traffic.total() > 0).then_some((host.clone(), traffic))
            })
            .collect::<Vec<_>>();
        entries.sort_by(|(left_host, left), (right_host, right)| {
            right
                .total()
                .cmp(&left.total())
                .then_with(|| left_host.cmp(right_host))
        });
        entries.truncate(n);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::capture::{Flow, LocalSocket, TransportProtocol};

    use chrono::Duration;

    use std::net::{IpAddr, Ipv4Addr};

    use std::sync::Arc;

    // ── outbound-domain dimension ────────────────────────────────────

    fn flow(direction: Direction, peer: [u8; 4], bytes: u64) -> Flow {
        flow_ip(direction, ip(peer), bytes)
    }

    fn flow_ip(direction: Direction, peer: IpAddr, bytes: u64) -> Flow {
        Flow {
            direction,
            peer,
            peer_port: None,
            bytes,
            local_socket: None,
            peer_local_socket: None,
            domain: None,
        }
    }

    fn flow_with_domain(
        direction: Direction,
        peer: [u8; 4],
        bytes: u64,
        domain: Option<Arc<str>>,
    ) -> Flow {
        Flow {
            direction,
            peer: ip(peer),
            peer_port: None,
            bytes,
            local_socket: None,
            peer_local_socket: None,
            domain,
        }
    }

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    #[test]
    fn record_flow_processes_at_records_swapped_both_local_rows() {
        let left_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let right_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let mut stats = Stats::default();
        stats.record_flow_processes_at(
            Flow {
                direction: Direction::Outbound,
                peer: right_ip,
                peer_port: Some(80),
                bytes: 40,
                local_socket: Some(LocalSocket {
                    ip: left_ip,
                    port: 49_152,
                    protocol: TransportProtocol::Tcp,
                }),
                peer_local_socket: Some(LocalSocket {
                    ip: right_ip,
                    port: 80,
                    protocol: TransportProtocol::Tcp,
                }),
                domain: None,
            },
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("left")),
                path: None,
            }),
            Some(ObservedProcess {
                pid: 8,
                name: Some(Arc::from("right")),
                path: None,
            }),
            "2026-07-15T08:00:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(10);
        let left = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(7))
            .unwrap();
        let right = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(8))
            .unwrap();
        assert_eq!(left.flows[0].local_ip, left_ip);
        assert_eq!(left.flows[0].remote_ip, right_ip);
        assert_eq!((left.flows[0].recv, left.flows[0].sent), (0, 40));
        assert_eq!(right.flows[0].local_ip, right_ip);
        assert_eq!(right.flows[0].remote_ip, left_ip);
        assert_eq!((right.flows[0].recv, right.flows[0].sent), (40, 0));
    }

    fn unique_ip(index: usize) -> IpAddr {
        let index = index as u32;
        IpAddr::V4(Ipv4Addr::new(
            10,
            ((index >> 16) & 0xff) as u8,
            ((index >> 8) & 0xff) as u8,
            (index & 0xff) as u8,
        ))
    }

    #[test]
    fn unattributed_flow_appears_in_attribution_summary() {
        let mut stats = Stats::default();
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            None,
            "2026-07-15T07:59:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(10);
        // ADR 0013: unattributed is not a process row; it only enters the
        // conservation summary.

        assert!(snapshot.processes.is_empty());
        assert_eq!(snapshot.attribution.unattributed.recv, 40);
        assert_eq!(snapshot.attribution.unattributed.sent, 0);
    }

    #[test]
    fn unattributed_flow_does_not_compete_for_top_n() {
        let mut stats = Stats::default();
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 10),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(flow(Direction::Inbound, [10, 0, 0, 2], 100), None);
        let snapshot = stats.snapshot(1);
        // ADR 0013: unattributed is out of the ranking; topN holds only
        // attributed processes.

        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].recv, 10);
        assert_eq!(snapshot.attribution.unattributed.recv, 100);
    }

    #[test]
    fn empty_snapshot_has_no_unattributed_process() {
        let snapshot = Stats::default().snapshot(10);
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn diagnostics_snapshot_reports_current_dimension_cardinality() {
        let mut stats = Stats::default();
        let process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("curl")),
            path: Some(Arc::from("/usr/bin/curl")),
        };
        let domain: Arc<str> = Arc::from("example.com");
        stats.record_flow(
            flow_with_domain(
                Direction::Outbound,
                [203, 0, 113, 1],
                40,
                Some(domain.clone()),
            ),
            Some(process.clone()),
        );
        stats.record_flow(
            flow_with_domain(Direction::Inbound, [203, 0, 113, 2], 20, Some(domain)),
            Some(process),
        );
        let diagnostics = stats.diagnostics_snapshot();
        assert_eq!(diagnostics.inbound_ip_entries, 1);
        assert_eq!(diagnostics.outbound_ip_entries, 1);
        assert_eq!(diagnostics.process_entries, 1);
        assert_eq!(diagnostics.domain_entries, 1);
        assert_eq!(diagnostics.inbound_observation_ip_entries, 1);
        assert_eq!(diagnostics.outbound_observation_ip_entries, 1);
        assert_eq!(diagnostics.ip_promotions, 0);
    }

    #[test]
    fn ip_dimensions_are_bounded_per_direction() {
        let mut stats = Stats::default();
        let observed_at: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        for index in 0..(MAX_IP_DIMENSION_ENTRIES + IP_DIMENSION_PRUNE_BATCH * 2) {
            stats.record_flow_at(
                flow_ip(Direction::Inbound, unique_ip(index), 1),
                None,
                observed_at,
            );
            stats.record_flow_at(
                flow_ip(Direction::Outbound, unique_ip(index + 1_000_000), 1),
                None,
                observed_at,
            );
        }
        let diagnostics = stats.diagnostics_snapshot();
        assert!(diagnostics.inbound_ip_entries <= MAX_IP_DIMENSION_ENTRIES);
        assert!(diagnostics.outbound_ip_entries <= MAX_IP_DIMENSION_ENTRIES);
    }

    #[test]
    fn ip_dimension_prunes_lowest_traffic_without_changing_totals() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        for index in 0..MAX_IP_DIMENSION_ENTRIES {
            stats.record_flow_at(
                flow_ip(Direction::Inbound, unique_ip(index), (index + 1) as u64),
                None,
                first,
            );
        }
        let second = first + Duration::minutes(1);
        for offset in 0..IP_DIMENSION_PRUNE_BATCH {
            stats.record_flow_at(
                flow_ip(
                    Direction::Inbound,
                    unique_ip(MAX_IP_DIMENSION_ENTRIES + offset),
                    1_000_000,
                ),
                None,
                second,
            );
        }
        let snapshot = stats.snapshot(MAX_IP_DIMENSION_ENTRIES);
        assert_eq!(
            snapshot.in_bytes,
            (MAX_IP_DIMENSION_ENTRIES * (MAX_IP_DIMENSION_ENTRIES + 1) / 2) as u64
                + (IP_DIMENSION_PRUNE_BATCH * 1_000_000) as u64
        );
        assert_eq!(snapshot.out_bytes, 0);
        assert!(snapshot.inbound_ips.len() <= MAX_IP_DIMENSION_ENTRIES);
        assert!(
            !snapshot
                .inbound_ips
                .iter()
                .any(|entry| entry.ip == unique_ip(0))
        );
        assert!(
            snapshot
                .inbound_ips
                .iter()
                .any(|entry| entry.ip == unique_ip(IP_DIMENSION_PRUNE_BATCH + 1))
        );
        assert!(snapshot.inbound_ips.iter().any(|entry| {
            entry.ip == unique_ip(MAX_IP_DIMENSION_ENTRIES + IP_DIMENSION_PRUNE_BATCH - 1)
        }));
    }

    #[test]
    fn ip_tier_promotion_waits_for_two_buckets() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = first + Duration::minutes(1);
        let third = first + Duration::minutes(2);
        let peer = unique_ip(8);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 100), None, first);
        assert_eq!(
            stats.diagnostics_snapshot().inbound_observation_ip_entries,
            1
        );
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 200), None, second);
        assert_eq!(stats.diagnostics_snapshot().ip_promotions, 0);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 10), None, third);
        let diagnostics = stats.diagnostics_snapshot();
        assert_eq!(diagnostics.inbound_heavy_ip_entries, 1);
        assert_eq!(diagnostics.inbound_observation_ip_entries, 0);
        assert_eq!(diagnostics.ip_promotions, 1);
    }

    #[test]
    fn idle_heavy_ip_is_demoted_after_three_windows() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = first + Duration::minutes(1);
        let third = first + Duration::minutes(2);
        let after_idle = first + Duration::minutes(17);
        let peer = unique_ip(9);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 100), None, first);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 200), None, second);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 10), None, third);
        assert_eq!(stats.diagnostics_snapshot().inbound_heavy_ip_entries, 1);
        stats.record_flow_at(
            flow_ip(Direction::Inbound, unique_ip(10), 1),
            None,
            after_idle,
        );
        let diagnostics = stats.diagnostics_snapshot();
        assert_eq!(diagnostics.inbound_heavy_ip_entries, 0);
        assert!(diagnostics.ip_demotions >= 1);
    }

    #[test]
    fn snapshot_defaults_to_no_pending_attribution() {
        let snapshot = Stats::default().snapshot(10);
        assert_eq!(snapshot.pending_attribution_bytes, 0);
    }

    #[test]
    fn same_pid_with_different_paths_has_distinct_traffic_history() {
        let mut stats = Stats::default();
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("old-curl")),
                path: Some(Arc::from("/opt/old/curl")),
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("new-curl")),
                path: Some(Arc::from("/opt/new/curl")),
            }),
        );
        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.processes.len(), 2);
        let old = snapshot
            .processes
            .iter()
            .find(|process| process.path() == Some("/opt/old/curl"))
            .unwrap();
        let new = snapshot
            .processes
            .iter()
            .find(|process| process.path() == Some("/opt/new/curl"))
            .unwrap();
        assert_eq!((old.recv, old.sent), (40, 0));
        assert_eq!((new.recv, new.sent), (0, 60));
    }

    #[test]
    fn last_seen_advances_only_when_flow_is_recorded() {
        let mut stats = Stats::default();
        let first = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = "2026-07-15T08:01:30Z".parse().unwrap();
        let process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("curl")),
            path: Some(Arc::from("/usr/bin/curl")),
        };
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(process.clone()),
            first,
        );
        assert_eq!(stats.snapshot(10).processes[0].last_seen(), first);
        let unchanged = stats.snapshot(10);
        assert_eq!(unchanged.processes[0].last_seen(), first);
        stats.record_flow_at(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(process),
            second,
        );
        let updated = stats.snapshot(10);
        assert_eq!(
            (updated.processes[0].recv, updated.processes[0].sent),
            (40, 60)
        );
        assert_eq!(updated.processes[0].last_seen(), second);
    }

    #[test]
    fn process_buckets_partition_captured_traffic() {
        let mut stats = Stats::default();
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 10),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(flow(Direction::Inbound, [10, 0, 0, 3], 30), None);
        stats.record_flow(flow(Direction::Outbound, [10, 0, 0, 4], 20), None);
        let snapshot = stats.snapshot(10);
        let summary = snapshot.attribution;
        // ADR 0013: interface bytes conserve across the four channels;
        // process-row sums no longer equal interface bytes.

        assert_eq!(snapshot.in_bytes, 70);
        assert_eq!(snapshot.out_bytes, 30);
        assert_eq!(summary.exclusive.recv, 40);
        assert_eq!(summary.exclusive.sent, 10);
        assert_eq!(summary.unattributed.recv, 30);
        assert_eq!(summary.unattributed.sent, 20);
        assert_eq!(summary.total(), snapshot.in_bytes + snapshot.out_bytes);
    }

    /// Lists and top-N use lifetime totals: historical heavyweights outside
    /// the window keep their rank.
    #[test]
    fn top_n_ranks_by_lifetime_including_idle_heavyweights() {
        let mut stats = Stats::default();
        // Old heavyweight 1000 B (outside the window), new process 10 B (inside).

        stats.record_flow_at(
            flow(Direction::Outbound, [10, 0, 0, 1], 1000),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
            "2026-07-15T08:00:00Z".parse().unwrap(),
        );
        stats.record_flow_at(
            flow(Direction::Outbound, [10, 0, 0, 2], 10),
            Some(ObservedProcess {
                pid: 8,
                name: None,
                path: None,
            }),
            "2026-07-15T08:09:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].sent, 1000);
        assert_eq!(snapshot.processes[0].window.sent, 0);
        assert_eq!(snapshot.processes[1].pid(), Some(8));
        assert_eq!(snapshot.processes[1].sent, 10);
        assert_eq!(snapshot.processes[1].window.sent, 10);
    }

    #[test]
    fn zero_window_shared_candidates_remain_in_top_processes() {
        let mut stats = Stats::default();
        let old_candidates = vec![
            ObservedProcess {
                pid: 101,
                name: Some(Arc::from("sshd")),
                path: None,
            },
            ObservedProcess {
                pid: 102,
                name: Some(Arc::from("sshd")),
                path: None,
            },
        ];
        stats.record_shared(
            &old_candidates,
            Direction::Inbound,
            1000,
            "2026-07-15T08:00:00Z".parse().unwrap(),
            None,
        );
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 3], 10),
            Some(ObservedProcess {
                pid: 103,
                name: Some(Arc::from("curl")),
                path: None,
            }),
            "2026-07-15T08:09:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(50);
        let pids: Vec<_> = snapshot
            .processes
            .iter()
            .map(|process| process.pid().expect("attributed pid"))
            .collect();
        assert_eq!(pids.len(), 3);
        assert_eq!(pids[2], 103);
        assert!(pids[..2].contains(&101));
        assert!(pids[..2].contains(&102));
        assert_eq!(snapshot.processes[2].recv, 10);
        assert_eq!(snapshot.processes[0].recv, 1000);
        assert_eq!(snapshot.processes[1].recv, 1000);
    }

    /// ADR 0013 process windowing: window-basis conservation — the four
    /// channel sums inside the window equal exactly the bytes recorded in
    /// the window; once entries slide out they decay to 0 and the lifetime
    /// basis is unaffected.
    #[test]
    fn attribution_window_summary_tracks_recent_bytes_only() {
        let mut stats = Stats::default();
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 1], 100),
            None,
            "2026-07-15T08:00:00Z".parse().unwrap(),
        );
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 2], 40),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
            "2026-07-15T08:04:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(10);
        let window = stats.attribution_window_summary();
        assert_eq!(window.unattributed.recv, 100);
        assert_eq!(window.exclusive.recv, 40);
        assert_eq!(window.total(), 140);
        assert_eq!(snapshot.attribution.unattributed.recv, 100);
        assert_eq!(snapshot.attribution.exclusive.recv, 40);
        // Advance to 08:10: both earlier entries have slid out of the window.

        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 3], 1),
            Some(ObservedProcess {
                pid: 9,
                name: None,
                path: None,
            }),
            "2026-07-15T08:10:00Z".parse().unwrap(),
        );
        let window = stats.attribution_window_summary();
        assert_eq!(window.total(), 1);
        assert_eq!(window.unattributed.recv, 0);
        assert_eq!(window.exclusive.recv, 1);
    }

    #[test]
    fn snapshot_returns_ranked_top_n() {
        let mut stats = Stats::default();
        let process_name: Arc<str> = Arc::from("curl --silent");
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            Some(ObservedProcess {
                pid: 7,
                name: Some(process_name.clone()),
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Outbound, [10, 0, 0, 2], 60),
            Some(ObservedProcess {
                pid: 7,
                name: Some(process_name.clone()),
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 3], 30),
            Some(ObservedProcess {
                pid: 8,
                name: None,
                path: None,
            }),
        );
        stats.record_flow(
            flow(Direction::Inbound, [10, 0, 0, 4], 10),
            Some(ObservedProcess {
                pid: 9,
                name: None,
                path: None,
            }),
        );
        let snapshot = stats.snapshot(2);
        assert_eq!(snapshot.in_bytes, 80);
        assert_eq!(snapshot.out_bytes, 60);
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.processes[0].pid(), Some(7));
        assert_eq!(snapshot.processes[0].name(), Some("curl --silent"));
        assert_eq!(snapshot.processes[0].recv, 40);
        assert_eq!(snapshot.processes[0].sent, 60);
        assert_eq!(snapshot.processes[1].pid(), Some(8));
        assert!(snapshot.processes[1].name().is_none());
        assert!(snapshot.processes[1].path().is_none());
        assert!(
            !snapshot
                .processes
                .iter()
                .any(|process| process.pid() == Some(9))
        );
        assert_eq!(snapshot.inbound_ips.len(), 2);
        assert_eq!(snapshot.inbound_ips[0].ip, ip([10, 0, 0, 1]));
        assert_eq!(snapshot.inbound_ips[0].bytes, 40);
        assert!(
            !snapshot
                .inbound_ips
                .iter()
                .any(|entry| entry.ip == ip([10, 0, 0, 4]))
        );
        assert_eq!(snapshot.outbound_ips.len(), 1);
        assert_eq!(snapshot.outbound_ips[0].ip, ip([10, 0, 0, 2]));
        assert!(Arc::ptr_eq(
            match &snapshot.processes[0].identity {
                ProcessIdentity::Attributed {
                    name: Some(snapshot_name),
                    ..
                } => snapshot_name,
                _ => panic!("expected attributed process name"),
            },
            &process_name
        ));
    }

    #[test]
    fn recent_ranking_slides_forward_without_changing_cumulative_totals() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let recent = first + Duration::seconds(10);
        let now = first + Duration::seconds(11);
        let old_process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("old")),
            path: None,
        };
        let recent_process = ObservedProcess {
            pid: 8,
            name: Some(Arc::from("recent")),
            path: None,
        };
        stats.record_flow_at(
            flow_with_domain(
                Direction::Inbound,
                [203, 0, 113, 7],
                10_000,
                Some(Arc::from("old.example")),
            ),
            Some(old_process),
            first,
        );
        stats.record_flow_at(
            flow_with_domain(
                Direction::Inbound,
                [203, 0, 113, 8],
                1_000,
                Some(Arc::from("recent.example")),
            ),
            Some(recent_process),
            recent,
        );
        let cumulative = stats.snapshot_at(10, now, RankWindow::Cumulative);
        assert_eq!(cumulative.ranking.metric, RankingMetric::TotalBytes);
        assert_eq!(cumulative.processes[0].pid(), Some(7));
        assert_eq!(cumulative.processes[0].recv, 10_000);
        let recent = stats.snapshot_at(10, now, RankWindow::TEN_SECONDS);
        assert_eq!(recent.ranking.metric, RankingMetric::AverageThroughput);
        assert_eq!(recent.ranking.coverage_seconds, Some(10));
        assert_eq!(recent.processes.len(), 1);
        assert_eq!(recent.processes[0].pid(), Some(8));
        assert_eq!(recent.processes[0].recv, 1_000);
        assert_eq!(recent.processes[0].rank.recv, 100);
        assert_eq!(recent.inbound_ips.len(), 1);
        assert_eq!(recent.inbound_ips[0].ip, ip([203, 0, 113, 8]));
        assert_eq!(recent.inbound_ips[0].rank_bytes, 100);
        assert_eq!(recent.outbound_domains.len(), 1);
        assert_eq!(recent.outbound_domains[0].host(), "recent.example");
        assert_eq!(recent.outbound_domains[0].rank_in_bytes, 100);
    }

    #[test]
    fn recent_ranking_uses_actual_coverage_during_preheat() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let now = first + Duration::seconds(4);
        let process = ObservedProcess {
            pid: 7,
            name: None,
            path: None,
        };
        stats.record_flow_at(
            flow_with_domain(
                Direction::Outbound,
                [203, 0, 113, 7],
                500,
                Some(Arc::from("example.com")),
            ),
            Some(process),
            first,
        );
        let snapshot = stats.snapshot_at(10, now, RankWindow::TEN_SECONDS);
        assert_eq!(snapshot.ranking.coverage_seconds, Some(4));
        assert_eq!(snapshot.processes[0].rank.sent, 125);
        assert_eq!(snapshot.outbound_ips[0].rank_bytes, 125);
        assert_eq!(snapshot.outbound_domains[0].rank_out_bytes, 125);
    }

    #[test]
    fn recent_ranking_stores_are_bounded() {
        let mut stats = Stats::default();
        let observed_at: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        for index in 0..=MAX_RANKING_PROCESS_ENTRIES {
            stats.record_rank_proc(
                ProcessKey {
                    pid: index as u32,
                    path: None,
                },
                Direction::Inbound,
                1,
                observed_at,
            );
        }
        for index in 0..=MAX_RANKING_IP_ENTRIES {
            stats.record_rank_ip(true, unique_ip(index), 1, observed_at);
        }
        for index in 0..=MAX_RANKING_DOMAIN_ENTRIES {
            stats.record_rank_domain(
                Arc::from(format!("{index}.example")),
                Direction::Inbound,
                1,
                observed_at,
            );
        }
        assert_eq!(stats.rank_proc.len(), MAX_RANKING_PROCESS_ENTRIES);
        assert_eq!(stats.rank_in_ip.len(), MAX_RANKING_IP_ENTRIES);
        assert_eq!(stats.rank_domain.len(), MAX_RANKING_DOMAIN_ENTRIES);
        assert!(stats.rank_window_evictions >= 3);
    }

    #[test]
    fn ip_top_n_keeps_lifetime_byte_ranking() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = first + Duration::minutes(1);
        let historical = unique_ip(20);
        let recent = unique_ip(21);
        stats.record_flow_at(flow_ip(Direction::Inbound, historical, 1_000), None, first);
        stats.record_flow_at(flow_ip(Direction::Inbound, historical, 1), None, second);
        stats.record_flow_at(flow_ip(Direction::Inbound, recent, 500), None, second);
        let snapshot = stats.snapshot(1);
        assert_eq!(snapshot.inbound_ips[0].ip, historical);
        assert_eq!(snapshot.inbound_ips[0].bytes, 1_001);
    }

    #[test]
    fn add_proc_reuses_shared_name() {
        let mut stats = Stats::default();
        let name: Arc<str> = Arc::from("nginx");
        stats.add_proc(
            ObservedProcess {
                pid: 9,
                name: Some(name.clone()),
                path: None,
            },
            Direction::Outbound,
            50,
            Utc::now(),
        );
        let snapshot = stats.snapshot(1);
        assert!(Arc::ptr_eq(
            match &snapshot.processes[0].identity {
                ProcessIdentity::Attributed {
                    name: Some(snapshot_name),
                    ..
                } => snapshot_name,
                _ => panic!("expected attributed process name"),
            },
            &name
        ));
    }

    #[test]
    fn ip_last_seen_is_direction_specific_and_snapshot_does_not_refresh() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second: DateTime<Utc> = "2026-07-15T08:01:00Z".parse().unwrap();
        let third: DateTime<Utc> = "2026-07-15T08:02:00Z".parse().unwrap();
        stats.record_flow_at(flow(Direction::Inbound, [192, 0, 2, 10], 40), None, first);
        stats.record_flow_at(flow(Direction::Outbound, [192, 0, 2, 10], 60), None, second);
        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.inbound_ips[0].bytes, 40);
        assert_eq!(snapshot.inbound_ips[0].last_seen(), first);
        assert_eq!(snapshot.outbound_ips[0].bytes, 60);
        assert_eq!(snapshot.outbound_ips[0].last_seen(), second);
        let unchanged = stats.snapshot(10);
        assert_eq!(unchanged.inbound_ips[0].last_seen(), first);
        assert_eq!(unchanged.outbound_ips[0].last_seen(), second);
        stats.record_flow_at(flow(Direction::Inbound, [192, 0, 2, 10], 20), None, third);
        let updated = stats.snapshot(10);
        assert_eq!(updated.inbound_ips[0].bytes, 60);
        assert_eq!(updated.inbound_ips[0].last_seen(), third);
        assert_eq!(updated.outbound_ips[0].last_seen(), second);
    }

    #[test]
    fn domain_flow_aggregates_bidirectionally() {
        let mut stats = Stats::default();
        let host: Arc<str> = Arc::from("example.com");
        let observed_at: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        stats.record_flow_at(
            flow_with_domain(
                Direction::Outbound,
                [203, 0, 113, 9],
                100,
                Some(host.clone()),
            ),
            None,
            observed_at,
        );
        stats.record_flow_at(
            flow_with_domain(
                Direction::Inbound,
                [203, 0, 113, 9],
                240,
                Some(host.clone()),
            ),
            None,
            observed_at,
        );
        let snapshot = stats.snapshot(10);
        assert_eq!(snapshot.outbound_domains.len(), 1);
        let domain = &snapshot.outbound_domains[0];
        assert_eq!(domain.host(), "example.com");
        assert_eq!(domain.in_bytes, 240);
        assert_eq!(domain.out_bytes, 100);
        assert_eq!(domain.total_bytes(), 340);
    }

    #[test]
    fn outbound_domain_snapshots_are_ranked_by_total_bytes() {
        let mut stats = Stats::default();
        let a: Arc<str> = Arc::from("a.example");
        let b: Arc<str> = Arc::from("b.example");
        let c: Arc<str> = Arc::from("c.example");
        stats.record_flow(
            flow_with_domain(Direction::Outbound, [203, 0, 113, 1], 100, Some(a.clone())),
            None,
        );
        stats.record_flow(
            flow_with_domain(Direction::Inbound, [203, 0, 113, 2], 50, Some(b.clone())),
            None,
        );
        stats.record_flow(
            flow_with_domain(Direction::Outbound, [203, 0, 113, 3], 200, Some(c.clone())),
            None,
        );
        let snapshot = stats.snapshot(2);
        assert_eq!(snapshot.outbound_domains.len(), 2);
        assert_eq!(snapshot.outbound_domains[0].host(), "c.example");
        assert_eq!(snapshot.outbound_domains[0].total_bytes(), 200);
        assert_eq!(snapshot.outbound_domains[1].host(), "a.example");
        assert_eq!(snapshot.outbound_domains[1].total_bytes(), 100);
        assert!(
            !snapshot
                .outbound_domains
                .iter()
                .any(|domain| domain.host() == "b.example")
        );
    }

    #[test]
    fn unidentified_flows_do_not_enter_domain_dimension() {
        let mut stats = Stats::default();
        stats.record_flow(flow(Direction::Outbound, [203, 0, 113, 9], 100), None);
        stats.record_flow(flow(Direction::Inbound, [203, 0, 113, 9], 50), None);
        let snapshot = stats.snapshot(10);
        assert!(snapshot.outbound_domains.is_empty());
        // Unidentified traffic still enters the interface and IP dimensions;
        // the conservation boundary is unchanged.

        assert_eq!(snapshot.in_bytes, 50);
        assert_eq!(snapshot.out_bytes, 100);
    }

    #[test]
    fn domain_last_seen_advances_only_when_flow_is_recorded() {
        let mut stats = Stats::default();
        let host: Arc<str> = Arc::from("example.com");
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second: DateTime<Utc> = "2026-07-15T08:01:30Z".parse().unwrap();
        stats.record_flow_at(
            flow_with_domain(
                Direction::Outbound,
                [203, 0, 113, 9],
                40,
                Some(host.clone()),
            ),
            None,
            first,
        );
        assert_eq!(stats.snapshot(10).outbound_domains[0].last_seen(), first);
        // snapshot() does not update last_seen (same rule as the process dimension).

        let unchanged = stats.snapshot(10);
        assert_eq!(unchanged.outbound_domains[0].last_seen(), first);
        stats.record_flow_at(
            flow_with_domain(Direction::Inbound, [203, 0, 113, 9], 60, Some(host.clone())),
            None,
            second,
        );
        let updated = stats.snapshot(10);
        assert_eq!(updated.outbound_domains[0].last_seen(), second);
        assert_eq!(
            (
                updated.outbound_domains[0].in_bytes,
                updated.outbound_domains[0].out_bytes,
            ),
            (60, 40)
        );
    }

    #[test]
    fn domain_dimension_does_not_conserve_with_interface_totals() {
        let mut stats = Stats::default();
        let host: Arc<str> = Arc::from("example.com");
        // Identified traffic (enters the outbound-domain dimension): 100 + 50 = 150.

        stats.record_flow(
            flow_with_domain(
                Direction::Outbound,
                [203, 0, 113, 9],
                100,
                Some(host.clone()),
            ),
            None,
        );
        stats.record_flow(
            flow_with_domain(Direction::Inbound, [203, 0, 113, 9], 50, Some(host.clone())),
            None,
        );
        // Unidentified traffic (does not enter the domain dimension): 80 + 30 = 110.

        stats.record_flow(flow(Direction::Outbound, [198, 51, 100, 5], 80), None);
        stats.record_flow(flow(Direction::Inbound, [198, 51, 100, 5], 30), None);
        let snapshot = stats.snapshot(10);
        let domain_total: u64 = snapshot
            .outbound_domains
            .iter()
            .map(|domain| domain.total_bytes())
            .sum();
        // Interface total = 100 + 50 + 80 + 30 = 260.

        assert_eq!(snapshot.in_bytes, 80);
        assert_eq!(snapshot.out_bytes, 180);
        assert_eq!(snapshot.in_bytes + snapshot.out_bytes, 260);
        // Domain total = 150, a subset of the interface total (explicitly not conserving with it).

        assert_eq!(domain_total, 150);
        assert!(domain_total < snapshot.in_bytes + snapshot.out_bytes);
    }

    #[test]
    fn ranking_epoch_is_monotonic_when_observation_clock_moves_backwards() {
        let created: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let mut stats = Stats::new_at(created);
        let process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("worker")),
            path: Some(Arc::from("/srv/worker")),
        };
        stats.record_flow_at(
            flow(Direction::Outbound, [203, 0, 113, 7], 100),
            Some(process.clone()),
            created + Duration::seconds(10),
        );
        stats.record_flow_at(
            flow(Direction::Outbound, [203, 0, 113, 7], 200),
            Some(process),
            created - Duration::seconds(5),
        );
        assert_eq!(stats.rank_epoch, Some(created.timestamp() + 10));
        assert_eq!(stats.rank_start_epoch, Some(created.timestamp()));
        let snapshot = stats.snapshot_at(
            10,
            created + Duration::seconds(10),
            RankWindow::THIRTY_SECONDS,
        );
        assert_eq!(snapshot.ranking.coverage_seconds, Some(10));
        assert_eq!(snapshot.processes[0].selected.sent, 300);
        assert_eq!(snapshot.processes[0].rank.sent, 30);
    }

    #[test]
    fn ranking_coverage_starts_at_store_creation_and_is_zero_before_first_bucket() {
        let created: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let stats = Stats::new_at(created);
        let snapshot = stats.snapshot_at(
            10,
            created + Duration::seconds(20),
            RankWindow::THIRTY_SECONDS,
        );
        assert_eq!(snapshot.ranking.coverage_seconds, Some(0));
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn delayed_first_flow_uses_elapsed_time_since_store_creation_for_coverage() {
        let created: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let first_flow = created + Duration::seconds(20);
        let mut stats = Stats::new_at(created);
        stats.record_flow_at(
            flow(Direction::Outbound, [203, 0, 113, 8], 300),
            Some(ObservedProcess {
                pid: 8,
                name: None,
                path: None,
            }),
            first_flow,
        );
        let snapshot = stats.snapshot_at(10, first_flow, RankWindow::THIRTY_SECONDS);
        assert_eq!(snapshot.ranking.coverage_seconds, Some(20));
        assert_eq!(snapshot.processes[0].selected.sent, 300);
        assert_eq!(snapshot.processes[0].rank.sent, 15);
    }

    #[test]
    fn process_ties_use_the_complete_process_key() {
        let observed_at: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let mut stats = Stats::default();
        for path in ["/srv/z-worker", "/srv/a-worker"] {
            stats.record_flow_at(
                flow(Direction::Outbound, [203, 0, 113, 9], 100),
                Some(ObservedProcess {
                    pid: 7,
                    name: Some(Arc::from("worker")),
                    path: Some(Arc::from(path)),
                }),
                observed_at,
            );
        }
        let snapshot = stats.snapshot_at(10, observed_at, RankWindow::Cumulative);
        assert_eq!(snapshot.processes[0].path(), Some("/srv/a-worker"));
        assert_eq!(snapshot.processes[1].path(), Some("/srv/z-worker"));
    }

    #[test]
    fn ip_ties_use_normalized_address_bytes() {
        let observed_at: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let mut stats = Stats::default();
        let lower_byte: IpAddr = "2001:db8::2".parse().unwrap();
        let higher_byte: IpAddr = "2001:db8::10".parse().unwrap();
        stats.record_flow_at(
            flow_ip(Direction::Inbound, lower_byte, 100),
            None,
            observed_at,
        );
        stats.record_flow_at(
            flow_ip(Direction::Inbound, higher_byte, 100),
            None,
            observed_at,
        );
        let snapshot = stats.snapshot_at(10, observed_at, RankWindow::Cumulative);
        assert_eq!(snapshot.inbound_ips[0].ip, lower_byte);
        assert_eq!(snapshot.inbound_ips[1].ip, higher_byte);
    }

    #[test]
    fn domain_ties_use_lexicographic_host_order() {
        let observed_at: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let mut stats = Stats::default();
        for host in ["z.example", "a.example"] {
            stats.record_flow_at(
                flow_with_domain(
                    Direction::Outbound,
                    [203, 0, 113, 10],
                    100,
                    Some(Arc::from(host)),
                ),
                None,
                observed_at,
            );
        }
        let snapshot = stats.snapshot_at(10, observed_at, RankWindow::Cumulative);
        assert_eq!(snapshot.outbound_domains[0].host(), "a.example");
        assert_eq!(snapshot.outbound_domains[1].host(), "z.example");
    }

    #[test]
    fn ip_window_tracks_recent_bytes_and_surge() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = first + Duration::minutes(1);
        let third = first + Duration::minutes(2);
        let peer = unique_ip(7);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 100), None, first);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 50), None, second);
        stats.record_flow_at(flow_ip(Direction::Inbound, peer, 300), None, third);
        let state = stats.in_ip_windows.get(&peer).unwrap();
        assert_eq!(state.current_bucket_bytes(bucket_epoch(third)), 300);
        assert_eq!(state.window_bytes(bucket_epoch(third)), 450);
        assert_eq!(state.previous_window_bytes(bucket_epoch(third)), 150);
        assert_eq!(state.surge_bytes(bucket_epoch(third)), 1_050);
        assert_eq!(state.observed_buckets, 3);
    }

    #[test]
    fn rising_tier_keeps_recent_candidates_when_heavy_capacity_is_unused() {
        let mut stats = Stats::default();
        let first: DateTime<Utc> = "2026-07-15T08:00:00Z".parse().unwrap();
        let second = first + Duration::minutes(1);
        let third = first + Duration::minutes(2);
        for index in 0..100 {
            stats.record_flow_at(
                flow_ip(Direction::Inbound, unique_ip(index), 10),
                None,
                first,
            );
        }
        for index in 0..100 {
            let bytes = if index == 0 { 10_000 } else { 10 };
            stats.record_flow_at(
                flow_ip(Direction::Inbound, unique_ip(index), bytes),
                None,
                second,
            );
        }
        stats.record_flow_at(flow_ip(Direction::Inbound, unique_ip(0), 1), None, third);
        let diagnostics = stats.diagnostics_snapshot();
        assert_eq!(diagnostics.inbound_rising_ip_entries, 20);
        assert_eq!(diagnostics.inbound_heavy_ip_entries, 80);
        assert_eq!(stats.in_ip_windows[&unique_ip(0)].tier, IpTier::Rising);
    }
}
