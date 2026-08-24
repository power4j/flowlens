use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::capture::Flow;

// Keep per-direction peer history bounded while retaining high-volume behavior.
const MAX_IP_DIMENSION_ENTRIES: usize = 16_384;
const IP_DIMENSION_PRUNE_BATCH: usize = 256;
const IP_DIMENSION_TARGET_ENTRIES: usize = MAX_IP_DIMENSION_ENTRIES - IP_DIMENSION_PRUNE_BATCH;
const IP_WINDOW_BUCKETS: usize = 5;
const IP_BUCKET_SECONDS: i64 = 60;
const IP_IDLE_WINDOWS: i64 = 3;
const IP_OBSERVATION_BUCKETS: u8 = 2;
const IP_HEAVY_SHARE_PERCENT: usize = 70;
const IP_RISING_SHARE_PERCENT: usize = 20;
const IP_HEAVY_RESERVATION: usize = IP_DIMENSION_TARGET_ENTRIES * IP_HEAVY_SHARE_PERCENT / 100;
const IP_RISING_RESERVATION: usize = IP_DIMENSION_TARGET_ENTRIES * IP_RISING_SHARE_PERCENT / 100;
const IP_OBSERVATION_RESERVATION: usize =
    IP_DIMENSION_TARGET_ENTRIES - IP_HEAVY_RESERVATION - IP_RISING_RESERVATION;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum IpTier {
    Heavy,
    Rising,
    #[default]
    Observation,
}

#[derive(Clone, Copy, Debug, Default)]
struct IpBucket {
    epoch: i64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct IpWindowState {
    buckets: [IpBucket; IP_WINDOW_BUCKETS],
    last_bucket_epoch: i64,
    observed_buckets: u8,
    tier: IpTier,
    tier_changed_epoch: i64,
}

impl IpWindowState {
    fn new(epoch: i64, bytes: u64) -> Self {
        let mut state = Self {
            buckets: [IpBucket::default(); IP_WINDOW_BUCKETS],
            last_bucket_epoch: epoch,
            observed_buckets: 1,
            tier: IpTier::Observation,
            tier_changed_epoch: epoch,
        };
        state.record(epoch, bytes);
        state
    }

    fn record(&mut self, epoch: i64, bytes: u64) {
        if epoch != self.last_bucket_epoch {
            self.last_bucket_epoch = epoch;
            self.observed_buckets = self
                .observed_buckets
                .saturating_add(1)
                .min(IP_WINDOW_BUCKETS as u8);
        }
        let slot = epoch.rem_euclid(IP_WINDOW_BUCKETS as i64) as usize;
        if self.buckets[slot].epoch != epoch {
            self.buckets[slot] = IpBucket { epoch, bytes: 0 };
        }
        self.buckets[slot].bytes = self.buckets[slot].bytes.saturating_add(bytes);
    }

    fn current_bucket_bytes(&self, epoch: i64) -> u64 {
        self.buckets
            .iter()
            .find(|bucket| bucket.epoch == epoch)
            .map_or(0, |bucket| bucket.bytes)
    }

    fn window_bytes(&self, epoch: i64) -> u64 {
        let oldest = epoch - (IP_WINDOW_BUCKETS as i64 - 1);
        self.buckets
            .iter()
            .filter(|bucket| bucket.epoch >= oldest && bucket.epoch <= epoch)
            .map(|bucket| bucket.bytes)
            .sum()
    }

    fn previous_window_bytes(&self, epoch: i64) -> u64 {
        let oldest = epoch - (IP_WINDOW_BUCKETS as i64 - 1);
        self.buckets
            .iter()
            .filter(|bucket| bucket.epoch >= oldest && bucket.epoch < epoch)
            .map(|bucket| bucket.bytes)
            .sum()
    }

    fn surge_bytes(&self, epoch: i64) -> u64 {
        self.current_bucket_bytes(epoch)
            .saturating_mul((IP_WINDOW_BUCKETS - 1) as u64)
            .saturating_sub(self.previous_window_bytes(epoch))
    }

    fn idle_windows(&self, epoch: i64) -> i64 {
        (epoch - self.last_bucket_epoch).max(0) / IP_WINDOW_BUCKETS as i64
    }
}

#[derive(Default)]
struct IpDiagnosticsCounters {
    promotions: u64,
    demotions: u64,
    evictions_heavy: u64,
    evictions_rising: u64,
    evictions_observation: u64,
}

/// 双向滚动窗口（ADR 0013 第二刀）：复用 IP 维度 epoch bucket 机制，
/// 60s 桶 × `IP_WINDOW_BUCKETS` = 5 分钟滚动窗口，按方向拆分。
#[derive(Clone, Copy, Debug, Default)]
struct DirectionalWindows {
    inbound: IpWindowState,
    outbound: IpWindowState,
}

impl DirectionalWindows {
    fn record(&mut self, direction: Direction, epoch: i64, bytes: u64) {
        match direction {
            Direction::Inbound => self.inbound.record(epoch, bytes),
            Direction::Outbound => self.outbound.record(epoch, bytes),
        }
    }

    fn window(&self, epoch: i64) -> ProcTraffic {
        ProcTraffic {
            recv: self.inbound.window_bytes(epoch),
            sent: self.outbound.window_bytes(epoch),
        }
    }
}

/// Proc traffic with recv/sent breakdown.
#[derive(Default, Clone, Copy)]
pub struct ProcTraffic {
    /// Recv (inbound) bytes.
    pub recv: u64,
    /// Sent (outbound) bytes.
    pub sent: u64,
}

impl ProcTraffic {
    pub fn total(&self) -> u64 {
        self.recv.saturating_add(self.sent)
    }
}

/// 归属通道汇总（记录层口径，ADR 0013）：每字节恰好计入一个通道一次。
/// 守恒等式：total = exclusive + shared + system + unattributed（已结算，不含在途 pending）。
#[derive(Clone, Copy, Default)]
pub struct AttributionSummary {
    pub exclusive: ProcTraffic,
    pub shared: ProcTraffic,
    pub system: ProcTraffic,
    pub unattributed: ProcTraffic,
}

impl AttributionSummary {
    pub fn total(&self) -> u64 {
        self.exclusive
            .total()
            .saturating_add(self.shared.total())
            .saturating_add(self.system.total())
            .saturating_add(self.unattributed.total())
    }
}

/// 进程归属构成（ADR 0013）：exclusive 与 shared 双通道；进程行的 recv/sent 是两者之和（inclusive）。
#[derive(Clone, Default)]
pub struct ProcessAttribution {
    pub exclusive: ProcTraffic,
    pub shared: ProcTraffic,
    /// 共享伙伴的进程显示名。
    pub shared_with: Vec<Arc<str>>,
    /// 独占通道的证据来源集合（ADR 0013 第三刀）；共享通道证据不单独追踪。
    pub evidence: Evidence,
}

/// 归属证据来源（ADR 0013）：位标志，进程维度按出现顺序累积。
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Evidence(u8);

impl Evidence {
    pub(crate) const SNAPSHOT: Evidence = Evidence(1 << 0);
    pub(crate) const PROBE: Evidence = Evidence(1 << 1);
    pub(crate) const HISTORY: Evidence = Evidence(1 << 2);

    pub(crate) fn merge(self, other: Evidence) -> Evidence {
        Evidence(self.0 | other.0)
    }

    /// JSON `attribution.evidence` 的输出值。
    pub fn labels(&self) -> Vec<&'static str> {
        let mut labels = Vec::new();
        if self.0 & Self::SNAPSHOT.0 != 0 {
            labels.push("snapshot");
        }
        if self.0 & Self::PROBE.0 != 0 {
            labels.push("probe");
        }
        if self.0 & Self::HISTORY.0 != 0 {
            labels.push("history");
        }
        labels
    }
}

#[derive(Clone)]
pub struct ObservedProcess {
    pub pid: u32,
    pub name: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ProcessKey {
    pid: u32,
    path: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub struct TrafficSnapshot {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub process_data_fresh: bool,
    pub pending_attribution_bytes: u64,
    /// 记录层守恒汇总（ADR 0013）：总计 = 独占 + 共享 + 系统 + 未归属。
    pub attribution: AttributionSummary,
    /// 守恒汇总的窗口口径（5 分钟滚动，ADR 0013 第二刀）。
    pub attribution_window: AttributionSummary,
    pub processes: Arc<[ProcessSnapshot]>,
    pub inbound_ips: Arc<[IpSnapshot]>,
    pub outbound_ips: Arc<[IpSnapshot]>,
    /// 出站域名维度（05 票）；消费方：TUI 概览/详情页（06-07）、report plain/JSON 输出（08）。
    pub outbound_domains: Arc<[OutboundDomainSnapshot]>,
    pub diagnostics: Option<Arc<DiagnosticsSnapshot>>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsSnapshot {
    pub counters: DiagnosticsCounters,
    pub gauges: DiagnosticsGauges,
    pub ip: DiagnosticsIp,
    #[serde(skip)]
    pub miss_samples: Vec<DiagnosticsMissSample>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsCounters {
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
    pub probe_request_queued: u64,
    pub probe_result_unique: u64,
    pub probe_result_not_found: u64,
    pub probe_result_ambiguous: u64,
    pub probe_result_unavailable: u64,
    pub probe_result_dropped: u64,
    pub probe_result_late: u64,
    pub probe_query_count: u64,
    pub probe_query_ms: u128,
    pub pending_expired_bytes: u64,
    pub pending_capacity_bytes: u64,
    pub probe_unique_pending_bytes: u64,
    pub probe_not_found_pending_bytes: u64,
    pub probe_ambiguous_pending_bytes: u64,
    pub probe_unavailable_pending_bytes: u64,
    pub ip_promotions: u64,
    pub ip_demotions: u64,
    pub ip_evictions_heavy: u64,
    pub ip_evictions_rising: u64,
    pub ip_evictions_observation: u64,
    pub pcap_received: u64,
    pub pcap_dropped: u64,
    pub pcap_if_dropped: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsGauges {
    pub flow_table_entries: u64,
    pub process_entries: usize,
    pub domain_entries: usize,
    pub last_refresh_ms: u128,
    pub pending_records: usize,
    pub pending_bytes: u64,
    pub probe_last_query_ms: u128,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsIp {
    pub inbound_entries: usize,
    pub outbound_entries: usize,
    pub inbound_heavy_entries: usize,
    pub inbound_rising_entries: usize,
    pub inbound_observation_entries: usize,
    pub outbound_heavy_entries: usize,
    pub outbound_rising_entries: usize,
    pub outbound_observation_entries: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticsMissSample {
    pub reason: String,
    pub protocol: String,
    pub local: String,
    pub peer: String,
}

#[derive(Clone)]
pub struct ProcessSnapshot {
    identity: ProcessIdentity,
    /// Inclusive 口径总量（exclusive + shared），列表与 top-N 排序键（lifetime）。
    pub recv: u64,
    pub sent: u64,
    pub attribution: ProcessAttribution,
    /// 5 分钟滚动窗口内的 inclusive 字节；保留在详情页与报表，不作为列表主口径。
    pub window: ProcTraffic,
    last_seen: DateTime<Utc>,
}

#[derive(Clone)]
enum ProcessIdentity {
    Attributed {
        pid: u32,
        name: Option<Arc<str>>,
        path: Option<Arc<str>>,
    },
}

impl ProcessSnapshot {
    #[cfg(test)]
    pub(crate) fn attributed(
        pid: u32,
        name: Option<Arc<str>>,
        path: Option<Arc<str>>,
        last_seen: DateTime<Utc>,
        recv: u64,
        sent: u64,
    ) -> Self {
        Self {
            identity: ProcessIdentity::Attributed { pid, name, path },
            attribution: ProcessAttribution {
                exclusive: ProcTraffic { recv, sent },
                shared: ProcTraffic::default(),
                shared_with: Vec::new(),
                evidence: Evidence::default(),
            },
            window: ProcTraffic::default(),
            recv,
            sent,
            last_seen,
        }
    }

    pub(crate) fn attributed_with_shared(
        pid: u32,
        name: Option<Arc<str>>,
        path: Option<Arc<str>>,
        last_seen: DateTime<Utc>,
        exclusive: ProcTraffic,
        shared: ProcTraffic,
        shared_with: Vec<Arc<str>>,
    ) -> Self {
        Self {
            identity: ProcessIdentity::Attributed { pid, name, path },
            recv: exclusive.recv + shared.recv,
            sent: exclusive.sent + shared.sent,
            attribution: ProcessAttribution {
                exclusive,
                shared,
                shared_with,
                evidence: Evidence::default(),
            },
            window: ProcTraffic::default(),
            last_seen,
        }
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        match self.identity {
            ProcessIdentity::Attributed { pid, .. } => Some(pid),
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match &self.identity {
            ProcessIdentity::Attributed { name, .. } => name.as_deref(),
        }
    }

    pub(crate) fn path(&self) -> Option<&str> {
        match &self.identity {
            ProcessIdentity::Attributed { path, .. } => path.as_deref(),
        }
    }

    /// 列表 Attr 列语义（ADR 0013）：false = E（全部独占），true = M（含共享字节）。
    pub(crate) fn is_mixed(&self) -> bool {
        self.attribution.shared.recv > 0 || self.attribution.shared.sent > 0
    }

    pub(crate) fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }

    pub(crate) fn display_name(&self) -> &str {
        match &self.identity {
            ProcessIdentity::Attributed { name, .. } => name.as_deref().unwrap_or("?"),
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.recv.saturating_add(self.sent)
    }

    pub(crate) fn same_identity_as(&self, other: &Self) -> bool {
        match (&self.identity, &other.identity) {
            (
                ProcessIdentity::Attributed {
                    pid: left_pid,
                    path: left_path,
                    ..
                },
                ProcessIdentity::Attributed {
                    pid: right_pid,
                    path: right_path,
                    ..
                },
            ) => left_pid == right_pid && left_path == right_path,
        }
    }
}

#[derive(Clone)]
pub struct IpSnapshot {
    pub ip: IpAddr,
    pub bytes: u64,
    last_seen: DateTime<Utc>,
}

impl IpSnapshot {
    pub(crate) fn new(ip: IpAddr, bytes: u64, last_seen: DateTime<Utc>) -> Self {
        Self {
            ip,
            bytes,
            last_seen,
        }
    }

    pub(crate) fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }
}

/// 出站域名维度的快照项，对齐 ProcessSnapshot 的封装风格。
///
/// 字段语义对齐 spec：host / in_bytes / out_bytes / total_bytes / last_seen。
/// `in_bytes` / `out_bytes` 为 pub（同 ProcessSnapshot::recv / sent）；
/// `host` / `last_seen` 私有并通过 accessor 暴露（同进程维度的封装）。
///
/// 字段与 accessor 在 05 票中落地；消费方：TUI 概览/详情页（06-07）、
/// report plain/JSON 输出（08）。
#[derive(Clone)]
pub struct OutboundDomainSnapshot {
    host: Arc<str>,
    pub in_bytes: u64,
    pub out_bytes: u64,
    last_seen: DateTime<Utc>,
}

impl OutboundDomainSnapshot {
    pub(crate) fn new(
        host: Arc<str>,
        in_bytes: u64,
        out_bytes: u64,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self {
            host,
            in_bytes,
            out_bytes,
            last_seen,
        }
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }

    pub(crate) fn total_bytes(&self) -> u64 {
        self.in_bytes.saturating_add(self.out_bytes)
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
    /// 共享归属通道（ADR 0013）：per-process inclusive 投影；记录层总量在 `shared_total`。
    shared_by_proc: HashMap<ProcessKey, ProcTraffic>,
    /// 记录层共享字节总量（每字节只计一次），守恒等式使用。
    shared_total: ProcTraffic,
    /// 共享伙伴（进程统计身份），详情页 shared_with 数据来源。
    shared_partners: HashMap<ProcessKey, Vec<ProcessKey>>,
    /// 独占通道证据来源（ADR 0013 第三刀）。
    evidence_by_proc: HashMap<ProcessKey, Evidence>,
    /// 系统流量（无本地套接字，ADR 0013），独立于未归属。
    system: ProcTraffic,
    /// 进程维度滚动窗口（ADR 0013 第二刀）：per-process inclusive 字节。
    proc_windows: HashMap<ProcessKey, DirectionalWindows>,
    /// 记录层四通道滚动窗口（守恒摘要的窗口口径）。
    exclusive_window: DirectionalWindows,
    shared_window: DirectionalWindows,
    system_window: DirectionalWindows,
    unattributed_window: DirectionalWindows,
    /// 进程窗口参考 epoch（最近一次记录的 bucket epoch）。
    proc_window_epoch: Option<i64>,
    proc_names: HashMap<ProcessKey, Arc<str>>,
    by_domain: HashMap<Arc<str>, DomainTraffic>,
    domain_last_seen: HashMap<Arc<str>, DateTime<Utc>>,
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

/// 按域名累计的双向字节计数，对齐 ProcTraffic 的 recv/sent 拆分。
#[derive(Default, Clone, Copy)]
struct DomainTraffic {
    /// Recv (inbound) bytes —— 对端回包累计到此。
    recv: u64,
    /// Sent (outbound) bytes —— 本机发出包累计到此。
    sent: u64,
}

impl Stats {
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
        if flow.peer_local_socket.is_some() {
            self.record_process(process, Direction::Outbound, flow.bytes, observed_at);
            self.record_process(peer_process, Direction::Inbound, flow.bytes, observed_at);
            return;
        }

        self.record_process(process, flow.direction, flow.bytes, observed_at);
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

    pub(crate) fn record_process(
        &mut self,
        process: Option<ObservedProcess>,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
    ) {
        self.add_process_or_unattributed(process, direction, bytes, observed_at);
    }

    /// ADR 0013 第三刀：带证据来源的归属记录（snapshot / probe / history）。
    pub(crate) fn record_process_evidence(
        &mut self,
        process: ObservedProcess,
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
        evidence: Evidence,
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
        self.evidence_by_proc.insert(key, merged);
        self.record_process(Some(process), direction, bytes, observed_at);
    }

    /// 按 spec Q8 / Q10：已识别连接（domain=Some）的双向流量按方向累计到该域名，
    /// 并更新该域名的 last_seen；未识别（domain=None）不进维度。
    ///
    /// Last seen 规则与进程维度一致：只在 record_*_domain 被实际调用时更新，
    /// snapshot() 仅读取不更新。
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

    /// ADR 0013 共享归属：同一笔字节全额计入每个候选进程（inclusive 投影），
    /// 记录层只在 shared_total 计一次；候选不足 2 个不构成共享，退回未归属。
    pub(crate) fn record_shared(
        &mut self,
        candidates: &[ObservedProcess],
        direction: Direction,
        bytes: u64,
        observed_at: DateTime<Utc>,
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

    /// ADR 0013 系统流量：无本地套接字的协议流量（ICMP 等），不参与进程归属。
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

    /// 推进进程窗口参考 epoch（单调取最近），返回该 epoch 供各窗口记账。
    fn advance_proc_window_epoch(&mut self, observed_at: DateTime<Utc>) -> i64 {
        let epoch = bucket_epoch(observed_at);
        self.proc_window_epoch = Some(self.proc_window_epoch.map_or(epoch, |prev| prev.max(epoch)));
        epoch
    }

    /// 守恒汇总的窗口口径（5 分钟滚动，ADR 0013 第二刀）。
    pub(crate) fn attribution_window_summary(&self) -> AttributionSummary {
        let epoch = self.proc_window_epoch.unwrap_or(0);
        AttributionSummary {
            exclusive: self.exclusive_window.window(epoch),
            shared: self.shared_window.window(epoch),
            system: self.system_window.window(epoch),
            unattributed: self.unattributed_window.window(epoch),
        }
    }

    /// 记录层守恒汇总：总计 = 独占 + 共享 + 系统 + 未归属（ADR 0013）。
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

    pub fn snapshot(&self, top_n: usize) -> TrafficSnapshot {
        let proc_epoch = self.proc_window_epoch.unwrap_or(0);
        let processes = self
            .top_procs(top_n)
            .into_iter()
            .map(|(key, traffic)| {
                let last_seen = self.proc_last_seen[&key];
                let exclusive = self.by_proc.get(&key).copied().unwrap_or_default();
                let shared = self.shared_by_proc.get(&key).copied().unwrap_or_default();
                debug_assert_eq!(traffic.recv, exclusive.recv + shared.recv);
                debug_assert_eq!(traffic.sent, exclusive.sent + shared.sent);
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
                    key.path,
                    last_seen,
                    exclusive,
                    shared,
                    shared_with,
                );
                if let Some(evidence) = evidence {
                    process.attribution.evidence = evidence;
                }
                process.window = window;
                process
            })
            .collect::<Vec<_>>();
        // top_procs 已按 lifetime inclusive 总量排序并截断。
        let inbound_ips = self
            .top_in(top_n)
            .into_iter()
            .map(|(ip, bytes)| IpSnapshot::new(ip, bytes, self.in_ip_last_seen[&ip]))
            .collect::<Vec<_>>()
            .into();
        let outbound_ips = self
            .top_out(top_n)
            .into_iter()
            .map(|(ip, bytes)| IpSnapshot::new(ip, bytes, self.out_ip_last_seen[&ip]))
            .collect::<Vec<_>>()
            .into();
        let outbound_domains = self
            .top_domains(top_n)
            .into_iter()
            .map(|(host, traffic)| {
                let last_seen = self.domain_last_seen[&host];
                OutboundDomainSnapshot::new(host, traffic.recv, traffic.sent, last_seen)
            })
            .collect::<Vec<_>>()
            .into();

        TrafficSnapshot {
            attribution: self.attribution_summary(),
            attribution_window: self.attribution_window_summary(),
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

    fn top_in(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n_ip(&self.in_by_ip, n)
    }

    fn top_out(&self, n: usize) -> Vec<(IpAddr, u64)> {
        top_n_ip(&self.out_by_ip, n)
    }

    fn top_procs(&self, n: usize) -> Vec<(ProcessKey, ProcTraffic)> {
        // Inclusive 口径（独占 + 共享）按启动以来累计总量排序。
        let mut combined: HashMap<ProcessKey, ProcTraffic> = self.by_proc.clone();
        for (key, shared) in &self.shared_by_proc {
            let entry = combined.entry(key.clone()).or_default();
            entry.recv += shared.recv;
            entry.sent += shared.sent;
        }
        let mut entries: Vec<(ProcessKey, ProcTraffic)> = combined.into_iter().collect();
        entries
            .sort_unstable_by_key(|(_, lifetime)| std::cmp::Reverse(lifetime.recv + lifetime.sent));
        entries.truncate(n);
        entries
    }

    fn top_domains(&self, n: usize) -> Vec<(Arc<str>, DomainTraffic)> {
        let mut entries: Vec<(Arc<str>, DomainTraffic)> = self
            .by_domain
            .iter()
            .map(|(host, traffic)| (host.clone(), *traffic))
            .collect();
        entries.sort_unstable_by_key(|(_, t)| std::cmp::Reverse(t.recv + t.sent));
        entries.truncate(n);
        entries
    }
}

#[derive(Clone, Copy)]
struct IpCandidate {
    ip: IpAddr,
    last_seen: DateTime<Utc>,
    lifetime_bytes: u64,
    current_bucket_bytes: u64,
    window_bytes: u64,
    surge_bytes: u64,
    idle_windows: i64,
    observed_buckets: u8,
    tier: IpTier,
    tier_changed_epoch: i64,
}

fn bucket_epoch(observed_at: DateTime<Utc>) -> i64 {
    observed_at.timestamp().div_euclid(IP_BUCKET_SECONDS)
}

fn collect_ip_candidates(
    bytes_by_ip: &HashMap<IpAddr, u64>,
    last_seen_by_ip: &HashMap<IpAddr, DateTime<Utc>>,
    windows_by_ip: &HashMap<IpAddr, IpWindowState>,
    epoch: i64,
) -> Vec<IpCandidate> {
    bytes_by_ip
        .iter()
        .filter_map(|(ip, lifetime_bytes)| {
            let state = windows_by_ip.get(ip)?;
            let last_seen = last_seen_by_ip.get(ip)?;
            Some(IpCandidate {
                ip: *ip,
                last_seen: *last_seen,
                lifetime_bytes: *lifetime_bytes,
                current_bucket_bytes: state.current_bucket_bytes(epoch),
                window_bytes: state.window_bytes(epoch),
                surge_bytes: state.surge_bytes(epoch),
                idle_windows: state.idle_windows(epoch),
                observed_buckets: state.observed_buckets,
                tier: state.tier,
                tier_changed_epoch: state.tier_changed_epoch,
            })
        })
        .collect()
}

fn desired_ip_tiers(candidates: &[IpCandidate]) -> HashMap<IpAddr, IpTier> {
    let eligible = candidates
        .iter()
        .filter(|candidate| {
            candidate.observed_buckets >= IP_OBSERVATION_BUCKETS
                && candidate.idle_windows < IP_IDLE_WINDOWS
        })
        .copied()
        .collect::<Vec<_>>();

    let rising_target = eligible.len() * IP_RISING_SHARE_PERCENT / 100;
    let rising_target = rising_target.min(IP_RISING_RESERVATION);
    let rising_ips = select_rising_ips(&eligible, rising_target);

    let mut heavy = eligible
        .iter()
        .filter(|candidate| !rising_ips.contains(&candidate.ip))
        .copied()
        .collect::<Vec<_>>();
    heavy.sort_unstable_by_key(|candidate| std::cmp::Reverse(candidate.lifetime_bytes));
    let heavy_target = heavy.len().min(IP_HEAVY_RESERVATION);
    let heavy_ips = heavy
        .iter()
        .take(heavy_target)
        .map(|candidate| candidate.ip)
        .collect::<HashSet<_>>();

    candidates
        .iter()
        .map(|candidate| {
            let tier = if candidate.observed_buckets < IP_OBSERVATION_BUCKETS {
                IpTier::Observation
            } else if heavy_ips.contains(&candidate.ip) {
                IpTier::Heavy
            } else if rising_ips.contains(&candidate.ip) {
                IpTier::Rising
            } else {
                IpTier::Observation
            };
            (candidate.ip, tier)
        })
        .collect()
}

fn select_rising_ips(candidates: &[IpCandidate], target: usize) -> HashSet<IpAddr> {
    if target == 0 || candidates.is_empty() {
        return HashSet::new();
    }

    let mut by_window = candidates.to_vec();
    by_window.sort_unstable_by_key(|candidate| {
        (
            std::cmp::Reverse(candidate.window_bytes),
            std::cmp::Reverse(candidate.surge_bytes),
        )
    });
    let mut by_surge = candidates.to_vec();
    by_surge.sort_unstable_by_key(|candidate| {
        (
            std::cmp::Reverse(candidate.surge_bytes),
            std::cmp::Reverse(candidate.window_bytes),
        )
    });

    let mut selected = HashSet::new();
    for candidate in by_window.iter().take(target) {
        selected.insert(candidate.ip);
    }
    for candidate in by_surge.iter().take(target) {
        selected.insert(candidate.ip);
    }
    if selected.len() <= target {
        return selected;
    }

    let window_rank = by_window
        .iter()
        .enumerate()
        .map(|(rank, candidate)| (candidate.ip, rank))
        .collect::<HashMap<_, _>>();
    let surge_rank = by_surge
        .iter()
        .enumerate()
        .map(|(rank, candidate)| (candidate.ip, rank))
        .collect::<HashMap<_, _>>();
    let mut ranked = selected.into_iter().collect::<Vec<_>>();
    ranked.sort_unstable_by_key(|ip| {
        let window = window_rank[ip];
        let surge = surge_rank[ip];
        (window.min(surge), window.max(surge), window, surge)
    });
    ranked.truncate(target);
    ranked.into_iter().collect()
}

fn ip_tier_counts(windows_by_ip: &HashMap<IpAddr, IpWindowState>) -> (usize, usize, usize) {
    windows_by_ip.values().fold((0, 0, 0), |mut counts, state| {
        match state.tier {
            IpTier::Heavy => counts.0 += 1,
            IpTier::Rising => counts.1 += 1,
            IpTier::Observation => counts.2 += 1,
        }
        counts
    })
}

fn rebalance_ip_dimension(
    bytes_by_ip: &mut HashMap<IpAddr, u64>,
    last_seen_by_ip: &mut HashMap<IpAddr, DateTime<Utc>>,
    windows_by_ip: &mut HashMap<IpAddr, IpWindowState>,
    epoch: i64,
    diagnostics: &mut IpDiagnosticsCounters,
    refresh_tiers: bool,
) {
    if bytes_by_ip.is_empty() {
        return;
    }

    let candidates = collect_ip_candidates(bytes_by_ip, last_seen_by_ip, windows_by_ip, epoch);
    if refresh_tiers {
        let desired = desired_ip_tiers(&candidates);
        for candidate in &candidates {
            let Some(state) = windows_by_ip.get_mut(&candidate.ip) else {
                continue;
            };
            let desired_tier = desired[&candidate.ip];
            let idle = candidate.idle_windows >= IP_IDLE_WINDOWS;
            let held = epoch.saturating_sub(candidate.tier_changed_epoch) < 2;
            let next_tier = if candidate.observed_buckets < IP_OBSERVATION_BUCKETS || idle {
                IpTier::Observation
            } else if candidate.tier != desired_tier && held {
                candidate.tier
            } else {
                desired_tier
            };
            if state.tier != next_tier {
                if tier_rank(next_tier) > tier_rank(state.tier) {
                    diagnostics.promotions += 1;
                } else {
                    diagnostics.demotions += 1;
                }
                state.tier = next_tier;
                state.tier_changed_epoch = epoch;
            }
        }
    }

    if bytes_by_ip.len() <= MAX_IP_DIMENSION_ENTRIES {
        return;
    }

    let counts = ip_tier_counts(windows_by_ip);
    let current = if refresh_tiers {
        collect_ip_candidates(bytes_by_ip, last_seen_by_ip, windows_by_ip, epoch)
    } else {
        candidates
    };
    let mut victims = current
        .into_iter()
        .filter(|candidate| {
            let minimum = match candidate.tier {
                IpTier::Heavy => IP_HEAVY_RESERVATION,
                IpTier::Rising => IP_RISING_RESERVATION,
                IpTier::Observation => IP_OBSERVATION_RESERVATION,
            };
            let count = match candidate.tier {
                IpTier::Heavy => counts.0,
                IpTier::Rising => counts.1,
                IpTier::Observation => counts.2,
            };
            count > minimum
                || (candidate.tier == IpTier::Heavy && candidate.idle_windows >= IP_IDLE_WINDOWS)
        })
        .collect::<Vec<_>>();
    victims.sort_unstable_by_key(|candidate| {
        let tier = candidate.tier;
        let (primary, secondary) = match tier {
            IpTier::Heavy => (candidate.lifetime_bytes, candidate.window_bytes),
            IpTier::Rising => (candidate.window_bytes, candidate.surge_bytes),
            IpTier::Observation => (candidate.current_bucket_bytes, candidate.window_bytes),
        };
        (
            tier_rank(tier),
            if tier == IpTier::Heavy && candidate.idle_windows >= IP_IDLE_WINDOWS {
                0
            } else {
                1
            },
            primary,
            secondary,
            candidate.last_seen,
        )
    });

    let remove_count = bytes_by_ip
        .len()
        .saturating_sub(IP_DIMENSION_TARGET_ENTRIES);
    for candidate in victims.into_iter().take(remove_count) {
        bytes_by_ip.remove(&candidate.ip);
        last_seen_by_ip.remove(&candidate.ip);
        windows_by_ip.remove(&candidate.ip);
        match candidate.tier {
            IpTier::Heavy => diagnostics.evictions_heavy += 1,
            IpTier::Rising => diagnostics.evictions_rising += 1,
            IpTier::Observation => diagnostics.evictions_observation += 1,
        }
    }
}

fn tier_rank(tier: IpTier) -> u8 {
    match tier {
        IpTier::Observation => 0,
        IpTier::Rising => 1,
        IpTier::Heavy => 2,
    }
}

fn top_n_ip(map: &HashMap<IpAddr, u64>, n: usize) -> Vec<(IpAddr, u64)> {
    let mut entries: Vec<(IpAddr, u64)> = map.iter().map(|(ip, bytes)| (*ip, *bytes)).collect();
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    entries.truncate(n);
    entries
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::*;
    use crate::capture::Flow;

    #[test]
    fn unattributed_flow_appears_in_attribution_summary() {
        let mut stats = Stats::default();
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 1], 40),
            None,
            "2026-07-15T07:59:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(10);

        // ADR 0013：未归属不再作为进程行，只进守恒摘要。
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

        // ADR 0013：未归属移出排名，topN 只含已归属进程。
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

        // ADR 0013：通道划分取代"进程行求和=接口字节"的旧不变量。
        assert_eq!(snapshot.in_bytes, 70);
        assert_eq!(snapshot.out_bytes, 30);
        assert_eq!(summary.exclusive.recv, 40);
        assert_eq!(summary.exclusive.sent, 10);
        assert_eq!(summary.unattributed.recv, 30);
        assert_eq!(summary.unattributed.sent, 20);
        assert_eq!(summary.total(), snapshot.in_bytes + snapshot.out_bytes);
    }

    /// 列表与 top-N 使用 lifetime 累计：窗口外的历史大户仍占排名。
    #[test]
    fn top_n_ranks_by_lifetime_including_idle_heavyweights() {
        let mut stats = Stats::default();
        // 旧大户 1000 B（窗口外），新进程 10 B（窗口内）。
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

    /// ADR 0013 第二刀：窗口口径守恒——窗口内四通道之和恰为窗口内记录字节，
    /// 滑出窗口后衰减为 0，累计口径不受影响。
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
        let window = snapshot.attribution_window;
        assert_eq!(window.unattributed.recv, 100);
        assert_eq!(window.exclusive.recv, 40);
        assert_eq!(window.total(), 140);
        assert_eq!(snapshot.attribution.unattributed.recv, 100);
        assert_eq!(snapshot.attribution.exclusive.recv, 40);

        // 推进到 08:10：前两笔全部滑出窗口。
        stats.record_flow_at(
            flow(Direction::Inbound, [10, 0, 0, 3], 1),
            Some(ObservedProcess {
                pid: 9,
                name: None,
                path: None,
            }),
            "2026-07-15T08:10:00Z".parse().unwrap(),
        );
        let snapshot = stats.snapshot(10);
        let window = snapshot.attribution_window;
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

    // ── 出站域名维度（05 票） ──────────────────────────────────────────

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
        // 未识别流量仍然进入接口与 IP 维度，守恒边界不变。
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

        // snapshot() 不更新 last_seen（与进程维度规则一致）。
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

        // 已识别流量（进出站域名维度）：100 + 50 = 150。
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
        // 未识别流量（不进域名维度）：80 + 30 = 110。
        stats.record_flow(flow(Direction::Outbound, [198, 51, 100, 5], 80), None);
        stats.record_flow(flow(Direction::Inbound, [198, 51, 100, 5], 30), None);

        let snapshot = stats.snapshot(10);
        let domain_total: u64 = snapshot
            .outbound_domains
            .iter()
            .map(|domain| domain.total_bytes())
            .sum();

        // 接口总量 = 100 + 50 + 80 + 30 = 260。
        assert_eq!(snapshot.in_bytes, 80);
        assert_eq!(snapshot.out_bytes, 180);
        assert_eq!(snapshot.in_bytes + snapshot.out_bytes, 260);
        // 域名总量 = 150，是接口总量的子集（明确不与接口总量守恒）。
        assert_eq!(domain_total, 150);
        assert!(domain_total < snapshot.in_bytes + snapshot.out_bytes);
    }

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

    fn unique_ip(index: usize) -> IpAddr {
        let index = index as u32;
        IpAddr::V4(Ipv4Addr::new(
            10,
            ((index >> 16) & 0xff) as u8,
            ((index >> 8) & 0xff) as u8,
            (index & 0xff) as u8,
        ))
    }
}
