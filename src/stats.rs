use crate::capture::Flow;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

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
const RANKING_BUCKET_SECONDS: i64 = 1;
const RANKING_MAX_WINDOW_SECONDS: i64 = 5 * 60;
const MAX_RANKING_PROCESS_ENTRIES: usize = 1_000;
const MAX_RANKING_IP_ENTRIES: usize = 4_096;
const MAX_RANKING_DOMAIN_ENTRIES: usize = 4_096;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RankingWindow {
    #[default]
    Cumulative,
    Seconds(u32),
}
pub type RankWindow = RankingWindow;
impl RankingWindow {
    pub const FIVE_SECONDS: Self = Self::Seconds(5);
    pub const TEN_SECONDS: Self = Self::Seconds(10);
    pub const THIRTY_SECONDS: Self = Self::Seconds(30);
    pub const SIXTY_SECONDS: Self = Self::Seconds(60);
    pub const FIVE_MINUTES: Self = Self::Seconds(300);
    pub const fn seconds(self) -> Option<u32> {
        match self {
            Self::Cumulative => None,
            Self::Seconds(seconds) => Some(seconds),
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cumulative => "cumulative",
            Self::Seconds(5) => "5s",
            Self::Seconds(10) => "10s",
            Self::Seconds(30) => "30s",
            Self::Seconds(60) => "60s",
            Self::Seconds(300) => "5m",
            Self::Seconds(_) => "custom",
        }
    }
    pub fn next(self) -> Self {
        match self {
            Self::Cumulative => Self::FIVE_SECONDS,
            Self::Seconds(5) => Self::TEN_SECONDS,
            Self::Seconds(10) => Self::THIRTY_SECONDS,
            Self::Seconds(30) => Self::SIXTY_SECONDS,
            Self::Seconds(60) => Self::FIVE_MINUTES,
            Self::Seconds(300) | Self::Seconds(_) => Self::Cumulative,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Cumulative => Self::FIVE_MINUTES,
            Self::Seconds(5) => Self::Cumulative,
            Self::Seconds(10) => Self::FIVE_SECONDS,
            Self::Seconds(30) => Self::TEN_SECONDS,
            Self::Seconds(60) => Self::THIRTY_SECONDS,
            Self::Seconds(300) | Self::Seconds(_) => Self::SIXTY_SECONDS,
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Cumulative => 0,
            Self::Seconds(5) => 1,
            Self::Seconds(10) => 2,
            Self::Seconds(30) => 3,
            Self::Seconds(60) => 4,
            Self::Seconds(300) => 5,
            Self::Seconds(_) => 0,
        }
    }
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::FIVE_SECONDS,
            2 => Self::TEN_SECONDS,
            3 => Self::THIRTY_SECONDS,
            4 => Self::SIXTY_SECONDS,
            5 => Self::FIVE_MINUTES,
            _ => Self::Cumulative,
        }
    }
}
impl std::fmt::Display for RankingWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}
impl Serialize for RankingWindow {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.label())
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RankingMetric {
    #[default]
    TotalBytes,
    AverageThroughput,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RankingSnapshot {
    pub window: RankingWindow,
    pub metric: RankingMetric,
    pub coverage_seconds: Option<u32>,
}
#[derive(Clone, Copy, Debug, Default)]
struct RankingBucket {
    epoch: i64,
    traffic: ProcTraffic,
}
#[derive(Clone, Default)]
struct RankingEntityWindow {
    buckets: Vec<RankingBucket>,
    last_seen_epoch: i64,
}
impl RankingEntityWindow {
    fn record(&mut self, direction: Direction, epoch: i64, bytes: u64) {
        self.last_seen_epoch = epoch;
        if let Some(bucket) = self.buckets.iter_mut().find(|bucket| bucket.epoch == epoch) {
            Self::add_to_traffic(&mut bucket.traffic, direction, bytes);
        } else {
            let mut bucket = RankingBucket {
                epoch,
                traffic: ProcTraffic::default(),
            };
            Self::add_to_traffic(&mut bucket.traffic, direction, bytes);
            self.buckets.push(bucket);
        }
    }
    fn add_to_traffic(traffic: &mut ProcTraffic, direction: Direction, bytes: u64) {
        match direction {
            Direction::Inbound => traffic.recv = traffic.recv.saturating_add(bytes),
            Direction::Outbound => traffic.sent = traffic.sent.saturating_add(bytes),
        }
    }
    fn prune(&mut self, epoch: i64) {
        let oldest = epoch - (RANKING_MAX_WINDOW_SECONDS - RANKING_BUCKET_SECONDS);
        self.buckets
            .retain(|bucket| bucket.epoch >= oldest && bucket.epoch <= epoch);
    }
    fn traffic(&self, epoch: i64, window_seconds: u32) -> ProcTraffic {
        let oldest = epoch - (i64::from(window_seconds) - RANKING_BUCKET_SECONDS);
        self.buckets
            .iter()
            .filter(|bucket| bucket.epoch >= oldest && bucket.epoch <= epoch)
            .fold(ProcTraffic::default(), |mut total, bucket| {
                total.recv = total.recv.saturating_add(bucket.traffic.recv);
                total.sent = total.sent.saturating_add(bucket.traffic.sent);
                total
            })
    }
}
fn ip_sort_key(ip: IpAddr) -> (u8, [u8; 16]) {
    match ip {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[12..].copy_from_slice(&address.octets());
            (0, bytes)
        }
        IpAddr::V6(address) => (1, address.octets()),
    }
}
fn evict_oldest_ranking_entity<K>(store: &mut HashMap<K, RankingEntityWindow>) -> bool
where
    K: Clone + Eq + std::hash::Hash,
{
    let Some(oldest) = store
        .iter()
        .min_by_key(|(_, entry)| entry.last_seen_epoch)
        .map(|(key, _)| key)
        .cloned()
    else {
        return false;
    };
    store.remove(&oldest).is_some()
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
/// Bidirectional rolling window (ADR 0013 process windowing): reuses the IP
/// dimension's epoch-bucket machinery — 60s buckets × `IP_WINDOW_BUCKETS` =
/// a 5-minute rolling window, split by direction.
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
#[derive(Default, Clone, Copy, Debug)]
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
/// Attribution-channel summary (record-layer basis, ADR 0013): each byte is
/// counted into exactly one channel. Conservation identity: total =
/// exclusive + shared + system + unattributed (settled amounts only, no
/// in-flight pending).
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
/// Process attribution breakdown (ADR 0013): exclusive and shared channels;
/// the process row's recv/sent is their sum (inclusive).
#[derive(Clone, Default)]
pub struct ProcessAttribution {
    pub exclusive: ProcTraffic,
    pub shared: ProcTraffic,
    /// Display names of the shared partners.
    pub shared_with: Vec<Arc<str>>,
    /// Evidence sources of the exclusive channel (ADR 0013 history engine);
    /// shared-channel evidence is not tracked separately.
    pub evidence: Evidence,
}
/// Attribution evidence sources (ADR 0013): bit flags, accumulated in
/// arrival order per process.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Evidence(u8);
impl Evidence {
    pub(crate) const SNAPSHOT: Evidence = Evidence(1 << 0);
    pub(crate) const PROBE: Evidence = Evidence(1 << 1);
    pub(crate) const HISTORY: Evidence = Evidence(1 << 2);
    pub(crate) fn merge(self, other: Evidence) -> Evidence {
        Evidence(self.0 | other.0)
    }
    /// Output values of JSON `attribution.evidence`.
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
    /// Record-layer conservation summary (ADR 0013): total = exclusive +
    /// shared + system + unattributed.
    pub attribution: AttributionSummary,
    pub ranking: RankingSnapshot,
    pub processes: Arc<[ProcessSnapshot]>,
    pub inbound_ips: Arc<[IpSnapshot]>,
    pub outbound_ips: Arc<[IpSnapshot]>,
    /// Outbound-domain dimension; consumers: TUI overview/detail pages and
    /// the plain/JSON reports.
    pub outbound_domains: Arc<[OutboundDomainSnapshot]>,
    pub diagnostics: Option<Arc<DiagnosticsSnapshot>>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsSnapshot {
    pub counters: DiagnosticsCounters,
    pub gauges: DiagnosticsGauges,
    pub ip: DiagnosticsIp,
    pub capture: DiagnosticsCapture,
    #[serde(skip)]
    pub miss_samples: Vec<DiagnosticsMissSample>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsCapture {
    pub local_ips: Vec<IpAddr>,
    pub non_local_ipv4_samples: Vec<DiagnosticsEndpointSample>,
    pub non_local_ipv6_samples: Vec<DiagnosticsEndpointSample>,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct DiagnosticsEndpointSample {
    pub src: IpAddr,
    pub dst: IpAddr,
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
    pub capture_read_packets: u64,
    pub capture_read_bytes: u64,
    pub capture_parse_error_packets: u64,
    pub capture_parse_error_bytes: u64,
    pub capture_non_ip_packets: u64,
    pub capture_non_ip_bytes: u64,
    pub capture_non_local_ipv4_packets: u64,
    pub capture_non_local_ipv4_bytes: u64,
    pub capture_non_local_ipv6_packets: u64,
    pub capture_non_local_ipv6_bytes: u64,
    pub capture_duplicate_outgoing_packets: u64,
    pub capture_duplicate_outgoing_bytes: u64,
    pub capture_flow_created_packets: u64,
    pub capture_flow_created_bytes: u64,
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
    /// Inclusive total (exclusive + shared); the list and top-N sort key (lifetime).
    pub recv: u64,
    pub sent: u64,
    pub attribution: ProcessAttribution,
    /// Inclusive bytes within the 5-minute rolling window; kept for the
    /// detail page and reports, not the primary list basis.
    pub window: ProcTraffic,
    /// Selected ranking window bytes before throughput normalization.
    pub selected: ProcTraffic,
    /// Traffic attributed to this process under the selected ranking window.
    pub rank: ProcTraffic,
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
            selected: ProcTraffic::default(),
            rank: ProcTraffic::default(),
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
            selected: ProcTraffic::default(),
            rank: ProcTraffic::default(),
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
    /// Attr column semantics for lists (ADR 0013): false = E (all
    /// exclusive), true = M (contains shared bytes).
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
    pub selected_bytes: u64,
    pub rank_bytes: u64,
    last_seen: DateTime<Utc>,
}
impl IpSnapshot {
    #[cfg(test)]
    pub(crate) fn new(ip: IpAddr, bytes: u64, last_seen: DateTime<Utc>) -> Self {
        Self::with_rank(ip, bytes, bytes, last_seen)
    }
    #[cfg(test)]
    pub(crate) fn with_rank(
        ip: IpAddr,
        bytes: u64,
        rank_bytes: u64,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self::with_rank_and_selected(ip, bytes, rank_bytes, rank_bytes, last_seen)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_rank_and_selected(
        ip: IpAddr,
        bytes: u64,
        selected_bytes: u64,
        rank_bytes: u64,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self {
            ip,
            bytes,
            selected_bytes,
            rank_bytes,
            last_seen,
        }
    }
    pub(crate) fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }
}
/// Snapshot item of the outbound-domain dimension, following the
/// encapsulation style of ProcessSnapshot.
/// Field semantics: host / in_bytes / out_bytes / total_bytes / last_seen.
/// `in_bytes` / `out_bytes` are pub (like ProcessSnapshot::recv / sent);
/// `host` / `last_seen` are private, exposed via accessors (like the
/// process dimension).
/// Consumers: TUI overview/detail pages and the plain/JSON reports.
#[derive(Clone)]
pub struct OutboundDomainSnapshot {
    host: Arc<str>,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub selected_in_bytes: u64,
    pub selected_out_bytes: u64,
    pub rank_in_bytes: u64,
    pub rank_out_bytes: u64,
    last_seen: DateTime<Utc>,
}
impl OutboundDomainSnapshot {
    #[cfg(test)]
    pub(crate) fn new(
        host: Arc<str>,
        in_bytes: u64,
        out_bytes: u64,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self::with_rank(host, in_bytes, out_bytes, in_bytes, out_bytes, last_seen)
    }
    #[cfg(test)]
    pub(crate) fn with_rank(
        host: Arc<str>,
        in_bytes: u64,
        out_bytes: u64,
        rank_in_bytes: u64,
        rank_out_bytes: u64,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self::with_rank_and_selected(
            host,
            in_bytes,
            out_bytes,
            rank_in_bytes,
            rank_out_bytes,
            rank_in_bytes,
            rank_out_bytes,
            last_seen,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_rank_and_selected(
        host: Arc<str>,
        in_bytes: u64,
        out_bytes: u64,
        selected_in_bytes: u64,
        selected_out_bytes: u64,
        rank_in_bytes: u64,
        rank_out_bytes: u64,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self {
            host,
            in_bytes,
            out_bytes,
            selected_in_bytes,
            selected_out_bytes,
            rank_in_bytes,
            rank_out_bytes,
            last_seen,
        }
    }
    pub(crate) fn host(&self) -> &str {
        &self.host
    }
    pub(crate) fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }
    #[cfg(test)]
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
    /// Attribution record carrying evidence sources (snapshot / probe /
    /// history; ADR 0013 history engine).
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
                    key.path,
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
fn average_rank_bytes(bytes: u64, window: RankWindow, coverage_seconds: u64) -> u64 {
    if window == RankWindow::Cumulative {
        bytes
    } else {
        bytes.checked_div(coverage_seconds).unwrap_or_default()
    }
}
fn average_rank_traffic(
    traffic: ProcTraffic,
    window: RankWindow,
    coverage_seconds: u64,
) -> ProcTraffic {
    ProcTraffic {
        recv: average_rank_bytes(traffic.recv, window, coverage_seconds),
        sent: average_rank_bytes(traffic.sent, window, coverage_seconds),
    }
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Flow;
    use chrono::Duration;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
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

    // ── outbound-domain dimension ────────────────────────────────────

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
