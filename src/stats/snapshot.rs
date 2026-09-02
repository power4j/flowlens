//! Immutable traffic snapshots published to consumers.

use super::ranking::RankingSnapshot;
use crate::capture::{LocalSocket, TransportProtocol};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;

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
pub(crate) struct ProcessKey {
    pub(crate) pid: u32,
    pub(crate) path: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcFlowKey {
    pub(crate) local_ip: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote_ip: IpAddr,
    pub(crate) remote_port: u16,
    pub(crate) protocol: TransportProtocol,
}

impl ProcFlowKey {
    pub(crate) fn from_endpoint(local: LocalSocket, remote_ip: IpAddr, remote_port: u16) -> Self {
        Self {
            local_ip: local.ip,
            local_port: local.port,
            remote_ip,
            remote_port,
            protocol: local.protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProcFlowTraffic {
    pub(crate) recv: u64,
    pub(crate) sent: u64,
    pub(crate) last_seen_epoch: i64,
}

#[derive(Clone)]
pub struct ProcFlowSnapshot {
    pub(crate) local_ip: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote_ip: IpAddr,
    pub(crate) remote_port: u16,
    pub(crate) protocol: TransportProtocol,
    pub recv: u64,
    pub sent: u64,
    #[allow(dead_code)]
    pub(crate) last_seen: DateTime<Utc>,
}

impl ProcFlowSnapshot {
    pub(crate) fn total(&self) -> u64 {
        self.recv.saturating_add(self.sent)
    }
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
    pub(crate) identity: ProcessIdentity,
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
    pub(crate) last_seen: DateTime<Utc>,
    pub(crate) flows: Arc<[ProcFlowSnapshot]>,
}

#[derive(Clone)]
pub(crate) enum ProcessIdentity {
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
            flows: Arc::from([]),
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
            flows: Arc::from([]),
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
    pub(crate) last_seen: DateTime<Utc>,
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
    pub(crate) host: Arc<str>,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub selected_in_bytes: u64,
    pub selected_out_bytes: u64,
    pub rank_in_bytes: u64,
    pub rank_out_bytes: u64,
    pub(crate) last_seen: DateTime<Utc>,
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
