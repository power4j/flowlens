//! Ranking windows, IP dimension state, and rank selection algorithms.

use super::Direction;
use super::RankWindow;
use super::snapshot::ProcTraffic;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub(crate) const MAX_IP_DIMENSION_ENTRIES: usize = 16_384;

pub(crate) const IP_DIMENSION_PRUNE_BATCH: usize = 256;

pub(crate) const IP_DIMENSION_TARGET_ENTRIES: usize =
    MAX_IP_DIMENSION_ENTRIES - IP_DIMENSION_PRUNE_BATCH;

pub(crate) const IP_WINDOW_BUCKETS: usize = 5;

pub(crate) const IP_BUCKET_SECONDS: i64 = 60;

pub(crate) const IP_IDLE_WINDOWS: i64 = 3;

pub(crate) const IP_OBSERVATION_BUCKETS: u8 = 2;

pub(crate) const IP_HEAVY_SHARE_PERCENT: usize = 70;

pub(crate) const IP_RISING_SHARE_PERCENT: usize = 20;

pub(crate) const IP_HEAVY_RESERVATION: usize =
    IP_DIMENSION_TARGET_ENTRIES * IP_HEAVY_SHARE_PERCENT / 100;

pub(crate) const IP_RISING_RESERVATION: usize =
    IP_DIMENSION_TARGET_ENTRIES * IP_RISING_SHARE_PERCENT / 100;

pub(crate) const IP_OBSERVATION_RESERVATION: usize =
    IP_DIMENSION_TARGET_ENTRIES - IP_HEAVY_RESERVATION - IP_RISING_RESERVATION;

pub(crate) const RANKING_BUCKET_SECONDS: i64 = 1;

pub(crate) const RANKING_MAX_WINDOW_SECONDS: i64 = 5 * 60;

pub(crate) const MAX_RANKING_PROCESS_ENTRIES: usize = 1_000;

pub(crate) const MAX_RANKING_IP_ENTRIES: usize = 4_096;

pub(crate) const MAX_RANKING_DOMAIN_ENTRIES: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RankingWindow {
    #[default]
    Cumulative,
    Seconds(u32),
}

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
pub(crate) struct RankingBucket {
    epoch: i64,
    traffic: ProcTraffic,
}

#[derive(Clone, Default)]
pub(crate) struct RankingEntityWindow {
    buckets: Vec<RankingBucket>,
    last_seen_epoch: i64,
}

impl RankingEntityWindow {
    pub(crate) fn record(&mut self, direction: Direction, epoch: i64, bytes: u64) {
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
    pub(crate) fn add_to_traffic(traffic: &mut ProcTraffic, direction: Direction, bytes: u64) {
        match direction {
            Direction::Inbound => traffic.recv = traffic.recv.saturating_add(bytes),
            Direction::Outbound => traffic.sent = traffic.sent.saturating_add(bytes),
        }
    }
    pub(crate) fn prune(&mut self, epoch: i64) {
        let oldest = epoch - (RANKING_MAX_WINDOW_SECONDS - RANKING_BUCKET_SECONDS);
        self.buckets
            .retain(|bucket| bucket.epoch >= oldest && bucket.epoch <= epoch);
    }
    pub(crate) fn traffic(&self, epoch: i64, window_seconds: u32) -> ProcTraffic {
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

pub(crate) fn ip_sort_key(ip: IpAddr) -> (u8, [u8; 16]) {
    match ip {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[12..].copy_from_slice(&address.octets());
            (0, bytes)
        }
        IpAddr::V6(address) => (1, address.octets()),
    }
}

pub(crate) fn evict_oldest_ranking_entity<K>(store: &mut HashMap<K, RankingEntityWindow>) -> bool
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
pub(crate) enum IpTier {
    Heavy,
    Rising,
    #[default]
    Observation,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IpBucket {
    epoch: i64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IpWindowState {
    buckets: [IpBucket; IP_WINDOW_BUCKETS],
    last_bucket_epoch: i64,
    pub(crate) observed_buckets: u8,
    pub(crate) tier: IpTier,
    tier_changed_epoch: i64,
}

impl IpWindowState {
    pub(crate) fn new(epoch: i64, bytes: u64) -> Self {
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
    pub(crate) fn record(&mut self, epoch: i64, bytes: u64) {
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
    pub(crate) fn current_bucket_bytes(&self, epoch: i64) -> u64 {
        self.buckets
            .iter()
            .find(|bucket| bucket.epoch == epoch)
            .map_or(0, |bucket| bucket.bytes)
    }
    pub(crate) fn window_bytes(&self, epoch: i64) -> u64 {
        let oldest = epoch - (IP_WINDOW_BUCKETS as i64 - 1);
        self.buckets
            .iter()
            .filter(|bucket| bucket.epoch >= oldest && bucket.epoch <= epoch)
            .map(|bucket| bucket.bytes)
            .sum()
    }
    pub(crate) fn previous_window_bytes(&self, epoch: i64) -> u64 {
        let oldest = epoch - (IP_WINDOW_BUCKETS as i64 - 1);
        self.buckets
            .iter()
            .filter(|bucket| bucket.epoch >= oldest && bucket.epoch < epoch)
            .map(|bucket| bucket.bytes)
            .sum()
    }
    pub(crate) fn surge_bytes(&self, epoch: i64) -> u64 {
        self.current_bucket_bytes(epoch)
            .saturating_mul((IP_WINDOW_BUCKETS - 1) as u64)
            .saturating_sub(self.previous_window_bytes(epoch))
    }
    pub(crate) fn idle_windows(&self, epoch: i64) -> i64 {
        (epoch - self.last_bucket_epoch).max(0) / IP_WINDOW_BUCKETS as i64
    }
}

#[derive(Default)]
pub(crate) struct IpDiagnosticsCounters {
    pub(crate) promotions: u64,
    pub(crate) demotions: u64,
    pub(crate) evictions_heavy: u64,
    pub(crate) evictions_rising: u64,
    pub(crate) evictions_observation: u64,
}

/// Bidirectional rolling window (ADR 0013 process windowing): reuses the IP
/// dimension's epoch-bucket machinery — 60s buckets × `IP_WINDOW_BUCKETS` =
/// a 5-minute rolling window, split by direction.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DirectionalWindows {
    inbound: IpWindowState,
    outbound: IpWindowState,
}

impl DirectionalWindows {
    pub(crate) fn record(&mut self, direction: Direction, epoch: i64, bytes: u64) {
        match direction {
            Direction::Inbound => self.inbound.record(epoch, bytes),
            Direction::Outbound => self.outbound.record(epoch, bytes),
        }
    }
    pub(crate) fn window(&self, epoch: i64) -> ProcTraffic {
        ProcTraffic {
            recv: self.inbound.window_bytes(epoch),
            sent: self.outbound.window_bytes(epoch),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct IpCandidate {
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

pub(crate) fn bucket_epoch(observed_at: DateTime<Utc>) -> i64 {
    observed_at.timestamp().div_euclid(IP_BUCKET_SECONDS)
}

pub(crate) fn average_rank_bytes(bytes: u64, window: RankWindow, coverage_seconds: u64) -> u64 {
    if window == RankWindow::Cumulative {
        bytes
    } else {
        bytes.checked_div(coverage_seconds).unwrap_or_default()
    }
}

pub(crate) fn average_rank_traffic(
    traffic: ProcTraffic,
    window: RankWindow,
    coverage_seconds: u64,
) -> ProcTraffic {
    ProcTraffic {
        recv: average_rank_bytes(traffic.recv, window, coverage_seconds),
        sent: average_rank_bytes(traffic.sent, window, coverage_seconds),
    }
}

pub(crate) fn collect_ip_candidates(
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

pub(crate) fn desired_ip_tiers(candidates: &[IpCandidate]) -> HashMap<IpAddr, IpTier> {
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

pub(crate) fn select_rising_ips(candidates: &[IpCandidate], target: usize) -> HashSet<IpAddr> {
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

pub(crate) fn ip_tier_counts(
    windows_by_ip: &HashMap<IpAddr, IpWindowState>,
) -> (usize, usize, usize) {
    windows_by_ip.values().fold((0, 0, 0), |mut counts, state| {
        match state.tier {
            IpTier::Heavy => counts.0 += 1,
            IpTier::Rising => counts.1 += 1,
            IpTier::Observation => counts.2 += 1,
        }
        counts
    })
}

pub(crate) fn rebalance_ip_dimension(
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

pub(crate) fn tier_rank(tier: IpTier) -> u8 {
    match tier {
        IpTier::Observation => 0,
        IpTier::Rising => 1,
        IpTier::Heavy => 2,
    }
}
