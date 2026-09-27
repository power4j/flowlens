//! Default-off development observations of the actual domain stores.

use super::{RankingEntityWindow, Stats};
use crate::domain_parse::DomainKind;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Default, Serialize)]
pub(crate) struct DomainStoreSummary {
    pub cumulative_len: usize,
    pub cumulative_capacity: usize,
    pub ordinary_len: usize,
    pub public_sni_len: usize,
    pub name_bytes: usize,
    pub recv: u64,
    pub sent: u64,
    pub ordinary_recv: u64,
    pub ordinary_sent: u64,
    pub public_sni_recv: u64,
    pub public_sni_sent: u64,
    pub last_seen_len: usize,
    pub last_seen_capacity: usize,
    pub last_seen_min: Option<i64>,
    pub last_seen_max: Option<i64>,
    pub rank_len: usize,
    pub rank_capacity: usize,
    pub bucket_len: usize,
    pub bucket_capacity: usize,
    pub rank_epoch: Option<i64>,
    pub last_backfill_delivery: u64,
    pub rank_window_evictions: u64,
    pub windows: Vec<DomainWindowSummary>,
}

#[derive(Default, Serialize)]
pub(crate) struct DomainWindowSummary {
    pub seconds: u32,
    pub ordinary_active: usize,
    pub public_sni_active: usize,
    pub recv: u64,
    pub sent: u64,
}

#[derive(Serialize)]
pub(crate) struct DomainStoreRow<'a> {
    pub name: &'a str,
    pub kind: &'static str,
    pub recv: u64,
    pub sent: u64,
    pub last_seen: Option<i64>,
    pub rank_last_seen_epoch: Option<i64>,
    pub bucket_capacity: usize,
    pub buckets: Vec<DomainBucketRow>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DomainBucketRow {
    pub epoch: i64,
    pub recv: u64,
    pub sent: u64,
}

impl Stats {
    /// Fixed-size output, no names cloned or sorted; scans cumulative state and
    /// at most the retained 4096 ranking entities. Does not prune any store.
    pub(crate) fn observe_domain_summary(&self, now: DateTime<Utc>) -> DomainStoreSummary {
        let mut summary = DomainStoreSummary {
            cumulative_len: self.by_domain.len(),
            cumulative_capacity: self.by_domain.capacity(),
            last_seen_len: self.domain_last_seen.len(),
            last_seen_capacity: self.domain_last_seen.capacity(),
            rank_len: self.rank_domain.len(),
            rank_capacity: self.rank_domain.capacity(),
            rank_epoch: self.domain_rank_epoch,
            last_backfill_delivery: self.last_domain_backfill_delivery,
            rank_window_evictions: self.rank_window_evictions,
            ..Default::default()
        };
        for (name, traffic) in &self.by_domain {
            match name.kind() {
                DomainKind::Ordinary => {
                    summary.ordinary_len += 1;
                    summary.ordinary_recv += traffic.recv;
                    summary.ordinary_sent += traffic.sent;
                }
                DomainKind::PublicSni => {
                    summary.public_sni_len += 1;
                    summary.public_sni_recv += traffic.recv;
                    summary.public_sni_sent += traffic.sent;
                }
            }
            summary.name_bytes += name.name().len();
            summary.recv += traffic.recv;
            summary.sent += traffic.sent;
        }
        for at in self.domain_last_seen.values().map(DateTime::timestamp) {
            summary.last_seen_min = Some(summary.last_seen_min.map_or(at, |old| old.min(at)));
            summary.last_seen_max = Some(summary.last_seen_max.map_or(at, |old| old.max(at)));
        }
        for window in self.rank_domain.values() {
            let (len, capacity, _) = window.observe_storage();
            summary.bucket_len += len;
            summary.bucket_capacity += capacity;
        }
        summary.windows = [5, 10, 30, 60, 300]
            .into_iter()
            .map(|seconds| {
                let mut row = DomainWindowSummary {
                    seconds,
                    ..Default::default()
                };
                for (name, window) in &self.rank_domain {
                    let epoch = self
                        .domain_rank_epoch
                        .map_or(now.timestamp(), |at| at.max(now.timestamp()));
                    let traffic = window.traffic(epoch, seconds);
                    if traffic.recv > 0 || traffic.sent > 0 {
                        match name.kind() {
                            DomainKind::Ordinary => row.ordinary_active += 1,
                            DomainKind::PublicSni => row.public_sni_active += 1,
                        }
                    }
                    row.recv += traffic.recv;
                    row.sent += traffic.sent;
                }
                row
            })
            .collect();
        summary
    }

    /// Full audit is explicit and intended for small fixtures or after timing.
    /// Names borrow the real keys; buckets copy the real stored epoch counters.
    pub(crate) fn observe_domain_rows(&self) -> impl Iterator<Item = DomainStoreRow<'_>> {
        self.by_domain.iter().map(|(name, traffic)| {
            let rank = self.rank_domain.get(name);
            DomainStoreRow {
                name: name.name(),
                kind: match name.kind() {
                    DomainKind::Ordinary => "ordinary",
                    DomainKind::PublicSni => "public_sni",
                },
                recv: traffic.recv,
                sent: traffic.sent,
                last_seen: self.domain_last_seen.get(name).map(DateTime::timestamp),
                rank_last_seen_epoch: rank.map(|window| window.observe_storage().2),
                bucket_capacity: rank.map_or(0, |window| window.observe_storage().1),
                buckets: rank.map_or_else(Vec::new, |window: &RankingEntityWindow| {
                    window
                        .observe_buckets()
                        .map(|(epoch, recv, sent)| DomainBucketRow { epoch, recv, sent })
                        .collect()
                }),
            }
        })
    }
}
