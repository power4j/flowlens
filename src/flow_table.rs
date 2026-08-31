//! Connection-level domain flow table.
//!
//! A moka sync cache mapping 5-tuples to domain-parse results: the first
//! parse and its bounded retries populate the table per TCP connection, and
//! later packets go straight to lookup. A NoDomain hit allows another parse
//! while under the retry cap; past the cap parsing is skipped and the domain
//! stays None. When full, entries are evicted by moka's W-TinyLFU; the idle
//! timeout (default 5 minutes) comes from moka's native time_to_idle — no
//! hand-rolled eviction logic.
//!
//! No TCP state tracking (FIN/RST): 5-tuple reuse with a low probability of
//! mis-attribution is an accepted boundary. There is no Pending state: a
//! miss (no entry) means "not parsed yet", and the caller performs the
//! parse and writes Resolved/NoDomain. Skipping the Pending window keeps
//! the state machine simple.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;

/// Default table capacity (65,536 entries ~ 6MB, acceptable on a 1GB server).
pub const DEFAULT_FLOW_TABLE_CAPACITY: u64 = 65_536;

/// Default idle timeout (5 minutes, a typical TCP connection lifetime).
pub const DEFAULT_TTI: Duration = Duration::from_secs(5 * 60);

/// Maximum domain parses performed per TCP connection (including the first).
pub const MAX_NO_DOMAIN_PARSE_ATTEMPTS: u8 = 3;

/// The 5-tuple key of a TCP connection.
///
/// TCP flows only (the constructor filters): equivalent to (local IP, local
/// port, peer IP, peer port, TCP). UDP and non-TCP/UDP traffic never enters
/// the flow table.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
}

/// Domain-parse result.
///
/// No Pending variant: a miss (no entry in the table) means "not parsed
/// yet"; the caller performs the parse and writes Resolved or NoDomain.
#[derive(Clone, Debug)]
pub enum FlowEntry {
    /// Parse succeeded; carries the domain (Arc-shared, cheap to clone).
    Resolved(Arc<str>),
    /// Most recent parse failure; `attempts` counts the parses performed so
    /// far. No further retries once [`MAX_NO_DOMAIN_PARSE_ATTEMPTS`] is
    /// reached, so long-lived connections are not parsed forever.
    NoDomain { attempts: u8 },
}

/// Connection-level flow table: 5-tuple → domain-parse result.
///
/// Backed by a moka sync `Cache` (thread-safe; cloning to share across
/// threads is cheap). Configured with `max_capacity` (W-TinyLFU eviction
/// when full) + `time_to_idle` (idle-timeout eviction). Expiry and eviction
/// run lazily in moka's maintenance task on the caller's thread — `lookup`
/// triggers the expiry check (returning None), while the actual removal may
/// lag slightly; tests and production can call
/// [`FlowTable::run_pending_tasks`] to clean up immediately.
pub struct FlowTable {
    cache: Cache<FlowKey, FlowEntry>,
}

impl FlowTable {
    /// Build a table with the defaults (capacity 65,536, TTI 5 minutes).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_FLOW_TABLE_CAPACITY)
    }

    /// Use the given capacity with the default 5-minute TTI.
    pub fn with_capacity(capacity: u64) -> Self {
        Self::with_capacity_and_tti(capacity, DEFAULT_TTI)
    }

    /// Inject both capacity and TTI (tests and CLI).
    pub fn with_capacity_and_tti(capacity: u64, tti: Duration) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_idle(tti)
                .build(),
        }
    }

    /// Look up (refreshes the idle timer); returns None on miss or expiry.
    ///
    /// Note: this must use `get`, not `contains_key` — the latter does not
    /// refresh the idle timer, so under TTI it would evict entries early.
    pub fn lookup(&self, key: &FlowKey) -> Option<FlowEntry> {
        self.cache.get(key)
    }

    /// Write a Resolved entry (first-packet parse succeeded).
    pub fn insert_resolved(&self, key: FlowKey, domain: Arc<str>) {
        self.cache.insert(key, FlowEntry::Resolved(domain));
    }

    /// Write a one-attempt parse-failure entry. Later packets can still trigger parses under the cap.
    pub fn insert_no_domain(&self, key: FlowKey) {
        self.cache.insert(key, FlowEntry::NoDomain { attempts: 1 });
    }

    /// Record one more parse failure on a cache hit, for the caller's retry-cap logic.
    pub fn record_no_domain_attempt(&self, key: FlowKey) {
        let Some(FlowEntry::NoDomain { attempts }) = self.cache.get(&key) else {
            return;
        };
        let attempts = attempts.saturating_add(1).min(MAX_NO_DOMAIN_PARSE_ATTEMPTS);
        self.cache.insert(key, FlowEntry::NoDomain { attempts });
    }

    /// Run moka's pending maintenance (callable from tests and production,
    /// to speed up the physical removal of expired entries).
    #[allow(dead_code)]
    pub fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks();
    }

    /// Current entry count (best-effort; removal of expired entries may lag slightly).
    #[allow(dead_code)]
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build a test FlowKey (distinguished by the suffix).
    fn key(suffix: u8) -> FlowKey {
        FlowKey {
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            local_port: 10_000 + u16::from(suffix),
            peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, suffix)),
            peer_port: 443,
        }
    }

    // ── first-packet insert / lookup hit ─────────────────────────────

    #[test]
    fn empty_table_lookup_returns_none() {
        let table = FlowTable::new();
        assert!(table.lookup(&key(1)).is_none());
    }

    #[test]
    fn insert_resolved_then_lookup_returns_entry() {
        let table = FlowTable::new();
        let k = key(1);
        table.insert_resolved(k.clone(), Arc::from("example.com"));

        match table.lookup(&k) {
            Some(FlowEntry::Resolved(d)) => assert_eq!(d.as_ref(), "example.com"),
            other => panic!("期望 Resolved，得到 {other:?}"),
        }
    }

    #[test]
    fn insert_no_domain_then_lookup_returns_no_domain() {
        let table = FlowTable::new();
        let k = key(2);
        table.insert_no_domain(k.clone());

        assert!(matches!(
            table.lookup(&k),
            Some(FlowEntry::NoDomain { attempts: 1 })
        ));
    }

    // ── NoDomain bounded retries: the table counts attempts, the caller decides ──

    #[test]
    fn no_domain_entry_tracks_bounded_parse_attempts() {
        let table = FlowTable::new();
        let k = key(3);
        table.insert_no_domain(k.clone());

        assert!(matches!(
            table.lookup(&k),
            Some(FlowEntry::NoDomain { attempts: 1 })
        ));
        table.record_no_domain_attempt(k.clone());
        assert!(matches!(
            table.lookup(&k),
            Some(FlowEntry::NoDomain { attempts: 2 })
        ));
        table.record_no_domain_attempt(k.clone());
        table.record_no_domain_attempt(k.clone());
        assert!(matches!(
            table.lookup(&k),
            Some(FlowEntry::NoDomain {
                attempts: MAX_NO_DOMAIN_PARSE_ATTEMPTS
            })
        ));
        table.record_no_domain_attempt(k.clone());
        assert!(matches!(
            table.lookup(&k),
            Some(FlowEntry::NoDomain {
                attempts: MAX_NO_DOMAIN_PARSE_ATTEMPTS
            })
        ));
    }

    // ── idle-timeout eviction ────────────────────────────────────────

    #[test]
    fn idle_entry_expires_after_tti() {
        let table = FlowTable::with_capacity_and_tti(100, Duration::from_millis(75));
        let k = key(4);
        table.insert_resolved(k.clone(), Arc::from("example.com"));
        assert!(table.lookup(&k).is_some());

        std::thread::sleep(Duration::from_millis(120));
        table.run_pending_tasks();

        assert!(table.lookup(&k).is_none(), "TTI 过期后应淘汰");
    }

    #[test]
    fn accessed_entries_reset_idle_timer() {
        // TTI=500ms; each access refreshes the idle timer, so three consecutive 100ms sleeps (< 500ms) should all hit.
        let table = FlowTable::with_capacity_and_tti(100, Duration::from_millis(500));
        let k = key(5);
        table.insert_resolved(k.clone(), Arc::from("example.com"));

        std::thread::sleep(Duration::from_millis(100));
        assert!(table.lookup(&k).is_some(), "首次访问应命中");
        std::thread::sleep(Duration::from_millis(100));
        assert!(table.lookup(&k).is_some(), "TTI 应被 get 重置");
        std::thread::sleep(Duration::from_millis(100));
        assert!(table.lookup(&k).is_some(), "连续访问仍应命中");
    }

    // ── full-table fallback (W-TinyLFU, native to moka) ──────────────

    #[test]
    fn table_capacity_bounds_entry_count() {
        // moka uses W-TinyLFU; the requirement is only to bound the table
        // when full, not which entry gets evicted. Assert the count stays
        // within max_capacity rather than which key was evicted.
        let capacity = 8;
        let table = FlowTable::with_capacity_and_tti(capacity, Duration::from_secs(3600));

        for i in 0..(capacity + 5) {
            table.insert_resolved(key(i as u8), Arc::from("example.com"));
        }
        table.run_pending_tasks();

        let count = table.entry_count();
        assert!(
            count <= capacity,
            "条目数 {count} 应受容量上限 {capacity} 约束"
        );
    }

    // ── 5-tuple reuse ───────────────────────────────────────────────

    #[test]
    fn same_five_tuple_shares_entry() {
        let table = FlowTable::new();
        let k = key(7);
        table.insert_resolved(k.clone(), Arc::from("example.com"));

        for _ in 0..3 {
            let entry = table.lookup(&k).expect("已写入");
            match entry {
                FlowEntry::Resolved(d) => assert_eq!(d.as_ref(), "example.com"),
                _ => panic!("应命中 Resolved"),
            }
        }
    }

    #[test]
    fn different_five_tuples_are_distinct_entries() {
        let table = FlowTable::new();
        table.insert_resolved(key(10), Arc::from("a.com"));
        table.insert_resolved(key(11), Arc::from("b.com"));

        match table.lookup(&key(10)) {
            Some(FlowEntry::Resolved(d)) => assert_eq!(d.as_ref(), "a.com"),
            _ => panic!("k10 应为 a.com"),
        }
        match table.lookup(&key(11)) {
            Some(FlowEntry::Resolved(d)) => assert_eq!(d.as_ref(), "b.com"),
            _ => panic!("k11 应为 b.com"),
        }
    }

    #[test]
    fn default_table_is_constructible() {
        let _table = FlowTable::default();
    }
}
