//! Capture-owned connection generations, bounded handshake recovery and counters.
//! Deadline and progress indexes bound cleanup and pressure eviction work.
//! The moka adapter preserves historical single-packet parser injections;
//! production CompositeDomainParser uses the generation tracker below.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;

use crate::capture::tls_reassembly::TcpPrefix;
use crate::domain_parse::{
    DomainKind, DomainName, DomainParseResult, DomainParser, DomainReason, HelloObservation,
};
use crate::stats::Direction;
use chrono::{DateTime, Utc};

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_DELIVERY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
struct DeliveryDiagnostics {
    failures: AtomicU64,
    bytes: AtomicU64,
}

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
    tracker: Mutex<Tracker>,
    clock_origin: Instant,
}

impl FlowTable {
    #[cfg(feature = "tls-eval-observe")]
    #[allow(dead_code)]
    pub(crate) fn observe_resources(&self) -> FlowResourceSummary {
        let tracker = self.tracker.lock().unwrap();
        let mut result = FlowResourceSummary {
            entries: tracker.entries.len(),
            entries_capacity: tracker.entries.capacity(),
            deadlines: tracker.deadlines.len(),
            active_order: tracker.active_order.len(),
            raw_reserved: tracker.raw,
            metadata_reserved: tracker.metadata,
            held_cache_entries: self.cache.entry_count(),
            ..Default::default()
        };
        for entry in tracker.entries.values() {
            result.prior_isns += entry.prior_isns.iter().filter(|isn| isn.is_some()).count();
            if entry.reason.is_some() {
                result.rejected += 1;
            } else if entry.domain.is_some() {
                result.resolved += 1;
            } else if let Some(pending) = &entry.pending {
                if pending.first_payload.is_some() {
                    result.pending += 1;
                } else {
                    result.observing += 1;
                }
                result.pending_bucket_len += pending.buckets.len();
                result.pending_bucket_capacity += pending.buckets.capacity();
            }
            result.reset_tombstones += usize::from(entry.reset);
        }
        result
    }

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
            tracker: Mutex::new(Tracker::new(capacity as usize, tti)),
            clock_origin: Instant::now(),
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
        self.cache.entry_count() + self.tracker.lock().unwrap().entries.len() as u64
    }

    pub(crate) fn monotonic_now(&self) -> Duration {
        self.clock_origin.elapsed()
    }

    pub(crate) fn advance(&self, now: Duration) {
        self.tracker.lock().unwrap().advance(now);
    }

    pub(crate) fn finish(&self) {
        let mut tracker = self.tracker.lock().unwrap();
        let end = tracker.now + Duration::from_secs(10);
        tracker.advance(end);
    }

    pub(crate) fn observe(
        &self,
        key: FlowKey,
        packet: TcpObservation<'_>,
        parser: &dyn DomainParser,
    ) -> DomainEvent {
        self.tracker.lock().unwrap().observe(key, packet, parser)
    }

    #[allow(dead_code)]
    pub(crate) fn domain_diagnostics(&self) -> DomainDiagnostics {
        let tracker = self.tracker.lock().unwrap();
        DomainDiagnostics {
            started: tracker.started,
            resolved: tracker.resolved,
            public_sni_resolved: tracker.public_sni_resolved,
            active: tracker.active,
            raw_reserved: tracker.raw,
            raw_peak_reserved: tracker.peak_raw,
            metadata_reserved: tracker.metadata,
            metadata_peak_reserved: tracker.peak_metadata,
            active_peak: tracker.peak_active,
            reasons: tracker.reasons.clone(),
            delivery_failures: tracker
                .delivery_diagnostics
                .failures
                .load(Ordering::Relaxed),
            delivery_failed_bytes: tracker.delivery_diagnostics.bytes.load(Ordering::Relaxed),
        }
    }
}

#[cfg(feature = "tls-eval-observe")]
#[allow(dead_code)]
#[derive(Default, serde::Serialize)]
pub(crate) struct FlowResourceSummary {
    pub entries: usize,
    pub entries_capacity: usize,
    pub observing: usize,
    pub pending: usize,
    pub resolved: usize,
    pub rejected: usize,
    pub reset_tombstones: usize,
    pub pending_bucket_len: usize,
    pub pending_bucket_capacity: usize,
    pub deadlines: usize,
    pub active_order: usize,
    pub prior_isns: usize,
    pub raw_reserved: usize,
    pub metadata_reserved: usize,
    pub held_cache_entries: u64,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DomainDiagnostics {
    pub started: u64,
    pub resolved: u64,
    pub public_sni_resolved: u64,
    pub active: usize,
    pub raw_reserved: usize,
    pub raw_peak_reserved: usize,
    pub metadata_reserved: usize,
    pub metadata_peak_reserved: usize,
    pub active_peak: usize,
    pub reasons: HashMap<DomainReason, u64>,
    pub delivery_failures: u64,
    pub delivery_failed_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoleEvidence {
    Unknown,
    ConfirmedLocalInitiator,
    RemoteInitiator,
    TlsClientInferred,
    HttpClientInferred,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DomainBucket {
    pub epoch: i64,
    pub recv: u64,
    pub sent: u64,
}

#[derive(Debug)]
pub(crate) struct DomainBackfill {
    pub generation: u64,
    pub delivery_id: u64,
    pub recv: u64,
    pub sent: u64,
    pub buckets: Vec<DomainBucket>,
    pub last_seen: DateTime<Utc>,
    pub delivered: AtomicBool,
    delivery_diagnostics: Arc<DeliveryDiagnostics>,
}

impl Drop for DomainBackfill {
    fn drop(&mut self) {
        if !self.delivered.load(Ordering::Relaxed) {
            self.delivery_diagnostics
                .failures
                .fetch_add(1, Ordering::Relaxed);
            self.delivery_diagnostics
                .bytes
                .fetch_add(self.recv + self.sent, Ordering::Relaxed);
            eprintln!(
                "DomainBackfillDeliveryFailed generation={} bytes={}",
                self.generation,
                self.recv + self.sent
            );
        }
    }
}

#[derive(Debug)]
pub(crate) struct DomainEvent {
    pub generation: u64,
    #[allow(dead_code)] // Capture audit metadata; deliberately never carries payload.
    pub role: RoleEvidence,
    #[allow(dead_code)]
    pub observation: Option<HelloObservation>,
    pub reason: Option<DomainReason>,
    #[allow(dead_code)]
    pub state: DomainState,
    pub observed_at: DateTime<Utc>,
    pub domain: Option<DomainName>,
    pub backfill: Option<DomainBackfill>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainState {
    Observing,
    Pending,
    Resolved,
    Rejected(DomainReason),
}

pub(crate) struct TcpObservation<'a> {
    pub direction: Direction,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
    pub bytes: u64,
    pub observed_at: DateTime<Utc>,
    pub now: Duration,
}

#[derive(Default)]
struct PendingDomain {
    prefix: TcpPrefix,
    first_payload: Option<Duration>,
    progress_at: Duration,
    recv: u64,
    sent: u64,
    buckets: Vec<DomainBucket>,
    last_seen: Option<DateTime<Utc>>,
    http_mode: bool,
    http_attempts: u8,
}

impl PendingDomain {
    fn allocation(&self) -> usize {
        std::mem::size_of::<Self>() + self.buckets.capacity() * std::mem::size_of::<DomainBucket>()
    }
    fn record(&mut self, packet: &TcpObservation<'_>) {
        match packet.direction {
            Direction::Inbound => self.recv += packet.bytes,
            Direction::Outbound => self.sent += packet.bytes,
        }
        self.last_seen = Some(
            self.last_seen
                .map_or(packet.observed_at, |old| old.max(packet.observed_at)),
        );
        let epoch = packet.observed_at.timestamp();
        if let Some(bucket) = self.buckets.iter_mut().find(|bucket| bucket.epoch == epoch) {
            match packet.direction {
                Direction::Inbound => bucket.recv += packet.bytes,
                Direction::Outbound => bucket.sent += packet.bytes,
            }
        } else {
            if self.buckets.len() == 311 {
                let oldest = self
                    .buckets
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, bucket)| bucket.epoch)
                    .unwrap()
                    .0;
                if self.buckets[oldest].epoch > epoch {
                    return;
                }
                self.buckets.swap_remove(oldest);
            }
            self.buckets.reserve_exact(1);
            self.buckets.push(DomainBucket {
                epoch,
                recv: if packet.direction == Direction::Inbound {
                    packet.bytes
                } else {
                    0
                },
                sent: if packet.direction == Direction::Outbound {
                    packet.bytes
                } else {
                    0
                },
            });
        }
    }
}

struct Connection {
    generation: u64,
    role: RoleEvidence,
    isn: Option<(Direction, u32)>,
    prior_isns: [Option<(Direction, u32)>; 4],
    starts: [Option<u32>; 2],
    high: [Option<u32>; 2],
    previous: [Option<u32>; 2],
    fins: [Option<u32>; 2],
    created: Duration,
    deadline: Duration,
    pending: Option<Box<PendingDomain>>,
    observation: Option<HelloObservation>,
    domain: Option<DomainName>,
    reason: Option<DomainReason>,
    reset: bool,
}

impl Connection {
    fn reject(&mut self, reason: DomainReason) {
        self.reason = Some(reason);
        self.pending = None;
        self.domain = None;
    }
    fn event(&self, at: DateTime<Utc>) -> DomainEvent {
        DomainEvent {
            generation: self.generation,
            role: self.role,
            observation: self.observation.clone(),
            reason: self.reason,
            state: if let Some(reason) = self.reason {
                DomainState::Rejected(reason)
            } else if self.domain.is_some() {
                DomainState::Resolved
            } else if self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.first_payload.is_some())
            {
                DomainState::Pending
            } else {
                DomainState::Observing
            },
            observed_at: at,
            domain: self.domain.clone(),
            backfill: None,
        }
    }
}

struct Tracker {
    entries: HashMap<FlowKey, Connection>,
    deadlines: BTreeMap<(Duration, u64), FlowKey>,
    active_order: BTreeMap<(Duration, u64), FlowKey>,
    started: u64,
    resolved: u64,
    public_sni_resolved: u64,
    peak_raw: usize,
    peak_metadata: usize,
    peak_active: usize,
    delivery_diagnostics: Arc<DeliveryDiagnostics>,
    capacity: usize,
    tti: Duration,
    now: Duration,
    raw: usize,
    metadata: usize,
    active: usize,
    reasons: HashMap<DomainReason, u64>,
}

impl Tracker {
    fn new(capacity: usize, tti: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            deadlines: BTreeMap::new(),
            active_order: BTreeMap::new(),
            started: 0,
            resolved: 0,
            public_sni_resolved: 0,
            peak_raw: 0,
            peak_metadata: 0,
            peak_active: 0,
            delivery_diagnostics: Arc::default(),
            capacity: capacity.max(1),
            tti,
            now: Duration::ZERO,
            raw: 0,
            metadata: 0,
            active: 0,
            reasons: HashMap::new(),
        }
    }
    fn allocations(entry: &Connection) -> (usize, usize, usize) {
        // Reserve index/map/node overhead conservatively in addition to actual
        // counter-vector capacity. Resolved/tombstone entries have a separate cap.
        entry.pending.as_ref().map_or((0, 0, 0), |pending| {
            (pending.prefix.allocation(), pending.allocation() + 2048, 1)
        })
    }
    fn remove(&mut self, key: &FlowKey) -> Option<Connection> {
        let entry = self.entries.remove(key)?;
        self.deadlines.remove(&(entry.deadline, entry.generation));
        if let Some(pending) = entry.pending.as_ref() {
            self.active_order
                .remove(&(pending.progress_at, entry.generation));
        }
        let (raw, metadata, active) = Self::allocations(&entry);
        self.raw -= raw;
        self.metadata -= metadata;
        self.active -= active;
        Some(entry)
    }
    fn store(&mut self, key: FlowKey, entry: Connection) {
        let (raw, metadata, active) = Self::allocations(&entry);
        self.raw += raw;
        self.metadata += metadata;
        self.active += active;
        self.peak_raw = self.peak_raw.max(self.raw);
        self.peak_metadata = self.peak_metadata.max(self.metadata);
        self.peak_active = self.peak_active.max(self.active);
        self.deadlines
            .insert((entry.deadline, entry.generation), key.clone());
        if let Some(pending) = entry.pending.as_ref() {
            self.active_order
                .insert((pending.progress_at, entry.generation), key.clone());
        }
        self.entries.insert(key, entry);
    }
    fn count_reason(&mut self, reason: DomainReason) {
        *self.reasons.entry(reason).or_default() += 1;
    }
    fn advance(&mut self, now: Duration) {
        self.now = self.now.max(now);
        while self
            .deadlines
            .first_key_value()
            .is_some_and(|((deadline, _), _)| *deadline <= self.now)
        {
            let (_, key) = self.deadlines.pop_first().unwrap();
            if let Some(mut entry) = self.remove(&key)
                && let Some(pending) = entry.pending.as_ref()
            {
                let reason = if pending.first_payload.is_none() {
                    DomainReason::ObservationTimeout
                } else if pending.prefix.has_gap() {
                    DomainReason::GapAtDeadline
                } else {
                    DomainReason::HandshakeTimeout
                };
                entry.reject(reason);
                self.count_reason(reason);
                entry.deadline = self.now + self.tti;
                self.store(key, entry);
            }
        }
    }
    fn evict_active(&mut self) -> bool {
        let key = self
            .active_order
            .first_key_value()
            .map(|(_, key)| key.clone());
        let Some(key) = key else {
            return false;
        };
        let mut entry = self.remove(&key).unwrap();
        entry.reject(DomainReason::GlobalBudgetEvicted);
        entry.deadline = self.now + self.tti;
        self.count_reason(DomainReason::GlobalBudgetEvicted);
        self.store(key, entry);
        true
    }
    fn observe(
        &mut self,
        key: FlowKey,
        packet: TcpObservation<'_>,
        parser: &dyn DomainParser,
    ) -> DomainEvent {
        self.advance(packet.now);
        let side = usize::from(packet.direction == Direction::Inbound);
        let new_syn = packet.syn && !packet.ack;
        if new_syn
            && let Some(current) = self.entries.get(&key)
            && current
                .prior_isns
                .contains(&Some((packet.direction, packet.sequence)))
        {
            let mut event = current.event(packet.observed_at);
            event.domain = None;
            event.reason = Some(DomainReason::GenerationAmbiguous);
            return event;
        }
        let replacing = new_syn
            && self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.isn != Some((packet.direction, packet.sequence)));
        let mut previous = [None; 2];
        let mut prior_isns = [None; 4];
        if replacing && let Some(old) = self.remove(&key) {
            previous = old.high;
            prior_isns = old.prior_isns;
            if let Some(isn) = old.isn {
                prior_isns.rotate_right(1);
                prior_isns[0] = Some(isn);
            }
            if old.pending.is_some() {
                self.count_reason(DomainReason::GenerationReplaced);
            }
        }
        let mut entry = if let Some(entry) = self.remove(&key) {
            entry
        } else {
            while self.active >= 4096 || self.metadata + 4096 > 16 * 1024 * 1024 {
                if !self.evict_active() {
                    break;
                }
            }
            if self.entries.len() >= self.capacity
                && let Some((_, oldest)) = self.deadlines.pop_first()
                && let Some(old) = self.remove(&oldest)
                && old.pending.is_some()
            {
                self.count_reason(DomainReason::GlobalBudgetEvicted);
            }
            let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
            self.started += 1;
            Connection {
                generation,
                role: RoleEvidence::Unknown,
                isn: None,
                prior_isns,
                starts: [None; 2],
                high: [None; 2],
                previous,
                fins: [None; 2],
                created: self.now,
                deadline: self.now + Duration::from_secs(5),
                pending: Some(Box::new(PendingDomain {
                    progress_at: self.now,
                    ..PendingDomain::default()
                })),
                observation: None,
                domain: None,
                reason: None,
                reset: false,
            }
        };
        if new_syn {
            entry.isn = Some((packet.direction, packet.sequence));
            entry.role = if side == 0 {
                RoleEvidence::ConfirmedLocalInitiator
            } else {
                RoleEvidence::RemoteInitiator
            };
        }
        if packet.syn {
            entry.starts[side] = Some(packet.sequence.wrapping_add(1));
        }
        if entry.role == RoleEvidence::RemoteInitiator && entry.pending.is_some() {
            entry.reject(DomainReason::NonTargetProtocol);
            self.count_reason(DomainReason::NonTargetProtocol);
        }
        let sequence = packet.sequence.wrapping_add(u32::from(packet.syn));
        let end = sequence.wrapping_add(packet.payload.len() as u32);
        let ambiguous = !packet.syn
            && (entry.starts[side].is_some_and(|start| (sequence.wrapping_sub(start) as i32) < 0)
                || entry.high[side].is_some_and(|high| {
                    (sequence.wrapping_sub(high) as i32).unsigned_abs() > 1024 * 1024
                })
                || entry.previous[side].is_some_and(|old| {
                    (sequence.wrapping_sub(old) as i32).unsigned_abs() < 128 * 1024
                })
                || (packet.ack
                    && entry.starts[1 - side].is_some_and(|start| {
                        (packet.acknowledgment.wrapping_sub(start) as i32) < 0
                    }))
                || (!packet.payload.is_empty()
                    && entry.fins[side].is_some_and(|fin| (end.wrapping_sub(fin) as i32) > 0)));
        if ambiguous || entry.reset {
            let mut event = entry.event(packet.observed_at);
            event.domain = None;
            event.reason = Some(DomainReason::GenerationAmbiguous);
            self.store(key, entry);
            return event;
        }
        if entry.high[side].is_none_or(|high| (end.wrapping_sub(high) as i32) > 0) {
            entry.high[side] = Some(end);
        }
        if packet.fin {
            entry.fins[side] = Some(end);
        }
        let mut backfill = None;
        if let Some(pending) = entry.pending.as_mut() {
            if side == 0 && !packet.payload.is_empty() && !packet.rst {
                pending.first_payload.get_or_insert(self.now);
                if pending.prefix.origin_unset() {
                    pending.prefix = TcpPrefix::with_origin(entry.starts[0]);
                }
                // HTTP stays a single-packet parser. TLS only consumes the TCP
                // continuous prefix, never scans later bytes for a record boundary.
                let http =
                    crate::domain_parse_http::HttpDomainParser::is_request_prefix(packet.payload)
                        || [
                            b"GET ".as_slice(),
                            b"POST ",
                            b"HEAD ",
                            b"PUT ",
                            b"DELETE ",
                            b"CONNECT ",
                            b"OPTIONS ",
                            b"TRACE ",
                            b"PATCH ",
                        ]
                        .iter()
                        .any(|method| packet.payload.starts_with(method));
                let result = if pending.http_mode
                    || (http
                        && pending.prefix.is_empty()
                        && entry.starts[0].is_none_or(|start| start == sequence))
                {
                    pending.http_mode = true;
                    pending.http_attempts += 1;
                    match parser.parse_result(packet.payload) {
                        DomainParseResult::Rejected(DomainReason::NonTargetProtocol)
                            if pending.http_attempts < MAX_NO_DOMAIN_PARSE_ATTEMPTS =>
                        {
                            DomainParseResult::NeedMore
                        }
                        result => result,
                    }
                } else {
                    let required = packet.payload.len() * 3 + 2048;
                    while self.raw + pending.prefix.allocation() + required > 32 * 1024 * 1024 {
                        if !self.evict_active() {
                            break;
                        }
                    }
                    match pending.prefix.insert(
                        sequence,
                        packet.payload,
                        (32 * 1024 * 1024usize)
                            .saturating_sub(self.raw + pending.prefix.allocation()),
                    ) {
                        Ok(progress) => {
                            self.peak_raw =
                                self.peak_raw.max(self.raw + pending.prefix.allocation());
                            if progress {
                                pending.progress_at = self.now;
                            }
                            pending.prefix.fresh_prefix().map_or(
                                DomainParseResult::NeedMore,
                                |prefix| {
                                    if entry.starts[0].is_none()
                                        && prefix.first() != Some(&22)
                                        && !(prefix.len() >= 5
                                            && (20..=23).contains(&prefix[0])
                                            && prefix[1] == 3)
                                    {
                                        DomainParseResult::NeedMore
                                    } else {
                                        parser.parse_result(&prefix)
                                    }
                                },
                            )
                        }
                        Err(reason) => DomainParseResult::Rejected(reason),
                    }
                };
                match result {
                    DomainParseResult::NeedMore => {}
                    DomainParseResult::Rejected(reason) => {
                        entry.reject(reason);
                        self.count_reason(reason);
                    }
                    DomainParseResult::Complete(hello) => {
                        let reason = if hello.observed_sni.is_none() {
                            Some(DomainReason::NoSni)
                        } else {
                            None
                        };
                        entry.observation = Some(hello.clone());
                        if let Some(reason) = reason {
                            entry.reject(reason);
                            self.count_reason(reason);
                        } else {
                            if entry.role == RoleEvidence::Unknown {
                                entry.role = if packet.payload[0] == 22 || pending.prefix.is_tls() {
                                    RoleEvidence::TlsClientInferred
                                } else {
                                    RoleEvidence::HttpClientInferred
                                };
                            }
                            entry.domain = hello.visible_name();
                            if entry
                                .domain
                                .as_ref()
                                .is_some_and(|name| name.kind() == DomainKind::PublicSni)
                            {
                                self.public_sni_resolved += 1;
                            }
                            let pending = entry.pending.take().unwrap();
                            backfill = pending.last_seen.map(|last_seen| DomainBackfill {
                                generation: entry.generation,
                                delivery_id: NEXT_DELIVERY.fetch_add(1, Ordering::Relaxed),
                                recv: pending.recv,
                                sent: pending.sent,
                                buckets: pending.buckets,
                                last_seen,
                                delivered: AtomicBool::new(false),
                                delivery_diagnostics: self.delivery_diagnostics.clone(),
                            });
                            self.resolved += 1;
                        }
                    }
                }
            }
            if let Some(pending) = entry.pending.as_mut() {
                if self.metadata + pending.allocation() + 4096 > 16 * 1024 * 1024 {
                    entry.reject(DomainReason::GlobalBudgetEvicted);
                    self.count_reason(DomainReason::GlobalBudgetEvicted);
                } else {
                    pending.record(&packet);
                }
            }
        }
        let mut event = entry.event(packet.observed_at);
        event.backfill = backfill;
        if packet.rst {
            entry.reset = true;
            if entry.pending.is_some() {
                entry.reject(DomainReason::ClosedBeforeHello);
                self.count_reason(DomainReason::ClosedBeforeHello);
            }
            if event.domain.is_none() {
                event.reason = entry.reason;
                event.state = entry.event(packet.observed_at).state;
            }
        }
        entry.deadline = if let Some(pending) = entry.pending.as_ref() {
            pending
                .first_payload
                .map_or(entry.created + Duration::from_secs(5), |first| {
                    (first + Duration::from_secs(5))
                        .min(entry.created + Duration::from_secs(10))
                        .min(pending.progress_at + Duration::from_secs(2))
                })
        } else if entry.reset || entry.fins.iter().all(Option::is_some) {
            self.now + Duration::from_secs(2)
        } else {
            self.now + self.tti
        };
        self.store(key, entry);
        event
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
