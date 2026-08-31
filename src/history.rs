//! socket→PID interval log and history-based attribution (ADR 0013 history
//! engine).
//!
//! The operating system can only answer attribution for connections that
//! exist "now". Once a short-lived connection disappears inside the probe
//! window, the only evidence is that some proc_table generation once
//! observed it. The interval log records each generation's socket→PID
//! mappings as [valid_from, valid_to] intervals, and final-time attribution
//! looks them up by the flow's observation time. Recovered candidates must
//! pass the PID start-time hard gate — when a candidate's start time cannot
//! be verified or is later than the flow's observation time, it is rejected
//! outright, preventing PID reuse from producing wrong attribution (a wrong
//! attribution is worse than an unknown one).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};

use crate::capture::LocalSocket;
use crate::proc_table::{ProcInfo, SocketKey};
use crate::stats::ObservedProcess;

/// Default retention: 15 minutes (ADR 0013).
pub(crate) const HISTORY_RETENTION: Duration = Duration::minutes(15);
/// Default capacity: 8,192 entries (ADR 0013), roughly 1–2 MB.
pub(crate) const HISTORY_CAPACITY: usize = 8192;

struct HistoryInterval {
    valid_from: DateTime<Utc>,
    /// `None` = still present in the current generation; `Some(t)` = the last
    /// generation time it was observed.
    valid_to: Option<DateTime<Utc>>,
    name: Option<Arc<str>>,
    path: Option<Arc<str>>,
}

/// socket→PID interval log. Intervals are maintained per generation refresh
/// and evicted by retention and capacity.
pub(crate) struct AttributionHistory {
    intervals: HashMap<SocketKey, HashMap<u32, HistoryInterval>>,
    retention: Duration,
    capacity: usize,
}

impl Default for AttributionHistory {
    fn default() -> Self {
        Self::new(HISTORY_RETENTION, HISTORY_CAPACITY)
    }
}

impl AttributionHistory {
    pub(crate) fn new(retention: Duration, capacity: usize) -> Self {
        Self {
            intervals: HashMap::new(),
            retention,
            capacity,
        }
    }

    /// Generation refresh: mappings present in the current generation keep
    /// their interval or open a new one; those seen last generation but not
    /// this one are closed; then retention and capacity pruning runs.
    pub(crate) fn update<'a>(
        &mut self,
        now: DateTime<Utc>,
        entries: impl Iterator<Item = (SocketKey, &'a ProcInfo)>,
    ) {
        let mut seen: HashMap<SocketKey, HashSet<u32>> = HashMap::new();
        for (socket, info) in entries {
            seen.entry(socket).or_default().insert(info.pid);
            let by_pid = self.intervals.entry(socket).or_default();
            match by_pid.get_mut(&info.pid) {
                Some(interval) if interval.valid_to.is_none() => {
                    interval.name = info.name.clone();
                    interval.path = info.path.clone();
                }
                _ => {
                    by_pid.insert(
                        info.pid,
                        HistoryInterval {
                            valid_from: now,
                            valid_to: None,
                            name: info.name.clone(),
                            path: info.path.clone(),
                        },
                    );
                }
            }
        }
        for (socket, by_pid) in &mut self.intervals {
            for (pid, interval) in by_pid.iter_mut() {
                if interval.valid_to.is_none()
                    && !seen.get(socket).is_some_and(|pids| pids.contains(pid))
                {
                    interval.valid_to = Some(now);
                }
            }
        }
        self.prune(now);
    }

    /// Recovery: all candidates whose interval covers `at`, each passed
    /// through the PID start-time hard gate.
    pub(crate) fn lookup_verified(
        &self,
        socket: LocalSocket,
        at: DateTime<Utc>,
    ) -> Vec<ObservedProcess> {
        self.lookup(socket, at)
            .into_iter()
            .filter(|candidate| {
                process_start_time(candidate.pid).is_some_and(|started| started <= at)
            })
            .collect()
    }

    fn lookup(&self, socket: LocalSocket, at: DateTime<Utc>) -> Vec<ObservedProcess> {
        let key: SocketKey = (socket.ip, socket.port, socket.protocol);
        self.intervals
            .get(&key)
            .into_iter()
            .flatten()
            .filter(|(_, interval)| {
                interval.valid_from <= at && interval.valid_to.is_none_or(|to| at <= to)
            })
            .map(|(pid, interval)| ObservedProcess {
                pid: *pid,
                name: interval.name.clone(),
                path: interval.path.clone(),
            })
            .collect()
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.retention;
        for by_pid in self.intervals.values_mut() {
            by_pid.retain(|_, interval| match interval.valid_to {
                Some(to) => to >= cutoff,
                None => true,
            });
        }
        self.intervals.retain(|_, by_pid| !by_pid.is_empty());
        // Over capacity, evict the interval closed earliest (smallest
        // valid_to); if all are open, leave them this round — never delete
        // evidence that is still accumulating.
        let excess = self.len().saturating_sub(self.capacity);
        for _ in 0..excess {
            let victim = self
                .intervals
                .iter()
                .flat_map(|(socket, by_pid)| {
                    by_pid
                        .iter()
                        .map(move |(pid, interval)| (*socket, *pid, interval.valid_to))
                })
                .filter(|(_, _, valid_to)| valid_to.is_some())
                .min_by_key(|(_, _, valid_to)| *valid_to)
                .map(|(socket, pid, _)| (socket, pid));
            let Some((socket, pid)) = victim else {
                break;
            };
            if let Some(by_pid) = self.intervals.get_mut(&socket) {
                by_pid.remove(&pid);
                if by_pid.is_empty() {
                    self.intervals.remove(&socket);
                }
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.intervals.values().map(|by_pid| by_pid.len()).sum()
    }
}

/// PID start time (ADR 0013 hard gate): on Windows, queried via the process
/// creation time.
#[cfg(windows)]
pub(crate) fn process_start_time(pid: u32) -> Option<DateTime<Utc>> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: the handle is closed immediately; only time fields are read.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let queried = GetProcessTimes(
            handle,
            &mut creation,
            &mut exit_time,
            &mut kernel,
            &mut user,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if !queried {
            return None;
        }
        let ticks = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
        const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
        let unix_100ns = ticks.checked_sub(UNIX_EPOCH_FILETIME)?;
        DateTime::from_timestamp(
            (unix_100ns / 10_000_000) as i64,
            ((unix_100ns % 10_000_000) * 100) as u32,
        )
    }
}

/// PID start time: field 22 of /proc/{pid}/stat plus /proc/stat btime.
/// CLK_TCK is 100 on virtually every Linux distribution; converted as 100.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn process_start_time(pid: u32) -> Option<DateTime<Utc>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces/parentheses; take fields after the last ')' —
    // its first field is state, item 3.
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // starttime is item 22, index 22 - 3 = 19 relative to state (item 3).
    let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;
    let btime: i64 = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find(|line| line.starts_with("btime"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    DateTime::from_timestamp(
        btime + (starttime_ticks / 100) as i64,
        ((starttime_ticks % 100) * 10_000_000) as u32,
    )
}

/// Other platforms (macOS for architecture compatibility only) do not
/// support process start-time queries.
#[cfg(any(target_os = "macos", not(any(windows, unix))))]
pub(crate) fn process_start_time(_pid: u32) -> Option<DateTime<Utc>> {
    None
}

#[cfg(test)]
mod tests {
    use std::iter::once;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::capture::TransportProtocol;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const TCP: TransportProtocol = TransportProtocol::Tcp;

    fn t(minutes: i64) -> DateTime<Utc> {
        "2026-08-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::minutes(minutes)
    }

    fn socket(port: u16) -> LocalSocket {
        LocalSocket {
            ip: IP,
            port,
            protocol: TCP,
        }
    }

    fn info(pid: u32, name: &str) -> ProcInfo {
        ProcInfo {
            pid,
            name: Some(Arc::from(name)),
            path: None,
        }
    }

    #[test]
    fn interval_opens_closes_and_reopens_per_generation() {
        let mut history = AttributionHistory::new(Duration::minutes(15), 16);
        let entry = info(7, "server");
        history.update(t(0), once(((IP, 49_152, TCP), &entry)));
        // Open interval: any time after valid_from hits.
        assert_eq!(history.lookup(socket(49_152), t(5)).len(), 1);
        // Disappears -> closed at t(6); the closing instant itself still hits, later does not.
        history.update(t(6), std::iter::empty());
        assert_eq!(history.lookup(socket(49_152), t(6)).len(), 1);
        assert!(history.lookup(socket(49_152), t(7)).is_empty());
        // Reappears -> a new interval opens (simplified semantics: the old one is replaced).
        history.update(t(10), once(((IP, 49_152, TCP), &entry)));
        assert!(history.lookup(socket(49_152), t(7)).is_empty());
        assert_eq!(history.lookup(socket(49_152), t(12)).len(), 1);
    }

    #[test]
    fn multiple_pids_on_one_socket_are_all_candidates() {
        let mut history = AttributionHistory::default();
        let first = info(7, "alpha");
        let second = info(8, "beta");
        history.update(
            t(0),
            vec![((IP, 443, TCP), &first), ((IP, 443, TCP), &second)].into_iter(),
        );
        let found = history.lookup(socket(443), t(1));
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|process| process.pid == 7));
        assert!(found.iter().any(|process| process.pid == 8));
    }

    #[test]
    fn retention_prunes_only_closed_intervals() {
        let mut history = AttributionHistory::new(Duration::minutes(15), 64);
        let gone = info(7, "gone");
        let alive = info(8, "alive");
        history.update(
            t(0),
            vec![((IP, 10_000, TCP), &gone), ((IP, 10_001, TCP), &alive)].into_iter(),
        );
        // gone closes at t(1); alive stays open.
        history.update(t(1), once(((IP, 10_001, TCP), &alive)));
        // Both survive within the 15-minute retention.
        history.update(t(15), once(((IP, 10_001, TCP), &alive)));
        assert_eq!(history.len(), 2);
        // t(17): gone's valid_to = t(1), 16 minutes ago -> pruned; alive stays (open).
        history.update(t(17), once(((IP, 10_001, TCP), &alive)));
        assert_eq!(history.len(), 1);
        assert_eq!(history.lookup(socket(10_001), t(17)).len(), 1);
    }

    #[test]
    fn capacity_evicts_oldest_closed_interval_first() {
        let mut history = AttributionHistory::new(Duration::minutes(15), 2);
        let a = info(7, "a");
        let b = info(8, "b");
        let c = info(9, "c");
        history.update(
            t(0),
            vec![((IP, 10, TCP), &a), ((IP, 11, TCP), &b)].into_iter(),
        );
        // a closes at t(1); b stays.
        history.update(t(1), once(((IP, 11, TCP), &b)));
        // c opens at t(2) -> over capacity; a, closed earliest, is evicted.
        history.update(
            t(2),
            vec![((IP, 11, TCP), &b), ((IP, 12, TCP), &c)].into_iter(),
        );
        assert_eq!(history.len(), 2);
        assert!(history.lookup(socket(10), t(0)).is_empty());
        assert_eq!(history.lookup(socket(11), t(2)).len(), 1);
        assert_eq!(history.lookup(socket(12), t(2)).len(), 1);
    }

    /// ADR 0013 hard gate: reject a candidate PID whose start time cannot be
    /// resolved or is later than the flow's observation time.
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn start_time_gate_rejects_unverifiable_or_later_processes() {
        let mut history = AttributionHistory::default();
        // Positive case: the current test process (alive, started before now).
        let self_info = info(std::process::id(), "self");
        let now = Utc::now();
        history.update(now, once(((IP, 20_000, TCP), &self_info)));
        assert_eq!(
            history
                .lookup_verified(socket(20_000), now + Duration::seconds(1))
                .len(),
            1
        );
        // Negative case 1: flow observed before the process started (a fabricated past interval) -> rejected.
        let past: DateTime<Utc> = "2000-01-01T00:00:00Z".parse().unwrap();
        let past_info = info(std::process::id(), "past");
        history.update(past, once(((IP, 20_001, TCP), &past_info)));
        assert!(
            history
                .lookup_verified(socket(20_001), past + Duration::seconds(1))
                .is_empty()
        );
        // Negative case 2: nonexistent PID -> no start time -> rejected.
        let ghost = info(u32::MAX, "ghost");
        history.update(Utc::now(), once(((IP, 20_002, TCP), &ghost)));
        assert!(
            history
                .lookup_verified(socket(20_002), Utc::now())
                .is_empty()
        );
    }
}
