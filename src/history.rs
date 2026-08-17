//! socket→PID 区间日志与历史归属（ADR 0013 第三刀）。
//!
//! 操作系统只能回答「现在」的连接归属；短连接在探测窗口内消失后，
//! 唯一的证据是它曾被某一代 proc_table 观测到。区间日志把每次代次刷新
//! 中存在的 socket→PID 映射记录为 [valid_from, valid_to] 区间，终结归属时
//! 用流的观测时间回查。追回结果必须通过 PID 启动时间硬门槛——候选进程的
//! 启动时间无法验证或晚于流观测时间时一律拒绝，防止 PID 复用造成错误归属
//! （错误归属比未知更有害）。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};

use crate::capture::{LocalSocket, TransportProtocol};
use crate::proc_table::ProcInfo;
use crate::stats::ObservedProcess;

type SocketKey = (IpAddr, u16, TransportProtocol);

/// 默认保留 15 分钟（ADR 0013）。
pub(crate) const HISTORY_RETENTION: Duration = Duration::minutes(15);
/// 默认容量 8192 条（ADR 0013），约 1–2 MB 量级。
pub(crate) const HISTORY_CAPACITY: usize = 8192;

struct HistoryInterval {
    valid_from: DateTime<Utc>,
    /// `None` = 当前代仍存在；`Some(t)` = 最后一次被观测到的代次时间。
    valid_to: Option<DateTime<Utc>>,
    name: Option<Arc<str>>,
    path: Option<Arc<str>>,
}

/// socket→PID 区间日志。按代次刷新维护区间，按保留期与容量淘汰。
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

    /// 代次刷新：当前代存在的映射保持或新开区间；上一代有而本代没有的关闭；
    /// 随后按保留期与容量淘汰。
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

    /// 追回：`at` 落入区间的全部候选，逐个过 PID 启动时间硬门槛。
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
        // 容量超限时淘汰关闭最早（valid_to 最小）的区间；全部开启则本轮不动，
        // 避免误删正在计时的证据。
        while self.len() > self.capacity {
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

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// PID 启动时间（ADR 0013 硬门槛）：Windows 经进程创建时间查询。
#[cfg(windows)]
pub(crate) fn process_start_time(pid: u32) -> Option<DateTime<Utc>> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: 句柄立即关闭，仅读取时间字段。
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

/// PID 启动时间：/proc/{pid}/stat 字段 22 + /proc/stat btime。
/// CLK_TCK 在几乎所有 Linux 发行版上为 100，按 100 折算。
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn process_start_time(pid: u32) -> Option<DateTime<Utc>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm 可能含空格/括号，从最后一个 ')' 之后取字段；其后首字段是第 3 项 state。
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // starttime 是第 22 项，相对 state（第 3 项）索引为 22 - 3 = 19。
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

/// 其他平台（macOS 仅作架构兼容）不支持进程启动时间查询。
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
        // 开启区间：valid_from 之后任意时间命中。
        assert_eq!(history.lookup(socket(49_152), t(5)).len(), 1);
        // 消失 → 关闭于 t(6)；关闭时刻本身仍命中，之后不命中。
        history.update(t(6), std::iter::empty());
        assert_eq!(history.lookup(socket(49_152), t(6)).len(), 1);
        assert!(history.lookup(socket(49_152), t(7)).is_empty());
        // 复现 → 重开新区间（简化语义：旧区间被覆盖）。
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
        // gone 在 t(1) 关闭；alive 持续开启。
        history.update(t(1), once(((IP, 10_001, TCP), &alive)));
        // 15 分钟保留期内都在。
        history.update(t(15), once(((IP, 10_001, TCP), &alive)));
        assert_eq!(history.len(), 2);
        // t(17)：gone 的 valid_to = t(1) 距今 16 分钟 → 淘汰；alive 开启中保留。
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
        // a 关闭于 t(1)，b 保持。
        history.update(t(1), once(((IP, 11, TCP), &b)));
        // c 于 t(2) 开启 → 超容量，淘汰关闭最早的 a。
        history.update(
            t(2),
            vec![((IP, 11, TCP), &b), ((IP, 12, TCP), &c)].into_iter(),
        );
        assert_eq!(history.len(), 2);
        assert!(history.lookup(socket(10), t(0)).is_empty());
        assert_eq!(history.lookup(socket(11), t(2)).len(), 1);
        assert_eq!(history.lookup(socket(12), t(2)).len(), 1);
    }

    /// ADR 0013 硬门槛：候选 PID 查不到启动时间或启动晚于流观测时间 → 拒绝。
    #[test]
    fn start_time_gate_rejects_unverifiable_or_later_processes() {
        let mut history = AttributionHistory::default();
        // 正例：当前测试进程（存活，启动早于现在）。
        let self_info = info(std::process::id(), "self");
        let now = Utc::now();
        history.update(now, once(((IP, 20_000, TCP), &self_info)));
        assert_eq!(
            history
                .lookup_verified(socket(20_000), now + Duration::seconds(1))
                .len(),
            1
        );
        // 反例 1：流的观测时间早于进程启动（伪造的过去区间）→ 拒绝。
        let past: DateTime<Utc> = "2000-01-01T00:00:00Z".parse().unwrap();
        let past_info = info(std::process::id(), "past");
        history.update(past, once(((IP, 20_001, TCP), &past_info)));
        assert!(
            history
                .lookup_verified(socket(20_001), past + Duration::seconds(1))
                .is_empty()
        );
        // 反例 2：PID 不存在 → 查不到启动时间 → 拒绝。
        let ghost = info(u32::MAX, "ghost");
        history.update(Utc::now(), once(((IP, 20_002, TCP), &ghost)));
        assert!(
            history
                .lookup_verified(socket(20_002), Utc::now())
                .is_empty()
        );
    }
}
