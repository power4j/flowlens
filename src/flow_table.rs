//! 连接级域名流表（04 票）。
//!
//! 5-tuple → 域名解析结果的 moka sync 缓存：每条 TCP 连接首次解析及有限重试后填表，
//! 后续包直接查表；命中 NoDomain 时在重试上限内允许再次解析，
//! 达到上限后跳过解析并让 domain 留 None。表满走 moka W-TinyLFU 淘汰，空闲超时（默认 5 分钟）
//! 由 moka 原生 time_to_idle 提供——不手写淘汰逻辑（spec 缓存库决策）。
//!
//! 不做 TCP 状态追踪（FIN/RST），接受 5-tuple 复用低概率误归属（spec 边界）。
//! 不设 Pending 状态：未命中（无项）即表示"尚未解析过"，由调用方执行解析并
//! 写入 Resolved/NoDomain。无 Pending 窗口简化了状态机。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;

/// 流表默认容量（spec：65536 条 ~ 6MB，1G 服务器可接受）。
pub const DEFAULT_FLOW_TABLE_CAPACITY: u64 = 65_536;

/// 流表默认空闲超时（spec：5 分钟，对应 TCP 连接典型寿命）。
pub const DEFAULT_TTI: Duration = Duration::from_secs(5 * 60);

/// 单条 TCP 连接最多执行的域名解析次数（含首次解析）。
pub const MAX_NO_DOMAIN_PARSE_ATTEMPTS: u8 = 3;

/// TCP 连接的 5-tuple 键。
///
/// 仅用于 TCP 流（构造方过滤），等价于 (本机 IP, 本机端口, peer IP,
/// peer 端口, TCP)。UDP/非 TCP/UDP 流量不进流表。
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
}

/// 域名解析结果。
///
/// 不设 Pending：未命中（表中无项）即表示"尚未解析过"，由调用方执行
/// 解析并写入 Resolved/NoDomain。
#[derive(Clone, Debug)]
pub enum FlowEntry {
    /// 解析成功，携带域名（Arc 共享，clone 廉价）。
    Resolved(Arc<str>),
    /// 最近一次解析失败；attempts 记录已执行的解析次数。
    /// 达到 [`MAX_NO_DOMAIN_PARSE_ATTEMPTS`] 后不再重试，避免对长期连接持续解析。
    NoDomain { attempts: u8 },
}

/// 连接级流表：5-tuple → 域名解析结果。
///
/// 底层为 moka sync `Cache`（thread-safe，clone 跨线程共享廉价）。
/// 配置 `max_capacity`（表满 W-TinyLFU 淘汰）+ `time_to_idle`
/// （空闲超时淘汰）。过期与淘汰由 moka 在用户线程的 maintenance task
/// 中 lazy 执行——`lookup` 会触发过期判断（返回 None），实际删除可能略
/// 滞后；测试与生产可调用 [`FlowTable::run_pending_tasks`] 立即清理。
pub struct FlowTable {
    cache: Cache<FlowKey, FlowEntry>,
}

impl FlowTable {
    /// 按 spec 默认参数建表（容量 65536，TTI 5 分钟）。
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_FLOW_TABLE_CAPACITY)
    }

    /// 指定容量、TTI 用默认 5 分钟。
    pub fn with_capacity(capacity: u64) -> Self {
        Self::with_capacity_and_tti(capacity, DEFAULT_TTI)
    }

    /// 同时注入容量与 TTI（测试与 CLI 用）。
    pub fn with_capacity_and_tti(capacity: u64, tti: Duration) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_idle(tti)
                .build(),
        }
    }

    /// 查表（更新 idle timer）；未命中或已过期返回 None。
    ///
    /// 注意必须用 `get` 而非 `contains_key`——后者不更新 idle timer
    /// （moka 文档明确），TTI 场景下会导致条目提前淘汰。
    pub fn lookup(&self, key: &FlowKey) -> Option<FlowEntry> {
        self.cache.get(key)
    }

    /// 写入 Resolved 条目（首包解析成功）。
    pub fn insert_resolved(&self, key: FlowKey, domain: Arc<str>) {
        self.cache.insert(key, FlowEntry::Resolved(domain));
    }

    /// 写入一次解析失败条目。后续包可在上限内继续触发解析。
    pub fn insert_no_domain(&self, key: FlowKey) {
        self.cache.insert(key, FlowEntry::NoDomain { attempts: 1 });
    }

    /// 记录一次缓存命中的解析失败，供调用方控制重试上限。
    pub fn record_no_domain_attempt(&self, key: FlowKey) {
        let Some(FlowEntry::NoDomain { attempts }) = self.cache.get(&key) else {
            return;
        };
        let attempts = attempts.saturating_add(1).min(MAX_NO_DOMAIN_PARSE_ATTEMPTS);
        self.cache.insert(key, FlowEntry::NoDomain { attempts });
    }

    /// 触发 moka 的 pending maintenance（测试与生产均可主动调用，
    /// 用于加速过期条目的物理移除）。
    #[allow(dead_code)]
    pub fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks();
    }

    /// 当前条目数（best-effort；过期条目的实际删除可能略滞后）。
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

    /// 构造测试用 FlowKey（基于 suffix 区分）。
    fn key(suffix: u8) -> FlowKey {
        FlowKey {
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            local_port: 10_000 + u16::from(suffix),
            peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, suffix)),
            peer_port: 443,
        }
    }

    // ── 首包填表 / 查表命中 ────────────────────────────────────────────

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

    // ── NoDomain 有限重试：流表记录解析次数，调用方控制是否重试 ────────

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

    // ── 空闲超时淘汰 ─────────────────────────────────────────────────

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
        // TTI=500ms；每次访问重置 idle timer，连续三次 sleep 100ms < 500ms 应都命中。
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

    // ── 表满兜底（W-TinyLFU，moka 原生） ─────────────────────────────

    #[test]
    fn table_capacity_bounds_entry_count() {
        // moka 使用 W-TinyLFU；spec 只要求"表满兜底"，不指定具体淘汰项。
        // 验证条目数受 max_capacity 约束，不验证具体哪个 key 被淘汰。
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

    // ── 5-tuple 复用 ────────────────────────────────────────────────

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
