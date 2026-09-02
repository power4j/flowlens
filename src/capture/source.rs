//! Capture device discovery and the packet capture loop.

use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use pcap::{Capture, Device};

use super::counters::CaptureCounters;
use super::parser::FlowParseOutcome;
use super::parser::PacketDisposition;
use super::parser::packet_format;
use super::parser::parse_with_domain_parser_outcome;
use super::{Flow, InterfaceInfo};
use crate::domain_parse::DomainParser;
use crate::domain_parse_composite::CompositeDomainParser;
use crate::flow_table::{DEFAULT_FLOW_TABLE_CAPACITY, FlowTable};

/// How the capture source reads packets from the underlying pcap handle.
///
/// `Dispatch` (the default) uses the pcap 2.5.0 `dispatch` batch reader,
/// preferred since it reduces per-packet read overhead and was verified on
/// Windows/Npcap (silent read timeout, breakloop, ~120k PPS with zero drops).
/// `NextPacket` keeps the historical one-call-one-`next_packet()` baseline
/// for A/B comparison and rollback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum CaptureReadMode {
    /// Historical per-packet baseline, selectable via `--read-mode next` for
    /// A/B comparison and rollback.
    #[value(name = "next")]
    NextPacket,
    /// Batch dispatch path. Preferred production default since pcap 2.5.0:
    /// verified on Windows/Npcap (silent read timeout, breakloop, and ~120k
    /// PPS with zero drops).
    #[default]
    #[value(name = "dispatch")]
    Dispatch,
}

/// A per-packet result captured inside a dispatch callback, queued so that
/// the public `next()` keeps the historical one-callback-packet → one result
/// contract (`Ok(Some(flow))` / `Ok(None)` / `Err`).
pub(crate) enum PendingCaptureItem {
    Flow(Flow),
    Ignored,
    Error(anyhow::Error),
}

/// Default batch size passed to `dispatch(Some(..))`; the plan treats this as
/// an experimental starting point, not a commitment.
const DEFAULT_DISPATCH_BATCH_SIZE: usize = 128;

pub struct CaptureSource<C = pcap::Active>
where
    C: pcap::State,
{
    pub(crate) cap: Capture<C>,
    pub(crate) interface_name: String,
    pub(crate) link_type: pcap::Linktype,
    pub(crate) local_ips: HashSet<IpAddr>,
    pub(crate) domain_parser: Box<dyn DomainParser>,
    /// Connection-level domain flow table (5-tuple → Resolved/NoDomain),
    /// enabled by default on the production path.
    /// Tests may inject a custom instance via [`open_with_domain_parser`].
    pub(crate) flow_table: Arc<FlowTable>,
    pub(crate) pcap_counters: Arc<CaptureCounters>,
    pub(crate) last_pcap_stats_sample: Instant,
    /// Results already read from pcap but not yet surfaced through `next()`.
    /// Only the capture thread touches it; bounded by one batch at a time
    /// (the queue is only refilled once empty).
    pub(crate) pending: VecDeque<PendingCaptureItem>,
    pub(crate) read_mode: CaptureReadMode,
    pub(crate) batch_size: usize,
    /// True only for offline (savefile) sources created by tests. Live
    /// captures never set this.
    pub(crate) is_offline: bool,
    /// Once an offline dispatch returns 0 with an empty queue the file is
    /// exhausted; later `next()` calls return `Ok(None)` without re-entering
    /// pcap (no busy-wait, no invented packets).
    pub(crate) offline_exhausted: bool,
}

/// Determine the default route interface from /proc/net/route.
#[cfg(target_os = "linux")]
pub(crate) fn default_interface() -> Option<String> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 11 {
            let dest = u32::from_str_radix(fields[1], 16).ok()?;
            if dest == 0 {
                return Some(fields[0].to_string());
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn default_interface() -> Option<String> {
    None
}

/// Return available interfaces with the default-route interface highlighted.
pub fn interface_catalog() -> Result<Vec<InterfaceInfo>> {
    let default = default_interface();
    let devices = Device::list()?;
    Ok(interface_catalog_from_devices(devices, default.as_deref()))
}

pub(crate) fn interface_catalog_from_devices(
    devices: Vec<Device>,
    default: Option<&str>,
) -> Vec<InterfaceInfo> {
    devices
        .into_iter()
        .map(|device| {
            let mut addresses: Vec<_> = device
                .addresses
                .into_iter()
                .map(|address| address.addr)
                .collect();
            addresses.sort_unstable();
            addresses.dedup();
            InterfaceInfo {
                is_default_route: default == Some(device.name.as_str()),
                description: device.desc.unwrap_or_else(|| "No description".to_string()),
                name: device.name,
                addresses,
            }
        })
        .collect()
}

/// Print available interfaces with the default-route interface highlighted.
pub fn list_interfaces() -> Result<()> {
    print!("{}", format_interface_list(&interface_catalog()?));
    Ok(())
}

pub fn format_interface_list(interfaces: &[InterfaceInfo]) -> String {
    let mut output = String::from("Available interfaces:\n");
    for (index, interface) in interfaces.iter().enumerate() {
        let marker = if interface.is_default_route {
            "  [default route]"
        } else {
            ""
        };
        let (primary, secondary) = interface.display_labels();
        writeln!(output, "  {}. {}{marker}", index + 1, primary).unwrap();
        if let Some(secondary) = secondary {
            let label = if cfg!(windows) { "Name" } else { "Description" };
            writeln!(output, "     {label}: {secondary}").unwrap();
        }
    }
    output.push_str("\nUsage: flowlens <interface-or-number> [OPTIONS]\n");
    output.push_str("Run flowlens --help for full usage\n");
    output
}

pub(crate) fn select_device(selector: &str, mut devices: Vec<Device>) -> Result<Device> {
    if let Some(index) = devices.iter().position(|device| device.name == selector) {
        return Ok(devices.remove(index));
    }

    if !selector.is_empty() && selector.bytes().all(|byte| byte.is_ascii_digit()) {
        let index = selector
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1));
        if let Some(index) = index.filter(|index| *index < devices.len()) {
            return Ok(devices.remove(index));
        }
        if devices.is_empty() {
            return Err(anyhow!(
                "Invalid interface number: {selector} (no interfaces available)"
            ));
        }
        return Err(anyhow!(
            "Invalid interface number: {selector} (choose 1-{})",
            devices.len()
        ));
    }

    Err(anyhow!("Interface not found: {selector}"))
}

pub(crate) fn collect_local_ips(devices: &[Device]) -> HashSet<IpAddr> {
    collect_local_ips_with_native(devices, native_local_ips())
}

pub(crate) fn collect_local_ips_with_native(
    devices: &[Device],
    native_ips: impl IntoIterator<Item = IpAddr>,
) -> HashSet<IpAddr> {
    let mut local_ips: HashSet<IpAddr> = devices
        .iter()
        .flat_map(|device| device.addresses.iter().map(|address| address.addr))
        .collect();
    local_ips.extend(native_ips);
    local_ips
}

#[cfg(windows)]
pub(crate) fn native_local_ips() -> Vec<IpAddr> {
    match crate::windows_local_ips::query_native_local_ips() {
        Ok(addresses) => addresses,
        Err(error) => {
            eprintln!("native local IP query failed: {error}");
            Vec::new()
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn native_local_ips() -> Vec<IpAddr> {
    Vec::new()
}

impl CaptureSource<pcap::Active> {
    /// Open live capture on the named interface, using the composite
    /// TLS+HTTP parser and a default-capacity flow table.
    ///
    /// `flow_table_capacity` is passed through from the CLI `--flow-table`;
    /// 0 selects the default of 65536.
    /// Open with an explicit read mode; `CaptureReadMode::default()` is the
    /// batch dispatch path, `NextPacket` keeps the historical per-packet
    /// baseline (A/B and rollback).
    pub fn open_with_read_mode(
        selector: &str,
        flow_table_capacity: u64,
        read_mode: CaptureReadMode,
    ) -> Result<Self> {
        let parser = Box::new(CompositeDomainParser::new());
        let capacity = if flow_table_capacity == 0 {
            DEFAULT_FLOW_TABLE_CAPACITY
        } else {
            flow_table_capacity
        };
        let flow_table = Arc::new(FlowTable::with_capacity(capacity));
        Self::open_with_domain_parser_and_read_mode(selector, parser, flow_table, read_mode)
    }

    /// Same as [`open_with_read_mode`](Self::open_with_read_mode), but allows
    /// injecting a custom parser and flow table.
    ///
    /// For tests: inject a custom [`DomainParser`] (e.g. `RecordingParser`)
    /// to control parsing behavior; injecting a custom flow table isolates
    /// test state.
    pub fn open_with_domain_parser_and_read_mode(
        selector: &str,
        domain_parser: Box<dyn DomainParser>,
        flow_table: Arc<FlowTable>,
        read_mode: CaptureReadMode,
    ) -> Result<Self> {
        let devices = Device::list()?;
        let local_ips = collect_local_ips(&devices);
        let device = select_device(selector, devices)?;
        let interface_name = device.name.clone();

        let is_loopback = device.flags.is_loopback();
        let cap = Capture::from_device(device)?
            .timeout(150)
            .snaplen(65535)
            .buffer_size(2_000_000)
            .promisc(false)
            .open()?;
        if is_loopback {
            let _ = cap.direction(pcap::Direction::In);
        }
        let link_type = cap.get_datalink();
        packet_format(link_type)?;
        let pcap_counters = Arc::new(CaptureCounters::with_local_ips(&local_ips));

        Ok(Self {
            cap,
            interface_name,
            link_type,
            local_ips,
            domain_parser,
            flow_table,
            pcap_counters,
            last_pcap_stats_sample: Instant::now(),
            pending: VecDeque::new(),
            read_mode,
            batch_size: DEFAULT_DISPATCH_BATCH_SIZE,
            is_offline: false,
            offline_exhausted: false,
        })
    }
}

impl<C: pcap::Activated> CaptureSource<C> {
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub(crate) fn flow_table_entry_count(&self) -> u64 {
        self.flow_table.entry_count()
    }

    pub(crate) fn breakloop_handle(&mut self) -> pcap::BreakLoop {
        self.cap.breakloop_handle()
    }

    /// Read the next packet; Ok(None) when there is none (read timeout).
    ///
    /// One callback packet maps to exactly one result: a Flow item returns
    /// `Ok(Some(flow))`, an ignored packet returns `Ok(None)`, and a parse
    /// error returns `Err`. The dispatch path never skips `Ignored` items to
    /// hunt for a Flow, which preserves the `Ok(None)` cadence the pipeline
    /// relies on for attribution and stop liveness.
    pub fn next(&mut self) -> Result<Option<Flow>> {
        let result = if let Some(item) = self.pending.pop_front() {
            consume_pending_item(item)
        } else if self.offline_exhausted {
            // Offline dispatch reached end of file; keep returning empty
            // without re-entering pcap (no busy-wait, no invented packets).
            Ok(None)
        } else {
            self.fill_pending()?;
            match self.pending.pop_front() {
                Some(item) => consume_pending_item(item),
                None => Ok(None),
            }
        };
        self.sample_pcap_stats();
        result
    }

    /// Read one batch of packets into `pending` according to `read_mode`.
    ///
    /// `NextPacket`: reads a single packet (the historical baseline).
    /// `Dispatch`: reads at most `batch_size` packets via `pcap_dispatch`;
    /// the callback only parses, records stats, and appends to a local queue
    /// — it never touches any downstream channel.
    fn fill_pending(&mut self) -> Result<()> {
        match self.read_mode {
            CaptureReadMode::NextPacket => match self.cap.next_packet() {
                Ok(packet) => {
                    process_packet(
                        self.link_type,
                        packet.data,
                        &self.local_ips,
                        self.domain_parser.as_ref(),
                        self.flow_table.as_ref(),
                        self.pcap_counters.as_ref(),
                        &mut self.pending,
                    );
                    Ok(())
                }
                Err(pcap::Error::TimeoutExpired) => Ok(()),
                Err(e) => Err(anyhow::Error::from(e)),
            },
            CaptureReadMode::Dispatch => self.fill_pending_dispatch(),
        }
    }

    fn fill_pending_dispatch(&mut self) -> Result<()> {
        let batch_size = self.batch_size;
        let Self {
            cap,
            link_type,
            local_ips,
            domain_parser,
            flow_table,
            pcap_counters,
            pending,
            is_offline,
            offline_exhausted,
            ..
        } = self;
        let mut batch = VecDeque::new();
        let processed = cap.dispatch(Some(batch_size), |packet| {
            process_packet(
                *link_type,
                packet.data,
                local_ips,
                domain_parser.as_ref(),
                flow_table.as_ref(),
                pcap_counters.as_ref(),
                &mut batch,
            );
        })?;
        if processed == 0 && batch.is_empty() && *is_offline {
            // Offline savefiles report end-of-file as a zero-count dispatch.
            // Live captures never treat a zero return as exhaustion (a quiet
            // live interface may see timeouts/empty batches).
            *offline_exhausted = true;
        }
        pending.extend(batch);
        Ok(())
    }

    /// Sample pcap statistics (received/dropped/if_dropped) once per second
    /// for diagnostics output.
    pub(crate) fn sample_pcap_stats(&mut self) {
        if self.last_pcap_stats_sample.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_pcap_stats_sample = Instant::now();
        if let Ok(stat) = self.cap.stats() {
            self.pcap_counters
                .received
                .store(u64::from(stat.received), Ordering::Relaxed);
            self.pcap_counters
                .dropped
                .store(u64::from(stat.dropped), Ordering::Relaxed);
            self.pcap_counters
                .if_dropped
                .store(u64::from(stat.if_dropped), Ordering::Relaxed);
        }
    }

    pub fn pcap_counters(&self) -> Arc<CaptureCounters> {
        Arc::clone(&self.pcap_counters)
    }
}

/// Parse a single captured packet exactly like the historical `next()`
/// inline path: record per-packet stats, then queue the result as Flow /
/// Ignored / Error. Shared by the `NextPacket` baseline and the dispatch
/// callback so both paths are guaranteed identical per-packet behavior.
fn process_packet(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
    domain_parser: &dyn DomainParser,
    flow_table: &FlowTable,
    counters: &CaptureCounters,
    pending: &mut VecDeque<PendingCaptureItem>,
) {
    let captured_bytes = data.len() as u64;
    match parse_with_domain_parser_outcome(
        link_type,
        data,
        local_ips,
        domain_parser,
        Some(flow_table),
    ) {
        Ok(outcome) => {
            counters.record_packet(captured_bytes, &outcome);
            match outcome.flow {
                Some(flow) => pending.push_back(PendingCaptureItem::Flow(flow)),
                None => pending.push_back(PendingCaptureItem::Ignored),
            }
        }
        Err(error) => {
            counters.record_packet(
                captured_bytes,
                &FlowParseOutcome::discarded(PacketDisposition::ParseError),
            );
            pending.push_back(PendingCaptureItem::Error(error));
        }
    }
}

fn consume_pending_item(item: PendingCaptureItem) -> Result<Option<Flow>> {
    match item {
        PendingCaptureItem::Flow(flow) => Ok(Some(flow)),
        PendingCaptureItem::Ignored => Ok(None),
        PendingCaptureItem::Error(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_parse::DomainParser;
    use crate::flow_table::FlowTable;
    use crate::stats::Direction;
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    const LINKTYPE_ETHERNET: u32 = 1;

    // ── offline pcap fixture helpers ───────────────────────────────────

    fn temp_pcap_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("flowlens-pcap-dispatch-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// Write a minimal little-endian pcap file (linktype Ethernet) with the
    /// given frames in order.
    fn write_pcap_file(path: &PathBuf, frames: &[Vec<u8>]) {
        let mut file = std::fs::File::create(path).unwrap();
        // global header: magic, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1
        file.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
        file.write_all(&2u16.to_le_bytes()).unwrap();
        file.write_all(&4u16.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&65535u32.to_le_bytes()).unwrap();
        file.write_all(&LINKTYPE_ETHERNET.to_le_bytes()).unwrap();
        for (index, frame) in frames.iter().enumerate() {
            file.write_all(&(index as u32).to_le_bytes()).unwrap();
            file.write_all(&0u32.to_le_bytes()).unwrap();
            file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
            file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
            file.write_all(frame).unwrap();
        }
    }

    // ── frame builders (compact copies of capture::tests helpers) ──────

    fn endpoints<T: Copy>(direction: Direction, local: T, remote: T) -> (T, T) {
        if direction == Direction::Outbound {
            (local, remote)
        } else {
            (remote, local)
        }
    }

    const LOCAL_V4: [u8; 4] = [192, 0, 2, 10];
    const REMOTE_V4: [u8; 4] = [198, 51, 100, 5];

    fn tcp_frame(direction: Direction, payload: &[u8]) -> Vec<u8> {
        let (source_port, destination_port) = endpoints(direction, 12_345u16, 443u16);
        let mut transport = Vec::new();
        transport.extend_from_slice(&source_port.to_be_bytes());
        transport.extend_from_slice(&destination_port.to_be_bytes());
        transport.extend_from_slice(&[0; 8]);
        transport.extend_from_slice(&[0x50, 2, 0, 0, 0, 0, 0, 0]);
        transport.extend_from_slice(payload);
        ipv4_ethernet_frame(direction, 6, &transport)
    }

    fn udp_frame(direction: Direction) -> Vec<u8> {
        let (source_port, destination_port) = endpoints(direction, 5_353u16, 53u16);
        let mut transport = Vec::new();
        transport.extend_from_slice(&source_port.to_be_bytes());
        transport.extend_from_slice(&destination_port.to_be_bytes());
        transport.extend_from_slice(&[0, 8, 0, 0]);
        ipv4_ethernet_frame(direction, 17, &transport)
    }

    fn ipv4_ethernet_frame(direction: Direction, protocol: u8, transport: &[u8]) -> Vec<u8> {
        let (source, destination) = endpoints(direction, LOCAL_V4, REMOTE_V4);
        let total_length = (20 + transport.len()) as u16;
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&total_length.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&packet);
        frame
    }

    fn non_local_ipv4_frame() -> Vec<u8> {
        // src/dst are both non-local -> NonLocal disposition (flow = None).
        // Well-formed UDP transport (protocol 17): etherparse needs a full
        // 8-byte UDP header; a truncated "TCP" frame would fail L4 parsing
        // and degrade to ParseError before the NonLocal check.
        let transport = vec![0x04, 0xd2, 0x01, 0xbb, 0, 8, 0, 0];
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        packet.extend_from_slice(&[203, 0, 113, 90]);
        packet.extend_from_slice(&[198, 51, 100, 90]);
        packet.extend_from_slice(&transport);
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&packet);
        frame
    }

    fn arp_frame() -> Vec<u8> {
        // Not an IPv4/IPv6 ethertype -> NonIp disposition (flow = None).
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x06];
        frame.extend_from_slice(&[0; 20]);
        frame
    }

    fn truncated_frame() -> Vec<u8> {
        // 8 zero bytes: too short for an Ethernet/IP frame. Etherparse rejects
        // it, producing the ParseError *disposition* (flow = None), which the
        // historical next() surfaces as Ok(None) — not as an Err.
        vec![0; 8]
    }

    /// Deterministic parser: returns example.com for any non-empty outbound
    /// TCP payload, else None. Verifies domain/flow-table parity.
    #[derive(Clone)]
    struct ExampleDomainParser;

    impl DomainParser for ExampleDomainParser {
        fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>> {
            (!tcp_payload.is_empty()).then(|| Arc::from("example.com"))
        }
    }

    fn local_ips() -> HashSet<IpAddr> {
        HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
    }

    /// Open an offline `CaptureSource` in the given read mode from a pcap
    /// file written from `frames`.
    fn offline_source(path: &PathBuf, read_mode: CaptureReadMode) -> CaptureSource<pcap::Offline> {
        let cap = Capture::from_file(path).expect("open offline pcap");
        let link_type = cap.get_datalink();
        let local_ips = local_ips();
        let flow_table = Arc::new(FlowTable::with_capacity(1024));
        let counters = Arc::new(CaptureCounters::with_local_ips(&local_ips));
        CaptureSource {
            cap,
            interface_name: "offline-test".to_string(),
            link_type,
            local_ips,
            domain_parser: Box::new(ExampleDomainParser),
            flow_table,
            pcap_counters: counters,
            last_pcap_stats_sample: Instant::now(),
            pending: VecDeque::new(),
            read_mode,
            batch_size: DEFAULT_DISPATCH_BATCH_SIZE,
            is_offline: true,
            offline_exhausted: false,
        }
    }

    /// Compact projection of a `next()` result for exact cross-path equality.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Trace {
        Flow(u64),
        Empty,
        Error,
    }

    fn trace_result(result: &anyhow::Result<Option<Flow>>) -> Trace {
        match result {
            Ok(Some(flow)) => Trace::Flow(flow.bytes),
            Ok(None) => Trace::Empty,
            Err(_) => Trace::Error,
        }
    }

    #[test]
    fn dispatch_trace_matches_next_packet_on_mixed_frames() {
        let path = temp_pcap_path("mixed.pcap");
        let frames = vec![
            tcp_frame(
                Direction::Outbound,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
            arp_frame(),
            udp_frame(Direction::Outbound),
            truncated_frame(),
            non_local_ipv4_frame(),
            tcp_frame(Direction::Inbound, b""),
            tcp_frame(Direction::Outbound, b"hello"),
        ];
        write_pcap_file(&path, &frames);

        // Baseline: exactly one result per frame; read precisely N frames.
        let mut baseline_src = offline_source(&path, CaptureReadMode::NextPacket);
        let baseline: Vec<Trace> = (0..frames.len())
            .map(|_| trace_result(&baseline_src.next()))
            .collect();

        // Dispatch: one result per frame plus one terminal Ok(None) at EOF
        // (dispatch reports EOF as a zero-count batch).
        let mut dispatch_src = offline_source(&path, CaptureReadMode::Dispatch);
        let mut dispatch = Vec::new();
        while !dispatch_src.offline_exhausted {
            dispatch.push(trace_result(&dispatch_src.next()));
        }
        assert_eq!(
            dispatch.len(),
            frames.len() + 1,
            "frame results + terminal EOF"
        );
        assert_eq!(dispatch[..frames.len()], baseline[..], "per-packet parity");
        assert_eq!(dispatch[frames.len()], Trace::Empty, "EOF -> Ok(None)");
    }

    #[test]
    fn dispatch_never_skips_ignored_packets() {
        let path = temp_pcap_path("ignored.pcap");
        // Only ignored traffic (ARP + non-local), interleaved with one flow.
        // The 3-byte payload TCP frame is 14+20+20+3 = 57 bytes on the wire.
        let frames = vec![
            arp_frame(),
            non_local_ipv4_frame(),
            tcp_frame(Direction::Outbound, b"GET"),
            arp_frame(),
        ];
        write_pcap_file(&path, &frames);

        let mut source = offline_source(&path, CaptureReadMode::Dispatch);
        let mut results = Vec::new();
        while !source.offline_exhausted {
            results.push(trace_result(&source.next()));
        }
        assert_eq!(
            results,
            vec![
                Trace::Empty,    // ARP -> Ok(None)
                Trace::Empty,    // non-local -> Ok(None)
                Trace::Flow(57), // flow
                Trace::Empty,    // ARP -> Ok(None)
                Trace::Empty,    // EOF -> Ok(None)
            ]
        );
    }

    #[test]
    fn dispatch_surfaces_discarded_packets_in_position() {
        let path = temp_pcap_path("discarded.pcap");
        // A truncated frame is a ParseError *disposition*: it produces a flow
        // with no Flow (Ok(None)) exactly where the packet sat, on both paths.
        let frames = vec![
            tcp_frame(Direction::Outbound, b"one"),
            truncated_frame(),
            udp_frame(Direction::Outbound),
        ];
        write_pcap_file(&path, &frames);

        let mut baseline_src = offline_source(&path, CaptureReadMode::NextPacket);
        let baseline: Vec<Trace> = (0..frames.len())
            .map(|_| trace_result(&baseline_src.next()))
            .collect();

        let mut dispatch_src = offline_source(&path, CaptureReadMode::Dispatch);
        let mut dispatch = Vec::new();
        while !dispatch_src.offline_exhausted {
            dispatch.push(trace_result(&dispatch_src.next()));
        }
        assert_eq!(dispatch[..frames.len()], baseline[..], "per-packet parity");
        assert_eq!(
            dispatch[..frames.len()],
            [
                Trace::Flow(57), // outbound TCP + 3-byte payload
                Trace::Empty,    // truncated frame -> Ok(None)
                Trace::Flow(42), // outbound UDP (14+20+8)
            ]
        );
    }

    /// The Error pending item is defensive: on supported link types a real
    /// `Err` from the parser is not reachable through ordinary frames, but if
    /// one is ever queued it must map back to a single `Err` result.
    #[test]
    fn default_read_mode_is_dispatch() {
        assert_eq!(CaptureReadMode::default(), CaptureReadMode::Dispatch);
    }

    #[test]
    fn pending_error_item_maps_to_a_single_error_result() {
        let mut pending = VecDeque::new();
        pending.push_back(PendingCaptureItem::Error(anyhow!("boom")));
        assert!(consume_pending_item(pending.pop_front().unwrap()).is_err());
    }

    #[test]
    fn dispatch_empty_file_returns_empty_without_busy_waiting() {
        let path = temp_pcap_path("empty.pcap");
        write_pcap_file(&path, &[]);

        let mut source = offline_source(&path, CaptureReadMode::Dispatch);
        assert_eq!(trace_result(&source.next()), Trace::Empty);
        assert!(source.offline_exhausted, "empty file should be exhausted");
        assert!(source.pending.is_empty());
        // A second call must keep returning empty without re-entering pcap.
        assert_eq!(trace_result(&source.next()), Trace::Empty);
    }

    #[test]
    fn dispatch_batch_size_is_bounded() {
        let path = temp_pcap_path("bounded.pcap");
        // More frames than the batch can hold: the queue never exceeds one
        // batch, and all packets are still surfaced one at a time.
        let frames: Vec<Vec<u8>> = (0..300)
            .map(|i| {
                if i % 2 == 0 {
                    tcp_frame(Direction::Outbound, &[i as u8])
                } else {
                    arp_frame()
                }
            })
            .collect();
        write_pcap_file(&path, &frames);

        let mut source = offline_source(&path, CaptureReadMode::Dispatch);
        let mut count_flows = 0;
        let mut count_empty = 0;
        let mut count_batches = 0;
        while !source.offline_exhausted {
            if source.pending.is_empty() {
                count_batches += 1;
            }
            match source.next() {
                Ok(Some(_)) => count_flows += 1,
                Ok(None) => count_empty += 1,
                Err(_) => panic!("unexpected parse error in bounded fixture"),
            }
            assert!(source.pending.len() <= source.batch_size);
        }
        assert_eq!(count_flows, 150);
        assert_eq!(count_empty, 150 + 1, "150 ignored + 1 EOF");
        assert!(count_batches >= 3, "300 frames / 128 batch -> >=3 fills");
    }

    #[test]
    fn dispatch_records_stats_exactly_once_per_packet() {
        let path = temp_pcap_path("stats.pcap");
        let frames = vec![
            tcp_frame(Direction::Outbound, b"a"),
            arp_frame(),
            truncated_frame(),
            non_local_ipv4_frame(),
        ];
        write_pcap_file(&path, &frames);

        let mut source = offline_source(&path, CaptureReadMode::Dispatch);
        while !source.offline_exhausted {
            let _ = source.next();
        }
        let counters = source.pcap_counters();
        assert_eq!(counters.packets_read.load(Ordering::Relaxed), 4);
        assert_eq!(counters.flow_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.non_ip_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.non_local_ipv4_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.parse_error_packets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dispatch_flow_table_domain_parity() {
        let path = temp_pcap_path("domain.pcap");
        // Two outbound TCP frames on the same 5-tuple (same ports/ip), so
        // only the first triggers the domain parser; the second hits the
        // flow-table cache. A UDP frame has no domain.
        let frames = vec![
            tcp_frame(Direction::Outbound, b"first"),
            tcp_frame(Direction::Outbound, b"second"),
            udp_frame(Direction::Outbound),
        ];
        write_pcap_file(&path, &frames);

        let mut baseline_src = offline_source(&path, CaptureReadMode::NextPacket);
        let baseline_domains: Vec<Option<String>> = (0..frames.len())
            .map(|_| match baseline_src.next().ok().flatten() {
                Some(flow) => flow.domain.map(|d| d.to_string()),
                None => None,
            })
            .collect();

        let mut dispatch_src = offline_source(&path, CaptureReadMode::Dispatch);
        let mut dispatch_domains = Vec::new();
        while !dispatch_src.offline_exhausted {
            match dispatch_src.next() {
                Ok(Some(flow)) => dispatch_domains.push(flow.domain.map(|d| d.to_string())),
                Ok(None) => dispatch_domains.push(None),
                Err(_) => dispatch_domains.push(None),
            }
        }
        dispatch_domains.pop(); // drop the EOF Ok(None)
        assert_eq!(dispatch_domains, baseline_domains, "domain results match");
        assert_eq!(
            dispatch_domains[0],
            Some("example.com".to_string()),
            "first outbound TCP payload resolves"
        );
        assert_eq!(
            dispatch_domains[1],
            Some("example.com".to_string()),
            "flow-table hit restores the domain"
        );
        assert_eq!(dispatch_domains[2], None, "UDP has no domain");
    }

    #[test]
    fn next_packet_baseline_surfaces_eof_as_error_and_dispatch_as_empty() {
        let path = temp_pcap_path("baseline-eof.pcap");
        write_pcap_file(&path, &[arp_frame()]);

        let mut baseline_src = offline_source(&path, CaptureReadMode::NextPacket);
        assert_eq!(
            trace_result(&baseline_src.next()),
            Trace::Empty,
            "ARP is ignored"
        );
        assert!(
            baseline_src.next().is_err(),
            "offline next_packet EOF -> Err(NoMorePackets)"
        );

        let mut dispatch_src = offline_source(&path, CaptureReadMode::Dispatch);
        assert_eq!(
            trace_result(&dispatch_src.next()),
            Trace::Empty,
            "ARP is ignored"
        );
        assert_eq!(
            trace_result(&dispatch_src.next()),
            Trace::Empty,
            "dispatch EOF -> Ok(None)"
        );
    }
}
