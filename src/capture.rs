use std::collections::HashSet;
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use etherparse::{EtherType, NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};

use crate::domain_parse::DomainParser;
use crate::domain_parse_composite::CompositeDomainParser;
use crate::flow_table::{DEFAULT_FLOW_TABLE_CAPACITY, FlowEntry, FlowKey, FlowTable};
use crate::stats::Direction;

/// 指定网卡的抓包源。
pub struct CaptureSource {
    cap: Capture<pcap::Active>,
    interface_name: String,
    link_type: pcap::Linktype,
    local_ips: HashSet<IpAddr>,
    domain_parser: Box<dyn DomainParser>,
    /// 连接级域名流表（5-tuple → Resolved/NoDomain），生产路径默认启用。
    /// 测试可通过 [`open_with_domain_parser`] 注入自定义实例。
    flow_table: Arc<FlowTable>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub is_default_route: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceLabelOrder {
    NameFirst,
    DescriptionFirst,
}

impl InterfaceInfo {
    pub(crate) fn display_labels(&self) -> (&str, Option<&str>) {
        let order = if cfg!(windows) {
            InterfaceLabelOrder::DescriptionFirst
        } else {
            InterfaceLabelOrder::NameFirst
        };
        self.display_labels_for(order)
    }

    pub(crate) fn display_labels_for(&self, order: InterfaceLabelOrder) -> (&str, Option<&str>) {
        let description = (!self.description.is_empty() && self.description != "No description")
            .then_some(self.description.as_str());
        match order {
            InterfaceLabelOrder::NameFirst => (self.name.as_str(), description),
            InterfaceLabelOrder::DescriptionFirst => description
                .map_or((self.name.as_str(), None), |description| {
                    (description, Some(self.name.as_str()))
                }),
        }
    }
}

// rust-pcap exposes normalized LINKTYPE_RAW (101), while live Linux handles use DLT_RAW (12).
const LINUX_DLT_RAW: pcap::Linktype = pcap::Linktype(12);

#[derive(Clone, Copy, Eq, PartialEq)]
enum PacketFormat {
    Ethernet,
    Raw,
    Ipv4,
    Ipv6,
    Null,
    Loop,
    LinuxSll,
    LinuxSll2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SllPacketType {
    Host,
    Outgoing,
    Other,
}

struct IpPayload<'a> {
    packet: &'a [u8],
    expected_version: Option<IpVersion>,
    link_len: u64,
    sll_packet_type: Option<SllPacketType>,
}

/// 解析后的单向流量记录。
pub struct Flow {
    pub direction: Direction,
    /// 远端 IP（用于 IP 维度统计）。
    pub peer: IpAddr,
    /// 远端 TCP/UDP 端口；非 TCP/UDP 流量为 `None`。
    pub peer_port: Option<u16>,
    pub bytes: u64,
    /// 本机 socket，仅 TCP/UDP 有；用于进程关联。
    pub local_socket: Option<LocalSocket>,
    /// 第二个本机 socket，仅当源和目标都属于本机时存在。
    pub peer_local_socket: Option<LocalSocket>,
    /// 出站连接解析出的目标域名；入站或未识别时为 `None`。
    pub domain: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocalSocket {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: TransportProtocol,
}

/// Determine the default route interface from /proc/net/route.
#[cfg(target_os = "linux")]
fn default_interface() -> Option<String> {
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
fn default_interface() -> Option<String> {
    None
}

/// Return available interfaces with the default-route interface highlighted.
pub fn interface_catalog() -> Result<Vec<InterfaceInfo>> {
    let default = default_interface();
    let devices = Device::list()?;
    Ok(interface_catalog_from_devices(devices, default.as_deref()))
}

fn interface_catalog_from_devices(
    devices: Vec<Device>,
    default: Option<&str>,
) -> Vec<InterfaceInfo> {
    devices
        .into_iter()
        .map(|device| InterfaceInfo {
            is_default_route: default == Some(device.name.as_str()),
            description: device.desc.unwrap_or_else(|| "No description".to_string()),
            name: device.name,
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
    output.push_str("\nUsage: delray <interface-or-number> [OPTIONS]\n");
    output.push_str("Run delray --help for full usage\n");
    output
}

fn select_device(selector: &str, mut devices: Vec<Device>) -> Result<Device> {
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

fn collect_local_ips(devices: &[Device]) -> HashSet<IpAddr> {
    devices
        .iter()
        .flat_map(|device| device.addresses.iter().map(|address| address.addr))
        .collect()
}

impl CaptureSource {
    /// 按网卡名打开实时抓包，使用复合 TLS+HTTP parser 与默认容量的流表。
    ///
    /// `flow_table_capacity` 由 CLI `--flow-table` 透传；传 0 则使用 spec
    /// 默认 65536。
    pub fn open(selector: &str, flow_table_capacity: u64) -> Result<Self> {
        let parser = Box::new(CompositeDomainParser::new());
        let capacity = if flow_table_capacity == 0 {
            DEFAULT_FLOW_TABLE_CAPACITY
        } else {
            flow_table_capacity
        };
        let flow_table = Arc::new(FlowTable::with_capacity(capacity));
        Self::open_with_domain_parser(selector, parser, flow_table)
    }

    /// 与 [`open`](Self::open) 相同，但允许注入自定义 parser 与流表。
    ///
    /// 用于测试：注入自定义 [`DomainParser`]（如 `RecordingParser`）控制解析行为；
    /// 注入自定义流表可隔离测试状态。
    pub fn open_with_domain_parser(
        selector: &str,
        domain_parser: Box<dyn DomainParser>,
        flow_table: Arc<FlowTable>,
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

        Ok(Self {
            cap,
            interface_name,
            link_type,
            local_ips,
            domain_parser,
            flow_table,
        })
    }

    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub(crate) fn flow_table_entry_count(&self) -> u64 {
        self.flow_table.entry_count()
    }

    pub(crate) fn breakloop_handle(&mut self) -> pcap::BreakLoop {
        self.cap.breakloop_handle()
    }

    /// 读取下一个包；无包（读超时）返回 Ok(None)。
    pub fn next(&mut self) -> Result<Option<Flow>> {
        match self.cap.next_packet() {
            Ok(packet) => parse_with_domain_parser(
                self.link_type,
                packet.data,
                &self.local_ips,
                self.domain_parser.as_ref(),
                Some(self.flow_table.as_ref()),
            ),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }
}

/// 解析数据链路帧为单向流量记录；非 IP 或与本机无关返回 None。
///
/// 仅在测试中使用：production 路径走 [`parse_with_domain_parser`]，
/// 老 test 调用此 pure-parsing 入口验证链路层/IP/TCP 解析本身。
#[cfg(test)]
fn parse(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
) -> Result<Option<Flow>> {
    Ok(parse_with_payload(link_type, data, local_ips)?.map(|(flow, _)| flow))
}

/// 与 [`parse`] 相同，并额外返回 TCP payload（仅当本包为 TCP 且 payload 非空）。
///
/// payload 借用自 `data`，调用方须在 `data` 生命周期内使用。
/// L7 域名解析 seam 在此 payload 上调用 [`DomainParser`]；payload 不进入 Flow。
#[allow(clippy::type_complexity)]
fn parse_with_payload<'a>(
    link_type: pcap::Linktype,
    data: &'a [u8],
    local_ips: &HashSet<IpAddr>,
) -> Result<Option<(Flow, Option<&'a [u8]>)>> {
    let format = packet_format(link_type)?;
    let (headers, link_len, sll_packet_type) = match format {
        PacketFormat::Ethernet => (PacketHeaders::from_ethernet_slice(data).ok(), 14, None),
        format => {
            let payload = match ip_payload(format, data) {
                Some(payload) => payload,
                None => return Ok(None),
            };
            if payload
                .expected_version
                .is_some_and(|expected| ip_version(payload.packet) != Some(expected))
            {
                return Ok(None);
            }
            (
                PacketHeaders::from_ip_slice(payload.packet).ok(),
                payload.link_len,
                payload.sll_packet_type,
            )
        }
    };

    let Some(headers) = headers else {
        return Ok(None);
    };
    let Some(net) = headers.net else {
        return Ok(None);
    };
    let (src, dst, ip_bytes) = match net {
        NetHeaders::Ipv4(ip, _) => (
            IpAddr::V4(ip.source.into()),
            IpAddr::V4(ip.destination.into()),
            u64::from(ip.total_len),
        ),
        NetHeaders::Ipv6(ip, _) => (
            IpAddr::V6(ip.source.into()),
            IpAddr::V6(ip.destination.into()),
            u64::from(ip.payload_length) + 40,
        ),
        _ => return Ok(None),
    };

    let link_ext_len = if format == PacketFormat::Ethernet {
        headers
            .link_exts
            .iter()
            .map(|header| header.header_len() as u64)
            .sum()
    } else {
        0
    };
    let bytes = link_len + link_ext_len + ip_bytes;

    let src_local = local_ips.contains(&src);
    let dst_local = local_ips.contains(&dst);
    if src_local && dst_local && sll_packet_type == Some(SllPacketType::Outgoing) {
        return Ok(None);
    }
    let (direction, local_ip, peer) = if src_local {
        (Direction::Outbound, src, dst)
    } else if dst_local {
        (Direction::Inbound, dst, src)
    } else {
        return Ok(None);
    };

    let is_tcp = matches!(headers.transport, Some(TransportHeader::Tcp(_)));
    let (local_socket, peer_local_socket, peer_port) = match &headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let port = if direction == Direction::Outbound {
                tcp.source_port
            } else {
                tcp.destination_port
            };
            let peer_port = if direction == Direction::Outbound {
                tcp.destination_port
            } else {
                tcp.source_port
            };
            let local_socket = LocalSocket {
                ip: local_ip,
                port,
                protocol: TransportProtocol::Tcp,
            };
            let peer_local_socket = (src_local && dst_local).then_some(LocalSocket {
                ip: dst,
                port: tcp.destination_port,
                protocol: TransportProtocol::Tcp,
            });
            (Some(local_socket), peer_local_socket, Some(peer_port))
        }
        Some(TransportHeader::Udp(udp)) => {
            let port = if direction == Direction::Outbound {
                udp.source_port
            } else {
                udp.destination_port
            };
            let peer_port = if direction == Direction::Outbound {
                udp.destination_port
            } else {
                udp.source_port
            };
            let local_socket = LocalSocket {
                ip: local_ip,
                port,
                protocol: TransportProtocol::Udp,
            };
            let peer_local_socket = (src_local && dst_local).then_some(LocalSocket {
                ip: dst,
                port: udp.destination_port,
                protocol: TransportProtocol::Udp,
            });
            (Some(local_socket), peer_local_socket, Some(peer_port))
        }
        _ => (None, None, None),
    };

    let tcp_payload = if is_tcp {
        let payload = headers.payload.slice();
        (!payload.is_empty()).then_some(payload)
    } else {
        None
    };

    Ok(Some((
        Flow {
            direction,
            peer,
            peer_port,
            bytes,
            local_socket,
            peer_local_socket,
            domain: None,
        },
        tcp_payload,
    )))
}

/// 在 [`parse`] 基础上调用 L7 域名解析 seam，并配合流表实现"首包解析一次"。
///
/// 行为（spec Q12 / NoDomain 不重试 / 流表边界）：
/// - 非 TCP、非出站、无 payload → 跳过解析（`flow.domain` 留 None）。
/// - `flow_table` 为 None（测试用）：每次出站 TCP 有 payload 都调用 `parser`，
///   不缓存。
/// - `flow_table` 为 Some：
///   - 无法构造 FlowKey（local_socket/peer_port 缺失，或非 TCP）→ 直接调 parser、
///     不写表（边界情况，TCP+出站正常路径不会触发）；
///   - 流表命中 [`FlowEntry::Resolved`] → `flow.domain = Some(domain)`，跳过 parser；
///   - 流表命中 [`FlowEntry::NoDomain`] → 跳过 parser，`flow.domain` 留 None
///     （NoDomain 不重试）；
///   - 流表未命中 → 调 parser：`Some(domain)` 写 [`FlowEntry::Resolved`]，
///     `None` 写 [`FlowEntry::NoDomain`]。
///
/// [`parse`]: parse
pub(crate) fn parse_with_domain_parser(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
    parser: &dyn DomainParser,
    flow_table: Option<&FlowTable>,
) -> Result<Option<Flow>> {
    let Some((mut flow, payload)) = parse_with_payload(link_type, data, local_ips)? else {
        return Ok(None);
    };
    if flow.direction != Direction::Outbound {
        // Q8 双向统计：Inbound 回包不解析 payload（Q1 出站视角），但查流表补
        // domain，使对端回包累计到该域名的 in_bytes。NoDomain 或未命中则 domain 留 None。
        if let Some(table) = flow_table
            && let Some(key) = flow_key_from(&flow)
            && let Some(FlowEntry::Resolved(domain)) = table.lookup(&key)
        {
            flow.domain = Some(domain);
        }
        return Ok(Some(flow));
    }
    let Some(payload) = payload else {
        return Ok(Some(flow));
    };

    // 尝试构造 5-tuple 键；非 TCP / 缺端口时退化为"不查表、直接解析"。
    let key = flow_key_from(&flow);

    if let (Some(table), Some(key)) = (flow_table, key.as_ref()) {
        match table.lookup(key) {
            Some(FlowEntry::Resolved(domain)) => {
                flow.domain = Some(domain);
                return Ok(Some(flow));
            }
            Some(FlowEntry::NoDomain) => {
                // NoDomain 不重试：解析失败的连接后续包直接返回 None。
                return Ok(Some(flow));
            }
            None => {} // 首包未解析过，落入下方解析。
        }
    }

    let resolved = parser.parse_domain(payload);

    if let (Some(table), Some(key)) = (flow_table, key) {
        match &resolved {
            Some(domain) => table.insert_resolved(key, domain.clone()),
            None => table.insert_no_domain(key),
        }
    }

    if let Some(domain) = resolved {
        flow.domain = Some(domain);
    }
    Ok(Some(flow))
}

/// 从 [`Flow`] 构造 [`FlowKey`]；非 TCP 或缺端口返回 None。
///
/// 出站方向：local_socket 为本机端，peer/peer_port 为远端。
fn flow_key_from(flow: &Flow) -> Option<FlowKey> {
    let socket = flow.local_socket?;
    if socket.protocol != TransportProtocol::Tcp {
        return None;
    }
    let peer_port = flow.peer_port?;
    Some(FlowKey {
        local_ip: socket.ip,
        local_port: socket.port,
        peer_ip: flow.peer,
        peer_port,
    })
}

fn packet_format(link_type: pcap::Linktype) -> Result<PacketFormat> {
    if link_type == pcap::Linktype::ETHERNET {
        Ok(PacketFormat::Ethernet)
    } else if matches!(link_type, pcap::Linktype::RAW | LINUX_DLT_RAW) {
        Ok(PacketFormat::Raw)
    } else if link_type == pcap::Linktype::IPV4 {
        Ok(PacketFormat::Ipv4)
    } else if link_type == pcap::Linktype::IPV6 {
        Ok(PacketFormat::Ipv6)
    } else if link_type == pcap::Linktype::NULL {
        Ok(PacketFormat::Null)
    } else if link_type == pcap::Linktype::LOOP {
        Ok(PacketFormat::Loop)
    } else if link_type == pcap::Linktype::LINUX_SLL {
        Ok(PacketFormat::LinuxSll)
    } else if link_type == pcap::Linktype::LINUX_SLL2 {
        Ok(PacketFormat::LinuxSll2)
    } else {
        Err(anyhow!("Unsupported data link type: {}", link_type.0))
    }
}

fn ip_payload(format: PacketFormat, data: &[u8]) -> Option<IpPayload<'_>> {
    match format {
        PacketFormat::Raw => Some(IpPayload {
            packet: data,
            expected_version: None,
            link_len: 0,
            sll_packet_type: None,
        }),
        PacketFormat::Ipv4 => Some(IpPayload {
            packet: data,
            expected_version: Some(IpVersion::V4),
            link_len: 0,
            sll_packet_type: None,
        }),
        PacketFormat::Ipv6 => Some(IpPayload {
            packet: data,
            expected_version: Some(IpVersion::V6),
            link_len: 0,
            sll_packet_type: None,
        }),
        PacketFormat::Null => {
            let family = ip_version_from_family_header(data.get(..4)?.try_into().ok()?)?;
            Some(IpPayload {
                packet: data.get(4..)?,
                expected_version: Some(family),
                link_len: 4,
                sll_packet_type: None,
            })
        }
        PacketFormat::Loop => {
            let family = ip_version_from_family_header(data.get(..4)?.try_into().ok()?)?;
            Some(IpPayload {
                packet: data.get(4..)?,
                expected_version: Some(family),
                link_len: 4,
                sll_packet_type: None,
            })
        }
        PacketFormat::LinuxSll => {
            let packet_type = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
            let ether_type = u16::from_be_bytes(data.get(14..16)?.try_into().ok()?);
            Some(IpPayload {
                packet: data.get(16..)?,
                expected_version: Some(ip_version_from_ether_type(ether_type)?),
                link_len: 16,
                sll_packet_type: Some(sll_packet_type(packet_type)),
            })
        }
        PacketFormat::LinuxSll2 => {
            let ether_type = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
            let packet_type = *data.get(10)?;
            Some(IpPayload {
                packet: data.get(20..)?,
                expected_version: Some(ip_version_from_ether_type(ether_type)?),
                link_len: 20,
                sll_packet_type: Some(sll_packet_type(u16::from(packet_type))),
            })
        }
        PacketFormat::Ethernet => None,
    }
}

fn sll_packet_type(packet_type: u16) -> SllPacketType {
    match packet_type {
        0 => SllPacketType::Host,
        4 => SllPacketType::Outgoing,
        _ => SllPacketType::Other,
    }
}

fn ip_version(data: &[u8]) -> Option<IpVersion> {
    match data.first()? >> 4 {
        4 => Some(IpVersion::V4),
        6 => Some(IpVersion::V6),
        _ => None,
    }
}

fn ip_version_from_ether_type(ether_type: u16) -> Option<IpVersion> {
    match EtherType(ether_type) {
        EtherType::IPV4 => Some(IpVersion::V4),
        EtherType::IPV6 => Some(IpVersion::V6),
        _ => None,
    }
}

fn ip_version_from_family_header(header: [u8; 4]) -> Option<IpVersion> {
    ip_version_from_address_family(u32::from_be_bytes(header))
        .or_else(|| ip_version_from_address_family(u32::from_le_bytes(header)))
}

fn ip_version_from_address_family(family: u32) -> Option<IpVersion> {
    match family {
        2 => Some(IpVersion::V4),
        10 | 23 | 24 | 28 | 30 => Some(IpVersion::V6),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use pcap::{Address, DeviceFlags};

    use super::*;
    use crate::stats::{ObservedProcess, Stats};

    #[derive(Clone, Copy)]
    struct ExpectedFlow {
        direction: Direction,
        peer: IpAddr,
        peer_port: u16,
        local_ip: IpAddr,
        local_port: u16,
        protocol: TransportProtocol,
        bytes: u64,
    }

    #[test]
    fn non_tcp_udp_flow_has_no_local_socket() {
        let local_ip = Ipv4Addr::new(192, 0, 2, 10);
        let local_ips = HashSet::from([IpAddr::V4(local_ip)]);

        let icmp = parse(
            pcap::Linktype::ETHERNET,
            &ipv4_frame(1, 28, &[8, 0, 0, 0, 0, 0, 0, 0]),
            &local_ips,
        )
        .expect("supported data link")
        .expect("outbound ICMP flow");

        assert!(icmp.local_socket.is_none());
    }

    #[test]
    fn flow_carries_optional_domain_field() {
        let flow = Flow {
            direction: Direction::Outbound,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_port: None,
            bytes: 0,
            local_socket: None,
            peer_local_socket: None,
            domain: Some(Arc::from("example.com")),
        };

        assert_eq!(flow.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn parsed_flow_defaults_to_no_domain() {
        let local_ip = Ipv4Addr::new(192, 0, 2, 10);
        let local_ips = HashSet::from([IpAddr::V4(local_ip)]);

        let icmp = parse(
            pcap::Linktype::ETHERNET,
            &ipv4_frame(1, 28, &[8, 0, 0, 0, 0, 0, 0, 0]),
            &local_ips,
        )
        .expect("supported data link")
        .expect("outbound ICMP flow");

        assert!(icmp.domain.is_none());
    }

    #[test]
    fn outbound_tcp_packet_with_payload_invokes_domain_parser() {
        let parser = RecordingParser::new(Some(Arc::from("example.com")));
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

        let flow =
            parse_with_domain_parser(pcap::Linktype::ETHERNET, &packet, &local_ips, &parser, None)
                .expect("supported data link")
                .expect("outbound TCP flow");

        assert_eq!(flow.direction, Direction::Outbound);
        assert_eq!(flow.domain.as_deref(), Some("example.com"));
        assert_eq!(parser.call_count(), 1);
    }

    #[test]
    fn inbound_tcp_packet_skips_domain_parser() {
        let parser = RecordingParser::new(Some(Arc::from("example.com")));
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = inbound_tcp_ethernet_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        let flow =
            parse_with_domain_parser(pcap::Linktype::ETHERNET, &packet, &local_ips, &parser, None)
                .expect("supported data link")
                .expect("inbound TCP flow");

        assert_eq!(flow.direction, Direction::Inbound);
        assert!(flow.domain.is_none());
        assert_eq!(parser.call_count(), 0);
    }

    #[test]
    fn outbound_tcp_packet_without_payload_skips_domain_parser() {
        let parser = RecordingParser::new(Some(Arc::from("example.com")));
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(&[]);

        let flow =
            parse_with_domain_parser(pcap::Linktype::ETHERNET, &packet, &local_ips, &parser, None)
                .expect("supported data link")
                .expect("outbound TCP flow");

        assert_eq!(flow.direction, Direction::Outbound);
        assert!(flow.domain.is_none());
        assert_eq!(parser.call_count(), 0);
    }

    #[test]
    fn outbound_udp_packet_skips_domain_parser() {
        let parser = RecordingParser::new(Some(Arc::from("example.com")));
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let (ip_packet, _) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let packet = add_link_header(pcap::Linktype::ETHERNET, IpVersion::V4, ip_packet);

        let flow =
            parse_with_domain_parser(pcap::Linktype::ETHERNET, &packet, &local_ips, &parser, None)
                .expect("supported data link")
                .expect("outbound UDP flow");

        assert_eq!(flow.direction, Direction::Outbound);
        assert!(flow.domain.is_none());
        assert_eq!(parser.call_count(), 0);
    }

    #[test]
    fn outbound_tcp_payload_with_parser_returning_none_leaves_domain_unset() {
        let parser = RecordingParser::new(None);
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"\x16\x03\x01\x00\x00");

        let flow =
            parse_with_domain_parser(pcap::Linktype::ETHERNET, &packet, &local_ips, &parser, None)
                .expect("supported data link")
                .expect("outbound TCP flow");

        assert!(flow.domain.is_none());
        assert_eq!(parser.call_count(), 1);
    }

    // ── 流表 + parser 协作（04 票接线） ──────────────────────────────

    #[test]
    fn flow_table_hit_resolved_skips_parser_and_sets_domain() {
        // 首包：parser 返回 "cached.example" → 流表写入 Resolved。
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: ignored\r\n\r\n");

        let first = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &RecordingParser::new(Some(Arc::from("cached.example"))),
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");
        assert_eq!(first.domain.as_deref(), Some("cached.example"));

        // 第二个相同 5-tuple 的包：命中 Resolved，跳过 parser，返回缓存域名。
        let second_parser = RecordingParser::new(Some(Arc::from("would-not-be-used.com")));
        let flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &second_parser,
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");

        assert_eq!(flow.domain.as_deref(), Some("cached.example"));
        assert_eq!(second_parser.call_count(), 0, "命中 Resolved 不应调 parser");
    }

    #[test]
    fn flow_table_hit_no_domain_skips_parser_and_leaves_domain_none() {
        // 预填表标记 NoDomain：后续包不调 parser，flow.domain 留 None。
        let parser = RecordingParser::new(Some(Arc::from("would-be.com")));
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"\x16\x03\x01\x00\x00");

        // 第一包解析失败 → 流表写 NoDomain。
        let first = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &RecordingParser::new(None),
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");
        assert!(first.domain.is_none());
        let key = flow_key_from(&first).expect("TCP flow has a 5-tuple key");
        assert!(matches!(
            table.lookup(&key),
            Some(crate::flow_table::FlowEntry::NoDomain)
        ));

        // 第二包相同 5-tuple：应跳过 parser，domain 留 None。
        let flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &parser,
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");

        assert!(flow.domain.is_none());
        assert_eq!(parser.call_count(), 0, "命中 NoDomain 不应重试");
    }

    #[test]
    fn flow_table_miss_invokes_parser_and_populates_resolved() {
        let parser = RecordingParser::new(Some(Arc::from("first-packet.example")));
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet =
            outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: first-packet.example\r\n\r\n");

        let flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &parser,
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");

        assert_eq!(flow.domain.as_deref(), Some("first-packet.example"));
        assert_eq!(parser.call_count(), 1);

        // 流表应已写入 Resolved。
        let key = flow_key_from(&flow).expect("TCP flow has a 5-tuple key");
        match table.lookup(&key) {
            Some(crate::flow_table::FlowEntry::Resolved(d)) => {
                assert_eq!(d.as_ref(), "first-packet.example");
            }
            other => panic!("流表应写入 Resolved，得到 {other:?}"),
        }
    }

    #[test]
    fn flow_table_miss_with_parser_none_populates_no_domain() {
        let parser = RecordingParser::new(None);
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"\x16\x03\x01\x00\x00");

        let flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &parser,
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");

        assert!(flow.domain.is_none());
        let key = flow_key_from(&flow).expect("TCP flow has a 5-tuple key");
        assert!(matches!(
            table.lookup(&key),
            Some(crate::flow_table::FlowEntry::NoDomain)
        ));
    }

    #[test]
    fn flow_table_distinct_five_tuples_are_independent() {
        // 两条不同连接（不同 peer IP）应各自走首包解析一次。
        let parser = RecordingParser::new(Some(Arc::from("example.com")));
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet_a = outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

        // 第二个包改 peer IP（构造不同 5-tuple）。
        let mut transport = fixed_transport(TransportProtocol::Tcp, Direction::Outbound);
        transport.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let packet_b = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                [192, 0, 2, 10],
                [203, 0, 113, 99], // 不同 peer IP
                ip_protocol(TransportProtocol::Tcp),
                (20 + transport.len()) as u16,
                &transport,
            ),
        );

        parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet_a,
            &local_ips,
            &parser,
            Some(&table),
        )
        .expect("supported data link");
        parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet_b,
            &local_ips,
            &parser,
            Some(&table),
        )
        .expect("supported data link");

        assert_eq!(parser.call_count(), 2, "两条不同连接应各自解析一次");
    }

    #[test]
    fn inbound_flow_looks_up_flow_table_to_restore_domain() {
        // Q8 双向统计：Outbound 首包填表后，Inbound 回包查表补 domain，
        // 使对端回包累计到该域名的 in_bytes；Inbound 不解析 payload（Q1 出站视角）。
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);

        let outbound = outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let outbound_flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &outbound,
            &local_ips,
            &RecordingParser::new(Some(Arc::from("example.com"))),
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");
        assert_eq!(outbound_flow.domain.as_deref(), Some("example.com"));

        let inbound_parser = RecordingParser::new(Some(Arc::from("would-not-be-used.com")));
        let inbound = inbound_tcp_ethernet_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let inbound_flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &inbound,
            &local_ips,
            &inbound_parser,
            Some(&table),
        )
        .expect("supported data link")
        .expect("inbound TCP flow");

        assert_eq!(inbound_flow.direction, Direction::Inbound);
        assert_eq!(
            inbound_flow.domain.as_deref(),
            Some("example.com"),
            "Inbound 回包应查流表补 domain（Q8 双向统计）"
        );
        assert_eq!(inbound_parser.call_count(), 0, "Inbound 不应解析 payload");
    }

    /// 测试桩：记录调用次数并可配置返回结果。
    ///
    /// 该桩用于在 capture 层 seam 测试中验证调用时机与 payload 透传；
    /// 真实 TLS/HTTP 解析在 02/03 票实现。
    struct RecordingParser {
        calls: std::sync::Mutex<usize>,
        result: Option<Arc<str>>,
    }

    impl RecordingParser {
        fn new(result: Option<Arc<str>>) -> Self {
            Self {
                calls: std::sync::Mutex::new(0),
                result,
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().expect("parser call counter not poisoned")
        }
    }

    impl crate::domain_parse::DomainParser for RecordingParser {
        fn parse_domain(&self, _tcp_payload: &[u8]) -> Option<Arc<str>> {
            *self.calls.lock().expect("parser call counter not poisoned") += 1;
            self.result.clone()
        }
    }

    fn outbound_tcp_ethernet_frame(payload: &[u8]) -> Vec<u8> {
        tcp_ethernet_frame(Direction::Outbound, payload)
    }

    fn inbound_tcp_ethernet_frame(payload: &[u8]) -> Vec<u8> {
        tcp_ethernet_frame(Direction::Inbound, payload)
    }

    fn tcp_ethernet_frame(direction: Direction, payload: &[u8]) -> Vec<u8> {
        let mut transport = fixed_transport(TransportProtocol::Tcp, direction);
        transport.extend_from_slice(payload);
        let local = [192, 0, 2, 10];
        let remote = [198, 51, 100, 5];
        let (source, destination) = endpoints(direction, local, remote);
        let ip_packet = ipv4_packet_between(
            source,
            destination,
            ip_protocol(TransportProtocol::Tcp),
            (20 + transport.len()) as u16,
            &transport,
        );
        add_link_header(pcap::Linktype::ETHERNET, IpVersion::V4, ip_packet)
    }

    #[test]
    fn unsupported_data_link_type_returns_an_error() {
        let error = match parse(pcap::Linktype(999), &[], &HashSet::new()) {
            Err(error) => error,
            Ok(_) => panic!("unsupported data link type was accepted"),
        };

        assert_eq!(error.to_string(), "Unsupported data link type: 999");
    }

    #[test]
    fn supported_link_types_parse_tcp_udp_ipv4_and_ipv6() {
        let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let local_v6 = "2001:db8::10".parse::<IpAddr>().unwrap();
        let local_ips = HashSet::from([local_v4, local_v6]);
        let link_types = [
            (
                pcap::Linktype::ETHERNET,
                &[IpVersion::V4, IpVersion::V6][..],
            ),
            (pcap::Linktype::RAW, &[IpVersion::V4, IpVersion::V6][..]),
            (LINUX_DLT_RAW, &[IpVersion::V4, IpVersion::V6][..]),
            (pcap::Linktype::IPV4, &[IpVersion::V4][..]),
            (pcap::Linktype::IPV6, &[IpVersion::V6][..]),
            (pcap::Linktype::NULL, &[IpVersion::V4, IpVersion::V6][..]),
            (pcap::Linktype::LOOP, &[IpVersion::V4, IpVersion::V6][..]),
            (
                pcap::Linktype::LINUX_SLL,
                &[IpVersion::V4, IpVersion::V6][..],
            ),
            (
                pcap::Linktype::LINUX_SLL2,
                &[IpVersion::V4, IpVersion::V6][..],
            ),
        ];

        for (link_type, versions) in link_types {
            for version in versions {
                for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
                    let (ip_packet, mut expected) = fixed_ip_packet(*version, protocol);
                    let packet = add_link_header(link_type, *version, ip_packet);
                    expected.bytes = packet.len() as u64;

                    let flow = parse(link_type, &packet, &local_ips)
                        .expect("supported data link")
                        .expect("local flow");

                    assert_flow(flow, expected);
                }
            }
        }
    }

    #[test]
    fn parsed_packets_keep_network_direction_through_interface_and_process_stats() {
        let local = [192, 0, 2, 10];
        let inbound_peer = [198, 51, 100, 5];
        let outbound_peer = [203, 0, 113, 9];
        let inbound_transport = fixed_transport(TransportProtocol::Tcp, Direction::Inbound);
        let outbound_transport = fixed_transport(TransportProtocol::Tcp, Direction::Outbound);
        let inbound = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                inbound_peer,
                local,
                ip_protocol(TransportProtocol::Tcp),
                (20 + inbound_transport.len()) as u16,
                &inbound_transport,
            ),
        );
        let outbound = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                local,
                outbound_peer,
                ip_protocol(TransportProtocol::Tcp),
                (20 + outbound_transport.len()) as u16,
                &outbound_transport,
            ),
        );
        let local_ips = HashSet::from([IpAddr::V4(local.into())]);
        let process = ObservedProcess {
            pid: 7,
            name: Some(Arc::from("wget")),
            path: Some(Arc::from("/usr/bin/wget")),
        };
        let mut stats = Stats::default();

        let inbound_flow = parse(pcap::Linktype::ETHERNET, &inbound, &local_ips)
            .unwrap()
            .unwrap();
        let outbound_flow = parse(pcap::Linktype::ETHERNET, &outbound, &local_ips)
            .unwrap()
            .unwrap();
        assert!(matches!(inbound_flow.direction, Direction::Inbound));
        assert!(matches!(outbound_flow.direction, Direction::Outbound));

        let inbound_bytes = inbound_flow.bytes;
        let outbound_bytes = outbound_flow.bytes;
        stats.record_flow(inbound_flow, Some(process.clone()));
        stats.record_flow(outbound_flow, Some(process));
        let snapshot = stats.snapshot(10);
        let wget = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(7))
            .unwrap();

        assert_eq!(snapshot.in_bytes, inbound_bytes);
        assert_eq!(snapshot.out_bytes, outbound_bytes);
        assert_eq!(snapshot.inbound_ips[0].ip, IpAddr::V4(inbound_peer.into()));
        assert_eq!(
            snapshot.outbound_ips[0].ip,
            IpAddr::V4(outbound_peer.into())
        );
        assert_eq!((wget.recv, wget.sent), (inbound_bytes, outbound_bytes));
    }

    #[test]
    fn local_tcp_response_accounts_source_as_sent_and_destination_as_recv() {
        let local = [127, 0, 0, 1];
        let server_port = 18_765_u16;
        let client_port = 49_152_u16;
        let mut transport = Vec::new();
        transport.extend_from_slice(&server_port.to_be_bytes());
        transport.extend_from_slice(&client_port.to_be_bytes());
        transport.extend_from_slice(&[0; 8]);
        transport.extend_from_slice(&[0x50, 0x10, 0, 0, 0, 0, 0, 0]);
        let packet = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                local,
                local,
                ip_protocol(TransportProtocol::Tcp),
                (20 + transport.len()) as u16,
                &transport,
            ),
        );
        let local_ips = HashSet::from([IpAddr::V4(local.into())]);

        let flow = parse(pcap::Linktype::ETHERNET, &packet, &local_ips)
            .unwrap()
            .expect("local loopback flow");
        let source = flow.local_socket.expect("source local socket");
        let destination = flow.peer_local_socket.expect("destination local socket");
        assert_eq!(source.port, server_port);
        assert_eq!(destination.port, client_port);

        let bytes = flow.bytes;
        let mut stats = Stats::default();
        stats.record_flow_processes_at(
            flow,
            Some(ObservedProcess {
                pid: 18765,
                name: Some(Arc::from("python")),
                path: Some(Arc::from("/usr/bin/python")),
            }),
            Some(ObservedProcess {
                pid: 49152,
                name: Some(Arc::from("curl")),
                path: Some(Arc::from("/usr/bin/curl")),
            }),
            "2026-07-15T08:00:00Z".parse().unwrap(),
        );

        let snapshot = stats.snapshot(10);
        let server = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(18765))
            .unwrap();
        let client = snapshot
            .processes
            .iter()
            .find(|process| process.pid() == Some(49152))
            .unwrap();

        assert_eq!(snapshot.in_bytes, bytes);
        assert_eq!(snapshot.out_bytes, bytes);
        assert_eq!((server.recv, server.sent), (0, bytes));
        assert_eq!((client.recv, client.sent), (bytes, 0));
    }

    #[test]
    fn linux_dlt_raw_12_parses_raw_ip() {
        let (packet, mut expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        expected.bytes = packet.len() as u64;
        let local_ips = HashSet::from([expected.local_ip]);

        let flow = parse(pcap::Linktype(12), &packet, &local_ips)
            .expect("Linux DLT_RAW is supported")
            .expect("local raw IP flow");

        assert_flow(flow, expected);
    }

    #[test]
    fn linux_sll_local_outgoing_copy_is_ignored() {
        let local = [127, 0, 0, 1];
        let transport = fixed_transport(TransportProtocol::Tcp, Direction::Outbound);
        let ip_packet = ipv4_packet_between(
            local,
            local,
            ip_protocol(TransportProtocol::Tcp),
            (20 + transport.len()) as u16,
            &transport,
        );
        let local_ips = HashSet::from([IpAddr::V4(local.into())]);

        for link_type in [pcap::Linktype::LINUX_SLL, pcap::Linktype::LINUX_SLL2] {
            let mut outgoing = add_link_header(link_type, IpVersion::V4, ip_packet.clone());
            set_sll_packet_type(&mut outgoing, link_type, 4);
            let outgoing_flow =
                parse(link_type, &outgoing, &local_ips).expect("supported data link");
            assert!(outgoing_flow.is_none());

            let mut host = add_link_header(link_type, IpVersion::V4, ip_packet.clone());
            set_sll_packet_type(&mut host, link_type, 0);
            let host_flow = parse(link_type, &host, &local_ips)
                .expect("supported data link")
                .expect("host copy is retained");
            assert!(host_flow.peer_local_socket.is_some());
        }
    }

    #[test]
    fn linux_sll_remote_outgoing_copy_is_retained() {
        let local_ips = HashSet::from(["192.0.2.10".parse::<IpAddr>().unwrap()]);

        for link_type in [pcap::Linktype::LINUX_SLL, pcap::Linktype::LINUX_SLL2] {
            let (payload, mut expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
            let mut packet = add_link_header(link_type, IpVersion::V4, payload);
            set_sll_packet_type(&mut packet, link_type, 4);
            expected.bytes = packet.len() as u64;

            let flow = parse(link_type, &packet, &local_ips)
                .expect("supported data link")
                .expect("remote outgoing flow is retained");

            assert_flow(flow, expected);
        }
    }

    #[test]
    fn null_and_loop_accept_both_address_family_endiannesses() {
        let (payload, expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let local_ips = HashSet::from([expected.local_ip]);

        for link_type in [pcap::Linktype::NULL, pcap::Linktype::LOOP] {
            for family in [
                address_family(IpVersion::V4).to_be_bytes(),
                address_family(IpVersion::V4).to_le_bytes(),
            ] {
                let mut packet = family.to_vec();
                packet.extend_from_slice(&payload);
                let mut expected = expected;
                expected.bytes = packet.len() as u64;

                let flow = parse(link_type, &packet, &local_ips)
                    .expect("supported data link")
                    .expect("address family endian is accepted");

                assert_flow(flow, expected);
            }
        }
    }

    #[test]
    fn bytes_ignore_padding_after_ip_packet() {
        let (payload, mut expected) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let local_ips = HashSet::from([expected.local_ip]);
        let mut packet = add_link_header(pcap::Linktype::ETHERNET, IpVersion::V4, payload);
        expected.bytes = packet.len() as u64;
        packet.extend_from_slice(&[0; 16]);

        let flow = parse(pcap::Linktype::ETHERNET, &packet, &local_ips)
            .expect("supported data link")
            .expect("padded frame");

        assert_flow(flow, expected);
    }

    #[test]
    fn link_protocol_identifier_must_match_ip_payload() {
        let local_ips = HashSet::from([
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap(),
        ]);
        let mismatches = [
            (pcap::Linktype::IPV4, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::IPV6, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::NULL, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::NULL, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::LOOP, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::LOOP, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::LINUX_SLL, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::LINUX_SLL, IpVersion::V6, IpVersion::V4),
            (pcap::Linktype::LINUX_SLL2, IpVersion::V4, IpVersion::V6),
            (pcap::Linktype::LINUX_SLL2, IpVersion::V6, IpVersion::V4),
        ];

        for (link_type, advertised_version, payload_version) in mismatches {
            let (payload, _) = fixed_ip_packet(payload_version, TransportProtocol::Udp);
            let packet = add_link_header(link_type, advertised_version, payload);

            let flow = parse(link_type, &packet, &local_ips).expect("supported data link");

            assert!(flow.is_none());
        }
    }

    #[test]
    fn unsupported_link_protocol_identifier_is_ignored() {
        let local_ips = HashSet::from(["192.0.2.10".parse::<IpAddr>().unwrap()]);
        let (payload, _) = fixed_ip_packet(IpVersion::V4, TransportProtocol::Udp);
        let mut null = 999_u32.to_ne_bytes().to_vec();
        null.extend_from_slice(&payload);
        let mut loop_packet = 999_u32.to_be_bytes().to_vec();
        loop_packet.extend_from_slice(&payload);
        let mut sll = vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, 0x08, 0x06];
        sll.extend_from_slice(&payload);
        let mut sll2 = vec![
            0x08, 0x06, 0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0,
        ];
        sll2.extend_from_slice(&payload);

        for (link_type, packet) in [
            (pcap::Linktype::NULL, null),
            (pcap::Linktype::LOOP, loop_packet),
            (pcap::Linktype::LINUX_SLL, sll),
            (pcap::Linktype::LINUX_SLL2, sll2),
        ] {
            let flow = parse(link_type, &packet, &local_ips).expect("supported data link");
            assert!(flow.is_none());
        }
    }

    #[test]
    fn traffic_not_belonging_to_the_host_is_ignored() {
        let packet = ipv4_packet_between(
            [198, 51, 100, 5],
            [203, 0, 113, 9],
            17,
            28,
            &[0, 53, 0x14, 0xe9, 0, 8, 0, 0],
        );
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);

        let flow =
            parse(pcap::Linktype::RAW, &packet, &local_ips).expect("supported raw data link");

        assert!(flow.is_none());
    }

    #[test]
    fn interface_list_has_numbers_descriptions_and_full_names() {
        let devices = vec![
            device("eth0", Some("Wired Ethernet")),
            device(r"\Device\NPF_{1234}", None),
        ];

        let rendered =
            format_interface_list(&interface_catalog_from_devices(devices, Some("eth0")));

        let expected = if cfg!(windows) {
            concat!(
                "Available interfaces:\n",
                "  1. Wired Ethernet  [default route]\n",
                "     Name: eth0\n",
                "  2. \\Device\\NPF_{1234}\n",
                "\nUsage: delray <interface-or-number> [OPTIONS]\n",
                "Run delray --help for full usage\n",
            )
        } else {
            concat!(
                "Available interfaces:\n",
                "  1. eth0  [default route]\n",
                "     Description: Wired Ethernet\n",
                "  2. \\Device\\NPF_{1234}\n",
                "\nUsage: delray <interface-or-number> [OPTIONS]\n",
                "Run delray --help for full usage\n",
            )
        };
        assert_eq!(rendered, expected);
    }

    #[test]
    fn interface_catalog_keeps_names_descriptions_and_default_marker() {
        let catalog = interface_catalog_from_devices(
            vec![device("eth0", Some("Wired Ethernet")), device("lo", None)],
            Some("eth0"),
        );

        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog[0].name, "eth0");
        assert_eq!(catalog[0].description, "Wired Ethernet");
        assert!(catalog[0].is_default_route);
        assert_eq!(catalog[1].description, "No description");
        assert!(!catalog[1].is_default_route);
    }

    #[test]
    fn interface_labels_follow_platform_display_order() {
        let interface = InterfaceInfo {
            name: r"\Device\NPF_{1234}".to_string(),
            description: "Intel Ethernet Controller".to_string(),
            is_default_route: false,
        };

        assert_eq!(
            interface.display_labels_for(InterfaceLabelOrder::NameFirst),
            (r"\Device\NPF_{1234}", Some("Intel Ethernet Controller")),
        );
        assert_eq!(
            interface.display_labels_for(InterfaceLabelOrder::DescriptionFirst),
            ("Intel Ethernet Controller", Some(r"\Device\NPF_{1234}")),
        );
    }

    #[test]
    fn interface_labels_fall_back_to_name_without_description() {
        let interface = InterfaceInfo {
            name: "eth0".to_string(),
            description: "No description".to_string(),
            is_default_route: false,
        };

        assert_eq!(
            interface.display_labels_for(InterfaceLabelOrder::DescriptionFirst),
            ("eth0", None),
        );
    }

    #[test]
    fn interface_selection_accepts_current_number_or_full_name() {
        let by_number = select_device(
            "2",
            vec![
                device("eth0", Some("Wired Ethernet")),
                device(r"\Device\NPF_{1234}", Some("Npcap Adapter")),
            ],
        )
        .expect("current interface number");
        assert_eq!(by_number.name, r"\Device\NPF_{1234}");

        let by_name = select_device(
            r"\Device\NPF_{1234}",
            vec![
                device("eth0", Some("Wired Ethernet")),
                device(r"\Device\NPF_{1234}", Some("Npcap Adapter")),
            ],
        )
        .expect("full pcap device name");
        assert_eq!(by_name.name, r"\Device\NPF_{1234}");

        let numeric_name = select_device(
            "2",
            vec![
                device("eth0", None),
                device("lo", None),
                device("2", Some("Numeric device name")),
            ],
        )
        .expect("numeric full pcap device name");
        assert_eq!(numeric_name.name, "2");
    }

    #[test]
    fn invalid_interface_selection_returns_clear_errors() {
        for number in ["0", "3"] {
            let error = select_device(number, vec![device("eth0", None), device("lo", None)])
                .expect_err("invalid interface number");
            assert_eq!(
                error.to_string(),
                format!("Invalid interface number: {number} (choose 1-2)")
            );
        }

        let error = select_device("missing", vec![device("eth0", None)])
            .expect_err("missing interface name");
        assert_eq!(error.to_string(), "Interface not found: missing");
    }

    #[test]
    fn local_ips_include_addresses_from_all_interfaces() {
        let mut eth0 = device("eth0", None);
        eth0.addresses.push(address("192.0.2.10"));
        let any = device("any", Some("All interfaces"));
        let mut lo = device("lo", None);
        lo.addresses.push(address("::1"));

        let local_ips = collect_local_ips(&[eth0, any, lo]);

        assert_eq!(
            local_ips,
            HashSet::from([
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ])
        );
    }

    fn ipv4_frame(protocol: u8, total_length: u16, transport: &[u8]) -> Vec<u8> {
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&ipv4_packet_between(
            [192, 0, 2, 10],
            [198, 51, 100, 5],
            protocol,
            total_length,
            transport,
        ));
        frame
    }

    fn fixed_ip_packet(version: IpVersion, protocol: TransportProtocol) -> (Vec<u8>, ExpectedFlow) {
        let direction = if protocol == TransportProtocol::Tcp {
            Direction::Inbound
        } else {
            Direction::Outbound
        };
        let transport = fixed_transport(protocol, direction);
        let (packet, local_ip, peer) = match version {
            IpVersion::V4 => {
                let local = [192, 0, 2, 10];
                let remote = [198, 51, 100, 5];
                let (source, destination) = endpoints(direction, local, remote);
                (
                    ipv4_packet_between(
                        source,
                        destination,
                        ip_protocol(protocol),
                        (20 + transport.len()) as u16,
                        &transport,
                    ),
                    IpAddr::V4(local.into()),
                    IpAddr::V4(remote.into()),
                )
            }
            IpVersion::V6 => {
                let local = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
                let remote = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
                let (source, destination) = endpoints(direction, local, remote);
                (
                    ipv6_packet_between(source, destination, ip_protocol(protocol), &transport),
                    IpAddr::V6(local.into()),
                    IpAddr::V6(remote.into()),
                )
            }
        };
        let local_port = if protocol == TransportProtocol::Tcp {
            12_345
        } else {
            5_353
        };
        let peer_port = if protocol == TransportProtocol::Tcp {
            443
        } else {
            53
        };
        (
            packet,
            ExpectedFlow {
                direction,
                peer,
                peer_port,
                local_ip,
                local_port,
                protocol,
                bytes: 0,
            },
        )
    }

    fn fixed_transport(protocol: TransportProtocol, direction: Direction) -> Vec<u8> {
        let local_port = if protocol == TransportProtocol::Tcp {
            12_345_u16
        } else {
            5_353_u16
        };
        let remote_port = if protocol == TransportProtocol::Tcp {
            443_u16
        } else {
            53_u16
        };
        let (source_port, destination_port) = endpoints(direction, local_port, remote_port);
        let mut transport = Vec::new();
        transport.extend_from_slice(&source_port.to_be_bytes());
        transport.extend_from_slice(&destination_port.to_be_bytes());
        match protocol {
            TransportProtocol::Tcp => {
                transport.extend_from_slice(&[0; 8]);
                transport.extend_from_slice(&[0x50, 2, 0, 0, 0, 0, 0, 0]);
            }
            TransportProtocol::Udp => transport.extend_from_slice(&[0, 8, 0, 0]),
        }
        transport
    }

    fn endpoints<T: Copy>(direction: Direction, local: T, remote: T) -> (T, T) {
        if direction == Direction::Outbound {
            (local, remote)
        } else {
            (remote, local)
        }
    }

    fn ip_protocol(protocol: TransportProtocol) -> u8 {
        match protocol {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
        }
    }

    fn ipv4_packet_between(
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        total_length: u16,
        transport: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&total_length.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        packet
    }

    fn ipv6_packet_between(
        source: [u8; 16],
        destination: [u8; 16],
        next_header: u8,
        transport: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[next_header, 64]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        packet
    }

    fn add_link_header(link_type: pcap::Linktype, version: IpVersion, packet: Vec<u8>) -> Vec<u8> {
        let ether_type = match version {
            IpVersion::V4 => [0x08, 0x00],
            IpVersion::V6 => [0x86, 0xdd],
        };
        let mut header = if link_type == pcap::Linktype::ETHERNET {
            let mut header = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
            header.extend_from_slice(&ether_type);
            header
        } else if link_type == pcap::Linktype::NULL {
            address_family(version).to_ne_bytes().to_vec()
        } else if link_type == pcap::Linktype::LOOP {
            address_family(version).to_be_bytes().to_vec()
        } else if link_type == pcap::Linktype::LINUX_SLL {
            let mut header = vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0];
            header.extend_from_slice(&ether_type);
            header
        } else if link_type == pcap::Linktype::LINUX_SLL2 {
            let mut header = ether_type.to_vec();
            header.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0]);
            header
        } else {
            Vec::new()
        };
        header.extend_from_slice(&packet);
        header
    }

    fn set_sll_packet_type(packet: &mut [u8], link_type: pcap::Linktype, packet_type: u16) {
        if link_type == pcap::Linktype::LINUX_SLL {
            packet[..2].copy_from_slice(&packet_type.to_be_bytes());
        } else if link_type == pcap::Linktype::LINUX_SLL2 {
            packet[10] = packet_type as u8;
        }
    }

    fn address_family(version: IpVersion) -> u32 {
        match version {
            IpVersion::V4 => 2,
            IpVersion::V6 if cfg!(target_os = "windows") => 23,
            IpVersion::V6 => 10,
        }
    }

    fn assert_flow(flow: Flow, expected: ExpectedFlow) {
        assert!(flow.direction == expected.direction);
        assert_eq!(flow.peer, expected.peer);
        assert_eq!(flow.peer_port, Some(expected.peer_port));
        assert_eq!(flow.bytes, expected.bytes);
        let socket = flow.local_socket.expect("local socket");
        assert_eq!(socket.ip, expected.local_ip);
        assert_eq!(socket.port, expected.local_port);
        assert_eq!(socket.protocol, expected.protocol);
    }

    fn device(name: &str, desc: Option<&str>) -> Device {
        Device {
            name: name.to_string(),
            desc: desc.map(str::to_string),
            addresses: Vec::new(),
            flags: DeviceFlags::empty(),
        }
    }

    fn address(ip: &str) -> Address {
        Address {
            addr: ip.parse().unwrap(),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None,
        }
    }

    /// 出站域名解析路径的性能基准（09 票）。
    ///
    /// 默认 `#[ignore]` 不进 CI 回归；触发方式：
    /// `cargo test --release perf_benches -- --ignored --nocapture`。
    ///
    /// 每个测试用 `std::time::Instant` 测吞吐并 `eprintln!` 输出，宽松下限
    /// 用 `assert!` 守住——若架构退化（如 FlowKey hash 退化到 O(N) 查表）
    /// 会被抓到；但偶发的机器/负载波动不会误报。
    ///
    /// 三个场景对应 spec 的性能预算：
    /// - 每包热路径：FlowTable::lookup（moka W-TinyLFU O(1) 查表）；
    /// - 每连接开销：首包 TLS ClientHello 解析（tls-parser）；
    /// - 高并发连接：流表接近 65536 上限时的 lookup 行为。
    mod perf_benches {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use super::*;
        use crate::domain_parse_composite::CompositeDomainParser;
        use crate::domain_parse_tls::test_fixtures;
        use crate::flow_table::{FlowEntry, FlowKey, FlowTable};

        /// 场景 1：每包热路径——单连接后续包命中 Resolved 流表项。
        ///
        /// 模拟"首包已解析、后续大量包走查表"的稳态。spec 性能预算：
        /// moka lookup O(1)，远小于 pcap 抓包。
        #[test]
        #[ignore = "性能基准：cargo test --release perf_benches -- --ignored --nocapture"]
        fn flow_table_lookup_per_packet_throughput() {
            let table = FlowTable::new();
            let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
            let parser = RecordingParser::new(Some(Arc::from("example.com")));
            let packet =
                outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

            // 首包填表（一次解析）
            parse_with_domain_parser(
                pcap::Linktype::ETHERNET,
                &packet,
                &local_ips,
                &parser,
                Some(&table),
            )
            .expect("supported data link");
            assert_eq!(parser.call_count(), 1, "首包应触发解析");

            // 后续 N 包——应全部命中 Resolved，不再调 parser
            const N: usize = 100_000;
            let start = Instant::now();
            for _ in 0..N {
                let _ = parse_with_domain_parser(
                    pcap::Linktype::ETHERNET,
                    &packet,
                    &local_ips,
                    &parser,
                    Some(&table),
                )
                .expect("supported data link");
            }
            let elapsed = start.elapsed();

            assert_eq!(
                parser.call_count(),
                1,
                "后续包应全部命中流表，不应再调 parser"
            );

            let ns_per_packet = elapsed.as_nanos() as f64 / N as f64;
            let packets_per_sec = N as f64 / elapsed.as_secs_f64();
            eprintln!(
                "flow_table_lookup_per_packet: N={N} elapsed={elapsed:?} ns/packet={ns_per_packet:.1} packets/sec={packets_per_sec:.0}"
            );

            // 宽松下限：>100k packets/sec 表示查表 O(1)（含 L3/L4 parse + flow_key + moka get）。
            // 1 CPU/1G 服务器目标：网卡突发 100k pps 也远超 delray 处理能力，
            // delray 限速瓶颈是 pcap 抓包（系统调用）而非查表。
            assert!(
                packets_per_sec > 100_000.0,
                "查表吞吐 {packets_per_sec:.0} packets/sec 应大于 100k（O(1) lookup）"
            );
        }

        /// 场景 2：每连接首包解析开销。
        ///
        /// 模拟"每条新连接的首包都要走完整 TLS 解析"。spec 性能预算：
        /// 每连接一次解析，开销远小于 pcap 抓包和进程表刷新。
        #[test]
        #[ignore = "性能基准：cargo test --release perf_benches -- --ignored --nocapture"]
        fn first_packet_tls_parse_throughput() {
            let parser = CompositeDomainParser::new();
            let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
            // 用真实的 TLS ClientHello（含 SNI）payload，包在出站 TCP 帧里。
            let packet = outbound_tcp_ethernet_frame(&test_fixtures::tls_client_hello_with_sni(
                "example.com",
            ));

            const N: usize = 10_000;
            let start = Instant::now();
            for _ in 0..N {
                // 每次新建 FlowTable（= 不缓存），强制首包解析路径。
                let table = FlowTable::new();
                let flow = parse_with_domain_parser(
                    pcap::Linktype::ETHERNET,
                    &packet,
                    &local_ips,
                    &parser,
                    Some(&table),
                )
                .expect("supported data link")
                .expect("outbound TCP flow");
                assert_eq!(flow.domain.as_deref(), Some("example.com"));
            }
            let elapsed = start.elapsed();

            let ns_per_parse = elapsed.as_nanos() as f64 / N as f64;
            let parses_per_sec = N as f64 / elapsed.as_secs_f64();
            eprintln!(
                "first_packet_tls_parse: N={N} elapsed={elapsed:?} ns/parse={ns_per_parse:.1} parses/sec={parses_per_sec:.0}"
            );

            // 宽松下限：>1k parses/sec 表示单次解析在毫秒级以下
            // （1 CPU 也能跟上千新连接/秒，远超典型服务器的外连速率）。
            assert!(
                parses_per_sec > 1_000.0,
                "首包解析吞吐 {parses_per_sec:.0} parses/sec 应大于 1k"
            );
        }

        /// 场景 3：流表接近容量上限时的 lookup 性能。
        ///
        /// 模拟高并发连接（spec 边界 65536）。预填接近容量的条目，
        /// 再测 hot key lookup 吞吐——验证 W-TinyLFU 在大表下仍 O(1)。
        #[test]
        #[ignore = "性能基准：cargo test --release perf_benches -- --ignored --nocapture"]
        fn flow_table_near_capacity_lookup_throughput() {
            const CAPACITY: u64 = 65_536;
            // 预填条目数：moka 默认 window ratio 约下 1% 的 window + 99% probationary，
            // 预填 60k 已能逼近真实工作集大小，又能在合理时间内完成。
            const PRE_FILL: u64 = 60_000;
            const LOOKUPS: usize = 100_000;

            let table = FlowTable::with_capacity_and_tti(CAPACITY, Duration::from_secs(3600));
            let domain: Arc<str> = Arc::from("example.com");

            // 预填条目（不同 peer_ip + local_port 组合）
            for i in 0..PRE_FILL {
                let key = FlowKey {
                    local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                    local_port: 10_000 + ((i % 10_000) as u16),
                    peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i % 256) as u8)),
                    peer_port: 443,
                };
                table.insert_resolved(key, domain.clone());
            }
            table.run_pending_tasks();

            // 构造一个已命中的 hot key 反复 lookup
            let hot_key = FlowKey {
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                local_port: 10_000,
                peer_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                peer_port: 443,
            };
            assert!(
                matches!(table.lookup(&hot_key), Some(FlowEntry::Resolved(_))),
                "hot_key 应在预填条目中"
            );

            let start = Instant::now();
            for _ in 0..LOOKUPS {
                let _ = table.lookup(&hot_key);
            }
            let elapsed = start.elapsed();

            let ns_per_lookup = elapsed.as_nanos() as f64 / LOOKUPS as f64;
            let lookups_per_sec = LOOKUPS as f64 / elapsed.as_secs_f64();
            eprintln!(
                "flow_table_near_capacity_lookup: capacity={CAPACITY} prefilled={PRE_FILL} lookups={LOOKUPS} elapsed={elapsed:?} ns/lookup={ns_per_lookup:.1} lookups/sec={lookups_per_sec:.0}"
            );

            // 宽松下限：>100k lookups/sec，与空表场景 1 基本一致（W-TinyLFU 仍 O(1) hash）。
            assert!(
                lookups_per_sec > 100_000.0,
                "大表查表吞吐 {lookups_per_sec:.0} lookups/sec 应大于 100k"
            );
        }
    }
}
