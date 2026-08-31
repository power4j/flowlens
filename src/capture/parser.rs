//! Packet parsing: frame classification, IP payload extraction, and flow key derivation.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use etherparse::{EtherType, NetHeaders, PacketHeaders, TransportHeader};

use super::{Flow, LocalSocket, TransportProtocol};
use crate::domain_parse::DomainParser;
use crate::flow_table::{FlowEntry, FlowKey, FlowTable, MAX_NO_DOMAIN_PARSE_ATTEMPTS};
use crate::stats::Direction;
// rust-pcap exposes normalized LINKTYPE_RAW (101), while live Linux handles use DLT_RAW (12).
pub(crate) const LINUX_DLT_RAW: pcap::Linktype = pcap::Linktype(12);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PacketFormat {
    Ethernet,
    Raw,
    Ipv4,
    Ipv6,
    Null,
    Loop,
    LinuxSll,
    LinuxSll2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketDisposition {
    Accepted,
    ParseError,
    NonIp,
    NonLocal {
        version: IpVersion,
        src: IpAddr,
        dst: IpAddr,
    },
    DuplicateOutgoing,
}

pub(crate) struct PayloadParseOutcome<'a> {
    pub(crate) disposition: PacketDisposition,
    pub(crate) parsed: Option<(Flow, Option<&'a [u8]>)>,
}

impl<'a> PayloadParseOutcome<'a> {
    pub(crate) fn discarded(disposition: PacketDisposition) -> Self {
        Self {
            disposition,
            parsed: None,
        }
    }

    pub(crate) fn accepted(flow: Flow, payload: Option<&'a [u8]>) -> Self {
        Self {
            disposition: PacketDisposition::Accepted,
            parsed: Some((flow, payload)),
        }
    }
}

pub(crate) struct FlowParseOutcome {
    pub(crate) disposition: PacketDisposition,
    pub(crate) flow: Option<Flow>,
}

impl FlowParseOutcome {
    pub(crate) fn discarded(disposition: PacketDisposition) -> Self {
        Self {
            disposition,
            flow: None,
        }
    }

    pub(crate) fn accepted(flow: Flow) -> Self {
        Self {
            disposition: PacketDisposition::Accepted,
            flow: Some(flow),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SllPacketType {
    Host,
    Outgoing,
    Other,
}

pub(crate) struct IpPayload<'a> {
    pub(crate) packet: &'a [u8],
    pub(crate) expected_version: Option<IpVersion>,
    pub(crate) link_len: u64,
    pub(crate) sll_packet_type: Option<SllPacketType>,
}

/// Parse a data-link frame into a one-way traffic record; returns None for
/// non-IP frames or frames unrelated to this host.
///
/// Test-only: the production path goes through
/// [`parse_with_domain_parser_outcome`]; older tests call this pure-parsing
/// entry to verify the link-layer/IP/TCP parsing itself.
#[cfg(test)]
pub(crate) fn parse(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
) -> Result<Option<Flow>> {
    Ok(parse_with_payload(link_type, data, local_ips)?
        .parsed
        .map(|(flow, _)| flow))
}

/// Same as [`parse`], additionally returning the TCP payload (only when the
/// packet is TCP with a non-empty payload).
///
/// The payload borrows from `data`; callers must use it within `data`'s
/// lifetime. The L7 domain-parsing seam invokes [`DomainParser`] on this
/// payload; the payload never enters Flow.
#[allow(clippy::type_complexity)]
pub(crate) fn parse_with_payload<'a>(
    link_type: pcap::Linktype,
    data: &'a [u8],
    local_ips: &HashSet<IpAddr>,
) -> Result<PayloadParseOutcome<'a>> {
    let format = packet_format(link_type)?;
    let (headers, link_len, sll_packet_type) = match format {
        PacketFormat::Ethernet => {
            let headers = match PacketHeaders::from_ethernet_slice(data) {
                Ok(headers) => headers,
                Err(_) => {
                    return Ok(PayloadParseOutcome::discarded(
                        PacketDisposition::ParseError,
                    ));
                }
            };
            (headers, 14, None)
        }
        format => {
            let payload = match ip_payload(format, data) {
                Some(payload) => payload,
                None => {
                    return Ok(PayloadParseOutcome::discarded(PacketDisposition::NonIp));
                }
            };
            if payload
                .expected_version
                .is_some_and(|expected| ip_version(payload.packet) != Some(expected))
            {
                return Ok(PayloadParseOutcome::discarded(
                    PacketDisposition::ParseError,
                ));
            }
            let headers = match PacketHeaders::from_ip_slice(payload.packet) {
                Ok(headers) => headers,
                Err(_) => {
                    return Ok(PayloadParseOutcome::discarded(
                        PacketDisposition::ParseError,
                    ));
                }
            };
            (headers, payload.link_len, payload.sll_packet_type)
        }
    };

    let Some(net) = headers.net else {
        return Ok(PayloadParseOutcome::discarded(PacketDisposition::NonIp));
    };
    let (src, dst, ip_bytes, ip_version) = match net {
        NetHeaders::Ipv4(ip, _) => (
            IpAddr::V4(ip.source.into()),
            IpAddr::V4(ip.destination.into()),
            u64::from(ip.total_len),
            IpVersion::V4,
        ),
        NetHeaders::Ipv6(ip, _) => (
            IpAddr::V6(ip.source.into()),
            IpAddr::V6(ip.destination.into()),
            u64::from(ip.payload_length) + 40,
            IpVersion::V6,
        ),
        _ => return Ok(PayloadParseOutcome::discarded(PacketDisposition::NonIp)),
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
        return Ok(PayloadParseOutcome::discarded(
            PacketDisposition::DuplicateOutgoing,
        ));
    }
    let (direction, local_ip, peer) = if src_local {
        (Direction::Outbound, src, dst)
    } else if dst_local {
        (Direction::Inbound, dst, src)
    } else {
        return Ok(PayloadParseOutcome::discarded(
            PacketDisposition::NonLocal {
                version: ip_version,
                src,
                dst,
            },
        ));
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

    Ok(PayloadParseOutcome::accepted(
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
    ))
}

/// Calls the L7 domain-parsing seam on top of [`parse`], with the flow table
/// providing connection-level caching.
///
/// Behavior (bounded retries / flow-table boundaries):
/// - Non-TCP, non-outbound, no payload -> skip parsing (`flow.domain`
///   stays None).
/// - `flow_table` is None (tests): every outbound TCP packet with a payload
///   calls `parser`; nothing is cached.
/// - `flow_table` is Some:
///   - FlowKey cannot be built (local_socket/peer_port missing, or non-TCP)
///     -> call the parser directly, do not write the table (an edge case
///     never hit on the normal TCP+outbound path);
///   - table hit [`FlowEntry::Resolved`] -> `flow.domain = Some(domain)`,
///     skip the parser;
///   - table hit [`FlowEntry::NoDomain`] under the retry cap -> call the
///     parser;
///   - table hit [`FlowEntry::NoDomain`] at the retry cap -> skip the
///     parser, `flow.domain` stays None;
///   - table miss -> call the parser: `Some(domain)` writes
///     [`FlowEntry::Resolved`], `None` writes [`FlowEntry::NoDomain`].
///
/// [`parse`]: parse
#[cfg(test)]
pub(crate) fn parse_with_domain_parser(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
    parser: &dyn DomainParser,
    flow_table: Option<&FlowTable>,
) -> Result<Option<Flow>> {
    Ok(parse_with_domain_parser_outcome(link_type, data, local_ips, parser, flow_table)?.flow)
}

pub(crate) fn parse_with_domain_parser_outcome(
    link_type: pcap::Linktype,
    data: &[u8],
    local_ips: &HashSet<IpAddr>,
    parser: &dyn DomainParser,
    flow_table: Option<&FlowTable>,
) -> Result<FlowParseOutcome> {
    let parsed = parse_with_payload(link_type, data, local_ips)?;
    let Some((mut flow, payload)) = parsed.parsed else {
        return Ok(FlowParseOutcome::discarded(parsed.disposition));
    };
    if flow.direction != Direction::Outbound {
        // Bidirectional accounting: inbound replies do not parse the payload
        // (outbound perspective), but the flow table is consulted to restore
        // the domain, so peer replies accumulate into that domain's
        // in_bytes. NoDomain or a miss leaves domain None.
        if let Some(table) = flow_table
            && let Some(key) = flow_key_from(&flow)
            && let Some(FlowEntry::Resolved(domain)) = table.lookup(&key)
        {
            flow.domain = Some(domain);
        }
        return Ok(FlowParseOutcome::accepted(flow));
    }
    let Some(payload) = payload else {
        return Ok(FlowParseOutcome::accepted(flow));
    };

    // Try to build the 5-tuple key; non-TCP / missing ports degrade to
    // "no table, parse directly".
    let key = flow_key_from(&flow);

    let mut retrying_no_domain = false;
    if let (Some(table), Some(key)) = (flow_table, key.as_ref()) {
        match table.lookup(key) {
            Some(FlowEntry::Resolved(domain)) => {
                flow.domain = Some(domain);
                return Ok(FlowParseOutcome::accepted(flow));
            }
            Some(FlowEntry::NoDomain { attempts }) if attempts < MAX_NO_DOMAIN_PARSE_ATTEMPTS => {
                retrying_no_domain = true;
            }
            Some(FlowEntry::NoDomain { .. }) => {
                return Ok(FlowParseOutcome::accepted(flow));
            }
            None => {} // not parsed yet; falls through to the parse below
        }
    }

    let resolved = parser.parse_domain(payload);

    if let (Some(table), Some(key)) = (flow_table, key) {
        match &resolved {
            Some(domain) => table.insert_resolved(key, domain.clone()),
            None if retrying_no_domain => table.record_no_domain_attempt(key),
            None => table.insert_no_domain(key),
        }
    }

    if let Some(domain) = resolved {
        flow.domain = Some(domain);
    }
    Ok(FlowParseOutcome::accepted(flow))
}

/// Build a [`FlowKey`] from a [`Flow`]; None for non-TCP or missing ports.
///
/// Outbound direction: local_socket is the local end, peer/peer_port the
/// remote end.
pub(crate) fn flow_key_from(flow: &Flow) -> Option<FlowKey> {
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

pub(crate) fn packet_format(link_type: pcap::Linktype) -> Result<PacketFormat> {
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

pub(crate) fn ip_payload(format: PacketFormat, data: &[u8]) -> Option<IpPayload<'_>> {
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

pub(crate) fn sll_packet_type(packet_type: u16) -> SllPacketType {
    match packet_type {
        0 => SllPacketType::Host,
        4 => SllPacketType::Outgoing,
        _ => SllPacketType::Other,
    }
}

pub(crate) fn ip_version(data: &[u8]) -> Option<IpVersion> {
    match data.first()? >> 4 {
        4 => Some(IpVersion::V4),
        6 => Some(IpVersion::V6),
        _ => None,
    }
}

pub(crate) fn ip_version_from_ether_type(ether_type: u16) -> Option<IpVersion> {
    match EtherType(ether_type) {
        EtherType::IPV4 => Some(IpVersion::V4),
        EtherType::IPV6 => Some(IpVersion::V6),
        _ => None,
    }
}

pub(crate) fn ip_version_from_family_header(header: [u8; 4]) -> Option<IpVersion> {
    ip_version_from_address_family(u32::from_be_bytes(header))
        .or_else(|| ip_version_from_address_family(u32::from_le_bytes(header)))
}

pub(crate) fn ip_version_from_address_family(family: u32) -> Option<IpVersion> {
    match family {
        2 => Some(IpVersion::V4),
        10 | 23 | 24 | 28 | 30 => Some(IpVersion::V6),
        _ => None,
    }
}
