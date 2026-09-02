use std::net::IpAddr;
use std::sync::Arc;

use crate::stats::Direction;

mod counters;
mod parser;
mod source;

#[cfg(test)]
use crate::flow_table::FlowTable;
pub(crate) use counters::*;

#[cfg(test)]
pub(crate) use parser::*;
#[cfg(test)]
use pcap::Device;
pub(crate) use source::*;
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::sync::atomic::Ordering;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub addresses: Vec<IpAddr>,
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

/// A parsed one-way traffic record.
pub struct Flow {
    pub direction: Direction,
    /// Remote IP (for the IP dimension).
    pub peer: IpAddr,
    /// Remote TCP/UDP port; `None` for non-TCP/UDP traffic.
    pub peer_port: Option<u16>,
    pub bytes: u64,
    /// Local socket, present for TCP/UDP only; used for process attribution.
    pub local_socket: Option<LocalSocket>,
    /// Second local socket, present only when both source and destination
    /// are local.
    pub peer_local_socket: Option<LocalSocket>,
    /// Target domain resolved from the outbound connection; `None` for
    /// inbound or unidentified flows.
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
    fn parser_classifies_non_local_ipv4_and_malformed_frames() {
        let selected_local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))]);
        let frame = outbound_tcp_ethernet_frame(b"");
        let parser = RecordingParser::new(None);

        let non_local = parse_with_domain_parser_outcome(
            pcap::Linktype::ETHERNET,
            &frame,
            &selected_local_ips,
            &parser,
            None,
        )
        .expect("supported data link");
        assert_eq!(
            non_local.disposition,
            PacketDisposition::NonLocal {
                version: IpVersion::V4,
                src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            }
        );
        assert!(non_local.flow.is_none());

        let malformed = parse_with_domain_parser_outcome(
            pcap::Linktype::ETHERNET,
            &[0; 8],
            &selected_local_ips,
            &parser,
            None,
        )
        .expect("supported data link");
        assert_eq!(malformed.disposition, PacketDisposition::ParseError);
        assert!(malformed.flow.is_none());

        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let accepted = parse_with_domain_parser_outcome(
            pcap::Linktype::ETHERNET,
            &frame,
            &local_ips,
            &parser,
            None,
        )
        .expect("supported data link");
        assert_eq!(accepted.disposition, PacketDisposition::Accepted);
        assert!(accepted.flow.is_some());

        let counters = CaptureCounters::default();
        counters.record_packet(frame.len() as u64, &non_local);
        counters.record_packet(8, &malformed);
        counters.record_packet(frame.len() as u64, &accepted);

        assert_eq!(counters.packets_read.load(Ordering::Relaxed), 3);
        assert_eq!(counters.parse_error_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.non_local_ipv4_packets.load(Ordering::Relaxed), 1);
        assert_eq!(
            counters.diagnostics_snapshot().non_local_ipv4_samples,
            vec![NonLocalEndpointSample {
                src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            }]
        );
        assert_eq!(counters.flow_packets.load(Ordering::Relaxed), 1);
        assert_eq!(
            counters.bytes_read.load(Ordering::Relaxed),
            counters.parse_error_bytes.load(Ordering::Relaxed)
                + counters.non_local_ipv4_bytes.load(Ordering::Relaxed)
                + counters.flow_bytes.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn capture_diagnostics_snapshot_sorts_local_ips_and_bounds_non_local_samples() {
        let local_ips = HashSet::from([
            "2001:db8::10".parse::<IpAddr>().unwrap(),
            "192.0.2.10".parse::<IpAddr>().unwrap(),
        ]);
        let counters = CaptureCounters::with_local_ips(&local_ips);

        for index in 0..(NON_LOCAL_ENDPOINT_SAMPLE_LIMIT + 3) {
            counters.record_packet(
                64,
                &FlowParseOutcome::discarded(PacketDisposition::NonLocal {
                    version: IpVersion::V4,
                    src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, index as u8)),
                    dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                }),
            );
        }

        let snapshot = counters.diagnostics_snapshot();
        let mut expected_local_ips = local_ips.into_iter().collect::<Vec<_>>();
        expected_local_ips.sort_unstable();
        assert_eq!(snapshot.local_ips, expected_local_ips);
        assert_eq!(
            snapshot.non_local_ipv4_samples.len(),
            NON_LOCAL_ENDPOINT_SAMPLE_LIMIT
        );
        assert_eq!(
            snapshot.non_local_ipv4_samples[0],
            NonLocalEndpointSample {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            }
        );
        assert!(snapshot.non_local_ipv6_samples.is_empty());
    }

    #[test]
    fn capture_diagnostics_refreshes_samples_during_long_non_local_streams() {
        let counters = CaptureCounters::default();
        let initial = NonLocalEndpointSample {
            src: "10.0.0.1".parse().unwrap(),
            dst: "198.51.100.1".parse().unwrap(),
        };
        let later = NonLocalEndpointSample {
            src: "10.0.0.2".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
        };

        for _ in 0..NON_LOCAL_ENDPOINT_SAMPLE_LIMIT {
            counters.record_packet(
                64,
                &FlowParseOutcome::discarded(PacketDisposition::NonLocal {
                    version: IpVersion::V4,
                    src: initial.src,
                    dst: initial.dst,
                }),
            );
        }
        for _ in 0..NON_LOCAL_ENDPOINT_SAMPLE_INTERVAL {
            counters.record_packet(
                1_500,
                &FlowParseOutcome::discarded(PacketDisposition::NonLocal {
                    version: IpVersion::V4,
                    src: later.src,
                    dst: later.dst,
                }),
            );
        }

        let snapshot = counters.diagnostics_snapshot();
        assert_eq!(
            snapshot.non_local_ipv4_samples.len(),
            NON_LOCAL_ENDPOINT_SAMPLE_LIMIT
        );
        assert!(snapshot.non_local_ipv4_samples.contains(&later));
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

    // ── flow table + parser cooperation ─────────────────────────────

    #[test]
    fn flow_table_hit_resolved_skips_parser_and_sets_domain() {
        // First packet: the parser returns "cached.example" -> the table stores Resolved.
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

        // Second packet with the same 5-tuple: hits Resolved, skips the parser, returns the cached domain.
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
    fn flow_table_hit_no_domain_retries_and_can_resolve() {
        // After the first parse fails, later payloads on the same 5-tuple should allow bounded retries.
        let parser = RecordingParser::new(Some(Arc::from("would-be.com")));
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"\x16\x03\x01\x00\x00");

        // First packet's parse fails -> the table stores a one-attempt failure record.
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
            Some(crate::flow_table::FlowEntry::NoDomain { attempts: 1 })
        ));

        // Second packet, same 5-tuple: the parser is retried and succeeds.
        let flow = parse_with_domain_parser(
            pcap::Linktype::ETHERNET,
            &packet,
            &local_ips,
            &parser,
            Some(&table),
        )
        .expect("supported data link")
        .expect("outbound TCP flow");

        assert_eq!(flow.domain.as_deref(), Some("would-be.com"));
        assert_eq!(parser.call_count(), 1, "命中 NoDomain 且未达上限时应重试");
        assert!(matches!(
            table.lookup(&key),
            Some(crate::flow_table::FlowEntry::Resolved(domain))
                if domain.as_ref() == "would-be.com"
        ));
    }

    #[test]
    fn flow_table_hit_no_domain_stops_after_retry_limit() {
        let parser = RecordingParser::new(None);
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet = outbound_tcp_ethernet_frame(b"\x16\x03\x01\x00\x00");

        for _ in 0..=crate::flow_table::MAX_NO_DOMAIN_PARSE_ATTEMPTS {
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
        }

        assert_eq!(
            parser.call_count(),
            usize::from(crate::flow_table::MAX_NO_DOMAIN_PARSE_ATTEMPTS),
            "达到 NoDomain 重试上限后应停止调用 parser"
        );
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

        // The table should now hold Resolved.
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
            Some(crate::flow_table::FlowEntry::NoDomain { attempts: 1 })
        ));
    }

    #[test]
    fn flow_table_distinct_five_tuples_are_independent() {
        // Two distinct connections (different peer IPs) should each get one first-packet parse.
        let parser = RecordingParser::new(Some(Arc::from("example.com")));
        let table = FlowTable::new();
        let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let packet_a = outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

        // The second packet changes the peer IP (building a different 5-tuple).
        let mut transport = fixed_transport(TransportProtocol::Tcp, Direction::Outbound);
        transport.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let packet_b = add_link_header(
            pcap::Linktype::ETHERNET,
            IpVersion::V4,
            ipv4_packet_between(
                [192, 0, 2, 10],
                [203, 0, 113, 99], // different peer IP
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
        // Bidirectional accounting: after the outbound first packet fills
        // the table, the inbound reply looks the domain up so peer replies
        // accumulate into that domain's in_bytes; inbound does not parse the
        // payload (outbound perspective).
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
            "Inbound 回包应查流表补 domain（双向统计）"
        );
        assert_eq!(inbound_parser.call_count(), 0, "Inbound 不应解析 payload");
    }

    /// Test stub: records the call count with a configurable result.
    ///
    /// Used by capture-layer seam tests to verify call timing and payload
    /// pass-through.
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
                "\nUsage: flowlens <interface-or-number> [OPTIONS]\n",
                "Run flowlens --help for full usage\n",
            )
        } else {
            concat!(
                "Available interfaces:\n",
                "  1. eth0  [default route]\n",
                "     Description: Wired Ethernet\n",
                "  2. \\Device\\NPF_{1234}\n",
                "\nUsage: flowlens <interface-or-number> [OPTIONS]\n",
                "Run flowlens --help for full usage\n",
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
    fn interface_catalog_retains_sorted_unique_ip_addresses() {
        let mut device = device("eth0", Some("Wired Ethernet"));
        device.addresses = vec![
            address("2001:db8::10"),
            address("192.0.2.10"),
            address("192.0.2.10"),
        ];

        let catalog = interface_catalog_from_devices(vec![device], None);

        assert_eq!(
            catalog[0].addresses,
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::10".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn interface_labels_follow_platform_display_order() {
        let interface = InterfaceInfo {
            name: r"\Device\NPF_{1234}".to_string(),
            description: "Intel Ethernet Controller".to_string(),
            addresses: Vec::new(),
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
            addresses: Vec::new(),
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

        let local_ips = collect_local_ips_with_native(&[eth0, any, lo], []);

        assert_eq!(
            local_ips,
            HashSet::from([
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ])
        );
    }

    #[test]
    fn local_ips_include_native_addresses_missing_from_pcap_devices() {
        let mut virtio = device(r"\Device\NPF_{virtio}", None);
        virtio.addresses.push(address("100.127.185.26"));

        let local_ips =
            collect_local_ips_with_native(&[virtio], ["10.11.12.31".parse::<IpAddr>().unwrap()]);

        assert!(local_ips.contains(&"100.127.185.26".parse().unwrap()));
        assert!(local_ips.contains(&"10.11.12.31".parse().unwrap()));
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

    /// Performance benchmarks for the outbound domain-parsing path.
    ///
    /// `#[ignore]`d by default, out of CI regression; to run:
    /// `cargo test --release perf_benches -- --ignored --nocapture`.
    ///
    /// Each test measures throughput with `std::time::Instant` and prints
    /// via `eprintln!`, guarded by lenient `assert!` lower bounds — an
    /// architectural regression (e.g. FlowKey hashing degrading to O(N)
    /// lookups) gets caught, while occasional machine/load noise does not
    /// trip it.
    ///
    /// The three scenarios map to the performance budget:
    /// - per-packet hot path: FlowTable::lookup (moka W-TinyLFU O(1));
    /// - per-connection cost: first-packet TLS ClientHello parsing
    ///   (tls-parser);
    /// - high-concurrency connections: lookup behavior as the table nears
    ///   the 65536 cap.
    mod perf_benches {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use super::*;
        use crate::domain_parse_composite::CompositeDomainParser;
        use crate::domain_parse_tls::test_fixtures;
        use crate::flow_table::{FlowEntry, FlowKey, FlowTable};

        /// Scenario 1: per-packet hot path — later packets of a single
        /// connection hit the Resolved flow-table entry.
        ///
        /// Simulates the steady state of "first packet parsed, the rest go
        /// through the table". Budget: moka lookup is O(1), far below the
        /// pcap capture cost.
        #[test]
        #[ignore = "性能基准：cargo test --release perf_benches -- --ignored --nocapture"]
        fn flow_table_lookup_per_packet_throughput() {
            let table = FlowTable::new();
            let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
            let parser = RecordingParser::new(Some(Arc::from("example.com")));
            let packet =
                outbound_tcp_ethernet_frame(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

            // First packet fills the table (one parse)
            parse_with_domain_parser(
                pcap::Linktype::ETHERNET,
                &packet,
                &local_ips,
                &parser,
                Some(&table),
            )
            .expect("supported data link");
            assert_eq!(parser.call_count(), 1, "首包应触发解析");

            // The next N packets — all should hit Resolved; the parser is not called again
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

            // Lenient lower bound: >100k packets/sec indicates an O(1)
            // lookup (incl. L3/L4 parse + flow_key + moka get).
            // 1 CPU/1GB server target: even a 100k pps NIC burst far
            // exceeds flowlens' capacity — the bottleneck is pcap capture
            // (syscalls), not the lookup.
            assert!(
                packets_per_sec > 100_000.0,
                "查表吞吐 {packets_per_sec:.0} packets/sec 应大于 100k（O(1) lookup）"
            );
        }

        /// Scenario 2: per-connection first-packet parse cost.
        ///
        /// Simulates "every new connection's first packet goes through a
        /// full TLS parse". Budget: one parse per connection, far below the
        /// pcap capture and process-table refresh costs.
        #[test]
        #[ignore = "性能基准：cargo test --release perf_benches -- --ignored --nocapture"]
        fn first_packet_tls_parse_throughput() {
            let parser = CompositeDomainParser::new();
            let local_ips = HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
            // A real TLS ClientHello (with SNI) payload wrapped in an outbound TCP frame.
            let packet = outbound_tcp_ethernet_frame(&test_fixtures::tls_client_hello_with_sni(
                "example.com",
            ));

            const N: usize = 10_000;
            let start = Instant::now();
            for _ in 0..N {
                // A fresh FlowTable each time (= no caching) forces the first-packet parse path.
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

            // Lenient lower bound: >1k parses/sec means a single parse is
            // well under a millisecond (1 CPU keeps up with thousands of
            // new connections/sec, far beyond typical server rates).
            assert!(
                parses_per_sec > 1_000.0,
                "首包解析吞吐 {parses_per_sec:.0} parses/sec 应大于 1k"
            );
        }

        /// Scenario 3: lookup performance as the table nears capacity.
        ///
        /// Simulates high-concurrency connections (65536 boundary). Pre-fill
        /// near-capacity entries, then measure hot-key lookup throughput —
        /// verifying W-TinyLFU stays O(1) on a large table.
        #[test]
        #[ignore = "性能基准：cargo test --release perf_benches -- --ignored --nocapture"]
        fn flow_table_near_capacity_lookup_throughput() {
            const CAPACITY: u64 = 65_536;
            // Pre-fill size: moka's default window ratio is roughly a 1%
            // window + 99% probationary; 60k gets close to the real working
            // set while still finishing in reasonable time.
            const PRE_FILL: u64 = 60_000;
            const LOOKUPS: usize = 100_000;

            let table = FlowTable::with_capacity_and_tti(CAPACITY, Duration::from_secs(3600));
            let domain: Arc<str> = Arc::from("example.com");

            // Pre-fill entries (distinct peer_ip + local_port combinations)
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

            // Build one already-present hot key and look it up repeatedly
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

            // Lenient lower bound: >100k lookups/sec, in line with the empty-table scenario 1 (W-TinyLFU is still an O(1) hash).
            assert!(
                lookups_per_sec > 100_000.0,
                "大表查表吞吐 {lookups_per_sec:.0} lookups/sec 应大于 100k"
            );
        }
    }
}
