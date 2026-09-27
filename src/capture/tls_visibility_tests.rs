use super::Flow;
use super::parser::parse_with_domain_parser_at;
use crate::domain_parse::DomainKind;
use crate::domain_parse::{DomainParseResult, DomainParser, DomainReason};
use crate::domain_parse_composite::CompositeDomainParser;
use crate::domain_parse_tls::{TlsDomainParser, test_fixtures::*};
use crate::flow_table::{FlowTable, RoleEvidence};
use crate::stats::{RankWindow, Stats};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const BASE_TIME: i64 = 1_800_000_000;

fn frame(inbound: bool, sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let local = [192, 0, 2, 10];
    let peer = [198, 51, 100, 5];
    let (src, dst, sport, dport) = if inbound {
        (peer, local, 443u16, 12345u16)
    } else {
        (local, peer, 12345u16, 443u16)
    };
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[8, 0, 0x45, 0]);
    frame.extend_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&sport.to_be_bytes());
    frame.extend_from_slice(&dport.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

fn packet(
    table: &FlowTable,
    inbound: bool,
    sequence: u32,
    flags: u8,
    payload: &[u8],
    tick: u64,
    epoch: i64,
) -> Flow {
    parse_with_domain_parser_at(
        pcap::Linktype::ETHERNET,
        &frame(inbound, sequence, flags, payload),
        &HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        &CompositeDomainParser::new(),
        Some(table),
        DateTime::from_timestamp(epoch, 0).unwrap(),
        Duration::from_millis(tick),
    )
    .unwrap()
    .flow
    .unwrap()
}

fn syn(table: &FlowTable, isn: u32) -> Flow {
    packet(table, false, isn, 2, &[], 0, BASE_TIME)
}

fn acknowledged_packet(
    table: &FlowTable,
    inbound: bool,
    sequence: u32,
    flags: u8,
    payload: &[u8],
    tick: u64,
    epoch: i64,
) -> Flow {
    let mut bytes = frame(inbound, sequence, flags, payload);
    bytes[42..46].copy_from_slice(&(if inbound { 101u32 } else { 501u32 }).to_be_bytes());
    parse_with_domain_parser_at(
        pcap::Linktype::ETHERNET,
        &bytes,
        &HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        &CompositeDomainParser::new(),
        Some(table),
        DateTime::from_timestamp(epoch, 0).unwrap(),
        Duration::from_millis(tick),
    )
    .unwrap()
    .flow
    .unwrap()
}

fn adopted(flow: &Flow) -> Option<&str> {
    flow.domain
        .as_ref()
        .map(crate::domain_parse::DomainName::name)
}

/// Real parser flows for pipeline/session lifecycle regressions.
pub(crate) fn lifecycle_flows(public: bool, name: &str) -> Vec<Flow> {
    let table = FlowTable::new();
    let extras = if public {
        vec![build_raw_extension(0xfe0d, &[1])]
    } else {
        Vec::new()
    };
    let hello = tls_record_handshake(&client_hello_body(Some(name), &extras));
    let at = Utc::now().timestamp();
    vec![
        packet(&table, false, 100, 2, &[], 0, at),
        packet(&table, false, 101, 16, &hello[..20], 1, at),
        packet(&table, false, 121, 16, &hello[20..], 2, at),
        acknowledged_packet(&table, true, 501, 16, &[], 3, at),
    ]
}

#[cfg(feature = "tls-eval-observe")]
#[test]
fn actual_domain_buckets_and_inclusive_window_edges_follow_input_ledger() {
    use std::collections::BTreeMap;
    let mut stats = Stats::default();
    let mut ledgers = Vec::new();
    for public in [false, true] {
        let table = FlowTable::new();
        let extras = if public {
            vec![build_raw_extension(0xfe0d, &[1])]
        } else {
            Vec::new()
        };
        let hello = tls_record_handshake(&client_hello_body(Some("bucket.example"), &extras));
        let mut ledger = BTreeMap::<i64, (u64, u64)>::new();
        // TCP tail arrives first; capture event epochs and monotonic ticks are
        // deliberately distinct. Input accounting comes from actual frame sizes.
        for (inbound, seq, flags, payload, tick, epoch) in [
            (false, 100, 2, &[][..], 0, BASE_TIME),
            (true, 500, 18, &[][..], 1, BASE_TIME + 1),
            (false, 121, 16, &hello[20..], 2, BASE_TIME + 2),
            (false, 101, 16, &hello[..20], 3, BASE_TIME + 6),
        ] {
            let bytes = frame(inbound, seq, flags, payload).len() as u64;
            let counters = ledger.entry(epoch).or_default();
            if inbound {
                counters.0 += bytes;
            } else {
                counters.1 += bytes;
            }
            let mut flow = acknowledged_packet(&table, inbound, seq, flags, payload, tick, epoch);
            stats.record_flow_domain(&flow, Utc::now());
            if flow.domain.is_some() {
                flow.bytes = 0;
                stats.record_flow_domain(&flow, Utc::now());
            }
        }
        let row = stats
            .observe_domain_rows()
            .find(|row| row.kind == if public { "public_sni" } else { "ordinary" })
            .unwrap();
        let actual: BTreeMap<_, _> = row
            .buckets
            .iter()
            .map(|b| (b.epoch, (b.recv, b.sent)))
            .collect();
        assert_eq!(actual, ledger);
        assert_eq!(row.last_seen, Some(BASE_TIME + 6));
        assert_eq!(row.rank_last_seen_epoch, Some(BASE_TIME + 6));
        assert!(row.bucket_capacity >= row.buckets.len());
        let before_buckets = row.buckets;
        let before_last_seen = row.last_seen;
        let before_sent = row.sent;
        let old = acknowledged_packet(&table, false, 101, 16, &[], 4, BASE_TIME - 400);
        stats.record_flow_domain(&old, Utc::now());
        let after = stats
            .observe_domain_rows()
            .find(|row| row.kind == if public { "public_sni" } else { "ordinary" })
            .unwrap();
        assert_eq!(after.buckets, before_buckets);
        assert_eq!(after.last_seen, before_last_seen);
        assert_eq!(after.sent, before_sent + 54);
        table.finish();
        assert_eq!(table.observe_resources().resolved, 1);
        assert_eq!(table.observe_resources().raw_reserved, 0);
        table.advance(Duration::from_secs(311));
        let resources = table.observe_resources();
        assert_eq!(resources.entries, 0);
        assert_eq!(resources.deadlines, 0);
        assert_eq!(resources.active_order, 0);
        ledgers.push((public, ledger));
    }
    let baseline =
        stats.observe_domain_summary(DateTime::from_timestamp(BASE_TIME + 6, 0).unwrap());
    assert_eq!(
        (
            baseline.cumulative_len,
            baseline.ordinary_len,
            baseline.public_sni_len
        ),
        (2, 1, 1)
    );
    for window in [5, 10, 30, 60, 300] {
        // Every original second is tested exactly at the included endpoint and
        // one second beyond it. snapshot_at queries never mutate retained state.
        for boundary in [BASE_TIME, BASE_TIME + 1, BASE_TIME + 2, BASE_TIME + 6] {
            for now_epoch in [boundary + window - 1, boundary + window] {
                let now = DateTime::from_timestamp(now_epoch, 0).unwrap();
                let snapshot = stats.snapshot_at(10, now, RankWindow::Seconds(window as u32));
                let effective = now_epoch.max(BASE_TIME + 6);
                for (public, ledger) in &ledgers {
                    let expected = ledger
                        .range((effective - window + 1)..=effective)
                        .fold((0, 0), |(r, s), (_, (recv, sent))| (r + recv, s + sent));
                    let rows = if *public {
                        &snapshot.public_sni
                    } else {
                        &snapshot.outbound_domains
                    };
                    let actual = rows.first().map_or((0, 0), |row| {
                        (row.selected_in_bytes, row.selected_out_bytes)
                    });
                    assert_eq!(
                        actual, expected,
                        "public={public} window={window} now={now_epoch}"
                    );
                }
            }
        }
    }
    let after =
        stats.observe_domain_summary(DateTime::from_timestamp(BASE_TIME + 1000, 0).unwrap());
    assert_eq!(
        (
            after.recv,
            after.sent,
            after.last_seen_max,
            after.bucket_len
        ),
        (
            baseline.recv,
            baseline.sent,
            baseline.last_seen_max,
            baseline.bucket_len
        )
    );
    assert!(
        after
            .windows
            .iter()
            .all(|row| row.recv == 0 && row.sent == 0)
    );
}

#[test]
fn public_sni_keeps_outer_identity_across_segments_records_and_stats() {
    // The opaque extension includes a different synthetic inner name. This is
    // parser input, not proof of a real encrypted handshake or its inner target.
    for extension in [0xfe0d, 0xffce] {
        let data = if extension == 0xffce {
            valid_draft_ech_data()
        } else {
            b"inner.example".to_vec()
        };
        let message = client_hello_body(
            Some("shared.example"),
            &[build_raw_extension(extension, &data)],
        );
        let mut wire = tls_record_handshake(&message[..19]);
        wire.extend(tls_record_handshake(&message[19..]));
        for cut in 1..wire.len() {
            let table = FlowTable::new();
            let mut stats = Stats::default();
            let mut expected = 0;
            let first = syn(&table, 100);
            expected += first.bytes;
            stats.record_flow(first, None);
            let inbound = acknowledged_packet(&table, true, 500, 0x12, &[], 1, BASE_TIME + 1);
            expected += inbound.bytes;
            stats.record_flow(inbound, None);
            let prefix =
                acknowledged_packet(&table, false, 101, 0x10, &wire[..cut], 2, BASE_TIME + 2);
            assert!(prefix.domain.is_none(), "cut {cut}");
            expected += prefix.bytes;
            stats.record_flow(prefix, None);
            let mut resolved = acknowledged_packet(
                &table,
                false,
                101 + cut as u32,
                0x10,
                &wire[cut..],
                3,
                BASE_TIME + 6,
            );
            let name = resolved.domain.as_ref().unwrap_or_else(|| {
                panic!(
                    "extension={extension:x} cut={cut} event={:?}",
                    resolved.domain_event
                )
            });
            assert_eq!(name.name(), "shared.example");
            assert_eq!(name.kind(), DomainKind::PublicSni);
            expected += resolved.bytes;
            // Repeated supplement delivery counts no bytes twice. A zero-byte
            // copy reuses the same delivery without replaying the current packet.
            stats.record_flow_domain(&resolved, Utc::now());
            stats.record_interface_flow(&resolved, Utc::now());
            let current_bytes = resolved.bytes;
            resolved.bytes = 0;
            stats.record_flow_domain(&resolved, Utc::now());
            stats.record_process(None, resolved.direction, current_bytes, Utc::now());
            for (inbound, flags, epoch) in [(false, 0x10, 7), (true, 0x11, 8), (false, 0x14, 9)] {
                let flow = acknowledged_packet(
                    &table,
                    inbound,
                    if inbound {
                        501
                    } else {
                        101 + wire.len() as u32
                    },
                    flags,
                    &[],
                    epoch as u64,
                    BASE_TIME + epoch,
                );
                assert_eq!(flow.domain.as_ref().unwrap().kind(), DomainKind::PublicSni);
                expected += flow.bytes;
                stats.record_flow(flow, None);
            }
            let now = DateTime::from_timestamp(BASE_TIME + 9, 0).unwrap();
            let all = stats.snapshot_at(10, now, RankWindow::Cumulative);
            assert!(all.outbound_domains.is_empty());
            assert_eq!(all.public_sni.len(), 1);
            assert_eq!(all.public_sni[0].total_bytes(), expected);
            assert_eq!(all.public_sni[0].last_seen(), now);
            assert_eq!(stats.in_bytes + stats.out_bytes, expected);
            let recent = stats.snapshot_at(10, now, RankWindow::FIVE_SECONDS);
            assert_eq!(
                recent.public_sni[0].selected_in_bytes + recent.public_sni[0].selected_out_bytes,
                (54 + wire.len() - cut) as u64 + 3 * 54
            );
            assert_eq!(table.domain_diagnostics().resolved, 1);
            assert_eq!(table.domain_diagnostics().public_sni_resolved, 1);
            assert_eq!(table.domain_diagnostics().raw_reserved, 0);
            // A new SYN generation cannot inherit the previous public label.
            let replaced = syn(&table, 10000);
            assert!(replaced.domain.is_none());
            stats.record_flow(replaced, None);
            let late = packet(&table, false, 101, 0x10, &wire, 10, BASE_TIME + 10);
            assert!(late.domain.is_none());
            stats.record_flow(late, None);
            assert_eq!(
                stats
                    .snapshot_at(10, now, RankWindow::Cumulative)
                    .public_sni[0]
                    .total_bytes(),
                expected
            );
        }
    }
}

#[test]
fn public_and_ordinary_same_name_keep_independent_totals_windows_and_ranking() {
    let mut stats = Stats::default();
    let public = tls_record_handshake(&client_hello_body(
        Some("same.example"),
        &[build_raw_extension(0xfe0d, &[1])],
    ));
    let ordinary = tls_client_hello_with_sni("same.example");
    let http = b"GET / HTTP/1.1\r\nHost: same.example\r\n\r\n";
    let mut normal_bytes = 0;
    let mut public_bytes = 0;
    for (wire, epoch, public_kind) in [
        (&public[..], 0, true),
        (&ordinary[..], 10, false),
        (&http[..], 11, false),
    ] {
        let table = FlowTable::new();
        let flow = packet(&table, false, 1, 0x10, wire, 0, BASE_TIME + epoch);
        assert_eq!(
            flow.domain.as_ref().unwrap().kind(),
            if public_kind {
                DomainKind::PublicSni
            } else {
                DomainKind::Ordinary
            }
        );
        if public_kind {
            public_bytes += flow.bytes;
        } else {
            normal_bytes += flow.bytes;
        }
        stats.record_flow(flow, None);
    }
    let now = DateTime::from_timestamp(BASE_TIME + 11, 0).unwrap();
    let all = stats.snapshot_at(10, now, RankWindow::Cumulative);
    assert_eq!(all.outbound_domains[0].host(), "same.example");
    assert_eq!(all.public_sni[0].host(), "same.example");
    assert_eq!(all.outbound_domains[0].total_bytes(), normal_bytes);
    assert_eq!(all.public_sni[0].total_bytes(), public_bytes);
    assert_eq!(all.outbound_domains[0].last_seen(), now);
    assert_eq!(all.public_sni[0].last_seen().timestamp(), BASE_TIME);
    assert_eq!(all.domain_rows.len(), 2);
    assert!(all.domain_rows[0].total_bytes() >= all.domain_rows[1].total_bytes());
    let recent = stats.snapshot_at(10, now, RankWindow::FIVE_SECONDS);
    assert!(recent.public_sni.is_empty());
    assert_eq!(recent.outbound_domains[0].selected_out_bytes, normal_bytes);
    assert_eq!(
        all.outbound_domains[0].total_bytes() + all.public_sni[0].total_bytes(),
        stats.in_bytes + stats.out_bytes
    );
}

#[test]
fn public_sni_requires_complete_valid_extensions_and_visible_sni() {
    for extension in [0xfe0d, 0xffce] {
        let data = if extension == 0xffce {
            valid_draft_ech_data()
        } else {
            vec![1, 2, 3]
        };
        let hello = tls_record_handshake(&client_hello_body(
            Some("outer.example"),
            &[build_raw_extension(extension, &data)],
        ));
        let table = FlowTable::new();
        syn(&table, 100);
        // SNI is already present, but the later extension is incomplete.
        let incomplete = packet(
            &table,
            false,
            101,
            0,
            &hello[..hello.len() - 1],
            1,
            BASE_TIME,
        );
        assert!(incomplete.domain.is_none());
        let complete = packet(
            &table,
            false,
            101 + hello.len() as u32 - 1,
            0,
            &hello[hello.len() - 1..],
            2,
            BASE_TIME,
        );
        assert_eq!(
            complete.domain.as_ref().unwrap().kind(),
            DomainKind::PublicSni
        );
        Stats::default().record_flow(complete, None);
        for body in [
            client_hello_body(None, &[build_raw_extension(extension, &data)]),
            client_hello_body(
                Some("outer.example"),
                &[vec![(extension >> 8) as u8, extension as u8, 0, 9, 1]],
            ),
        ] {
            let table = FlowTable::new();
            let mut stats = Stats::default();
            let flow = packet(
                &table,
                false,
                1,
                0,
                &tls_record_handshake(&body),
                0,
                BASE_TIME,
            );
            assert!(flow.domain.is_none());
            stats.record_flow(flow, None);
            let snapshot = stats.snapshot(10);
            assert!(snapshot.outbound_domains.is_empty());
            assert!(snapshot.public_sni.is_empty());
        }
    }
}

#[test]
fn every_tcp_cut_and_reverse_order_uses_the_real_parser() {
    let hello = tls_client_hello_with_sni("split.example");
    for cut in 1..hello.len() {
        for reverse in [false, true] {
            let table = FlowTable::new();
            syn(&table, 100);
            let pieces = if reverse {
                [(cut, hello.len()), (0, cut)]
            } else {
                [(0, cut), (cut, hello.len())]
            };
            let first = packet(
                &table,
                false,
                101 + pieces[0].0 as u32,
                0,
                &hello[pieces[0].0..pieces[0].1],
                1,
                BASE_TIME,
            );
            assert!(adopted(&first).is_none());
            let last = packet(
                &table,
                false,
                101 + pieces[1].0 as u32,
                0,
                &hello[pieces[1].0..pieces[1].1],
                2,
                BASE_TIME,
            );
            assert_eq!(
                adopted(&last),
                Some("split.example"),
                "cut={cut} reverse={reverse}"
            );
            assert_eq!(
                last.domain_event.as_ref().unwrap().role,
                RoleEvidence::ConfirmedLocalInitiator
            );
            assert_eq!(table.domain_diagnostics().raw_reserved, 0);
            let mut stats = Stats::default();
            stats.record_flow(last, None);
            assert_eq!(table.domain_diagnostics().delivery_failures, 0);
        }
    }
}

#[test]
fn handshake_header_spans_records_and_more_than_three_segments() {
    let message = client_hello_body(Some("records.example"), &[]);
    let mut wire = tls_record_handshake(&message[..2]);
    wire.extend(tls_record_handshake(&message[2..17]));
    wire.extend(tls_record_handshake(&message[17..]));
    wire.extend(tls_record(23, &[1, 2, 3]));
    let table = FlowTable::new();
    syn(&table, u32::MAX - 10);
    let mut stats = Stats::default();
    for (index, chunk) in wire.chunks(7).enumerate() {
        let flow = packet(
            &table,
            false,
            (u32::MAX - 9).wrapping_add((index * 7) as u32),
            0,
            chunk,
            index as u64,
            BASE_TIME,
        );
        stats.record_flow(flow, None);
    }
    let ack = packet(
        &table,
        false,
        (u32::MAX - 9).wrapping_add(wire.len() as u32),
        0,
        &[],
        99,
        BASE_TIME,
    );
    assert_eq!(adopted(&ack), Some("records.example"));
    assert_eq!(table.domain_diagnostics().resolved, 1);
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
}

#[test]
fn precommit_overlap_conflict_is_terminal_and_frees_raw() {
    let hello = tls_client_hello_with_sni("conflict.example");
    let table = FlowTable::new();
    syn(&table, 100);
    packet(&table, false, 101, 0, &hello[..20], 1, BASE_TIME);
    let duplicate = packet(&table, false, 101, 0, &hello[..20], 2, BASE_TIME);
    assert!(duplicate.domain.is_none());
    let mut conflict = hello[..20].to_vec();
    conflict[10] ^= 1;
    let rejected = packet(&table, false, 101, 0, &conflict, 3, BASE_TIME);
    assert_eq!(
        rejected.domain_event.unwrap().reason,
        Some(DomainReason::OverlapConflict)
    );
    let tail = packet(&table, false, 121, 0, &hello[20..], 4, BASE_TIME);
    assert!(tail.domain.is_none());
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
}

#[test]
fn domain_freezes_after_commit_and_syn_reuse_isolated() {
    let table = FlowTable::new();
    let hello = tls_client_hello_with_sni("first.example");
    syn(&table, 100);
    let first = packet(&table, false, 101, 0, &hello, 1, BASE_TIME);
    let generation = first.domain_event.as_ref().unwrap().generation;
    Stats::default().record_flow(first, None);
    let conflict = packet(&table, false, 101, 0, &[0; 20], 2, BASE_TIME);
    assert_eq!(adopted(&conflict), Some("first.example"));
    let retransmitted_syn = packet(&table, false, 100, 2, &[], 3, BASE_TIME);
    assert_eq!(
        retransmitted_syn.domain_event.as_ref().unwrap().generation,
        generation
    );
    let new_syn = packet(&table, false, 2_000_000, 2, &[], 4, BASE_TIME);
    assert!(new_syn.domain.is_none());
    let late = packet(&table, false, 101, 0, &hello, 5, BASE_TIME);
    assert!(late.domain.is_none());
    let second = packet(
        &table,
        false,
        2_000_001,
        0,
        &tls_client_hello_with_sni("second.example"),
        6,
        BASE_TIME,
    );
    assert_eq!(adopted(&second), Some("second.example"));
    Stats::default().record_flow(second, None);
}

#[test]
fn inferred_client_and_remote_initiator_have_distinct_policy() {
    let hello = tls_client_hello_with_sni("role.example");
    let table = FlowTable::new();
    let flow = packet(&table, false, 100, 0, &hello, 0, BASE_TIME);
    assert_eq!(adopted(&flow), Some("role.example"));
    assert_eq!(
        flow.domain_event.unwrap().role,
        RoleEvidence::TlsClientInferred
    );
    let table = FlowTable::new();
    packet(&table, true, 500, 2, &[], 0, BASE_TIME);
    let flow = packet(&table, false, 100, 0, &hello, 1, BASE_TIME);
    assert!(flow.domain.is_none());
    assert_eq!(
        flow.domain_event.unwrap().role,
        RoleEvidence::RemoteInitiator
    );
}

#[test]
fn reordered_fin_waits_for_hello_and_half_close_keeps_label() {
    let table = FlowTable::new();
    let hello = tls_client_hello_with_sni("fin.example");
    syn(&table, 100);
    packet(
        &table,
        false,
        101 + hello.len() as u32,
        1,
        &[],
        1,
        BASE_TIME,
    );
    packet(&table, false, 131, 0, &hello[30..], 2, BASE_TIME);
    let final_part = packet(&table, false, 101, 0, &hello[..30], 3, BASE_TIME);
    assert_eq!(adopted(&final_part), Some("fin.example"));
    let mut stats = Stats::default();
    stats.record_flow(final_part, None);
    let reply = packet(&table, true, 500, 0, &[], 4, BASE_TIME);
    assert_eq!(adopted(&reply), Some("fin.example"));
    let reset = packet(&table, true, 500, 4, &[], 5, BASE_TIME);
    assert_eq!(adopted(&reset), Some("fin.example"));
    assert!(
        packet(&table, true, 500, 0, &[], 6, BASE_TIME)
            .domain
            .is_none()
    );
}

#[test]
fn no_progress_absolute_deadline_and_observation_tick_release_resources() {
    let hello = tls_client_hello_with_sni("gap.example");
    let table = FlowTable::new();
    syn(&table, 100);
    packet(&table, false, 121, 0, &hello[20..], 1, BASE_TIME);
    packet(&table, false, 121, 0, &hello[20..], 1900, BASE_TIME);
    table.advance(Duration::from_millis(2001));
    let flow = packet(&table, false, 101, 0, &hello[..20], 2002, BASE_TIME);
    assert_eq!(
        flow.domain_event.unwrap().reason,
        Some(DomainReason::GapAtDeadline)
    );
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
    let table = FlowTable::new();
    syn(&table, 100);
    table.advance(Duration::from_secs(5));
    assert_eq!(
        table.domain_diagnostics().reasons[&DomainReason::ObservationTimeout],
        1
    );
    assert_eq!(table.domain_diagnostics().active, 0);
}

#[test]
fn ech_observation_resolves_public_sni_and_malformed_wins() {
    let parser = TlsDomainParser::new();
    let DomainParseResult::Complete(hello) = parser.parse_result(&tls_client_hello_with_ech())
    else {
        panic!("complete ECH");
    };
    assert!(hello.ech_extension_present);
    assert_eq!(hello.observed_sni.as_deref(), Some("cover.example"));
    let table = FlowTable::new();
    let flow = packet(
        &table,
        false,
        1,
        0,
        &tls_client_hello_with_ech(),
        0,
        BASE_TIME,
    );
    let event = flow.domain_event.unwrap();
    assert_eq!(event.reason, None);
    assert_eq!(
        event.domain.unwrap().kind(),
        crate::domain_parse::DomainKind::PublicSni
    );
    assert!(event.observation.unwrap().ech_extension_present);
    let malformed = tls_record_handshake(&client_hello_body(
        Some("cover.example"),
        &[vec![0xfe, 0x0d, 0, 9, 1]],
    ));
    assert_eq!(
        parser.parse_result(&malformed),
        DomainParseResult::Rejected(DomainReason::Malformed)
    );
}

#[test]
fn bidirectional_backfill_keeps_original_seconds_and_normal_stats_once() {
    let table = FlowTable::new();
    let hello = tls_client_hello_with_sni("bytes.example");
    let mut stats = Stats::default();
    let flows = [
        syn(&table, 100),
        packet(&table, true, 500, 0, &[], 1, BASE_TIME + 1),
        packet(&table, false, 101, 0, &hello[..20], 2, BASE_TIME + 2),
        packet(&table, false, 121, 0, &hello[20..], 3, BASE_TIME + 6),
        packet(
            &table,
            false,
            101 + hello.len() as u32,
            0,
            &[],
            4,
            BASE_TIME + 7,
        ),
    ];
    let expected = flows.iter().map(|flow| flow.bytes).sum::<u64>();
    for flow in flows {
        stats.record_flow(flow, None);
    }
    let now = DateTime::<Utc>::from_timestamp(BASE_TIME + 7, 0).unwrap();
    let snapshot = stats.snapshot_at(10, now, RankWindow::FIVE_SECONDS);
    let domain = &snapshot.outbound_domains[0];
    assert_eq!(domain.total_bytes(), expected);
    assert_eq!(
        domain.selected_in_bytes + domain.selected_out_bytes,
        54 + (hello.len() - 20) as u64 + 54
    );
    assert_eq!(stats.in_bytes + stats.out_bytes, expected);
    assert_eq!(domain.last_seen, now);
    assert_eq!(table.domain_diagnostics().delivery_failures, 0);
}

#[test]
fn budget_failures_release_buffers_and_drop_reports_delivery_failure() {
    let table = FlowTable::new();
    syn(&table, 100);
    let oversized = vec![22; 44 * 1024];
    let flow = packet(&table, false, 101, 0, &oversized, 1, BASE_TIME);
    assert_eq!(
        flow.domain_event.unwrap().reason,
        Some(DomainReason::PerFlowBudget)
    );
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
    let table = FlowTable::new();
    syn(&table, 100);
    let flow = packet(
        &table,
        false,
        101,
        0,
        &tls_client_hello_with_sni("delivery.example"),
        1,
        BASE_TIME,
    );
    drop(flow);
    assert_eq!(table.domain_diagnostics().delivery_failures, 1);
    assert_eq!(table.domain_diagnostics().delivery_failed_bytes, 54);
}

#[test]
fn original_seconds_expiration_duplicate_backfill_and_last_seen_are_stable() {
    let table = FlowTable::new();
    let mut stats = Stats::default();
    let hello = tls_client_hello_with_sni("windows.example");
    stats.record_flow(syn(&table, 100), None);
    stats.record_flow(
        packet(&table, false, 101, 0, &hello[..20], 1, BASE_TIME + 1),
        None,
    );
    let resolved = packet(&table, false, 121, 0, &hello[20..], 2, BASE_TIME + 6);
    let success_bytes = resolved.bytes;
    stats.record_flow_domain(&resolved, Utc::now());
    let expected = 54 + 74 + success_bytes;
    // Only the supplement is idempotent; the current packet remains an ordinary
    // byte event. Replaying that event here isolates the supplement guard.
    stats.record_flow_domain(&resolved, Utc::now());
    let now = DateTime::from_timestamp(BASE_TIME + 6, 0).unwrap();
    let total = stats
        .snapshot_at(10, now, RankWindow::Cumulative)
        .outbound_domains[0]
        .total_bytes();
    assert_eq!(total, expected + success_bytes);
    for (window, expected_window) in [
        (5, success_bytes * 2),
        (10, total),
        (30, total),
        (60, total),
        (300, total),
    ] {
        let snapshot = stats.snapshot_at(10, now, RankWindow::Seconds(window));
        assert_eq!(
            snapshot.outbound_domains[0].selected_out_bytes,
            expected_window
        );
    }
    let older = packet(&table, false, 101, 0, &[], 3, BASE_TIME - 400);
    stats.record_flow(older, None);
    let snapshot = stats.snapshot_at(10, now, RankWindow::FIVE_MINUTES);
    assert_eq!(snapshot.outbound_domains[0].selected_out_bytes, total);
    assert_eq!(snapshot.outbound_domains[0].last_seen, now);
    assert_eq!(snapshot.outbound_domains[0].total_bytes(), total + 54);
}

#[test]
fn no_syn_reverse_segments_adjust_start_before_inference() {
    let table = FlowTable::new();
    let hello = tls_client_hello_with_sni("inferred.example");
    packet(&table, false, 120, 0, &hello[20..], 0, BASE_TIME);
    let flow = packet(&table, false, 100, 0, &hello[..20], 1, BASE_TIME);
    assert_eq!(adopted(&flow), Some("inferred.example"));
    assert_eq!(
        flow.domain_event.as_ref().unwrap().role,
        RoleEvidence::TlsClientInferred
    );
    Stats::default().record_flow(flow, None);
}

#[test]
fn ipv4_fragments_never_adopt_even_when_first_fragment_contains_hello() {
    let table = FlowTable::new();
    let mut bytes = frame(
        false,
        100,
        0,
        &tls_client_hello_with_sni("fragment.example"),
    );
    bytes[20] = 0x20;
    let flow = parse_with_domain_parser_at(
        pcap::Linktype::ETHERNET,
        &bytes,
        &HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        &CompositeDomainParser::new(),
        Some(&table),
        DateTime::from_timestamp(BASE_TIME, 0).unwrap(),
        Duration::ZERO,
    )
    .unwrap()
    .flow
    .unwrap();
    assert!(flow.domain.is_none());
    assert!(flow.domain_event.is_none());
    assert_eq!(table.domain_diagnostics().started, 0);
}

#[test]
fn http_coverage_stays_single_packet() {
    let table = FlowTable::new();
    syn(&table, 100);
    let flow = packet(
        &table,
        false,
        101,
        0,
        b"GET / HTTP/1.1\r\nHost: http.example\r\n\r\n",
        1,
        BASE_TIME,
    );
    assert_eq!(adopted(&flow), Some("http.example"));
    Stats::default().record_flow(flow, None);
    let table = FlowTable::new();
    syn(&table, 100);
    packet(&table, false, 101, 0, b"GET / HTTP/1.1\r\n", 1, BASE_TIME);
    let flow = packet(
        &table,
        false,
        117,
        0,
        b"Host: split.example\r\n\r\n",
        2,
        BASE_TIME,
    );
    assert!(flow.domain.is_none());
}

#[test]
fn active_and_global_raw_pressure_are_bounded_and_finish_cleans_up() {
    use crate::flow_table::{FlowKey, TcpObservation};
    let parser = CompositeDomainParser::new();
    let key = |port| FlowKey {
        local_ip: "192.0.2.10".parse().unwrap(),
        local_port: port,
        peer_ip: "198.51.100.5".parse().unwrap(),
        peer_port: 443,
    };
    let observe = |table: &FlowTable, port, payload: &[u8]| {
        table.observe(
            key(port),
            TcpObservation {
                direction: crate::stats::Direction::Outbound,
                sequence: 101,
                acknowledgment: 0,
                syn: false,
                ack: false,
                fin: false,
                rst: false,
                payload,
                bytes: 54 + payload.len() as u64,
                observed_at: DateTime::from_timestamp(BASE_TIME, 0).unwrap(),
                now: Duration::ZERO,
            },
            &parser,
        )
    };
    let table = FlowTable::new();
    for port in 10000..14100 {
        observe(&table, port, &[]);
    }
    let diagnostics = table.domain_diagnostics();
    assert_eq!(diagnostics.active, 4096);
    assert_eq!(diagnostics.reasons[&DomainReason::GlobalBudgetEvicted], 4);
    assert!(diagnostics.metadata_peak_reserved <= 16 * 1024 * 1024);
    table.finish();
    assert_eq!(table.domain_diagnostics().active, 0);
    assert_eq!(table.domain_diagnostics().metadata_reserved, 0);
    let table = FlowTable::new();
    let mut incomplete = vec![0; 12 * 1024];
    incomplete[..5].copy_from_slice(&[22, 3, 3, 0xff, 0xff]);
    for port in 10000..11200 {
        observe(&table, port, &incomplete);
    }
    let diagnostics = table.domain_diagnostics();
    assert!(diagnostics.reasons[&DomainReason::GlobalBudgetEvicted] > 0);
    assert!(diagnostics.raw_peak_reserved <= 32 * 1024 * 1024);
    assert!(diagnostics.active_peak <= 4096);
    table.finish();
    let diagnostics = table.domain_diagnostics();
    assert_eq!(diagnostics.raw_reserved, 0);
    assert_eq!(
        diagnostics.started,
        diagnostics.resolved + diagnostics.reasons.values().sum::<u64>()
    );
}

#[test]
fn sparse_interval_budget_is_terminal() {
    let table = FlowTable::new();
    syn(&table, 100);
    for index in 0..64 {
        let flow = packet(
            &table,
            false,
            102 + index * 2,
            0,
            &[0],
            index as u64,
            BASE_TIME,
        );
        assert!(flow.domain_event.unwrap().reason.is_none());
    }
    let flow = packet(&table, false, 230, 0, &[0], 65, BASE_TIME);
    assert_eq!(
        flow.domain_event.unwrap().reason,
        Some(DomainReason::PerFlowBudget)
    );
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
}

#[test]
fn older_generation_can_resolve_later_and_new_source_deliveries_do_not_collide() {
    let parser = CompositeDomainParser::new();
    let old = FlowTable::new();
    let newer = FlowTable::new();
    let mut stats = Stats::default();
    stats.record_flow(syn(&old, 100), None);
    stats.record_flow(syn(&newer, 100), None);
    let newer_flow = packet(
        &newer,
        false,
        101,
        0,
        &tls_client_hello_with_sni("newer.example"),
        1,
        BASE_TIME,
    );
    let newer_generation = newer_flow.domain_event.as_ref().unwrap().generation;
    stats.record_flow(newer_flow, None);
    let old_flow = packet(
        &old,
        false,
        101,
        0,
        &tls_client_hello_with_sni("older.example"),
        1,
        BASE_TIME,
    );
    assert!(old_flow.domain_event.as_ref().unwrap().generation < newer_generation);
    let old_expected = 54 + old_flow.bytes;
    stats.record_flow(old_flow, None);
    let snapshot = stats.snapshot_at(
        10,
        DateTime::from_timestamp(BASE_TIME, 0).unwrap(),
        RankWindow::Cumulative,
    );
    let old_domain = snapshot
        .outbound_domains
        .iter()
        .find(|domain| domain.host() == "older.example")
        .unwrap();
    assert_eq!(old_domain.total_bytes(), old_expected);
    assert_eq!(old.domain_diagnostics().delivery_failures, 0);
    assert_eq!(newer.domain_diagnostics().delivery_failures, 0);
    assert!(parser.supports_streams());
}

#[test]
fn delayed_old_syn_cannot_replace_a_resolved_new_generation() {
    let table = FlowTable::new();
    syn(&table, 100);
    let first = packet(
        &table,
        false,
        101,
        0,
        &tls_client_hello_with_sni("old.example"),
        1,
        BASE_TIME,
    );
    Stats::default().record_flow(first, None);
    packet(&table, false, 2_000_000, 2, &[], 2, BASE_TIME);
    let second = packet(
        &table,
        false,
        2_000_001,
        0,
        &tls_client_hello_with_sni("new.example"),
        3,
        BASE_TIME,
    );
    let generation = second.domain_event.as_ref().unwrap().generation;
    Stats::default().record_flow(second, None);
    let old_syn = packet(&table, false, 100, 2, &[], 4, BASE_TIME);
    assert_eq!(
        old_syn.domain_event.as_ref().unwrap().generation,
        generation
    );
    assert_eq!(
        old_syn.domain_event.as_ref().unwrap().reason,
        Some(DomainReason::GenerationAmbiguous)
    );
    assert!(old_syn.domain.is_none());
    assert!(
        packet(
            &table,
            false,
            101,
            0,
            &tls_client_hello_with_sni("old.example"),
            5,
            BASE_TIME
        )
        .domain
        .is_none()
    );
    assert_eq!(
        adopted(&packet(&table, false, 2_000_001, 0, &[], 6, BASE_TIME)),
        Some("new.example")
    );
    assert_eq!(table.domain_diagnostics().started, 2);
}

#[test]
fn http_retries_single_packets_without_combining_headers() {
    let table = FlowTable::new();
    syn(&table, 100);
    let partial = packet(
        &table,
        false,
        101,
        0,
        b"PROPFIND / HTTP/1.1\r\n",
        1,
        BASE_TIME,
    );
    assert!(partial.domain_event.as_ref().unwrap().reason.is_none());
    let request = b"PROPFIND / HTTP/1.1\r\nHost: retry.example\r\n\r\n";
    let full_retransmission = packet(&table, false, 101, 0, request, 2, BASE_TIME);
    assert_eq!(adopted(&full_retransmission), Some("retry.example"));
    Stats::default().record_flow(full_retransmission, None);
    let table = FlowTable::new();
    syn(&table, 100);
    for tick in 1..=3 {
        let flow = packet(
            &table,
            false,
            101,
            0,
            b"GET / HTTP/1.1\r\n",
            tick,
            BASE_TIME,
        );
        assert_eq!(
            flow.domain_event.as_ref().unwrap().reason,
            if tick < 3 {
                None
            } else {
                Some(DomainReason::NonTargetProtocol)
            }
        );
    }
    assert!(
        packet(
            &table,
            false,
            101,
            0,
            b"GET / HTTP/1.1\r\nHost: too-late.example\r\n\r\n",
            4,
            BASE_TIME
        )
        .domain
        .is_none()
    );
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
}

#[test]
fn short_http_method_tokens_allow_a_complete_single_packet_retry() {
    for confirmed in [false, true] {
        for (prefix, method) in [
            (b"G".as_slice(), "GET"),
            (b"PRO".as_slice(), "PROPFIND"),
            (b"X-".as_slice(), "X-CUSTOM"),
            (b"x-1".as_slice(), "x-1-custom"),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHI".as_slice(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN",
            ),
        ] {
            let table = FlowTable::new();
            if confirmed {
                syn(&table, 100);
            }
            let partial = packet(&table, false, 101, 0, prefix, 1, BASE_TIME);
            assert!(partial.domain.is_none());
            assert!(partial.domain_event.as_ref().unwrap().reason.is_none());
            assert_eq!(table.domain_diagnostics().raw_reserved, 0);
            let request = format!("{method} / HTTP/1.1\r\nHost: retry.example\r\n\r\n");
            let complete = packet(&table, false, 101, 0, request.as_bytes(), 2, BASE_TIME);
            assert_eq!(adopted(&complete), Some("retry.example"));
            assert_eq!(
                complete.domain_event.as_ref().unwrap().role,
                if confirmed {
                    RoleEvidence::ConfirmedLocalInitiator
                } else {
                    RoleEvidence::HttpClientInferred
                }
            );
            Stats::default().record_flow(complete, None);
        }
    }
    let table = FlowTable::new();
    syn(&table, 100);
    for tick in 1..=3 {
        let attempt = packet(&table, false, 101, 0, b"G", tick, BASE_TIME);
        assert!(attempt.domain.is_none());
        assert_eq!(
            attempt.domain_event.as_ref().unwrap().reason,
            (tick == 3).then_some(DomainReason::NonTargetProtocol)
        );
    }
    assert_eq!(table.domain_diagnostics().raw_reserved, 0);
}

#[test]
fn rst_event_and_ledger_agree_on_terminal_state() {
    use crate::flow_table::DomainState;
    for pending in [false, true] {
        let table = FlowTable::new();
        syn(&table, 100);
        if pending {
            packet(&table, false, 101, 0, &[22, 3], 1, BASE_TIME);
        }
        let reset = packet(&table, false, 103, 4, &[], 2, BASE_TIME);
        let event = reset.domain_event.unwrap();
        assert_eq!(event.reason, Some(DomainReason::ClosedBeforeHello));
        assert_eq!(
            event.state,
            DomainState::Rejected(DomainReason::ClosedBeforeHello)
        );
        let diagnostics = table.domain_diagnostics();
        assert_eq!(diagnostics.raw_reserved, 0);
        assert_eq!(diagnostics.reasons[&DomainReason::ClosedBeforeHello], 1);
        assert_eq!(diagnostics.active, 0);
    }
}

#[test]
fn ipv6_hello_and_fragments_keep_domain_and_normal_counting_separate() {
    use super::parser::{PacketDisposition, parse_with_payload};
    use std::net::Ipv6Addr;
    let local: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let peer: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let ips = HashSet::from([IpAddr::V6(local)]);
    let hello = tls_client_hello_with_sni("ipv6.example");
    let tcp = frame(false, 101, 0, &hello)[34..].to_vec();
    for fragment in [None, Some(1u16), Some(8u16)] {
        let mut wire = vec![0; 12];
        wire.extend_from_slice(&[0x86, 0xdd]);
        wire.extend_from_slice(&[0x60, 0, 0, 0]);
        wire.extend_from_slice(
            &((tcp.len() + usize::from(fragment.is_some()) * 8) as u16).to_be_bytes(),
        );
        wire.extend_from_slice(&[if fragment.is_some() { 44 } else { 6 }, 64]);
        wire.extend_from_slice(&local.octets());
        wire.extend_from_slice(&peer.octets());
        if let Some(offset_and_flags) = fragment {
            wire.extend_from_slice(&[6, 0]);
            wire.extend_from_slice(&offset_and_flags.to_be_bytes());
            wire.extend_from_slice(&1u32.to_be_bytes());
        }
        wire.extend_from_slice(&tcp);
        let ordinary = parse_with_payload(pcap::Linktype::ETHERNET, &wire, &ips).unwrap();
        let table = FlowTable::new();
        let parsed = parse_with_domain_parser_at(
            pcap::Linktype::ETHERNET,
            &wire,
            &ips,
            &CompositeDomainParser::new(),
            Some(&table),
            DateTime::from_timestamp(BASE_TIME, 0).unwrap(),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(parsed.disposition, ordinary.disposition);
        assert_eq!(parsed.disposition, PacketDisposition::Accepted);
        let flow = parsed.flow.unwrap();
        assert_eq!(flow.bytes, wire.len() as u64);
        assert_eq!(flow.bytes, ordinary.parsed.unwrap().0.bytes);
        if fragment.is_none() {
            assert_eq!(adopted(&flow), Some("ipv6.example"));
            assert_eq!(
                flow.domain_event.as_ref().unwrap().role,
                RoleEvidence::TlsClientInferred
            );
        } else {
            assert!(flow.domain.is_none());
            assert!(flow.domain_event.is_none());
            assert_eq!(table.domain_diagnostics().started, 0);
        }
        let mut stats = Stats::default();
        stats.record_flow(flow, None);
        assert_eq!(stats.snapshot(10).out_bytes, wire.len() as u64);
    }
}
