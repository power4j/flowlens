//! Development-only replay adapter. No user CLI or parser implementation.
#![allow(dead_code)]
#[cfg(not(target_pointer_width = "64"))]
compile_error!("tls_domain_eval state-audit resource ledger requires a 64-bit Rust target");
#[path = "../src/capture/mod.rs"]
mod capture;
#[path = "../src/domain_parse.rs"]
mod domain_parse;
#[path = "../src/domain_parse_composite.rs"]
mod domain_parse_composite;
#[path = "../src/domain_parse_http.rs"]
mod domain_parse_http;
#[path = "../src/domain_parse_tls.rs"]
mod domain_parse_tls;
#[path = "../src/flow_table.rs"]
mod flow_table;
#[path = "../src/stats/mod.rs"]
mod stats;
#[cfg(windows)]
#[path = "../src/windows_local_ips.rs"]
mod windows_local_ips;

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

fn diagnostics(table: &flow_table::FlowTable) -> serde_json::Value {
    let d = table.domain_diagnostics();
    let reasons: std::collections::BTreeMap<_, _> = d
        .reasons
        .iter()
        .map(|(r, n)| (format!("{r:?}"), n))
        .collect();
    serde_json::json!({"started":d.started,"resolved":d.resolved,"normal_resolved":d.resolved-d.public_sni_resolved,"public_sni_resolved":d.public_sni_resolved,"active":d.active,"raw_reserved":d.raw_reserved,"raw_peak":d.raw_peak_reserved,"metadata_reserved":d.metadata_reserved,"metadata_peak":d.metadata_peak_reserved,"active_peak":d.active_peak,"reasons":reasons,"delivery_failures":d.delivery_failures,"delivery_failed_bytes":d.delivery_failed_bytes})
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let cap = pcap::Capture::from_file(&args[1])?;
    let table = Arc::new(flow_table::FlowTable::new());
    let locals: HashSet<_> = args
        .get(4)
        .map(String::as_str)
        .unwrap_or("192.0.2.10")
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let counters = Arc::new(capture::CaptureCounters::with_local_ips(&locals));
    let mut source = capture::CaptureSource {
        link_type: cap.get_datalink(),
        cap,
        interface_name: "development-offline".into(),
        local_ips: locals,
        domain_parser: Box::new(domain_parse_composite::CompositeDomainParser::new()),
        flow_table: table.clone(),
        pcap_counters: counters,
        last_pcap_stats_sample: Instant::now(),
        pending: VecDeque::new(),
        read_mode: capture::CaptureReadMode::NextPacket,
        batch_size: 1,
        is_offline: true,
        offline_exhausted: false,
    };
    let audit = args.get(3).is_some_and(|s| s == "audit");
    let state_audit = args.get(3).is_some_and(|s| s == "state-audit");
    let mut output = std::io::BufWriter::new(std::fs::File::create(&args[2])?);
    let mut stats = stats::Stats::default();
    let mut frames = 0u64;
    let mut accepted = 0u64;
    let mut bytes = 0u64;
    let mut errors = 0u64;
    let start = Instant::now();
    loop {
        let item = source.next();
        if item.as_ref().err().is_some_and(|e| {
            matches!(
                e.downcast_ref::<pcap::Error>(),
                Some(pcap::Error::NoMorePackets)
            )
        }) {
            break;
        }
        frames += 1;
        match item {
            Ok(Some(flow)) => {
                accepted += 1;
                bytes += flow.bytes;
                if audit || state_audit {
                    let event = flow.domain_event.as_ref();
                    let row = serde_json::json!({
                        "frame": frames, "bytes": flow.bytes,
                        "port": flow.local_socket.map(|s| s.port),
                        "local_ip": flow.local_socket.map(|s| s.ip.to_string()),
                        "peer_ip": flow.peer.to_string(), "peer_port": flow.peer_port,
                        "direction": format!("{:?}", flow.direction),
                        "domain": flow.domain.as_ref().filter(|d| d.kind() == domain_parse::DomainKind::Ordinary).map(domain_parse::DomainName::name),
                        "public_sni": flow.domain.as_ref().filter(|d| d.kind() == domain_parse::DomainKind::PublicSni).map(domain_parse::DomainName::name),
                        "generation": event.map(|e| e.generation),
                        "role": event.map(|e| format!("{:?}",e.role)),
                        "state": event.map(|e| format!("{:?}",e.state)),
                        "reason": event.and_then(|e|e.reason).map(|r|format!("{r:?}")),
                        "observed_at": event.map(|e|e.observed_at.timestamp_micros()),
                        "diagnostics": state_audit.then(|| diagnostics(&table)),
                        "backfill": event.and_then(|e|e.backfill.as_ref()).map(|b|
                            serde_json::json!({"recv": b.recv,"sent": b.sent,"delivery":b.delivery_id})),
                    });
                    writeln!(output, "{row}")?;
                }
                let now = chrono::Utc::now();
                stats.record_interface_flow(&flow, now);
                stats.record_flow_domain(&flow, now);
                stats.record_process(None, flow.direction, flow.bytes, now);
            }
            Ok(None) => {}
            Err(e) => {
                errors += 1;
                if audit || state_audit {
                    writeln!(
                        output,
                        "{}",
                        serde_json::json!({"frame":frames,"error":e.to_string()})
                    )?;
                }
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let diag = diagnostics(&table);
    let snapshot = stats.snapshot_at(
        usize::MAX,
        chrono::Utc::now(),
        stats::RankWindow::Cumulative,
    );
    let domains: Vec<_> = snapshot
        .outbound_domains
        .iter()
        .map(|d| serde_json::json!({"host":d.host(),"recv":d.in_bytes,"sent":d.out_bytes}))
        .collect();
    let public_sni: Vec<_> = snapshot
        .public_sni
        .iter()
        .map(|d| serde_json::json!({"host":d.host(),"recv":d.in_bytes,"sent":d.out_bytes}))
        .collect();
    writeln!(
        output,
        "{}",
        serde_json::json!({"summary":true,"frames":frames,
        "accepted":accepted,"bytes":bytes,"errors":errors,"wall_seconds":elapsed,
        "domains":domains,"public_sni":public_sni,"diagnostics":diag,"interface_recv":snapshot.in_bytes,"interface_sent":snapshot.out_bytes,
        "ip_recv":snapshot.inbound_ips.iter().map(|p|p.bytes).sum::<u64>(),
        "ip_sent":snapshot.outbound_ips.iter().map(|p|p.bytes).sum::<u64>(),
        "attribution_total":snapshot.attribution.total()})
    )?;
    Ok(())
}
