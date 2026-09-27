//! Paced synthetic parser -> FlowTable -> Stats acceptance. No NIC or pipeline.
#![allow(dead_code, unused_imports)]
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

use anyhow::{Result, ensure};
use chrono::Utc;
use clap::Parser;
use domain_parse_tls::test_fixtures::*;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    output: PathBuf,
    /// smoke (4 seconds), windows (12 seconds), acceptance (1150 seconds).
    #[arg(long, default_value = "smoke", value_parser = ["smoke", "windows", "acceptance"])]
    profile: String,
    /// Override idle/fixed/growth/reuse/cooldown seconds, comma separated.
    #[arg(long, value_delimiter = ',')]
    seconds: Vec<u64>,
    #[arg(long, default_value_t = 100)]
    fixed_rate: u64,
    #[arg(long, default_value_t = 200)]
    growth_rate: u64,
    #[arg(long, default_value_t = 100)]
    reuse_rate: u64,
    /// Full actual snapshots at each checkpoint, only for <=4096 identities.
    #[arg(long)]
    audit_snapshots: bool,
    /// Generate the real production snapshot each second (default top_n=10).
    #[arg(long, default_value_t = 10)]
    snapshot_top_n: usize,
    /// Selected snapshot window: 0 cumulative, or 5/10/30/60/300 seconds.
    #[arg(long, default_value_t = 0)]
    snapshot_window: u32,
}

#[cfg(test)]
mod runtime_cli_tests {
    use super::*;

    #[test]
    fn accepts_five_comma_separated_phase_durations() {
        let args = Args::try_parse_from([
            "tls_runtime_eval",
            "--output",
            "unused",
            "--seconds",
            "0,0,5,0,1",
        ])
        .unwrap();
        assert_eq!(args.seconds, [0, 0, 5, 0, 1]);
    }
}

// A compact oracle follows input construction, never actual parser labels or
// backfill. The disk ledger preserves each intended identity/original epoch.
#[derive(Default)]
struct Oracle {
    recv: u64,
    sent: u64,
    ordinary_recv: u64,
    ordinary_sent: u64,
    public_sni_recv: u64,
    public_sni_sent: u64,
    seconds: BTreeMap<i64, (u64, u64)>,
}

impl Oracle {
    fn record(&mut self, public: bool, inbound: bool, bytes: u64, epoch: i64) {
        if inbound {
            self.recv += bytes;
            if public {
                self.public_sni_recv += bytes;
            } else {
                self.ordinary_recv += bytes;
            }
            self.seconds.entry(epoch).or_default().0 += bytes;
        } else {
            self.sent += bytes;
            if public {
                self.public_sni_sent += bytes;
            } else {
                self.ordinary_sent += bytes;
            }
            self.seconds.entry(epoch).or_default().1 += bytes;
        }
        self.seconds.retain(|at, _| *at >= epoch - 299);
    }
}

fn frame(
    port: u16,
    inbound: bool,
    seq: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let local = [192, 0, 2, 10];
    let peer = [198, 51, 100, 5];
    let (src, dst, sport, dport) = if inbound {
        (peer, local, 443, port)
    } else {
        (local, peer, port, 443)
    };
    let mut wire = Vec::with_capacity(54 + payload.len());
    etherparse::Ethernet2Header {
        source: [0; 6],
        destination: [0; 6],
        ether_type: etherparse::EtherType::IPV4,
    }
    .write(&mut wire)?;
    etherparse::Ipv4Header::new(
        (20 + payload.len()) as u16,
        64,
        etherparse::IpNumber::TCP,
        src,
        dst,
    )?
    .write(&mut wire)?;
    let mut tcp = etherparse::TcpHeader::new(sport, dport, seq, 65535);
    tcp.syn = flags & 2 != 0;
    tcp.ack = flags & 16 != 0;
    tcp.rst = flags & 4 != 0;
    tcp.acknowledgment_number = acknowledgment;
    tcp.write(&mut wire)?;
    wire.extend_from_slice(payload);
    Ok(wire)
}

#[allow(clippy::too_many_arguments)]
fn connection(
    serial: u64,
    identity: u64,
    table: &flow_table::FlowTable,
    stats: &mut stats::Stats,
    start: Instant,
    oracle: &mut Oracle,
    ledger: &mut impl Write,
) -> Result<()> {
    let public = identity % 2 == 1;
    let name = format!("n{:08}.runtime.example", identity / 2);
    let extras = if public {
        vec![build_raw_extension(0xfe0d, &[1])]
    } else {
        Vec::new()
    };
    let hello = tls_record_handshake(&client_hello_body(Some(&name), &extras));
    let port = 1024 + (serial % 60_000) as u16;
    let isn = 100u32.wrapping_add((serial / 60_000) as u32 * 1_000_000);
    let cut = hello.len() / 2;
    for (inbound, sequence, flags, payload) in [
        (false, isn, 2, &[][..]),
        (false, isn + 1, 16, &hello[..cut]),
        (false, isn + 1 + cut as u32, 16, &hello[cut..]),
        (true, 501, 16, &[][..]),
        (false, isn + 1 + hello.len() as u32, 20, &[][..]),
    ] {
        let acknowledgment = if inbound {
            isn + 1 + hello.len() as u32
        } else {
            501
        };
        let wire = frame(port, inbound, sequence, acknowledgment, flags, payload)?;
        let at = Utc::now();
        oracle.record(public, inbound, wire.len() as u64, at.timestamp());
        writeln!(
            ledger,
            "{}",
            serde_json::json!({"serial":serial,"identity":identity,"kind":if public {"public_sni"} else {"ordinary"},"name":name,"epoch":at.timestamp(),"direction":if inbound {"recv"} else {"sent"},"bytes":wire.len()})
        )?;
        let flow = capture::parse_with_domain_parser_at(
            pcap::Linktype::ETHERNET,
            &wire,
            &HashSet::from(["192.0.2.10".parse()?]),
            &domain_parse_composite::CompositeDomainParser::new(),
            Some(table),
            at,
            start.elapsed(),
        )?
        .flow
        .ok_or_else(|| anyhow::anyhow!("fixture rejected"))?;
        stats.record_interface_flow(&flow, at);
        stats.record_flow_domain(&flow, at);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn checkpoint(
    output: &mut impl Write,
    phase: &str,
    start: Instant,
    table: &flow_table::FlowTable,
    stats: &stats::Stats,
    oracle: &Oracle,
    identities: u64,
    args: &Args,
    scheduled: Instant,
) -> Result<()> {
    let now = Utc::now();
    let checkpoint_lateness = scheduled.elapsed().as_secs_f64();
    let actual = stats.observe_domain_summary(now);
    ensure!(
        actual.cumulative_len as u64 == identities,
        "identity count mismatch"
    );
    let expected_fixed = (args.fixed_rate * args.seconds[1]).min(512);
    let fixed = identities.min(expected_fixed);
    let growth = identities.saturating_sub(expected_fixed);
    ensure!(
        actual.ordinary_len as u64 == fixed.div_ceil(2) + growth.div_ceil(2)
            && actual.public_sni_len as u64 == fixed / 2 + growth / 2,
        "typed identity count mismatch"
    );
    ensure!(
        actual.name_bytes as u64 == identities * "n00000000.runtime.example".len() as u64,
        "name byte count mismatch"
    );
    ensure!(
        (actual.recv, actual.sent) == (oracle.recv, oracle.sent),
        "cumulative mismatch"
    );
    ensure!(
        (
            actual.ordinary_recv,
            actual.ordinary_sent,
            actual.public_sni_recv,
            actual.public_sni_sent
        ) == (
            oracle.ordinary_recv,
            oracle.ordinary_sent,
            oracle.public_sni_recv,
            oracle.public_sni_sent
        ),
        "typed cumulative mismatch"
    );
    let windows: Vec<_> = [5, 10, 30, 60, 300]
        .into_iter()
        .map(|seconds| {
            let totals = oracle
                .seconds
                .range((now.timestamp() - (seconds - 1))..=now.timestamp())
                .fold((0, 0), |(r, s), (_, (recv, sent))| (r + recv, s + sent));
            serde_json::json!({"seconds":seconds,"recv":totals.0,"sent":totals.1})
        })
        .collect();
    if identities <= 4096 {
        for (row, expected) in actual.windows.iter().zip(&windows) {
            ensure!(
                row.recv == expected["recv"].as_u64().unwrap()
                    && row.sent == expected["sent"].as_u64().unwrap(),
                "recent window mismatch"
            );
        }
    }
    let snapshot_start = Instant::now();
    let selected = if args.snapshot_window == 0 {
        stats::RankWindow::Cumulative
    } else {
        stats::RankWindow::Seconds(args.snapshot_window)
    };
    let production_snapshot = stats.snapshot_at(args.snapshot_top_n, now, selected);
    let snapshot_seconds = snapshot_start.elapsed().as_secs_f64();
    let snapshot_cost = serde_json::json!({"seconds":snapshot_seconds,"top_n":args.snapshot_top_n,"window":selected,"ordinary_rows":production_snapshot.outbound_domains.len(),"public_sni_rows":production_snapshot.public_sni.len()});
    drop(production_snapshot);
    let mut snapshots = Vec::new();
    if args.audit_snapshots {
        for (seconds, expected) in [5, 10, 30, 60, 300].into_iter().zip(&windows) {
            let snapshot = stats.snapshot_at(4096, now, stats::RankWindow::Seconds(seconds));
            let totals = snapshot
                .outbound_domains
                .iter()
                .chain(snapshot.public_sni.iter())
                .fold((0, 0), |(recv, sent), row| {
                    (recv + row.selected_in_bytes, sent + row.selected_out_bytes)
                });
            ensure!(
                totals
                    == (
                        expected["recv"].as_u64().unwrap(),
                        expected["sent"].as_u64().unwrap()
                    ),
                "actual snapshot window mismatch"
            );
            let rows: Vec<_> = snapshot.outbound_domains.iter().chain(snapshot.public_sni.iter()).map(|row| serde_json::json!({"name":row.host(),"kind":format!("{:?}",row.kind()),"recv":row.selected_in_bytes,"sent":row.selected_out_bytes,"lifetime_recv":row.in_bytes,"lifetime_sent":row.out_bytes,"last_seen":row.last_seen.timestamp()})).collect();
            snapshots.push(serde_json::json!({"seconds":seconds,"rows":rows}));
        }
    }
    writeln!(
        output,
        "{}",
        serde_json::json!({"phase":phase,"elapsed":start.elapsed().as_secs_f64(),"epoch":now.timestamp(),"checkpoint_lateness_seconds":checkpoint_lateness,"actual":actual,"flow":table.observe_resources(),"oracle":{"identities":identities,"recv":oracle.recv,"sent":oracle.sent,"all_input_windows":windows},"production_snapshot":snapshot_cost,"snapshots":snapshots})
    )?;
    output.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    let seconds = if args.seconds.is_empty() {
        match args.profile.as_str() {
            "acceptance" => vec![30, 90, 600, 120, 310],
            "windows" => vec![0, 1, 0, 0, 11],
            _ => vec![0, 1, 1, 1, 1],
        }
    } else {
        args.seconds.clone()
    };
    args.seconds = seconds.clone();
    ensure!(
        seconds.len() == 5 && seconds.iter().sum::<u64>() <= 3600,
        "duration must be at most one hour"
    );
    ensure!(
        [args.fixed_rate, args.growth_rate, args.reuse_rate]
            .into_iter()
            .all(|rate| (1..=1000).contains(&rate)),
        "rates must be 1..1000"
    );
    let fixed_count = (seconds[1] * args.fixed_rate).min(512);
    let growth_count = seconds[2] * args.growth_rate;
    ensure!(
        growth_count <= 200_000,
        "growth identities must be <=200000"
    );
    ensure!(
        !args.audit_snapshots || fixed_count + growth_count <= 4096,
        "full snapshots require <=4096 identities"
    );
    ensure!(
        seconds[3] == 0 || fixed_count > 0,
        "reuse requires fixed input"
    );
    ensure!(
        [0, 5, 10, 30, 60, 300].contains(&args.snapshot_window) && args.snapshot_top_n <= 4096,
        "invalid snapshot selection"
    );
    std::fs::create_dir_all(&args.output)?;
    let mut output = std::io::BufWriter::new(std::fs::File::create(
        args.output.join("checkpoints.jsonl"),
    )?);
    let mut ledger = std::io::BufWriter::new(std::fs::File::create(
        args.output.join("input-ledger.jsonl"),
    )?);
    writeln!(
        output,
        "{}",
        serde_json::json!({"scope":"synthetic parser -> FlowTable -> direct Stats; no NIC/full pipeline","pid":std::process::id(),"profile":args.profile,"seconds":seconds,"rates":[args.fixed_rate,args.growth_rate,args.reuse_rate],"rank_capacity":4096,"oracle":"input frame construction, disk ledger; no retained full names","measurement":"observer summary scans without name cloning/sorting; real production topN snapshot is separately timed (default cumulative); ledger IO is part of process cost"})
    )?;
    output.flush()?;
    let start = Instant::now();
    let table = flow_table::FlowTable::new();
    let mut stats = stats::Stats::default();
    let mut oracle = Oracle::default();
    let mut serial = 0;
    let mut fixed_seen = 0;
    let mut growth_seen = 0;
    let mut next_checkpoint = start;
    for (index, phase) in ["idle", "fixed", "growth", "reuse", "cooldown"]
        .into_iter()
        .enumerate()
    {
        let rate = match index {
            1 => args.fixed_rate,
            2 => args.growth_rate,
            3 => args.reuse_rate,
            _ => 0,
        };
        let phase_start = Instant::now();
        let phase_end = phase_start + Duration::from_secs(seconds[index]);
        let mut emitted = 0;
        let target = rate * seconds[index];
        while Instant::now() < phase_end || emitted < target {
            table.advance(start.elapsed());
            let due = phase_start + Duration::from_secs_f64(emitted as f64 / rate.max(1) as f64);
            if emitted < target && Instant::now() >= due {
                let identity = match index {
                    1 => {
                        fixed_seen = (emitted + 1).min(512);
                        emitted % 512
                    }
                    2 => {
                        growth_seen = emitted + 1;
                        512 + emitted
                    }
                    3 => emitted % fixed_count,
                    _ => unreachable!(),
                };
                connection(
                    serial,
                    identity,
                    &table,
                    &mut stats,
                    start,
                    &mut oracle,
                    &mut ledger,
                )?;
                serial += 1;
                emitted += 1;
            }
            if Instant::now() >= next_checkpoint {
                checkpoint(
                    &mut output,
                    phase,
                    start,
                    &table,
                    &stats,
                    &oracle,
                    fixed_seen + growth_seen,
                    &args,
                    next_checkpoint,
                )?;
                next_checkpoint = Instant::now() + Duration::from_secs(1);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        checkpoint(
            &mut output,
            &format!("{phase}_end"),
            start,
            &table,
            &stats,
            &oracle,
            fixed_seen + growth_seen,
            &args,
            Instant::now(),
        )?;
    }
    ledger.flush()?;
    // Full name/bucket serialization starts only after all timed checkpoints.
    let mut full = std::io::BufWriter::new(std::fs::File::create(
        args.output.join("actual-domains-after-timing.jsonl"),
    )?);
    for row in stats.observe_domain_rows() {
        writeln!(full, "{}", serde_json::to_string(&row)?)?;
    }
    full.flush()?;
    Ok(())
}
