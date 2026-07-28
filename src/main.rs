mod attribution;
mod capture;
mod domain_parse;
mod domain_parse_composite;
mod domain_parse_http;
mod domain_parse_tls;
mod flow_table;
mod palette;
mod pipeline;
mod proc_table;
mod process_probe;
mod report;
mod session;
mod stats;
mod tui;
#[cfg(windows)]
#[allow(dead_code)]
mod windows_connection_probe;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use capture::{CaptureSource, TransportProtocol};
use proc_table::LookupMissReason;
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_TOP_N: u64 = 10;
const DEFAULT_PROC_REFRESH: u64 = 2;
const DEFAULT_FLOW_TABLE: u64 = 65_536;
#[cfg_attr(not(windows), allow(dead_code))]
const NPCAP_REQUIRED_MESSAGE: &str =
    "Npcap Runtime is required. Install Npcap from https://npcap.com/ and try again.";

#[cfg(windows)]
unsafe extern "system" {
    fn LoadLibraryW(file_name: *const u16) -> *mut std::ffi::c_void;
    fn FreeLibrary(module: *mut std::ffi::c_void) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchMode {
    InteractiveSelector,
    ExplicitInterface,
    MissingInterface,
}

fn dispatch_mode(cli: &Cli) -> DispatchMode {
    if cli.interface.is_some() {
        DispatchMode::ExplicitInterface
    } else if cli.output.is_none() && cli.format == "plain" {
        DispatchMode::InteractiveSelector
    } else {
        DispatchMode::MissingInterface
    }
}

fn main() -> ExitCode {
    run(Cli::parse(), require_npcap)
}

fn run(cli: Cli, require_npcap: impl FnOnce() -> Result<(), &'static str>) -> ExitCode {
    if let Err(message) = require_npcap() {
        eprintln!("{message}");
        return ExitCode::FAILURE;
    }

    if dispatch_mode(&cli) == DispatchMode::MissingInterface {
        eprintln!("An explicit interface is required for JSON or background file output.");
        if let Err(error) = capture::list_interfaces() {
            eprintln!("Failed to enumerate interfaces: {error}");
        }
        return ExitCode::FAILURE;
    }

    let proc_table = proc_table::spawn(Duration::from_secs(cli.proc_refresh));
    let top_n = cli.top_n as usize;
    let is_json = cli.format == "json";

    if cli.output.is_none() && !is_json {
        let mut session = match session::TrafficSession::discover(proc_table, top_n, cli.flow_table)
        {
            Ok(session) => session,
            Err(error) => {
                eprintln!("Failed to enumerate interfaces: {error}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(selector) = cli.interface.as_deref()
            && let Err(error) = session.activate(selector)
        {
            eprintln!("Failed to open interface: {error}");
            return ExitCode::FAILURE;
        }
        if let Err(error) = tui::run(&mut session) {
            eprintln!("TUI error: {error}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let interface_selector = cli
        .interface
        .as_deref()
        .expect("dispatch requires interface");

    let started_wall = chrono::Local::now();
    let started_at = Instant::now();
    let mut source = match CaptureSource::open(interface_selector, cli.flow_table) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open interface: {e}");
            return ExitCode::FAILURE;
        }
    };
    let interface = source.interface_name().to_string();

    match &cli.output {
        Some(path) => {
            // Background file mode: write snapshot each refresh tick.
            eprintln!(
                "Background mode: refreshing stats to {path} every {}s",
                REFRESH_INTERVAL.as_secs()
            );
            background_loop(
                &mut source,
                &proc_table,
                path,
                &interface,
                &started_wall,
                started_at,
                top_n,
                is_json,
                cli.diagnostics,
            );
        }
        None => {
            // Foreground mode.
            if is_json {
                // JSON streams to stdout as a data source (no TUI).
                json_stdout_loop(
                    &mut source,
                    &proc_table,
                    &interface,
                    &started_wall,
                    started_at,
                    top_n,
                    cli.diagnostics,
                );
            }
        }
    }

    ExitCode::SUCCESS
}

#[cfg(windows)]
fn require_npcap() -> Result<(), &'static str> {
    let library_name: Vec<u16> = "wpcap.dll\0".encode_utf16().collect();
    // SAFETY: `library_name` is NUL-terminated and remains alive for the call.
    let module = unsafe { LoadLibraryW(library_name.as_ptr()) };
    if module.is_null() {
        return Err(NPCAP_REQUIRED_MESSAGE);
    }
    // SAFETY: `module` was returned by `LoadLibraryW` above and is non-null.
    unsafe {
        FreeLibrary(module);
    }
    Ok(())
}

#[cfg(not(windows))]
fn require_npcap() -> Result<(), &'static str> {
    Ok(())
}

/// Background file loop: capture continuously, write snapshot every refresh interval.
#[allow(clippy::too_many_arguments)]
fn background_loop(
    source: &mut CaptureSource,
    proc_table: &proc_table::SharedProcTable,
    path: &str,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    top_n: usize,
    is_json: bool,
    diagnostics: bool,
) {
    let mut stats = stats::Stats::default();
    let mut attributor = attribution::PendingAttributor::with_probe(
        attribution::PENDING_ATTRIBUTION_WINDOW,
        attribution::PENDING_ATTRIBUTION_CAPACITY,
        process_probe::ProcessProbe::spawn(),
    );
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
    loop {
        process_next(|| source.next(), proc_table, &mut stats, &mut attributor);
        if Instant::now() >= next_refresh {
            attributor.advance(&mut stats, proc_table, Instant::now());
            let res = if is_json {
                report::render_file_json(path, interface, started_wall, started_at, &stats, top_n)
            } else {
                report::render_file(path, interface, started_wall, started_at, &stats, top_n)
            };
            if let Err(e) = res {
                eprintln!("Failed to write output file: {e}");
            }
            if diagnostics {
                emit_diagnostics(
                    proc_table,
                    &attributor,
                    &stats,
                    source.flow_table_entry_count(),
                );
            }
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

/// JSON stdout loop: stream one compact JSON line per refresh interval.
#[allow(clippy::too_many_arguments)]
fn json_stdout_loop(
    source: &mut CaptureSource,
    proc_table: &proc_table::SharedProcTable,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    top_n: usize,
    diagnostics: bool,
) {
    let mut stats = stats::Stats::default();
    let mut attributor = attribution::PendingAttributor::with_probe(
        attribution::PENDING_ATTRIBUTION_WINDOW,
        attribution::PENDING_ATTRIBUTION_CAPACITY,
        process_probe::ProcessProbe::spawn(),
    );
    let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
    loop {
        process_next(|| source.next(), proc_table, &mut stats, &mut attributor);
        if Instant::now() >= next_refresh {
            attributor.advance(&mut stats, proc_table, Instant::now());
            report::render_jsonl(interface, started_wall, started_at, &stats, top_n);
            if diagnostics {
                emit_diagnostics(
                    proc_table,
                    &attributor,
                    &stats,
                    source.flow_table_entry_count(),
                );
            }
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
    }
}

fn emit_diagnostics(
    proc_table: &proc_table::SharedProcTable,
    attributor: &attribution::PendingAttributor,
    stats: &stats::Stats,
    flow_table_entries: u64,
) {
    let Some(proc) = proc_table::diagnostics_snapshot(proc_table) else {
        eprintln!("diagnostics: process table unavailable");
        return;
    };
    let pending = attributor.snapshot();
    let stats = stats.diagnostics_snapshot();
    eprintln!(
        concat!(
            "diagnostics: lookup_hits={} lookup_misses={} no_local_socket={} ",
            "lookup_no_candidate={} lookup_ambiguous={} lookup_stale={} ",
            "lookup_no_candidate_bytes={} lookup_ambiguous_bytes={} lookup_stale_bytes={} ",
            "lookup_v4_mapped_hits={} ",
            "refresh_requests={} refresh_actual={} refresh_success={} refresh_failure={} ",
            "refresh_records={} refresh_v4_mapped_records={} ",
            "flow_table_entries={} inbound_ip_entries={} outbound_ip_entries={} ",
            "process_entries={} domain_entries={} ",
            "inbound_heavy_ip_entries={} inbound_rising_ip_entries={} inbound_observation_ip_entries={} ",
            "outbound_heavy_ip_entries={} outbound_rising_ip_entries={} outbound_observation_ip_entries={} ",
            "ip_promotions={} ip_demotions={} ",
            "ip_evictions_heavy={} ip_evictions_rising={} ip_evictions_observation={} ",
            "last_refresh_ms={} pending_records={} pending_bytes={} ",
            "probe_request_queued={} probe_result_unique={} ",
            "probe_result_not_found={} probe_result_ambiguous={} ",
            "probe_result_unavailable={} probe_result_dropped={} probe_result_late={} ",
            "probe_query_count={} probe_query_ms={} probe_last_query_ms={} ",
            " pending_expired_bytes={} pending_capacity_bytes={} ",
            "probe_unique_pending_bytes={} probe_not_found_pending_bytes={} ",
            "probe_ambiguous_pending_bytes={} probe_unavailable_pending_bytes={}"
        ),
        proc.lookup_hits,
        proc.lookup_misses,
        proc.no_local_socket,
        proc.lookup_no_candidate,
        proc.lookup_ambiguous,
        proc.lookup_stale,
        proc.lookup_no_candidate_bytes,
        proc.lookup_ambiguous_bytes,
        proc.lookup_stale_bytes,
        proc.lookup_v4_mapped_hits,
        proc.refresh_requests,
        proc.refresh_actual,
        proc.refresh_success,
        proc.refresh_failure,
        proc.refresh_records,
        proc.refresh_v4_mapped_records,
        flow_table_entries,
        stats.inbound_ip_entries,
        stats.outbound_ip_entries,
        stats.process_entries,
        stats.domain_entries,
        stats.inbound_heavy_ip_entries,
        stats.inbound_rising_ip_entries,
        stats.inbound_observation_ip_entries,
        stats.outbound_heavy_ip_entries,
        stats.outbound_rising_ip_entries,
        stats.outbound_observation_ip_entries,
        stats.ip_promotions,
        stats.ip_demotions,
        stats.ip_evictions_heavy,
        stats.ip_evictions_rising,
        stats.ip_evictions_observation,
        proc.last_refresh_duration.as_millis(),
        pending.records,
        pending.bytes,
        pending.probe_request_queued,
        pending.probe_result_unique,
        pending.probe_result_not_found,
        pending.probe_result_ambiguous,
        pending.probe_result_unavailable,
        pending.probe_result_dropped,
        pending.probe_result_late,
        pending.probe_query_count,
        pending.probe_query_ms,
        pending.probe_last_query_ms,
        pending.pending_expired_bytes,
        pending.pending_capacity_bytes,
        pending.probe_unique_pending_bytes,
        pending.probe_not_found_pending_bytes,
        pending.probe_ambiguous_pending_bytes,
        pending.probe_unavailable_pending_bytes,
    );
    for sample in proc.lookup_miss_samples {
        eprintln!(
            "diagnostics_miss_sample: reason={} protocol={} local={}:{} peer={}:{}",
            lookup_miss_reason_label(sample.reason),
            transport_protocol_label(sample.local_socket.protocol),
            sample.local_socket.ip,
            sample.local_socket.port,
            sample.peer_ip,
            sample.peer_port,
        );
    }
}

fn lookup_miss_reason_label(reason: LookupMissReason) -> &'static str {
    match reason {
        LookupMissReason::NoCandidate => "no_candidate",
        LookupMissReason::Ambiguous => "ambiguous",
        LookupMissReason::Stale => "stale",
    }
}

fn transport_protocol_label(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    }
}

fn process_next<N, E>(
    mut next_flow: N,
    proc_table: &proc_table::SharedProcTable,
    stats: &mut stats::Stats,
    attributor: &mut attribution::PendingAttributor,
) where
    N: FnMut() -> Result<Option<capture::Flow>, E>,
    E: std::fmt::Display,
{
    let now = Instant::now();
    match next_flow() {
        Ok(Some(flow)) => {
            attributor.record_flow(stats, flow, proc_table, now, chrono::Utc::now());
        }
        Ok(None) => {
            attributor.advance(stats, proc_table, now);
        }
        Err(e) => {
            eprintln!("Capture error: {e}");
            attributor.advance(stats, proc_table, now);
        }
    }
}

/// CLI arguments.
#[derive(Parser)]
#[command(name = "delray", version, about = "Network traffic analyzer")]
struct Cli {
    /// Network interface to capture on (omit to select interactively in plain foreground mode)
    interface: Option<String>,
    /// Process table refresh interval in seconds (must be > 0)
    #[arg(long, default_value_t = DEFAULT_PROC_REFRESH, value_parser = positive_u64)]
    proc_refresh: u64,
    /// Output file for background mode (omit for foreground terminal display)
    #[arg(long)]
    output: Option<String>,
    /// Output format: plain (default) or json
    #[arg(long = "format", short = 'f', default_value = "plain", value_parser = ["plain", "json"])]
    format: String,
    /// Number of entries per top-N list (default: 10, min: 1)
    #[arg(long = "top-n", short = 'n', default_value_t = DEFAULT_TOP_N, value_parser = clap::value_parser!(u64).range(1..))]
    top_n: u64,
    /// Connection flow table capacity in 5-tuples (default: 65536, min: 1)
    #[arg(long = "flow-table", default_value_t = DEFAULT_FLOW_TABLE, value_parser = clap::value_parser!(u64).range(1..))]
    flow_table: u64,
    /// Emit process attribution diagnostics to stderr on each output refresh
    #[arg(long)]
    diagnostics: bool,
}

fn positive_u64(s: &str) -> Result<u64, String> {
    match s.parse::<u64>() {
        Ok(v) if v > 0 => Ok(v),
        Ok(_) => Err(String::from("value must be greater than 0")),
        Err(_) => Err(String::from("value must be a positive integer")),
    }
}

#[cfg(test)]
mod scheduling_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, RwLock};

    use super::*;

    #[test]
    fn continuous_traffic_yields_after_one_flow() {
        let proc_table = Arc::new(RwLock::new(proc_table::ProcTable::default()));
        let mut stats = stats::Stats::default();
        let mut attributor = attribution::PendingAttributor::default();
        let mut calls = 0;

        process_next(
            || {
                calls += 1;
                Ok::<_, &'static str>(Some(capture::Flow {
                    direction: stats::Direction::Inbound,
                    peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    peer_port: None,
                    bytes: 64,
                    local_socket: None,
                    peer_local_socket: None,
                    domain: None,
                }))
            },
            &proc_table,
            &mut stats,
            &mut attributor,
        );

        assert_eq!(calls, 1);
        assert_eq!(stats.snapshot(10).in_bytes, 64);
        let diagnostics = proc_table::diagnostics_snapshot(&proc_table).unwrap();
        assert_eq!(diagnostics.no_local_socket, 1);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn missing_npcap_fails_before_capture_setup() {
        let cli = Cli::try_parse_from(["delray", "--format", "json"]).unwrap();

        assert_eq!(run(cli, || Err(NPCAP_REQUIRED_MESSAGE)), ExitCode::FAILURE);
    }

    #[test]
    fn parses_all_args() {
        let cli = Cli::try_parse_from([
            "delray",
            "eth0",
            "--proc-refresh",
            "5",
            "--output",
            "out.txt",
        ])
        .unwrap();
        assert_eq!(cli.interface.as_deref(), Some("eth0"));
        assert_eq!(cli.proc_refresh, 5);
        assert_eq!(cli.output.as_deref(), Some("out.txt"));
        assert!(!cli.diagnostics);
    }

    #[test]
    fn diagnostics_flag_is_available_for_linux_validation() {
        let cli =
            Cli::try_parse_from(["delray", "eth0", "--format", "json", "--diagnostics"]).unwrap();

        assert!(cli.diagnostics);
    }

    #[test]
    fn proc_refresh_defaults_to_two() {
        let cli = Cli::try_parse_from(["delray", "eth0"]).unwrap();
        assert_eq!(cli.proc_refresh, DEFAULT_PROC_REFRESH);
        assert!(cli.output.is_none());
    }

    #[test]
    fn proc_refresh_zero_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--proc-refresh", "0"]);
        assert!(result.is_err());
    }

    #[test]
    fn flow_table_defaults_to_65536() {
        let cli = Cli::try_parse_from(["delray", "eth0"]).unwrap();
        assert_eq!(cli.flow_table, DEFAULT_FLOW_TABLE);
    }

    #[test]
    fn flow_table_accepts_custom_capacity() {
        let cli = Cli::try_parse_from(["delray", "eth0", "--flow-table", "4096"]).unwrap();
        assert_eq!(cli.flow_table, 4096);
    }

    #[test]
    fn flow_table_zero_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--flow-table", "0"]);
        assert!(result.is_err());
    }

    #[test]
    fn flow_table_non_numeric_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--flow-table", "huge"]);
        assert!(result.is_err());
    }

    #[test]
    fn interface_optional() {
        let cli = Cli::try_parse_from(["delray"]).unwrap();
        assert!(cli.interface.is_none());
    }

    #[test]
    fn missing_interface_starts_selector_only_for_plain_foreground_mode() {
        let plain = Cli::try_parse_from(["delray"]).unwrap();
        let json = Cli::try_parse_from(["delray", "--format", "json"]).unwrap();
        let file = Cli::try_parse_from(["delray", "--output", "traffic.txt"]).unwrap();

        assert_eq!(dispatch_mode(&plain), DispatchMode::InteractiveSelector);
        assert_eq!(dispatch_mode(&json), DispatchMode::MissingInterface);
        assert_eq!(dispatch_mode(&file), DispatchMode::MissingInterface);
    }

    #[test]
    fn proc_refresh_non_numeric_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--proc-refresh", "abc"]);
        assert!(result.is_err());
    }

    #[test]
    fn proc_refresh_negative_rejected() {
        let result = Cli::try_parse_from(["delray", "eth0", "--proc-refresh", "-5"]);
        assert!(result.is_err());
    }
}
