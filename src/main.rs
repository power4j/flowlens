mod attribution;
mod capture;
mod diagnostics;
mod domain_parse;
mod domain_parse_composite;
mod domain_parse_http;
mod domain_parse_tls;
mod flow_table;
mod history;
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

#[cfg(windows)]
mod windows_local_ips;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use capture::CaptureSource;
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

    let diagnostics_writer = match open_diagnostics_writer(&cli) {
        Ok(writer) => writer,
        Err(error) => {
            eprintln!("Failed to open diagnostics output: {error}");
            return ExitCode::FAILURE;
        }
    };
    let proc_table = proc_table::spawn(Duration::from_secs(cli.proc_refresh));
    let top_n = cli.top_n as usize;
    let proc_flows = cli.proc_flows as usize;
    let is_json = cli.format == "json";

    if cli.output.is_none() && !is_json {
        return run_tui_mode(&cli, diagnostics_writer, proc_table, top_n, proc_flows);
    }

    run_capture_mode(
        &cli,
        diagnostics_writer,
        proc_table,
        top_n,
        proc_flows,
        is_json,
    )
}

fn run_tui_mode(
    cli: &Cli,
    diagnostics_writer: Option<diagnostics::DiagnosticsWriter>,
    proc_table: proc_table::SharedProcTable,
    top_n: usize,
    proc_flows: usize,
) -> ExitCode {
    let mut session = match session::TrafficSession::discover(
        proc_table,
        top_n,
        proc_flows,
        cli.flow_table,
        cli.diagnostics,
        cli.read_mode,
    ) {
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
    session.rank_window_handle().store(
        cli.rank_window.to_u8(),
        std::sync::atomic::Ordering::Release,
    );
    let diagnostics_enabled = session.diagnostics_enabled_handle();
    let rank_window = session.rank_window_handle();
    if let Err(error) = tui::run(
        &mut session,
        diagnostics_writer,
        diagnostics_enabled,
        rank_window,
    ) {
        eprintln!("TUI error: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_capture_mode(
    cli: &Cli,
    diagnostics_writer: Option<diagnostics::DiagnosticsWriter>,
    proc_table: proc_table::SharedProcTable,
    top_n: usize,
    proc_flows: usize,
    is_json: bool,
) -> ExitCode {
    let interface_selector = cli
        .interface
        .as_deref()
        .expect("dispatch requires interface");

    let started_wall = chrono::Local::now();
    let started_at = Instant::now();
    let mut source =
        match CaptureSource::open_with_read_mode(interface_selector, cli.flow_table, cli.read_mode)
        {
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
                proc_flows,
                cli.rank_window,
                is_json,
                diagnostics_writer,
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
                    proc_flows,
                    cli.rank_window,
                    diagnostics_writer,
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

fn open_diagnostics_writer(cli: &Cli) -> std::io::Result<Option<diagnostics::DiagnosticsWriter>> {
    if !cli.diagnostics {
        if cli.diagnostics_output.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--diagnostics-output requires --diagnostics",
            ));
        }
        return Ok(None);
    }
    let path = cli
        .diagnostics_output
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(diagnostics::default_output_path);
    diagnostics::DiagnosticsWriter::create(path).map(Some)
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
    proc_flows: usize,
    rank_window: stats::RankWindow,
    is_json: bool,
    mut diagnostics_writer: Option<diagnostics::DiagnosticsWriter>,
) {
    let mut stats = stats::Stats::new_at(chrono::Utc::now());
    stats.set_proc_flow_limits(proc_flows, stats::MAX_PROC_FLOWS_TOTAL);
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
                report::render_file_json(
                    path,
                    interface,
                    started_wall,
                    started_at,
                    &stats,
                    top_n,
                    rank_window,
                )
            } else {
                report::render_file(
                    path,
                    interface,
                    started_wall,
                    started_at,
                    &stats,
                    top_n,
                    rank_window,
                )
            };
            if let Err(e) = res {
                eprintln!("Failed to write output file: {e}");
            }
            if let Some(writer) = diagnostics_writer.as_mut()
                && let Some(snapshot) = diagnostics::collect(diagnostics::DiagnosticsInputs {
                    proc_table,
                    pending: attributor.snapshot(),
                    stats: stats.diagnostics_snapshot(),
                    flow_table_entries: source.flow_table_entry_count(),
                    pcap: Some(source.pcap_counters().as_ref()),
                })
                && let Err(error) = writer.write(interface, &snapshot)
            {
                eprintln!("Failed to write diagnostics output: {error}");
                diagnostics_writer = None;
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
    proc_flows: usize,
    rank_window: stats::RankWindow,
    mut diagnostics_writer: Option<diagnostics::DiagnosticsWriter>,
) {
    let mut stats = stats::Stats::new_at(chrono::Utc::now());
    stats.set_proc_flow_limits(proc_flows, stats::MAX_PROC_FLOWS_TOTAL);
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
            report::render_jsonl(
                interface,
                started_wall,
                started_at,
                &stats,
                top_n,
                rank_window,
            );
            if let Some(writer) = diagnostics_writer.as_mut()
                && let Some(snapshot) = diagnostics::collect(diagnostics::DiagnosticsInputs {
                    proc_table,
                    pending: attributor.snapshot(),
                    stats: stats.diagnostics_snapshot(),
                    flow_table_entries: source.flow_table_entry_count(),
                    pcap: Some(source.pcap_counters().as_ref()),
                })
                && let Err(error) = writer.write(interface, &snapshot)
            {
                eprintln!("Failed to write diagnostics output: {error}");
                diagnostics_writer = None;
            }
            next_refresh = Instant::now() + REFRESH_INTERVAL;
        }
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
#[command(name = "flowlens", version, about = "Network traffic analyzer")]
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
    /// Max connection rows per process on the process-detail page (default: 256, min: 1)
    #[arg(long = "proc-flows", default_value_t = stats::DEFAULT_PROC_FLOWS as u64, value_parser = clap::value_parser!(u64).range(1..))]
    proc_flows: u64,
    /// Ranking window: cumulative, 5s, 10s, 30s, 60s, or 5m
    #[arg(long = "rank-window", default_value = "cumulative", value_parser = parse_rank_window)]
    rank_window: stats::RankWindow,
    /// Connection flow table capacity in 5-tuples (default: 65536, min: 1)
    #[arg(long = "flow-table", default_value_t = DEFAULT_FLOW_TABLE, value_parser = clap::value_parser!(u64).range(1..))]
    flow_table: u64,
    /// Write process attribution diagnostics to a JSONL file on each output refresh
    #[arg(long)]
    diagnostics: bool,
    /// Write diagnostics JSONL records to this file (default: flowlens-<timestamp>-<pid>.log)
    #[arg(long = "diagnostics-output")]
    diagnostics_output: Option<String>,
    /// Packet read mode: dispatch (batch, default) or next (per-packet baseline).
    #[arg(long, value_enum, default_value_t = capture::CaptureReadMode::default(), hide = true)]
    read_mode: capture::CaptureReadMode,
}

fn positive_u64(s: &str) -> Result<u64, String> {
    match s.parse::<u64>() {
        Ok(v) if v > 0 => Ok(v),
        Ok(_) => Err(String::from("value must be greater than 0")),
        Err(_) => Err(String::from("value must be a positive integer")),
    }
}

fn parse_rank_window(value: &str) -> Result<stats::RankWindow, String> {
    match value {
        "cumulative" => Ok(stats::RankWindow::Cumulative),
        "5s" => Ok(stats::RankWindow::FIVE_SECONDS),
        "10s" => Ok(stats::RankWindow::TEN_SECONDS),
        "30s" => Ok(stats::RankWindow::THIRTY_SECONDS),
        "60s" => Ok(stats::RankWindow::SIXTY_SECONDS),
        "5m" => Ok(stats::RankWindow::FIVE_MINUTES),
        _ => Err(String::from(
            "must be one of: cumulative, 5s, 10s, 30s, 60s, 5m",
        )),
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
        let cli = Cli::try_parse_from(["flowlens", "--format", "json"]).unwrap();

        assert_eq!(run(cli, || Err(NPCAP_REQUIRED_MESSAGE)), ExitCode::FAILURE);
    }

    #[test]
    fn parses_all_args() {
        let cli = Cli::try_parse_from([
            "flowlens",
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
            Cli::try_parse_from(["flowlens", "eth0", "--format", "json", "--diagnostics"]).unwrap();

        assert!(cli.diagnostics);
    }

    #[test]
    fn diagnostics_output_requires_diagnostics_flag() {
        let cli = Cli::try_parse_from(["flowlens", "eth0", "--diagnostics-output", "diag.jsonl"])
            .unwrap();
        let error = match open_diagnostics_writer(&cli) {
            Ok(_) => panic!("diagnostics output should require the flag"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("requires --diagnostics"));
    }

    #[test]
    fn diagnostics_output_path_is_preserved() {
        let cli = Cli::try_parse_from([
            "flowlens",
            "eth0",
            "--diagnostics",
            "--diagnostics-output",
            "diag.jsonl",
        ])
        .unwrap();
        assert_eq!(cli.diagnostics_output.as_deref(), Some("diag.jsonl"));
    }

    #[test]
    fn proc_refresh_defaults_to_two() {
        let cli = Cli::try_parse_from(["flowlens", "eth0"]).unwrap();
        assert_eq!(cli.proc_refresh, DEFAULT_PROC_REFRESH);
        assert!(cli.output.is_none());
    }

    #[test]
    fn proc_refresh_zero_rejected() {
        let result = Cli::try_parse_from(["flowlens", "eth0", "--proc-refresh", "0"]);
        assert!(result.is_err());
    }

    #[test]
    fn flow_table_defaults_to_65536() {
        let cli = Cli::try_parse_from(["flowlens", "eth0"]).unwrap();
        assert_eq!(cli.flow_table, DEFAULT_FLOW_TABLE);
    }

    #[test]
    fn flow_table_accepts_custom_capacity() {
        let cli = Cli::try_parse_from(["flowlens", "eth0", "--flow-table", "4096"]).unwrap();
        assert_eq!(cli.flow_table, 4096);
    }

    #[test]
    fn flow_table_zero_rejected() {
        let result = Cli::try_parse_from(["flowlens", "eth0", "--flow-table", "0"]);
        assert!(result.is_err());
    }

    #[test]
    fn proc_flows_defaults_to_256() {
        let cli = Cli::try_parse_from(["flowlens", "eth0"]).unwrap();
        assert_eq!(cli.proc_flows, stats::DEFAULT_PROC_FLOWS as u64);
    }

    #[test]
    fn proc_flows_accepts_custom_limit() {
        let cli = Cli::try_parse_from(["flowlens", "eth0", "--proc-flows", "32"]).unwrap();
        assert_eq!(cli.proc_flows, 32);
    }

    #[test]
    fn proc_flows_zero_rejected() {
        let result = Cli::try_parse_from(["flowlens", "eth0", "--proc-flows", "0"]);
        assert!(result.is_err());
    }

    #[test]
    fn flow_table_non_numeric_rejected() {
        let result = Cli::try_parse_from(["flowlens", "eth0", "--flow-table", "huge"]);
        assert!(result.is_err());
    }

    #[test]
    fn interface_optional() {
        let cli = Cli::try_parse_from(["flowlens"]).unwrap();
        assert!(cli.interface.is_none());
    }

    #[test]
    fn missing_interface_starts_selector_only_for_plain_foreground_mode() {
        let plain = Cli::try_parse_from(["flowlens"]).unwrap();
        let json = Cli::try_parse_from(["flowlens", "--format", "json"]).unwrap();
        let file = Cli::try_parse_from(["flowlens", "--output", "traffic.txt"]).unwrap();

        assert_eq!(dispatch_mode(&plain), DispatchMode::InteractiveSelector);
        assert_eq!(dispatch_mode(&json), DispatchMode::MissingInterface);
        assert_eq!(dispatch_mode(&file), DispatchMode::MissingInterface);
    }

    #[test]
    fn proc_refresh_non_numeric_rejected() {
        let result = Cli::try_parse_from(["flowlens", "eth0", "--proc-refresh", "abc"]);
        assert!(result.is_err());
    }

    #[test]
    fn rank_window_accepts_only_the_six_supported_values() {
        for value in ["cumulative", "5s", "10s", "30s", "60s", "5m"] {
            assert!(parse_rank_window(value).is_ok(), "{value}");
        }
        for value in ["total", "1m"] {
            assert!(parse_rank_window(value).is_err(), "{value}");
        }
    }

    #[test]
    fn proc_refresh_negative_rejected() {
        let result = Cli::try_parse_from(["flowlens", "eth0", "--proc-refresh", "-5"]);
        assert!(result.is_err());
    }
}
