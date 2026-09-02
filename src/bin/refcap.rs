//! refcap — minimal reference capture counter for capture-parity verification.
//!
//! Counts what Npcap hands to userspace at the raw packet layer, without
//! running FlowLens's parsing/attribution pipeline. Together with
//! scripts/verify-capture.ps1 it separates capture-side loss (kernel buffer
//! overflow, driver drops) from FlowLens-side loss (strict parsing, pipeline
//! backpressure) and from the counting scope (non-IP frames, ARP, padding).
//!
//! Usage:
//!   refcap --list
//!   refcap <device-or-index> [--interval 1] [--out FILE] [--seconds N]
//!          [--snaplen 65535] [--buffer-size 2000000]
//!          [--read-mode next|dispatch] [--batch-size 128]
//!          [--breakloop-after N] [--breakloop-exit]
//!
//! Output is JSONL; one object per interval with per-interval deltas.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use pcap::{Capture, Device, Linktype};

const DEFAULT_SNAPLEN: i32 = 65_535;
const DEFAULT_BUFFER_SIZE: i32 = 2_000_000;
use clap::Parser;
const DEFAULT_INTERVAL_SECS: u64 = 1;

/// Minimal reference capture counter for capture-parity verification.
#[derive(Parser)]
#[command(name = "refcap", version, about = "Minimal reference capture counter for capture-parity verification.", long_about = None)]
struct Cli {
    /// Capture device name or 1-based index (see `--list`).
    selector: Option<String>,
    /// List capture devices as tab-separated rows and exit.
    #[arg(short = 'l', long)]
    list: bool,
    /// Seconds between JSONL output lines.
    #[arg(long, default_value_t = DEFAULT_INTERVAL_SECS)]
    interval: u64,
    /// Write JSONL to FILE instead of stdout.
    #[arg(long)]
    out: Option<String>,
    /// Stop after N seconds of capture.
    #[arg(long)]
    seconds: Option<u64>,
    /// Capture snaplen in bytes.
    #[arg(long, default_value_t = DEFAULT_SNAPLEN)]
    snaplen: i32,
    /// Capture kernel buffer size in bytes.
    #[arg(long, default_value_t = DEFAULT_BUFFER_SIZE)]
    buffer_size: i32,
    /// Capture in promiscuous mode (needed to see locally-sent packets on
    /// some Windows/Npcap adapters).
    #[arg(long)]
    promisc: bool,
    /// Packet read mode: next (per-packet baseline) or dispatch (batch probe).
    #[arg(long, value_enum, default_value_t = ReadMode::Next)]
    read_mode: ReadMode,
    /// Packets per dispatch call when --read-mode dispatch.
    #[arg(long, default_value_t = DEFAULT_DISPATCH_BATCH)]
    batch_size: usize,
    /// Call pcap breakloop() after this many seconds from a helper thread.
    /// Diagnostic only; validates that breakloop interrupts a blocked
    /// dispatch/next_packet on the target platform.
    #[arg(long)]
    breakloop_after: Option<u64>,
    /// After breakloop returns an error, exit immediately (used to measure
    /// the join latency precisely instead of waiting out --seconds).
    #[arg(long)]
    breakloop_exit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum ReadMode {
    Next,
    Dispatch,
}

const DEFAULT_DISPATCH_BATCH: usize = 128;

#[derive(Default)]
struct Totals {
    packets: u64,
    bytes_wire: u64,
    bytes_caplen: u64,
    bytes_ip: u64,
    ipv4_packets: u64,
    ipv6_packets: u64,
    arp_packets: u64,
    other_packets: u64,
    ip_invalid_packets: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.list {
        return list_devices();
    }
    let Some(ref selector) = cli.selector else {
        eprintln!("refcap: missing device selector; run `refcap --list` to enumerate devices");
        return ExitCode::FAILURE;
    };
    match run(selector, &cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("refcap: {message}");
            ExitCode::FAILURE
        }
    }
}

fn list_devices() -> ExitCode {
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(error) => {
            eprintln!("refcap: cannot list devices: {error}");
            return ExitCode::FAILURE;
        }
    };
    if devices.is_empty() {
        eprintln!("refcap: no capture devices found (is Npcap installed?)");
        return ExitCode::FAILURE;
    }
    for (index, device) in devices.iter().enumerate() {
        let addresses: Vec<String> = device
            .addresses
            .iter()
            .map(|address| address.addr.to_string())
            .collect();
        let description = device.desc.as_deref().unwrap_or("");
        println!(
            "{}\t{}\t{}\t{}",
            index + 1,
            device.name,
            description,
            addresses.join(",")
        );
    }
    ExitCode::SUCCESS
}

fn resolve_device<'a>(selector: &str, devices: &'a [Device]) -> Result<&'a Device, String> {
    if let Some(device) = devices.iter().find(|device| device.name == selector) {
        return Ok(device);
    }
    if !selector.is_empty() && selector.bytes().all(|byte| byte.is_ascii_digit()) {
        let number = selector.parse::<usize>().ok();
        if let Some(number) = number.filter(|number| *number >= 1)
            && let Some(device) = devices.get(number - 1)
        {
            return Ok(device);
        }
        return Err(format!("invalid interface number: {selector}"));
    }
    Err(format!("interface not found: {selector}"))
}

fn run(selector: &str, cli: &Cli) -> Result<(), String> {
    let interval = Duration::from_secs(cli.interval);
    let devices = Device::list().map_err(|error| error.to_string())?;
    let device = resolve_device(selector, &devices)?.clone();

    let mut cap = Capture::from_device(device)
        .map_err(|error| error.to_string())?
        .timeout(150)
        .snaplen(cli.snaplen)
        .buffer_size(cli.buffer_size)
        .promisc(cli.promisc)
        .open()
        .map_err(|error| error.to_string())?;
    let link = cap.get_datalink();

    let mut writer: Box<dyn Write> = match &cli.out {
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|error| error.to_string())?,
        )),
        None => Box::new(BufWriter::new(std::io::stdout())),
    };

    // Breakloop probe: arm a helper thread that calls breakloop() after the
    // requested delay. The handle is Send+Sync; calling breakloop() from
    // another thread is the documented way to interrupt a blocked capture.
    let breakloop_after = cli.breakloop_after;
    let breakloop = cap.breakloop_handle();
    if let Some(delay) = breakloop_after {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(delay));
            breakloop.breakloop();
        });
    }

    let started = Instant::now();
    let mut last_emit = Instant::now();
    let mut totals = Totals::default();
    let mut last_stat: Option<pcap::Stat> = None;
    let mut dispatch: DispatchDeltas = DispatchDeltas::default();
    let mut end_reason: &'static str = "timeout";

    loop {
        match cli.read_mode {
            ReadMode::Next => match cap.next_packet() {
                Ok(packet) => {
                    let wire_len = u64::from(packet.header.len);
                    count_frame(link, packet.data, wire_len, &mut totals);
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(error) => {
                    if breakloop_after.is_some() {
                        // Expected when breakloop fired: record the observed
                        // error (observation only, no string matching) and
                        // treat it as the end of the probe.
                        end_reason = "breakloop";
                        eprintln!("refcap: capture returned after breakloop: {error}");
                        if cli.breakloop_exit {
                            break;
                        }
                    } else {
                        return Err(format!("capture error: {error}"));
                    }
                }
            },
            ReadMode::Dispatch => {
                let call_started = Instant::now();
                match cap.dispatch(Some(cli.batch_size), |packet| {
                    let wire_len = u64::from(packet.header.len);
                    count_frame(link, packet.data, wire_len, &mut totals);
                }) {
                    Ok(processed) => {
                        dispatch.calls += 1;
                        dispatch.packets += processed as u64;
                        dispatch.max_call_ms = dispatch
                            .max_call_ms
                            .max(call_started.elapsed().as_millis() as u64);
                    }
                    Err(error) => {
                        if breakloop_after.is_some() {
                            end_reason = "breakloop";
                            eprintln!("refcap: capture returned after breakloop: {error}");
                            if cli.breakloop_exit {
                                break;
                            }
                        } else {
                            return Err(format!("capture error: {error}"));
                        }
                    }
                }
            }
        }

        let now = Instant::now();
        if now.duration_since(last_emit) >= interval {
            let stat = cap.stats().ok();
            let deltas = stat_deltas(last_stat, stat);
            last_stat = stat;
            let uptime_secs = now.duration_since(started).as_secs();
            let line = serde_json::json!({
                "uptime_secs": uptime_secs,
                "packets": totals.packets,
                "bytes_wire": totals.bytes_wire,
                "bytes_caplen": totals.bytes_caplen,
                "bytes_ip": totals.bytes_ip,
                "ipv4_packets": totals.ipv4_packets,
                "ipv6_packets": totals.ipv6_packets,
                "arp_packets": totals.arp_packets,
                "other_packets": totals.other_packets,
                "ip_invalid_packets": totals.ip_invalid_packets,
                "dropped": deltas.dropped,
                "if_dropped": deltas.if_dropped,
                "received": deltas.received,
                "read_mode": match cli.read_mode {
                    ReadMode::Next => "next",
                    ReadMode::Dispatch => "dispatch",
                },
                "end_reason": end_reason,
                "dispatch_calls": dispatch.calls,
                "dispatch_packets": dispatch.packets,
                "dispatch_max_call_ms": dispatch.max_call_ms,
            });
            writeln!(writer, "{line}").map_err(|error| error.to_string())?;
            writer.flush().map_err(|error| error.to_string())?;
            totals = Totals::default();
            dispatch = DispatchDeltas::default();
            last_emit = now;
            if cli.seconds.is_some_and(|seconds| uptime_secs >= seconds) {
                break;
            }
        }
    }
    Ok(())
}

/// Per-interval dispatch-call deltas emitted in each JSONL line (0 in the
/// per-packet baseline mode).
#[derive(Clone, Copy, Debug, Default)]
struct DispatchDeltas {
    calls: u64,
    packets: u64,
    max_call_ms: u64,
}

/// Per-interval pcap statistics deltas emitted in each JSONL line.
#[derive(Clone, Copy, Debug, Default)]
struct StatDelta {
    dropped: u64,
    if_dropped: u64,
    received: u64,
}

fn stat_deltas(before: Option<pcap::Stat>, after: Option<pcap::Stat>) -> StatDelta {
    let (Some(before), Some(after)) = (before, after) else {
        return StatDelta::default();
    };
    StatDelta {
        dropped: u64::from(after.dropped.saturating_sub(before.dropped)),
        if_dropped: u64::from(after.if_dropped.saturating_sub(before.if_dropped)),
        received: u64::from(after.received.saturating_sub(before.received)),
    }
}

fn count_frame(link: Linktype, data: &[u8], wire_len: u64, totals: &mut Totals) {
    totals.packets += 1;
    totals.bytes_wire += wire_len;
    totals.bytes_caplen += data.len() as u64;
    match link {
        Linktype::ETHERNET => {
            if data.len() < 14 {
                totals.other_packets += 1;
                return;
            }
            let ether_type = u16::from_be_bytes([data[12], data[13]]);
            count_ip(ether_type, &data[14..], 14, totals);
        }
        Linktype::NULL | Linktype::LOOP => {
            if data.len() < 4 {
                totals.other_packets += 1;
                return;
            }
            let family_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let family_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let family = if matches!(family_be, 2 | 10 | 23 | 24 | 28 | 30) {
                family_be
            } else {
                family_le
            };
            let ether_type = match family {
                2 => 0x0800,
                10 | 23 | 24 | 28 | 30 => 0x86DD,
                _ => 0,
            };
            count_ip(ether_type, &data[4..], 4, totals);
        }
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => {
            let ether_type = if data.first().is_some_and(|byte| byte >> 4 == 4) {
                0x0800
            } else {
                0x86DD
            };
            count_ip(ether_type, data, 0, totals);
        }
        Linktype::LINUX_SLL => {
            if data.len() < 16 {
                totals.other_packets += 1;
                return;
            }
            let ether_type = u16::from_be_bytes([data[14], data[15]]);
            count_ip(ether_type, &data[16..], 16, totals);
        }
        Linktype::LINUX_SLL2 => {
            if data.len() < 20 {
                totals.other_packets += 1;
                return;
            }
            let ether_type = u16::from_be_bytes([data[0], data[1]]);
            count_ip(ether_type, &data[20..], 20, totals);
        }
        _ => totals.other_packets += 1,
    }
}

fn count_ip(ether_type: u16, ip: &[u8], link_len: u64, totals: &mut Totals) {
    match ether_type {
        0x0800 => {
            if ip.len() >= 20 {
                let total = u16::from_be_bytes([ip[2], ip[3]]) as u64;
                if (20..=ip.len() as u64).contains(&total) {
                    totals.ipv4_packets += 1;
                    totals.bytes_ip += link_len + total;
                    return;
                }
            }
            totals.ip_invalid_packets += 1;
        }
        0x86DD => {
            if ip.len() >= 40 {
                let payload = u16::from_be_bytes([ip[4], ip[5]]) as u64;
                let total = payload + 40;
                if (40..=ip.len() as u64).contains(&total) {
                    totals.ipv6_packets += 1;
                    totals.bytes_ip += link_len + total;
                    return;
                }
            }
            totals.ip_invalid_packets += 1;
        }
        0x0806 => totals.arp_packets += 1,
        _ => totals.other_packets += 1,
    }
}
