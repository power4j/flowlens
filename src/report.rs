use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::stats::Stats;

// ── shared helpers ──

pub fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

pub fn human_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;
    const TB: f64 = 1024.0 * GB;
    let value = n as f64;
    if value >= TB {
        format!("{:.2} TB", value / TB)
    } else if value >= GB {
        format!("{:.2} GB", value / GB)
    } else if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.2} KB", value / KB)
    } else {
        format!("{n} B")
    }
}

pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head: String = s.chars().take(max_chars).collect();
    format!("{head}…")
}

// ── plain file output (tab-separated, no table borders) ──

/// Render plain-text snapshot for background file output: section headers + tab-separated columns.
pub fn render_file(
    path: &str,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> std::io::Result<()> {
    std::fs::write(
        path,
        plain_snapshot(interface, started_wall, started_at, stats, top_n),
    )
}

fn plain_snapshot(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> String {
    let host = hostname();
    let now = chrono::Local::now();
    let snapshot = stats.snapshot(top_n);
    let mut out = String::new();

    out.push_str(&format!(
        "flowlens\t{interface}\thost: {host}\tstarted: {}\tuptime: {}\t{}\n\n",
        started_wall.format("%Y-%m-%d %H:%M:%S"),
        fmt_elapsed(started_at.elapsed()),
        now.format("%Y-%m-%d %H:%M:%S")
    ));

    out.push_str("Interface Traffic\n");
    out.push_str(&format!("Inbound\t{}\n", human_bytes(snapshot.in_bytes)));
    out.push_str(&format!(
        "Outbound\t{}\n\n",
        human_bytes(snapshot.out_bytes)
    ));

    out.push_str(&format!("Top Processes ({top_n})\n"));
    out.push_str("Process\tPID\tRecv\tSent\tTotal\tLast Seen\tPath\n");
    for process in snapshot.processes.iter() {
        let name = process.display_name();
        let pid = process
            .pid()
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string());
        let path = process.path().unwrap_or("-");
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            name,
            pid,
            human_bytes(process.recv),
            human_bytes(process.sent),
            human_bytes(process.total()),
            process.last_seen().to_rfc3339(),
            path
        ));
    }

    out.push_str(&format!("\nTop Hosts ({top_n})\n"));
    out.push_str("Host\tIn\tOut\tTotal\tLast Seen\n");
    for domain in snapshot.outbound_domains.iter() {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            domain.host(),
            human_bytes(domain.in_bytes),
            human_bytes(domain.out_bytes),
            human_bytes(domain.total_bytes()),
            domain.last_seen().to_rfc3339(),
        ));
    }

    out.push_str(&format!("\nTop Inbound IPs ({top_n})\n"));
    out.push_str("IP\tTotal\tLast Seen\n");
    for entry in snapshot.inbound_ips.iter() {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            entry.ip,
            human_bytes(entry.bytes),
            entry.last_seen().to_rfc3339()
        ));
    }

    out.push_str(&format!("\nTop Outbound IPs ({top_n})\n"));
    out.push_str("IP\tTotal\tLast Seen\n");
    for entry in snapshot.outbound_ips.iter() {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            entry.ip,
            human_bytes(entry.bytes),
            entry.last_seen().to_rfc3339()
        ));
    }

    out
}

// ── JSON output ──

#[derive(Serialize)]
struct JsonFrame<'a> {
    interface: &'a str,
    host: String,
    started_at: String,
    now: String,
    uptime_secs: u64,
    totals: JsonTotals,
    top_processes: Vec<JsonProc>,
    top_hosts: Vec<JsonHost>,
    top_inbound_ips: Vec<JsonIp>,
    top_outbound_ips: Vec<JsonIp>,
}

#[derive(Serialize)]
struct JsonTotals {
    in_bytes: u64,
    out_bytes: u64,
}

#[derive(Serialize)]
struct JsonProc {
    pid: Option<u32>,
    name: Option<String>,
    path: Option<String>,
    last_seen: String,
    recv: u64,
    sent: u64,
    total: u64,
}

#[derive(Serialize)]
struct JsonIp {
    ip: String,
    bytes: u64,
    last_seen: String,
}

#[derive(Serialize)]
struct JsonHost {
    host: String,
    in_bytes: u64,
    out_bytes: u64,
    total_bytes: u64,
    last_seen: String,
}

fn build_json_frame<'a>(
    interface: &'a str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &'a Stats,
    top_n: usize,
) -> JsonFrame<'a> {
    let host = hostname();
    let now = chrono::Local::now();

    let snapshot = stats.snapshot(top_n);
    let top_processes = snapshot
        .processes
        .iter()
        .map(|process| JsonProc {
            pid: process.pid(),
            name: process.name().map(str::to_string),
            path: process.path().map(str::to_string),
            last_seen: process.last_seen().to_rfc3339(),
            recv: process.recv,
            sent: process.sent,
            total: process.total(),
        })
        .collect();

    let top_inbound_ips = snapshot
        .inbound_ips
        .iter()
        .map(|entry| JsonIp {
            ip: entry.ip.to_string(),
            bytes: entry.bytes,
            last_seen: entry.last_seen().to_rfc3339(),
        })
        .collect();

    let top_outbound_ips = snapshot
        .outbound_ips
        .iter()
        .map(|entry| JsonIp {
            ip: entry.ip.to_string(),
            bytes: entry.bytes,
            last_seen: entry.last_seen().to_rfc3339(),
        })
        .collect();

    let top_hosts = snapshot
        .outbound_domains
        .iter()
        .map(|domain| JsonHost {
            host: domain.host().to_string(),
            in_bytes: domain.in_bytes,
            out_bytes: domain.out_bytes,
            total_bytes: domain.total_bytes(),
            last_seen: domain.last_seen().to_rfc3339(),
        })
        .collect();

    JsonFrame {
        interface,
        host: host.clone(),
        started_at: started_wall.to_rfc3339(),
        now: now.to_rfc3339(),
        uptime_secs: started_at.elapsed().as_secs(),
        totals: JsonTotals {
            in_bytes: snapshot.in_bytes,
            out_bytes: snapshot.out_bytes,
        },
        top_processes,
        top_hosts,
        top_inbound_ips,
        top_outbound_ips,
    }
}

/// stdout JSONL: one compact line per frame, no clear-screen.
pub fn render_jsonl(
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) {
    let frame = build_json_frame(interface, started_wall, started_at, stats, top_n);
    if let Ok(line) = serde_json::to_string(&frame) {
        println!("{line}");
    }
}

/// File JSON: indented object overwritten each refresh.
pub fn render_file_json(
    path: &str,
    interface: &str,
    started_wall: &chrono::DateTime<chrono::Local>,
    started_at: Instant,
    stats: &Stats,
    top_n: usize,
) -> std::io::Result<()> {
    let frame = build_json_frame(interface, started_wall, started_at, stats, top_n);
    let json = serde_json::to_string_pretty(&frame).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::*;
    use crate::capture::Flow;
    use crate::stats::{Direction, ObservedProcess};

    #[test]
    fn plain_snapshot_renders_process_path_and_last_seen() {
        let mut stats = Stats::default();
        stats.record_flow_at(
            flow(Direction::Inbound, 40),
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("curl")),
                path: Some(Arc::from("/usr/bin/curl")),
            }),
            "2026-07-15T08:00:00Z".parse().unwrap(),
        );

        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);

        assert!(rendered.contains("Process\tPID\tRecv\tSent\tTotal\tLast Seen\tPath"));
        assert!(
            rendered.contains("curl\t7\t40 B\t0 B\t40 B\t2026-07-15T08:00:00+00:00\t/usr/bin/curl")
        );
    }

    #[test]
    fn plain_snapshot_renders_unattributed_traffic() {
        let mut stats = Stats::default();
        let observed_at = "2026-07-15T08:02:00Z".parse().unwrap();
        stats.record_flow_at(flow(Direction::Inbound, 40), None, observed_at);
        stats.record_flow_at(flow(Direction::Outbound, 60), None, observed_at);

        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);

        assert!(rendered.contains(
            "<unattributed traffic>\t-\t40 B\t60 B\t100 B\t2026-07-15T08:02:00+00:00\t-"
        ));
    }

    #[test]
    fn json_snapshot_renders_unattributed_traffic_as_null_identity() {
        let mut stats = Stats::default();
        let observed_at = "2026-07-15T08:02:00Z".parse().unwrap();
        stats.record_flow_at(flow(Direction::Inbound, 40), None, observed_at);
        stats.record_flow_at(flow(Direction::Outbound, 60), None, observed_at);

        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();
        let process = &value["top_processes"][0];

        assert!(process["pid"].is_null());
        assert!(process["name"].is_null());
        assert!(process["path"].is_null());
        assert_eq!(process["last_seen"], "2026-07-15T08:02:00+00:00");
        assert_eq!(process["recv"], 40);
        assert_eq!(process["sent"], 60);
        assert_eq!(process["total"], 100);
    }

    #[test]
    fn json_snapshot_renders_process_path_and_last_seen() {
        let mut stats = Stats::default();
        stats.record_flow_at(
            flow(Direction::Outbound, 60),
            Some(ObservedProcess {
                pid: 7,
                name: Some(Arc::from("curl")),
                path: Some(Arc::from("/usr/bin/curl")),
            }),
            "2026-07-15T08:01:30Z".parse().unwrap(),
        );

        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();
        let process = &value["top_processes"][0];

        assert_eq!(process["path"], "/usr/bin/curl");
        assert_eq!(process["last_seen"], "2026-07-15T08:01:30+00:00");
    }

    #[test]
    fn missing_process_name_and_path_keep_known_pid() {
        let mut stats = Stats::default();
        stats.record_flow_at(
            flow(Direction::Inbound, 40),
            Some(ObservedProcess {
                pid: 7,
                name: None,
                path: None,
            }),
            "2026-07-15T08:03:00Z".parse().unwrap(),
        );

        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        assert!(rendered.contains("?\t7\t40 B\t0 B\t40 B\t2026-07-15T08:03:00+00:00\t-"));

        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();
        let process = &value["top_processes"][0];
        assert_eq!(process["pid"], 7);
        assert!(process["name"].is_null());
        assert!(process["path"].is_null());
    }

    #[test]
    fn plain_snapshot_renders_ip_total_and_last_seen() {
        let mut stats = Stats::default();
        let observed_at = "2026-07-15T08:04:00Z".parse().unwrap();
        stats.record_flow_at(flow(Direction::Inbound, 40), None, observed_at);
        stats.record_flow_at(flow(Direction::Outbound, 60), None, observed_at);

        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);

        assert!(rendered.contains("Top Inbound IPs (10)\nIP\tTotal\tLast Seen\n"));
        assert!(rendered.contains("127.0.0.1\t40 B\t2026-07-15T08:04:00+00:00\n"));
        assert!(rendered.contains("Top Outbound IPs (10)\nIP\tTotal\tLast Seen\n"));
        assert!(rendered.contains("127.0.0.1\t60 B\t2026-07-15T08:04:00+00:00\n"));
    }

    #[test]
    fn json_snapshot_renders_ip_last_seen_without_removing_bytes() {
        let mut stats = Stats::default();
        let observed_at = "2026-07-15T08:04:00Z".parse().unwrap();
        stats.record_flow_at(flow(Direction::Inbound, 40), None, observed_at);

        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();
        let entry = &value["top_inbound_ips"][0];

        assert_eq!(entry["ip"], "127.0.0.1");
        assert_eq!(entry["bytes"], 40);
        assert_eq!(entry["last_seen"], "2026-07-15T08:04:00+00:00");
    }

    fn flow(direction: Direction, bytes: u64) -> Flow {
        Flow {
            direction,
            peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
            peer_port: None,
            bytes,
            local_socket: None,
            peer_local_socket: None,
            domain: None,
        }
    }

    fn flow_with_domain(direction: Direction, bytes: u64, domain: Option<Arc<str>>) -> Flow {
        Flow {
            direction,
            peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
            peer_port: None,
            bytes,
            local_socket: None,
            peer_local_socket: None,
            domain,
        }
    }

    #[test]
    fn plain_snapshot_renders_top_hosts_section() {
        let mut stats = Stats::default();
        let host: Arc<str> = Arc::from("example.com");
        let observed_at = "2026-07-15T08:00:00Z".parse().unwrap();
        stats.record_flow_at(
            flow_with_domain(Direction::Outbound, 100, Some(host.clone())),
            None,
            observed_at,
        );
        stats.record_flow_at(
            flow_with_domain(Direction::Inbound, 240, Some(host)),
            None,
            observed_at,
        );

        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);

        assert!(rendered.contains("Top Hosts (10)\n"));
        assert!(rendered.contains("Host\tIn\tOut\tTotal\tLast Seen\n"));
        assert!(rendered.contains("example.com\t240 B\t100 B\t340 B\t2026-07-15T08:00:00+00:00\n"));
    }

    #[test]
    fn plain_snapshot_renders_empty_top_hosts_section() {
        let stats = Stats::default();
        let rendered = plain_snapshot("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);

        // Section header and column row still appear when no domains observed.
        assert!(rendered.contains("Top Hosts (10)\n"));
        assert!(rendered.contains("Host\tIn\tOut\tTotal\tLast Seen\n"));
        // No domain data rows.
        assert!(!rendered.contains("example.com"));
    }

    #[test]
    fn json_snapshot_renders_top_hosts_array() {
        let mut stats = Stats::default();
        let host: Arc<str> = Arc::from("example.com");
        let observed_at = "2026-07-15T08:00:00Z".parse().unwrap();
        stats.record_flow_at(
            flow_with_domain(Direction::Outbound, 100, Some(host.clone())),
            None,
            observed_at,
        );
        stats.record_flow_at(
            flow_with_domain(Direction::Inbound, 240, Some(host)),
            None,
            observed_at,
        );

        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();

        let top_hosts = value["top_hosts"].as_array().unwrap();
        assert_eq!(top_hosts.len(), 1);
        let entry = &top_hosts[0];
        assert_eq!(entry["host"], "example.com");
        assert_eq!(entry["in_bytes"], 240);
        assert_eq!(entry["out_bytes"], 100);
        assert_eq!(entry["total_bytes"], 340);
        // RFC 3339 (matches process/IP dimension's last_seen format).
        assert_eq!(entry["last_seen"], "2026-07-15T08:00:00+00:00");
    }

    #[test]
    fn json_snapshot_renders_empty_top_hosts_array() {
        let stats = Stats::default();
        let frame = build_json_frame("eth0", &chrono::Local::now(), Instant::now(), &stats, 10);
        let value = serde_json::to_value(frame).unwrap();

        assert!(value["top_hosts"].is_array());
        assert!(value["top_hosts"].as_array().unwrap().is_empty());
    }
}
