//! Capture device discovery and the packet capture loop.

use std::collections::HashSet;
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use pcap::{Capture, Device};

use super::counters::CaptureCounters;
use super::parser::FlowParseOutcome;
use super::parser::PacketDisposition;
use super::parser::packet_format;
use super::parser::parse_with_domain_parser_outcome;
use super::{Flow, InterfaceInfo};
use crate::domain_parse::DomainParser;
use crate::domain_parse_composite::CompositeDomainParser;
use crate::flow_table::{DEFAULT_FLOW_TABLE_CAPACITY, FlowTable};

pub struct CaptureSource {
    pub(crate) cap: Capture<pcap::Active>,
    pub(crate) interface_name: String,
    pub(crate) link_type: pcap::Linktype,
    pub(crate) local_ips: HashSet<IpAddr>,
    pub(crate) domain_parser: Box<dyn DomainParser>,
    /// Connection-level domain flow table (5-tuple → Resolved/NoDomain),
    /// enabled by default on the production path.
    /// Tests may inject a custom instance via [`open_with_domain_parser`].
    pub(crate) flow_table: Arc<FlowTable>,
    pub(crate) pcap_counters: Arc<CaptureCounters>,
    pub(crate) last_pcap_stats_sample: Instant,
}

/// Determine the default route interface from /proc/net/route.
#[cfg(target_os = "linux")]
pub(crate) fn default_interface() -> Option<String> {
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
pub(crate) fn default_interface() -> Option<String> {
    None
}

/// Return available interfaces with the default-route interface highlighted.
pub fn interface_catalog() -> Result<Vec<InterfaceInfo>> {
    let default = default_interface();
    let devices = Device::list()?;
    Ok(interface_catalog_from_devices(devices, default.as_deref()))
}

pub(crate) fn interface_catalog_from_devices(
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
    output.push_str("\nUsage: flowlens <interface-or-number> [OPTIONS]\n");
    output.push_str("Run flowlens --help for full usage\n");
    output
}

pub(crate) fn select_device(selector: &str, mut devices: Vec<Device>) -> Result<Device> {
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

pub(crate) fn collect_local_ips(devices: &[Device]) -> HashSet<IpAddr> {
    collect_local_ips_with_native(devices, native_local_ips())
}

pub(crate) fn collect_local_ips_with_native(
    devices: &[Device],
    native_ips: impl IntoIterator<Item = IpAddr>,
) -> HashSet<IpAddr> {
    let mut local_ips: HashSet<IpAddr> = devices
        .iter()
        .flat_map(|device| device.addresses.iter().map(|address| address.addr))
        .collect();
    local_ips.extend(native_ips);
    local_ips
}

#[cfg(windows)]
pub(crate) fn native_local_ips() -> Vec<IpAddr> {
    match crate::windows_local_ips::query_native_local_ips() {
        Ok(addresses) => addresses,
        Err(error) => {
            eprintln!("native local IP query failed: {error}");
            Vec::new()
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn native_local_ips() -> Vec<IpAddr> {
    Vec::new()
}

impl CaptureSource {
    /// Open live capture on the named interface, using the composite
    /// TLS+HTTP parser and a default-capacity flow table.
    ///
    /// `flow_table_capacity` is passed through from the CLI `--flow-table`;
    /// 0 selects the default of 65536.
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

    /// Same as [`open`](Self::open), but allows injecting a custom parser
    /// and flow table.
    ///
    /// For tests: inject a custom [`DomainParser`] (e.g. `RecordingParser`)
    /// to control parsing behavior; injecting a custom flow table isolates
    /// test state.
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
        let pcap_counters = Arc::new(CaptureCounters::with_local_ips(&local_ips));

        Ok(Self {
            cap,
            interface_name,
            link_type,
            local_ips,
            domain_parser,
            flow_table,
            pcap_counters,
            last_pcap_stats_sample: Instant::now(),
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

    /// Read the next packet; Ok(None) when there is none (read timeout).
    pub fn next(&mut self) -> Result<Option<Flow>> {
        let result = match self.cap.next_packet() {
            Ok(packet) => {
                let captured_bytes = packet.data.len() as u64;
                match parse_with_domain_parser_outcome(
                    self.link_type,
                    packet.data,
                    &self.local_ips,
                    self.domain_parser.as_ref(),
                    Some(self.flow_table.as_ref()),
                ) {
                    Ok(outcome) => {
                        self.pcap_counters.record_packet(captured_bytes, &outcome);
                        Ok(outcome.flow)
                    }
                    Err(error) => {
                        self.pcap_counters.record_packet(
                            captured_bytes,
                            &FlowParseOutcome::discarded(PacketDisposition::ParseError),
                        );
                        Err(error)
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e)),
        };
        self.sample_pcap_stats();
        result
    }

    /// Sample pcap statistics (received/dropped/if_dropped) once per second
    /// for diagnostics output.
    pub(crate) fn sample_pcap_stats(&mut self) {
        if self.last_pcap_stats_sample.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_pcap_stats_sample = Instant::now();
        if let Ok(stat) = self.cap.stats() {
            self.pcap_counters
                .received
                .store(u64::from(stat.received), Ordering::Relaxed);
            self.pcap_counters
                .dropped
                .store(u64::from(stat.dropped), Ordering::Relaxed);
            self.pcap_counters
                .if_dropped
                .store(u64::from(stat.if_dropped), Ordering::Relaxed);
        }
    }

    pub fn pcap_counters(&self) -> Arc<CaptureCounters> {
        Arc::clone(&self.pcap_counters)
    }
}
