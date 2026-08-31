//! Capture counters and non-local endpoint sampling diagnostics.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::parser::FlowParseOutcome;
use super::parser::{IpVersion, PacketDisposition};
pub(crate) const NON_LOCAL_ENDPOINT_SAMPLE_LIMIT: usize = 8;
pub(crate) const NON_LOCAL_ENDPOINT_SAMPLE_INTERVAL: u64 = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NonLocalEndpointSample {
    pub src: IpAddr,
    pub dst: IpAddr,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CaptureDiagnosticsSnapshot {
    pub local_ips: Vec<IpAddr>,
    pub non_local_ipv4_samples: Vec<NonLocalEndpointSample>,
    pub non_local_ipv6_samples: Vec<NonLocalEndpointSample>,
}

pub(crate) struct NonLocalEndpointSamples {
    pub(crate) ipv4: Vec<NonLocalEndpointSample>,
    pub(crate) ipv6: Vec<NonLocalEndpointSample>,
}

impl Default for NonLocalEndpointSamples {
    fn default() -> Self {
        Self {
            ipv4: Vec::with_capacity(NON_LOCAL_ENDPOINT_SAMPLE_LIMIT),
            ipv6: Vec::with_capacity(NON_LOCAL_ENDPOINT_SAMPLE_LIMIT),
        }
    }
}

/// Capture counters for a given interface.
/// Cumulative pcap-level counters, sampled periodically by the capture
/// thread for diagnostics output.
#[derive(Default)]
pub struct CaptureCounters {
    pub received: AtomicU64,
    pub dropped: AtomicU64,
    pub if_dropped: AtomicU64,
    pub packets_read: AtomicU64,
    pub bytes_read: AtomicU64,
    pub parse_error_packets: AtomicU64,
    pub parse_error_bytes: AtomicU64,
    pub non_ip_packets: AtomicU64,
    pub non_ip_bytes: AtomicU64,
    pub non_local_ipv4_packets: AtomicU64,
    pub non_local_ipv4_bytes: AtomicU64,
    pub non_local_ipv6_packets: AtomicU64,
    pub non_local_ipv6_bytes: AtomicU64,
    pub duplicate_outgoing_packets: AtomicU64,
    pub duplicate_outgoing_bytes: AtomicU64,
    pub flow_packets: AtomicU64,
    pub flow_bytes: AtomicU64,
    pub(crate) local_ips: Arc<[IpAddr]>,
    pub(crate) non_local_samples: Mutex<NonLocalEndpointSamples>,
    pub(crate) non_local_ipv4_packets_seen: AtomicU64,
    pub(crate) non_local_ipv6_packets_seen: AtomicU64,
}

impl CaptureCounters {
    pub(crate) fn with_local_ips(local_ips: &HashSet<IpAddr>) -> Self {
        let mut local_ips = local_ips.iter().copied().collect::<Vec<_>>();
        local_ips.sort_unstable();
        Self {
            local_ips: local_ips.into(),
            ..Self::default()
        }
    }

    pub(crate) fn record_packet(&self, captured_bytes: u64, outcome: &FlowParseOutcome) {
        self.packets_read.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(captured_bytes, Ordering::Relaxed);

        let (packets, bytes) = match outcome.disposition {
            PacketDisposition::Accepted => (&self.flow_packets, &self.flow_bytes),
            PacketDisposition::ParseError => (&self.parse_error_packets, &self.parse_error_bytes),
            PacketDisposition::NonIp => (&self.non_ip_packets, &self.non_ip_bytes),
            PacketDisposition::NonLocal { version, src, dst } => {
                self.record_non_local_endpoint(version, src, dst);
                match version {
                    IpVersion::V4 => (&self.non_local_ipv4_packets, &self.non_local_ipv4_bytes),
                    IpVersion::V6 => (&self.non_local_ipv6_packets, &self.non_local_ipv6_bytes),
                }
            }
            PacketDisposition::DuplicateOutgoing => (
                &self.duplicate_outgoing_packets,
                &self.duplicate_outgoing_bytes,
            ),
        };
        packets.fetch_add(1, Ordering::Relaxed);
        bytes.fetch_add(captured_bytes, Ordering::Relaxed);
    }

    pub(crate) fn record_non_local_endpoint(&self, version: IpVersion, src: IpAddr, dst: IpAddr) {
        let packets_seen = match version {
            IpVersion::V4 => &self.non_local_ipv4_packets_seen,
            IpVersion::V6 => &self.non_local_ipv6_packets_seen,
        }
        .fetch_add(1, Ordering::Relaxed)
            + 1;
        let replacement_index = if packets_seen <= NON_LOCAL_ENDPOINT_SAMPLE_LIMIT as u64 {
            None
        } else if packets_seen.is_multiple_of(NON_LOCAL_ENDPOINT_SAMPLE_INTERVAL) {
            Some(
                ((packets_seen / NON_LOCAL_ENDPOINT_SAMPLE_INTERVAL - 1)
                    % NON_LOCAL_ENDPOINT_SAMPLE_LIMIT as u64) as usize,
            )
        } else {
            return;
        };

        let mut samples = self
            .non_local_samples
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let samples = match version {
            IpVersion::V4 => &mut samples.ipv4,
            IpVersion::V6 => &mut samples.ipv6,
        };
        let sample = NonLocalEndpointSample { src, dst };
        if let Some(index) = replacement_index {
            samples[index] = sample;
        } else {
            samples.push(sample);
        }
    }

    pub(crate) fn diagnostics_snapshot(&self) -> CaptureDiagnosticsSnapshot {
        let samples = self
            .non_local_samples
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        CaptureDiagnosticsSnapshot {
            local_ips: self.local_ips.to_vec(),
            non_local_ipv4_samples: samples.ipv4.clone(),
            non_local_ipv6_samples: samples.ipv6.clone(),
        }
    }
}
