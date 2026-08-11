use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use chrono::Utc;
use serde::Serialize;

use crate::attribution::PendingAttributionSnapshot;
use crate::capture::CaptureCounters;
use crate::proc_table::{LookupMissSample, ProcDiagnosticsSnapshot, SharedProcTable};
use crate::stats::{
    DiagnosticsCounters, DiagnosticsGauges, DiagnosticsIp, DiagnosticsMissSample,
    DiagnosticsSnapshot, StatsDiagnostics,
};

pub(crate) const SCHEMA_VERSION: u8 = 1;

pub(crate) fn default_output_path() -> PathBuf {
    PathBuf::from(format!(
        "flowlens-{}-{}.log",
        Utc::now().format("%Y%m%dT%H%M%SZ%f"),
        std::process::id()
    ))
}

pub(crate) struct DiagnosticsInputs<'a> {
    pub proc_table: &'a SharedProcTable,
    pub pending: PendingAttributionSnapshot,
    pub stats: StatsDiagnostics,
    pub flow_table_entries: u64,
    pub pcap: Option<&'a CaptureCounters>,
}

pub(crate) fn collect(inputs: DiagnosticsInputs<'_>) -> Option<DiagnosticsSnapshot> {
    let proc = crate::proc_table::diagnostics_snapshot(inputs.proc_table)?;
    Some(from_parts(proc, inputs))
}

pub(crate) fn from_parts(
    proc: ProcDiagnosticsSnapshot,
    inputs: DiagnosticsInputs<'_>,
) -> DiagnosticsSnapshot {
    DiagnosticsSnapshot {
        counters: DiagnosticsCounters {
            lookup_hits: proc.lookup_hits,
            lookup_misses: proc.lookup_misses,
            lookup_no_candidate: proc.lookup_no_candidate,
            lookup_ambiguous: proc.lookup_ambiguous,
            lookup_stale: proc.lookup_stale,
            lookup_no_candidate_bytes: proc.lookup_no_candidate_bytes,
            lookup_ambiguous_bytes: proc.lookup_ambiguous_bytes,
            lookup_stale_bytes: proc.lookup_stale_bytes,
            lookup_v4_mapped_hits: proc.lookup_v4_mapped_hits,
            no_local_socket: proc.no_local_socket,
            refresh_requests: proc.refresh_requests,
            refresh_actual: proc.refresh_actual,
            refresh_success: proc.refresh_success,
            refresh_failure: proc.refresh_failure,
            refresh_records: proc.refresh_records,
            refresh_v4_mapped_records: proc.refresh_v4_mapped_records,
            probe_request_queued: inputs.pending.probe_request_queued,
            probe_result_unique: inputs.pending.probe_result_unique,
            probe_result_not_found: inputs.pending.probe_result_not_found,
            probe_result_ambiguous: inputs.pending.probe_result_ambiguous,
            probe_result_unavailable: inputs.pending.probe_result_unavailable,
            probe_result_dropped: inputs.pending.probe_result_dropped,
            probe_result_late: inputs.pending.probe_result_late,
            probe_query_count: inputs.pending.probe_query_count,
            probe_query_ms: inputs.pending.probe_query_ms,
            pending_expired_bytes: inputs.pending.pending_expired_bytes,
            pending_capacity_bytes: inputs.pending.pending_capacity_bytes,
            probe_unique_pending_bytes: inputs.pending.probe_unique_pending_bytes,
            probe_not_found_pending_bytes: inputs.pending.probe_not_found_pending_bytes,
            probe_ambiguous_pending_bytes: inputs.pending.probe_ambiguous_pending_bytes,
            probe_unavailable_pending_bytes: inputs.pending.probe_unavailable_pending_bytes,
            ip_promotions: inputs.stats.ip_promotions,
            ip_demotions: inputs.stats.ip_demotions,
            ip_evictions_heavy: inputs.stats.ip_evictions_heavy,
            ip_evictions_rising: inputs.stats.ip_evictions_rising,
            ip_evictions_observation: inputs.stats.ip_evictions_observation,
            pcap_received: inputs
                .pcap
                .map_or(0, |c| c.received.load(Ordering::Relaxed)),
            pcap_dropped: inputs.pcap.map_or(0, |c| c.dropped.load(Ordering::Relaxed)),
            pcap_if_dropped: inputs
                .pcap
                .map_or(0, |c| c.if_dropped.load(Ordering::Relaxed)),
        },
        gauges: DiagnosticsGauges {
            flow_table_entries: inputs.flow_table_entries,
            process_entries: inputs.stats.process_entries,
            domain_entries: inputs.stats.domain_entries,
            last_refresh_ms: proc.last_refresh_duration.as_millis(),
            pending_records: inputs.pending.records,
            pending_bytes: inputs.pending.bytes,
            probe_last_query_ms: inputs.pending.probe_last_query_ms,
        },
        ip: DiagnosticsIp {
            inbound_entries: inputs.stats.inbound_ip_entries,
            outbound_entries: inputs.stats.outbound_ip_entries,
            inbound_heavy_entries: inputs.stats.inbound_heavy_ip_entries,
            inbound_rising_entries: inputs.stats.inbound_rising_ip_entries,
            inbound_observation_entries: inputs.stats.inbound_observation_ip_entries,
            outbound_heavy_entries: inputs.stats.outbound_heavy_ip_entries,
            outbound_rising_entries: inputs.stats.outbound_rising_ip_entries,
            outbound_observation_entries: inputs.stats.outbound_observation_ip_entries,
        },
        miss_samples: proc
            .lookup_miss_samples
            .into_iter()
            .map(miss_sample)
            .collect(),
    }
}

fn miss_sample(sample: LookupMissSample) -> DiagnosticsMissSample {
    DiagnosticsMissSample {
        reason: match sample.reason {
            crate::proc_table::LookupMissReason::NoCandidate => "no_candidate",
            crate::proc_table::LookupMissReason::Ambiguous => "ambiguous",
            crate::proc_table::LookupMissReason::Stale => "stale",
        }
        .to_string(),
        protocol: match sample.local_socket.protocol {
            crate::capture::TransportProtocol::Tcp => "tcp",
            crate::capture::TransportProtocol::Udp => "udp",
        }
        .to_string(),
        local: format!("{}:{}", sample.local_socket.ip, sample.local_socket.port),
        peer: format!("{}:{}", sample.peer_ip, sample.peer_port),
    }
}

pub(crate) struct DiagnosticsWriter {
    writer: BufWriter<File>,
    run_id: String,
    sequence: u64,
    path: PathBuf,
}

impl DiagnosticsWriter {
    pub(crate) fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let run_id = format!(
            "{}-{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            std::process::id()
        );
        Ok(Self {
            writer: BufWriter::new(file),
            run_id,
            sequence: 0,
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn file_name(&self) -> Option<String> {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    }

    pub(crate) fn write(
        &mut self,
        interface: &str,
        snapshot: &DiagnosticsSnapshot,
    ) -> io::Result<()> {
        self.sequence += 1;
        let timestamp = Utc::now().to_rfc3339();
        let record = SnapshotRecord {
            schema_version: SCHEMA_VERSION,
            run_id: &self.run_id,
            seq: self.sequence,
            kind: "snapshot",
            timestamp: &timestamp,
            interface,
            counters: &snapshot.counters,
            gauges: &snapshot.gauges,
            ip: &snapshot.ip,
            miss_sample_count: snapshot.miss_samples.len(),
        };
        serde_json::to_writer(&mut self.writer, &record).map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        for sample in &snapshot.miss_samples {
            let event = MissSampleRecord {
                schema_version: SCHEMA_VERSION,
                run_id: &self.run_id,
                seq: self.sequence,
                kind: "lookup_miss_sample",
                timestamp: &timestamp,
                interface,
                reason: &sample.reason,
                protocol: &sample.protocol,
                local: &sample.local,
                peer: &sample.peer,
            };
            serde_json::to_writer(&mut self.writer, &event).map_err(io::Error::other)?;
            self.writer.write_all(b"\n")?;
        }
        self.writer.flush()
    }
}

#[derive(Serialize)]
struct SnapshotRecord<'a> {
    schema_version: u8,
    run_id: &'a str,
    seq: u64,
    kind: &'static str,
    timestamp: &'a str,
    interface: &'a str,
    counters: &'a DiagnosticsCounters,
    gauges: &'a DiagnosticsGauges,
    ip: &'a DiagnosticsIp,
    miss_sample_count: usize,
}

#[derive(Serialize)]
struct MissSampleRecord<'a> {
    schema_version: u8,
    run_id: &'a str,
    seq: u64,
    kind: &'static str,
    timestamp: &'a str,
    interface: &'a str,
    reason: &'a str,
    protocol: &'a str,
    local: &'a str,
    peer: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::DiagnosticsMissSample;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "flowlens-diagnostics-{label}-{}-{}.jsonl",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    #[test]
    fn default_path_contains_timestamp_pid_and_log_extension() {
        let path = default_output_path();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("flowlens-"));
        assert!(name.ends_with(".log"));
        assert!(name.contains(&std::process::id().to_string()));
    }

    #[test]
    fn writer_emits_snapshot_then_miss_events_with_shared_sequence() {
        let path = temp_path("records");
        let mut writer = DiagnosticsWriter::create(&path).unwrap();
        let snapshot = DiagnosticsSnapshot {
            miss_samples: vec![DiagnosticsMissSample {
                reason: "ambiguous".to_string(),
                protocol: "tcp".to_string(),
                local: "192.0.2.1:1234".to_string(),
                peer: "198.51.100.2:443".to_string(),
            }],
            ..DiagnosticsSnapshot::default()
        };

        writer.write("eth0", &snapshot).unwrap();
        drop(writer);
        let content = std::fs::read_to_string(&path).unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["kind"], "snapshot");
        assert_eq!(records[0]["seq"], 1);
        assert_eq!(records[0]["miss_sample_count"], 1);
        assert_eq!(records[1]["kind"], "lookup_miss_sample");
        assert_eq!(records[1]["seq"], 1);
        assert_eq!(records[1]["reason"], "ambiguous");
        std::fs::remove_file(path).unwrap();
    }
}
