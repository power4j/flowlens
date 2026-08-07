# Capture Parity Verification

A repeatable, automated way to verify FlowLens's traffic totals against a trusted
reference, instead of relying on manual comparison with Sniffnet and the Windows
Task Manager on a user's machine.

## Problem

On Windows, FlowLens's interface totals can be orders of magnitude lower than the
wire traffic (observed with a 4K video streamed over a LAN SMB share). A
verification tool must be able to say *where* bytes are lost:

1. kernel/driver capture layer (Npcap buffer overflow, driver drops),
2. FlowLens's raw-packet handling (strict parsing dropping frames, capture-thread
   backpressure), or
3. counting scope (non-IP frames, ARP, local-to-local double counting, padding).

## Components

| Component | Role |
| --- | --- |
| `src/bin/refcap.rs` (binary `refcap`) | Minimal raw capture counter. Reads the same Npcap device as FlowLens, counts packets/wire bytes/IP bytes by EtherType, and reports Npcap's `dropped` / `if_dropped` stats every second. No protocol parsing, no attribution, no bounded channel. |
| `scripts/verify-capture.ps1` | Orchestrates one run: starts `refcap` + `flowlens` concurrently, generates traffic (iperf3 or SMB copy), samples Windows adapter counters before/after, computes three ratios, writes `report.txt`/`report.json`, returns a CI-friendly exit code. |
| `temp/iperf-3.21-win64/iperf3.exe` | High-rate TCP traffic generator (already vendored in the repo). |

## The three layers and what each ratio tells you

| Ratio | Formula | What it isolates |
| --- | --- | --- |
| `capture_ratio` | refcap `bytes_wire` / adapter counter delta | pcap read path vs wire. Adapter counters are the same source as Task Manager (includes framing overhead, so a small tolerance is expected). If low → Npcap is not handing packets to userspace (buffer too small, driver drops, wrong adapter). |
| `pipeline_ratio` | FlowLens `in_bytes+out_bytes` / refcap `bytes_ip` | FlowLens's total pipeline vs raw IP bytes that Npcap actually delivered. If low while `capture_ratio` is high → FlowLens-side loss: strict parser dropping frames, capture-thread backpressure (2 MB buffer + 8k bounded channel + 100 ms blocking sleep), or scope (non-IP, ARP). This is the ratio that will confirm/reject the "architecture design" hypothesis for the order-of-magnitude shortfall. |
| `traffic_generated` | adapter delta ≥ max(10 MB, 10% of expected) | Guards against a run where no traffic actually flowed (e.g. iperf3 server unreachable). |

## Prerequisites

- Windows test machine with Npcap installed; the script (and FlowLens/refcap) must
  run as Administrator.
- Built binaries: `target\release\flowlens.exe` and `target\release\refcap.exe`
  (`cargo build --release --bins`).
- Either:
  - an iperf3 server reachable on the LAN (`iperf3 -s` on another machine), or
  - an SMB share containing a large file (the automated proxy for the 4K video
    scenario; SMB-over-TCP 445 like the original test).

## Usage

```powershell
# High-rate TCP (recommended first run)
.\scripts\verify-capture.ps1 -IperfServer 192.168.1.10 -DurationSec 30 -Bandwidth 400M

# Same, with an explicit interface (from refcap --list)
.\scripts\verify-capture.ps1 -Interface '\Device\NPF_{GUID}' -IperfServer 192.168.1.10

# Single-machine loopback smoke (no second host needed; exercises the pipeline
# but NOT the physical NIC)
.\scripts\verify-capture.ps1 -Interface '\Device\NPF_Loopback' -IperfServer 127.0.0.1 -StartLocalIperfServer -DurationSec 30 -Bandwidth 400M

# Manual traffic mode: start capturing, then play a real video (e.g. from an
# SMB share) when prompted. Only the "start playing" step is manual.
.\scripts\verify-capture.ps1 -Interface 12 -ManualMode -DurationSec 60

# SMB proxy for the video scenario
.\scripts\verify-capture.ps1 -SmbCopySource \\nas\share\movie.mkv -DurationSec 60

# Test whether a larger Npcap kernel buffer changes capture-side loss
.\scripts\verify-capture.ps1 -IperfServer 192.168.1.10 -BufferSize 16777216 -Snaplen 65535
```

Artifacts are written to `temp\verify-capture-<timestamp>\`:
`refcap.jsonl`, `flowlens.json`, `iperf*.txt`, `report.txt`, `report.json`.

## Reading a report

| capture_ratio | pipeline_ratio | Conclusion |
| --- | --- | --- |
| ≈ 1 | ≈ 1 | Capture and pipeline both fine on this test; any earlier gap is environmental (rate, adapter) or a scope difference (ARP/non-IP share). |
| low | — | Capture layer: Npcap buffer/driver cannot keep up at this rate. Re-run with `-BufferSize 16777216`; if it recovers, the 2 MB default buffer is the problem. |
| ≈ 1 | low | FlowLens-side: strict parsing drops and/or pipeline backpressure. Compare `ip_invalid_packets`; inspect FlowLens diagnostics for probe/lookup latency. This is the architecture hypothesis. |
| ≈ 1 | ≈ 1 but totals differ slightly | Counting-scope differences only (ARP, non-IP, local↔local double counting, framing overhead). |

`report.json` is machine-readable for CI; the script exits 0 only when all three
checks pass, so it can be wired into a scheduled run on a test bench.

## Limitations

- `Get-NetAdapterStatistics` counters are cumulative and vendor-dependent; on
  adapters where they are unavailable the script reports `adapter_counters:
  null` and `capture_ratio` cannot be computed (refcap IP bytes then remain the
  best available reference).
- Loopback traffic is not covered; Npcap loopback capture on Windows has
  separate adapter/direction quirks (FlowLens intentionally restricts loopback to
  inbound).
- Sniffnet remains a valid manual cross-check but is not required by this
  harness; `refcap` is the automated oracle.
- The SMB copy mode approximates the 4K playback load pattern; playback
  specifically can be reproduced later with a scripted media player run, but the
  copy already exercises SMB-over-TCP at high rate.

## Conclusion (2026-08-03, current build)

Measured on the ASIX USB Gigabit adapter (192.168.100.102) with the release
build:

| Scenario | Load | refcap/adapter | FlowLens/refcap-IP | Npcap dropped | Verdict |
| --- | --- | --- | --- | --- | --- |
| iperf3 400M x1, 30 s | ~177 Mbps sustained | 99.7% | 99.6% | 0 | PASS |
| video playback, 60 s (physical NIC, Tailscale outer traffic) | ~13 Mbps | 99.9% | 99.6% | 0 | PASS |
| iperf3 1000M x4, 30 s | ~487 Mbps (adapter ceiling) | 100.0% | 99.9% | 0 | PASS |

The capture pipeline retains >=99.6% of raw pcap bytes up to the adapter's
physical ceiling with zero Npcap drops, so the previously reported
order-of-magnitude shortfall is not reproducible with the current build on this
hardware. Remaining hypotheses for the original report: interface-selection
mismatch between FlowLens and Sniffnet in the original run (compare the
`\Device\NPF_...` GUIDs), an older FlowLens build, or measurement-scope
differences.

Since this verification, FlowLens's diagnostics JSONL also reports pcap-layer
counters (`counters.pcap_received`, `counters.pcap_dropped`,
`counters.pcap_if_dropped`, sampled once per second from `cap.stats()`), so
capture-side drops are visible without an external reference counter.
