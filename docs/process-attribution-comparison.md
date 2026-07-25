# Process Attribution Comparison

Use this runbook to compare the old build and the ProcessProbe build on the same machine. The capture interface, traffic generator, duration, permissions, and output cadence must stay the same for both runs.

## Capture

Run one version at a time for a fixed window, for example 10 minutes. Keep JSONL on stdout and diagnostics on stderr. A typical command is:

    delray.exe <interface> --format json --diagnostics > new.jsonl 2> new.diag

Use the same command for the old executable and replace the output names. Record the OS build, Delray commit, Rust toolchain, Npcap/listeners version, interface selector, start/end time, and whether the process ran elevated.

Generate known traffic during each window:

- TCP: curl to a fixed HTTP or HTTPS endpoint, repeating the same request count and payload size.
- Browser: open the same fixed page and download the same fixed file.
- UDP: use the same UDP sender/receiver pair, with a recorded payload size and duration.

Avoid unrelated traffic where possible. If loopback is used, record that the transfer may appear in both directions because of capture semantics.

## Compare

For every JSONL frame, extract:

- totals.in_bytes and totals.out_bytes;
- the process row whose identity is <unattributed traffic>;
- the sum of all attributed process rows;
- frame timestamp and elapsed time.

For every diagnostics line, record these cumulative counters:

    no_local_socket
    lookup_no_candidate
    lookup_ambiguous
    lookup_stale
    lookup_no_candidate_bytes
    lookup_ambiguous_bytes
    lookup_stale_bytes
    probe_request_queued
    probe_result_unique
    probe_result_not_found
    probe_result_ambiguous
    probe_result_unavailable
    probe_result_dropped
    probe_result_late
    pending_expired_bytes
    pending_capacity_bytes
    probe_unique_pending_bytes
    probe_not_found_pending_bytes
    probe_ambiguous_pending_bytes
    probe_unavailable_pending_bytes
    probe_query_count
    probe_query_ms
    probe_last_query_ms

Compare both the final totals and the per-window deltas. The useful result is the composition of unidentified traffic, not only the final <unattributed traffic> byte count.

Interpretation:

- lookup_stale or lookup_no_candidate dominant: investigate refresh cadence or pending duration.
- probe_result_late dominant: the listener query is completing after pending expiry; optimize query latency or decouple socket indexing from process metadata.
- lookup_ambiguous or probe_result_ambiguous dominant: local socket matching is insufficient; add connection endpoint disambiguation before considering any heuristic attribution.
- no_local_socket dominant: the packet has no local TCP/UDP socket in the capture model; user-space listener probing cannot recover ownership.
- many probe_request_queued with few probe_result_unique: the probe data source does not cover the main unidentified traffic and retry tuning is unlikely to help.

## Report

Keep the raw *.jsonl and *.diag files with the experiment notes. Report totals, attributed bytes, unidentified bytes, and diagnostics deltas separately for TCP, browser, and UDP traffic. Do not combine runs from different interfaces or different time windows.
