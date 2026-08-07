# Windows Connection Endpoint Analysis

## Finding

The Windows implementation used by listeners 0.6.0 calls the IP Helper APIs:

- GetExtendedTcpTable(..., TCP_TABLE_OWNER_PID_ALL, ...)
- GetExtendedUdpTable(..., UDP_TABLE_OWNER_PID, ...)

The native TCP row contains:

    state
    local_addr
    local_port
    remote_addr
    remote_port
    owning_pid

The TCP6 row contains the equivalent IPv6 local and remote fields. The UDP rows contain local address, local port, and owning PID.

listeners currently converts each native row into an internal ProtoListener containing only:

    local_addr
    local_port
    pid
    protocol
    state

Its public Listener therefore exposes no remote address or remote port. FlowLens cannot recover the discarded endpoint by calling listeners::get_all().

## Host verification

On 2026-07-26, privileged Get-NetTCPConnection -State Established on the validation host returned local address, local port, remote address, remote port, owning PID, and state for loopback and physical connections. Examples included:

    127.0.0.1:64225 -> 127.0.0.1:64224, PID 6412
    192.168.100.102:64243 -> 34.107.243.93:443, PID 38008

This confirms that the operating system exposes the data needed for connection-aware matching.

## Historical consequence

Before the connection adapter, ProcessProbe could only answer:

    local address + local port + protocol -> PID candidates

That lookup could not distinguish established connections that shared a local socket or a wildcard/local-port entry. Retry tuning and longer pending windows could not recover the discarded remote endpoint.

## Implementation

The Windows connection snapshot adapter is implemented in:

    src/windows_connection_probe.rs

TCP probe requests now match the local address, local port, protocol, and remote endpoint against the Windows owner-PID table in `src/process_probe.rs`. A unique endpoint match is attributed to its PID. Multiple PIDs remain ambiguous and are not guessed.

When the endpoint record has disappeared before the probe runs, the implementation falls back to the existing local-socket index only when it has a unique candidate. This preserves attribution for short-lived connections without weakening the ambiguous-socket rule.

The behavior is covered by unit tests for unique endpoint matches, ambiguous endpoint matches, and the unique local-socket fallback.
