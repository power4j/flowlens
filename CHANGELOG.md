# Changelog

All notable changes to FlowLens are recorded in this file.

## [Unreleased]

### Added

- Configurable ranking windows: cumulative totals, 5s, 10s, 30s, 60s, and 5m average throughput, selectable from the settings overlay or with `--rank-window`. The active window is shown in the TUI.
- Process details now include a scrollable connection table with local and remote endpoints plus received and sent totals. Use `--proc-flows` to set the maximum retained rows per process.

### Changed

- Packet capture now uses the pcap 2.5.0 batch `dispatch` reader by default, reducing per-packet read overhead on high-PPS interfaces. The per-packet `next_packet()` baseline remains selectable with `--read-mode next` for A/B comparison and rollback.
- Process, IP, and outbound-domain rankings can now use sliding-window average throughput while interface totals remain cumulative. Finite-window rankings also show their current coverage while warming up.

### Fixed

- TCP domain detection now performs bounded retries after an initial payload lacks SNI or an HTTP `Host`, allowing later payloads to populate domain rankings without repeatedly parsing long-lived connections.
- Ranking tables reserve enough width for rate values such as `100.00 KB/s`, and finite-window domain views distinguish having no recent observations from having no cumulative observations.
- On Windows, local-address detection now supplements Npcap device metadata with the native adapter-address API. This prevents Tailscale file-transfer traffic on Red Hat VirtIO Ethernet adapters from being incorrectly treated as non-local and omitted from FlowLens totals.

### Removed

### Deprecated

### Security

## [0.5.0] - 2026-08-24

### Added

- TUI quit confirmation: `q`, `Esc` (when it would leave the app), and `Ctrl+C` open a prompt; confirm with `q`/`y`/`Enter`, or cancel with `n`/`Esc`. Process details `Esc` still returns to the list.

### Changed

- Process list, overview preview, conservation summary, and top-N ranking use start-of-capture lifetime totals. Historical heavy hitters stay visible. The 5-minute window remains on the process detail page and in JSON/TSV reports.
- Process details show `Last seen` under `Path`.
- Process-detail Attribution rows use equal-width Exclusive/Shared/Total labels and right-aligned Recv/Sent values.

### Fixed

- The Attribution `Total` equation no longer inherits Recv/Sent padding, so values such as `Shared 0 B` are not stretched.

### Removed

### Deprecated

### Security

## [0.4.0] - 2026-08-22

### Added

- Linux `x86_64`/`aarch64` one-click installer (`install.sh`) that fetches GitHub Releases, verifies `SHA256SUMS`, and supports dry-run, PATH updates, `--setcap`, and uninstall. After install it prints glibc `2.28+`, libpcap, and `CAP_NET_RAW` next steps. macOS is recognized but fails until Release assets exist.
- Inclusive graded process attribution: exclusive, shared, system, and unattributed channels with a conservation summary. Shared bytes are counted in full on each candidate process and process-row totals can exceed interface totals.
- Process TUI summary for Exclusive, Shared, System, and Unattributed traffic, an `Attr` column (`E` exclusive-only, `M` mixed), and a process-detail Attribution breakdown with shared-with partners.
- Socket-to-PID history recovery with a PID start-time gate, so short-lived connections can be attributed without PID-reuse misattribution.
- A 5-minute rolling window for process top-N ranking; lifetime totals remain in process details and reports. JSON and TSV include window fields.

### Changed

- Process top-N ranks by exclusive plus shared window totals. System and unattributed traffic stay in the summary and no longer occupy ranked rows.
- Process-detail Attribution labels lifetime versus 5-minute window totals, and states that shared traffic is included in Total and may appear in multiple processes.

### Fixed

- Processes with no traffic in the current 5-minute window are excluded from the top list.

### Removed

### Deprecated

### Security

## [0.3.0] - 2026-08-14

### Added

- TUI settings overlay can toggle diagnostics at runtime from the settings UI; each enable writes to a fresh timestamped log file and the overlay shows the current file name.

### Changed

- Settings overlay uses a unified select-then-change interaction: `j/k`/arrows select an item, `h/l`/arrows change its value, with a full-row highlight and a `> ` selection marker that keeps the selected row identifiable on 16-color/monochrome terminals; the `d` shortcut and `Enter` value cycling were removed.
- Release workflows now build and publish Linux `x86_64`/`aarch64` and Windows `x86_64`/`aarch64` archives with architecture-specific checksums.

### Fixed

### Removed

### Deprecated

### Security

## [0.2.0] - 2026-07-31

### Added

- TUI views for interface totals, processes, IP addresses, outbound domains, and application information.
- Plain-text, JSON, and JSON Lines output modes.
- Best-effort process attribution with PID, executable identity, and unattributed traffic reporting.
- Outbound-domain detection for TCP TLS SNI and plaintext HTTP `Host` headers.
- Linux `x86_64` and Windows `x86_64` release targets.

### Changed

### Fixed

- Improved Windows TCP process attribution by matching active connections with both local and remote endpoints, with a conservative fallback for short-lived connections.

### Removed

### Deprecated

### Security
