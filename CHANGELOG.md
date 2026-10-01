# Changelog

All notable changes to FlowLens are recorded in this file.

## [Unreleased]

### Added

- Optional static-libpcap Linux trial builds in the Build Test workflow, with an exact-key native dependency cache that validates cached contents before reuse. Ordinary source builds continue to use the system libpcap.
- Linux release binary audits and capture smoke checks without system libpcap on Debian 12, Ubuntu 24.04, Fedora 43, and Rocky Linux 8, including root, permission-denied, and CAP_NET_RAW-only scenarios on both architectures.

### Changed

- Linux release builds now bundle checksum-pinned libpcap 1.10.7 while retaining dynamic glibc with the 2.28 baseline. Archives include the bundled library's license and copyright notices.
- The system installer automatically prepares missing runtime packages on Debian/Ubuntu and RPM-family distributions after download verification and install preflight. Explicit `--setcap` also prepares the capability tool; default installs do not grant capabilities. User/custom installs, dry runs, and uninstalls do not change system packages.
- macOS builds use system-only library linkage and explicit deployment targets, with binary audits and root loopback capture checks on native macOS 15 runners. macOS archives remain experimental, unsigned, and unnotarized; older systems and full runtime behavior remain unverified.
- Windows ARM64 archives remain available with cross-build and binary/dependency audit coverage; ARM64 real-hardware capture is unverified and must be identified as a release limitation.

### Fixed

- Restored macOS loopback capture by avoiding the incoming-only direction filter on `lo0`, while retaining the existing direction behavior on other platforms.

### Removed

### Deprecated

### Security

## [0.7.2] - 2026-09-30

### Added

- Public SNI reporting for visible TLS ClientHello names accompanied by ECH or legacy ESNI. Plain-text reports include a separate Public SNI section; JSON adds `top_public_sni` alongside ordinary `top_outbound_domains`, with independent top-N limits. The visible name may differ from the actual target.
- Offline TLS runtime and PCAP stress-evaluation tools for checking domain detection, traffic accounting, and bounded resource usage without network access or privileged capture. These are development evaluations, not release benchmarks.

### Changed

- The Linux installer now defaults to a system installation in `/usr/local/bin`, with its manifest under `/usr/local/share/flowlens`. Use `--user` for the previous per-user behavior; custom installation directories remain supported. System operations require write access or sudo and do not silently fall back to a user installation.
- The Domains page uses compact `Std`/`Pub` type labels and explains Public SNI's visibility limitation. The overview omits the type column to leave more room for host names.

### Fixed

- TLS domain detection now uses bounded TCP reassembly to recover ClientHello messages split across packets or TLS records, including reordered and retransmitted segments, and backfills traffic observed before name resolution.

### Removed

### Deprecated

### Security

## [0.7.1] - 2026-09-24

### Added

### Changed

- Relicensed the current development tree and future releases under GPL-3.0-only. Releases up to and including v0.7.0 remain under Apache-2.0.
- Omitted `--theme` now always selects Signal Deck. Removed `NO_COLOR`, `COLORTERM`, and `TERM`-based theme selection; `--theme auto` now resolves as an ordinary named custom theme and loads `auto.json` when present.

### Fixed

### Removed

### Deprecated

### Security

## [0.7.0] - 2026-09-18

### Added

- Configurable TUI themes with FlowLens Dark, Signal Deck, ANSI 16, and Mono built-ins; automatic terminal-capability selection; live switching in Settings; and custom JSON themes loaded by name or path with `--theme`.
- Experimental, unsigned, and unnotarized macOS `x86_64` and `aarch64` Release archives, built and checked on native GitHub-hosted runners. Full runtime and packet-capture behavior remains unvalidated.

### Changed

- Signal Deck is now the default theme for true-color, 256-color, and otherwise unclassified terminals. `NO_COLOR` and limited-color terminals still select Mono or ANSI 16.

### Fixed

- Process details now align Name/PID, Recv/Sent/Total, and Selected/Rank summary values into consistent columns.

### Removed

### Deprecated

### Security

## [0.6.1] - 2026-09-09

### Added

- Process-detail flow tables now split bidirectional traffic into inbound and outbound rows, ordered by transferred bytes, so endpoint direction is explicit.

### Changed

- Process-detail flow tables now adapt endpoint spacing to compact and wide terminals, and use higher-contrast port text for readability.
- Interface IP address popups now use a selectable, scrollable table with clearer IPv4/IPv6 grouping and bounded keyboard navigation.

### Fixed

- Process-detail scrolling now follows the rendered directional rows and clamps to the available range, including when traffic changes or a flow has only one direction.

### Removed

### Deprecated

### Security

## [0.6.0] - 2026-09-04

### Added

- Configurable ranking windows: cumulative totals, 5s, 10s, 30s, 60s, and 5m average throughput, selectable from the settings overlay or with `--rank-window`. The active window is shown in the TUI.
- Process details now include a scrollable TCP/UDP flow table showing endpoint pairs, protocol, and accumulated bytes for each retained 5-tuple. Use `--proc-flows` to set the per-process row limit.
- The interface selector now provides a scrollable popup for the selected interface's IPv4 and IPv6 addresses via `i`.

### Changed

- Packet capture now uses the pcap 2.5.0 batch `dispatch` reader by default, reducing per-packet read overhead on high-PPS interfaces. The per-packet `next_packet()` baseline remains selectable with `--read-mode next` for A/B comparison and rollback.
- Process, IP, and outbound-domain rankings can now use sliding-window average throughput while interface totals remain cumulative. Finite-window rankings also show their current coverage while warming up.
- Process detail layouts now group endpoint columns and adapt more clearly across compact and wide terminals.

### Fixed

- TCP domain detection now performs bounded retries after an initial payload lacks SNI or an HTTP `Host`, allowing later payloads to populate domain rankings without repeatedly parsing long-lived connections.
- Ranking tables reserve enough width for rate values such as `100.00 KB/s`, and finite-window domain views distinguish having no recent observations from having no cumulative observations.
- On Windows, local-address detection now supplements Npcap device metadata with the native adapter-address API. This prevents Tailscale file-transfer traffic on Red Hat VirtIO Ethernet adapters from being incorrectly treated as non-local and omitted from FlowLens totals.
- Process detail flow scrolling now resets when rows disappear, and opening the settings overlay preserves the current process detail state.

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
