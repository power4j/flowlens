# Changelog

All notable changes to Delray are recorded in this file.

## [Unreleased]

### Added

- TUI settings overlay can toggle diagnostics at runtime from the settings UI; each enable writes to a fresh timestamped log file and the overlay shows the current file name.

### Changed

- Settings overlay uses a unified select-then-change interaction: `j/k`/arrows select an item, `h/l`/arrows change its value, with a full-row highlight and a `> ` selection marker that keeps the selected row identifiable on 16-color/monochrome terminals; the `d` shortcut and `Enter` value cycling were removed.

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
