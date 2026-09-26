# FlowLens

English | [简体中文](README_CN.md)

FlowLens is a command-line network traffic analyzer for resource-constrained Linux and Windows hosts. It shows interface traffic and provides best-effort process, IP, and outbound-domain attribution. Experimental macOS builds are also available.

![FlowLens traffic overview](assets/screen/screen-main.jpg)

*Traffic overview in the Signal Deck theme.*

## Highlights

- **At-a-glance traffic overview.** View interface totals, top processes, remote IPs, and outbound domains on one screen.
- **Explainable process attribution.** Distinguish exclusive, shared, system, and unattributed traffic with a conservation summary.
- **Process drill-down.** Inspect the PID, executable path, last-seen time, attribution breakdown, and ranked bidirectional TCP/UDP endpoint flows.
- **Configurable ranking windows.** Switch between cumulative totals and 5-second, 10-second, 30-second, 60-second, or 5-minute average throughput, with warm-up coverage for finite windows.
- **Outbound-domain visibility.** Identify domains from TLS ClientHello SNI and plaintext HTTP/1.x `Host` headers on locally initiated TCP connections.
- **Interactive interface selection.** Switch capture interfaces in the TUI and inspect their IPv4 and IPv6 addresses.
- **Multiple output modes.** Use the interactive TUI, plain-text snapshots, JSON Lines streams, formatted JSON files, or separate JSONL diagnostics.
- **Cross-platform and themeable.** Run supported releases on Linux and Windows, try experimental macOS builds on `x86_64` and `aarch64`, and choose from four built-in themes or custom JSON themes.

## Process details

Drill into a process to review its identity, attribution composition, traffic totals, and ranked endpoint flows.

![FlowLens process details](assets/screen/screen-proc-detail.jpg)

## Built-in themes

FlowLens includes four themes for true-color, ANSI 16-color, and monochrome terminals. Signal Deck is the default when `--theme` is omitted. See [TUI themes](docs/theme.md) for selection behavior and custom JSON themes.

<table>
  <tr>
    <th width="50%">FlowLens Dark</th>
    <th width="50%">Signal Deck</th>
  </tr>
  <tr>
    <td><img src="assets/screen/theme-dark.jpg" alt="FlowLens Dark theme"></td>
    <td><img src="assets/screen/theme-signal-deck.jpg" alt="Signal Deck theme"></td>
  </tr>
  <tr>
    <th>ANSI 16</th>
    <th>Mono</th>
  </tr>
  <tr>
    <td><img src="assets/screen/theme-ansi16.jpg" alt="ANSI 16 theme"></td>
    <td><img src="assets/screen/theme-mono.jpg" alt="Mono theme"></td>
  </tr>
</table>

## Supported platforms

| Platform | Availability and runtime requirements |
| --- | --- |
| Linux `x86_64` | glibc `2.28` or newer, libpcap, and root or `CAP_NET_RAW` |
| Linux `aarch64` | glibc `2.28` or newer, libpcap, and root or `CAP_NET_RAW` |
| Windows `x86_64` | Windows with [Npcap Runtime](https://npcap.com/) installed |
| Windows `aarch64` | Windows on ARM with [Npcap Runtime](https://npcap.com/) installed |
| macOS `x86_64` | Experimental, unsigned, and unnotarized archive; minimum macOS version and full runtime behavior are not validated |
| macOS `aarch64` | Experimental, unsigned, and unnotarized archive; minimum macOS version and full runtime behavior are not validated |

FlowLens supports Linux `x86_64`/`aarch64`, Windows `x86_64`/`aarch64`, and macOS `x86_64`/`aarch64`. Linux and Windows releases meet the minimum acceptance bar for core functionality and basic stability; this does not mean that every boundary condition has been exhaustively tested. macOS support is experimental and has not received the same level of runtime validation.

## Install

Linux `x86_64` and `aarch64` can use the installer script. The default command installs the latest stable Release into `/usr/local/bin`, with an installer manifest under `/usr/local/share/flowlens`:

```bash
curl -fsSL https://raw.githubusercontent.com/power4j/flowlens/main/install.sh | sudo bash
```

Pin a reviewed script and an exact version:

```bash
curl -fsSL https://raw.githubusercontent.com/power4j/flowlens/main/install.sh -o install.sh
less install.sh
sudo bash install.sh --version v0.3.0
```

Pipe additional installer arguments with `sudo bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/power4j/flowlens/main/install.sh | sudo bash -s -- --version v0.3.0
```

Use `--user` without sudo for the previous `~/.local/bin` installation behavior, including Bash or Zsh PATH setup when needed:

```bash
bash install.sh --user
sudo "$HOME/.local/bin/flowlens"
```

Updating your shell PATH does not change sudo's command search path; use the absolute path above for a user installation. `--system` explicitly selects the default system scope and cannot be combined with `--user` or a custom directory. A standalone `--install-dir DIR` or `FLOWLENS_INSTALL_DIR` keeps the custom directory behavior and user manifest location (`~/.local/share/flowlens`); the command-line directory takes precedence over the environment variable. The installer only attempts noninteractive `sudo -n` internally. If it cannot write the system directories, it fails with directions to run the script with sudo or choose `--user`; it does not prompt for a password or fall back to a user installation.

Uninstall an installer-managed system copy with `sudo bash install.sh --uninstall`. To uninstall a user copy, run `bash install.sh --user --uninstall` as the original user, without sudo. Custom installations require the same directory option or environment variable used to install them.

To migrate an existing user installation, download the new script and verify the system copy before removing the old one:

```bash
curl -fsSL https://raw.githubusercontent.com/power4j/flowlens/main/install.sh -o install.sh
sudo bash install.sh
sudo /usr/local/bin/flowlens --version
sudo /usr/local/bin/flowlens
# After successful startup, exit FlowLens, then run as the original user without sudo:
bash install.sh --user --uninstall
# Reopen your shell, then confirm that this resolves to /usr/local/bin/flowlens:
command -v flowlens
```

System installation leaves an old `~/.local/bin/flowlens` in place and warns that it may take precedence in your shell. The cleanup command above applies only to installer-managed copies; review and remove unmanaged copies manually after verifying the system installation.

The installer requires Bash 3.2+, `curl`, `tar`, and `sha256sum` or `shasum`. It does not install `libpcap`. The installer supports Linux only and rejects macOS. Windows and experimental macOS builds use the archives below.

Download the archive for the target operating system and CPU architecture from the [GitHub Releases](https://github.com/power4j/flowlens/releases/latest) page and extract the single executable inside it.

### Linux

Install the libpcap runtime if it is not already available:

```bash
# Debian or Ubuntu
sudo apt install libpcap0.8

# RHEL-compatible distributions
sudo dnf install libpcap
```

For a system installation, run FlowLens as root, or grant the executable `CAP_NET_RAW`:

```bash
sudo flowlens
# If sudo cannot find it, or another copy is selected:
sudo /usr/local/bin/flowlens
# or
sudo setcap cap_net_raw+ep /usr/local/bin/flowlens
/usr/local/bin/flowlens
```

For a manually extracted archive, use `sudo ./flowlens` from the extraction directory.

### Windows

Install [Npcap](https://npcap.com/) before starting FlowLens. The Windows archive contains only `flowlens.exe`; it does not include Npcap Runtime.

FlowLens checks for `wpcap.dll` at startup and reports a missing Npcap Runtime before opening a capture device.

### macOS (experimental)

Download `flowlens-vX.Y.Z-macos-x86_64.tar.gz` for an Intel Mac or `flowlens-vX.Y.Z-macos-aarch64.tar.gz` for Apple Silicon from [GitHub Releases](https://github.com/power4j/flowlens/releases/latest), then extract the `flowlens` binary. These archives are not supported by `install.sh`.

The macOS binary is unsigned and unnotarized, so macOS may block or warn about it. Review the downloaded archive and follow the security policy for the target Mac; FlowLens does not currently provide a signed build.

Both architectures are built on native GitHub-hosted macOS runners and checked with `file`, `otool`, `flowlens --help`, and `flowlens --version`. A complete macOS runtime validation environment is not available, so real packet capture, permissions, interface behavior, process attribution, long-running stability, performance, and the minimum supported macOS version have not been fully tested.

## Usage

These examples use a manually extracted `./flowlens` binary. For a Linux script installation, replace `./flowlens` with `sudo flowlens`, or the absolute user-install command shown above.

Start the foreground TUI without selecting an interface:

```bash
./flowlens
```

Start directly on an interface:

```bash
./flowlens eth0
```

Choose a built-in TUI theme, load a named user theme, or load an explicit JSON theme file:

```bash
./flowlens --theme ansi16
./flowlens --theme ocean
./flowlens eth0 --theme ./my-theme.json
```

`--theme` is available only in the foreground interactive TUI. See [TUI themes](docs/theme.md) for default and explicit selection, and JSON theme authoring.

Write periodic plain-text snapshots to a file:

```bash
./flowlens eth0 --output /tmp/stats.txt
```

Stream JSON Lines to standard output:

```bash
./flowlens eth0 --format json
```

Write JSON snapshots to a file:

```bash
./flowlens eth0 --format json --output /tmp/stats.json
```

Limit each top-N list:

```bash
./flowlens eth0 --top-n 3
```

Write process-attribution diagnostics as JSONL to the default `.log` file:

```bash
./flowlens eth0 --format json --diagnostics
```

Specify the diagnostics output file:

```bash
./flowlens eth0 --diagnostics --diagnostics-output /tmp/flowlens-diagnostics.jsonl
```

In TUI mode, diagnostics are written to this file and never to the terminal.

Use `flowlens --help` for the complete option list.

## Known limitations

Process attribution is best-effort. Permissions, network namespaces, containers, WSL proxy paths, port reuse, and process-table timing can leave traffic under `<unattributed traffic>`.

Outbound-domain statistics cover TCP TLS ClientHello SNI and plaintext HTTP/1.x `Host` headers. They do not cover QUIC/HTTP3, inbound-initiated connections, encrypted SNI, or payloads that cannot be parsed.

Loopback capture can show the same transfer as both inbound and outbound traffic. This reflects the operating system's capture semantics and does not mean that the public transfer happened twice.

The process attribution and capture behavior may differ between Linux, Windows, and macOS. macOS builds remain experimental under the validation limits described above. The release notes document platform-specific prerequisites and known limitations for each version.

## License

The current development tree and all FlowLens releases after v0.7.0 are licensed under the [GNU General Public License version 3 only](LICENSE) (`GPL-3.0-only`).

Copyright (C) 2026 power4j. Contact: power4j@outlook.com.

Releases up to and including v0.7.0 remain licensed under the Apache License 2.0 included with those releases. Individual contribution attribution remains in the Git history.

For development and source-build instructions, see [`docs/development.md`](docs/development.md).
