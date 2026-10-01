# FlowLens

English | [简体中文](README_CN.md)

FlowLens is a command-line network traffic analyzer for resource-constrained Linux and Windows hosts. It shows interface traffic and provides best-effort process, IP, and outbound-domain attribution. Experimental macOS builds are also available.

![FlowLens traffic overview](assets/screen/screen-main.jpg)

*Traffic overview in the Signal Deck theme.*

## Highlights

- **At-a-glance traffic overview.** View interface totals, top processes, remote IPs, and outbound domains on one screen.
- **Visible TLS names.** ClientHello with ECH or legacy ESNI and visible SNI appears as `Public SNI`, separately from ordinary outbound domains. The visible name may differ from the actual target. JSON keeps ordinary names in `top_outbound_domains` and adds `top_public_sni`; each group has its own top-N limit.
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
| Linux `x86_64` | glibc `2.28` or newer and root or `CAP_NET_RAW`; older dynamic archives also need matching libpcap |
| Linux `aarch64` | glibc `2.28` or newer and root or `CAP_NET_RAW`; older dynamic archives also need matching libpcap |
| Windows `x86_64` | Windows with [Npcap Runtime](https://npcap.com/) installed |
| Windows `aarch64` | Windows on ARM with [Npcap Runtime](https://npcap.com/) installed; cross-built and binary-audited, but ARM64 real-hardware capture is unverified |
| macOS `x86_64` | Experimental, unsigned, and unnotarized archive; minimum macOS version and full runtime behavior are not validated |
| macOS `aarch64` | Experimental, unsigned, and unnotarized archive; minimum macOS version and full runtime behavior are not validated |

FlowLens supports Linux `x86_64`/`aarch64`, Windows `x86_64`/`aarch64`, and macOS `x86_64`/`aarch64`. Linux and Windows releases meet the minimum acceptance bar for core functionality and basic stability; this does not mean that every boundary condition has been exhaustively tested. macOS support is experimental and has not received the same level of runtime validation.

## Install

Linux `x86_64` and `aarch64` can use the installer script. The default command installs the latest stable Release into `/usr/local/bin`, with an installer manifest under `/usr/local/share/flowlens`. Linux system installation grants only `CAP_NET_RAW`, so ordinary users can start capture without sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/power4j/flowlens/main/install.sh | sudo bash
flowlens
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
/usr/local/bin/flowlens --version
/usr/local/bin/flowlens
# After successful startup, exit FlowLens, then run as the original user without sudo:
bash install.sh --user --uninstall
# Reopen your shell, then confirm that this resolves to /usr/local/bin/flowlens:
command -v flowlens
```

System installation leaves an old `~/.local/bin/flowlens` in place and warns that it may take precedence in your shell. The cleanup command above applies only to installer-managed copies; review and remove unmanaged copies manually after verifying the system installation.

The installer requires Bash 3.2+, `curl`, `tar`, `ldd`, and `sha256sum` or `shasum`. New Linux distribution builds embed libpcap; already-published dynamic archives still need the matching runtime. After verifying the download and completing install preflight, default system installation prepares missing libpcap runtime packages only when the binary requires them on Debian/Ubuntu (`apt-get`, selecting `libpcap0.8t64` when available or legacy `libpcap0.8`) and RPM families (`dnf` or `yum`, installing `libpcap`). It does not install development packages. Package operations are noninteractive, require root or working `sudo -n`, and do not consume piped script input. The installer supports Linux only and rejects macOS. Windows and experimental macOS builds use the archives below.

Download the archive for the target operating system and CPU architecture from the [GitHub Releases](https://github.com/power4j/flowlens/releases/latest) page and extract the single executable inside it.

### Linux

#### Installer runtime and capture permissions

Default Linux system installs and explicit `--system` installs grant only `cap_net_raw+ep`, never `CAP_NET_ADMIN`. After download verification and install preflight, system installation prepares the missing `setcap` tool (`libcap2-bin` on Debian/Ubuntu, `libcap` on RPM families). Start capture as an ordinary user:

```bash
flowlens
# If another copy is selected:
/usr/local/bin/flowlens
```

To upgrade or reinstall, rerun the same default command. Each replacement binary receives `CAP_NET_RAW` again; no extra `--setcap` flag is needed:

```bash
sudo bash install.sh
flowlens
```

To retain sudo-only capture, pass `--no-setcap` on each install or upgrade:

```bash
sudo bash install.sh --no-setcap
sudo flowlens
# If sudo cannot find it, or another copy is selected:
sudo /usr/local/bin/flowlens
```

`FLOWLENS_SETCAP=true` explicitly enables the capability and `FLOWLENS_SETCAP=false` disables it. Command-line `--setcap` or `--no-setcap` takes precedence over the environment; combining both flags is an error. User/custom installs grant no capability by default. Explicit `--setcap` remains available for those scopes when the tool and privileges have been prepared manually.

`--user` and custom-directory installs never change system packages, even when run as root. Missing dependencies stop installation with manual setup guidance. `--dry-run` and `--uninstall` never change packages; dry-run does not grant capabilities. Unsupported distributions or package managers require manual dependency setup. Package setup failures stop binary publication; packages already installed are not rolled back.

Linux distribution builds use a pinned, statically linked libpcap and do not require a system libpcap package. glibc remains dynamic with the `2.28` baseline. Local source builds and older releases may still link libpcap dynamically. Readiness is checked against the verified binary's loader requirements, not merely the installed package name. Some RPM systems provide `libpcap.so.1` but the release artifact may require `libpcap.so.0.8`; installation stops if that requirement remains unresolved. Do not create compatibility symlinks between different SONAMEs.

#### Manual Linux archives

For a manually extracted archive, inspect it first:

```bash
ldd ./flowlens
```

Only older/dynamic archives showing a missing libpcap dependency need a matching system runtime:

```bash
# Debian/Ubuntu: refresh metadata and inspect available runtime packages
sudo apt-get update
apt-cache policy libpcap0.8t64 libpcap0.8
# Modern Debian/Ubuntu, when libpcap0.8t64 has a candidate:
sudo apt-get install -y libpcap0.8t64
# Older Debian/Ubuntu, instead:
sudo apt-get install -y libpcap0.8
# RPM families (use yum in place of dnf if needed):
sudo dnf install -y libpcap
```

From the extraction directory, check dependencies and run capture as root:

```bash
ldd ./flowlens
sudo ./flowlens
```

Alternatively, install the `setcap` tool manually (`libcap2-bin` on Debian/Ubuntu or `libcap` on RPM families), then opt into the capability:

```bash
sudo setcap cap_net_raw+ep ./flowlens
./flowlens
```

### Windows

Install [Npcap](https://npcap.com/) before starting FlowLens. The Windows archive contains only `flowlens.exe`; it does not include Npcap Runtime.

FlowLens checks for `wpcap.dll` at startup and reports a missing Npcap Runtime before opening a capture device.

### macOS (experimental)

Download `flowlens-vX.Y.Z-macos-x86_64.tar.gz` for an Intel Mac or `flowlens-vX.Y.Z-macos-aarch64.tar.gz` for Apple Silicon from [GitHub Releases](https://github.com/power4j/flowlens/releases/latest), then extract the `flowlens` binary. These archives are not supported by `install.sh`.

The macOS binary is unsigned and unnotarized, so macOS may block or warn about it. Review the downloaded archive and follow the security policy for the target Mac; FlowLens does not currently provide a signed build.

Both architectures are built on native GitHub-hosted macOS 15 runners with explicit deployment targets matching Rust 1.96.0 defaults (`10.12` for Intel, `11.0` for Apple Silicon). They link the system libpcap, not Homebrew. CI audits architecture, the deployment target, and system-only dynamic library paths. Test-build and Release workflows also exercise root loopback capture. This is a build baseline, not a claim of compatibility with older macOS versions. Non-root capture permissions, other interfaces, process attribution, long-running stability, and performance remain incompletely validated.

## Usage

These examples use a manually extracted `./flowlens` binary. For a default Linux system script installation, replace `./flowlens` with `flowlens`; use `sudo flowlens` after `--no-setcap`, or the absolute user-install command shown above.

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

Releases up to and including v0.7.0 remain licensed under the Apache License 2.0 included with those releases. Individual contribution attribution remains in the Git history. Linux archives built by the static-libpcap workflow append the bundled libpcap license and copyright notices to the archive's `LICENSE`.

For development and source-build instructions, see [`docs/development.md`](docs/development.md).
For offline TLS domain and resource evaluations, see [`docs/tls-evaluation.md`](docs/tls-evaluation.md).
