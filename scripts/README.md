# Maintained developer tools

Keep repeatable current-source build, validation and maintenance tools here.
One-off probes, copied binaries and captured reports belong in ignored `tmp/`,
not in this directory. Regression tests belong in `tests/`.

## Release and CI tools

| Tool | Long-term purpose |
| --- | --- |
| `build-linux-release.sh` | Optional static-libpcap distribution build and exact native cache; used by Build Test and Release. |
| `verify-linux-binary.sh` | Check architecture, interpreter, glibc baseline and expected libpcap linkage before packaging. |
| `verify-macos-binary.sh` | Check architecture, deployment metadata and system-only dylib linkage. |
| `smoke-capture.py` | Generate local UDP traffic and assert capture success or expected permission denial; shared by Linux/macOS workflows. |
| `smoke-linux-release.sh` | Check release capture without system libpcap, including unprivileged denial and CAP_NET_RAW-only capture in disposable containers. |

See [development](../docs/development.md) for build commands. Smoke tools require
an explicitly prepared test environment; they do not provision a user's host.

## Manual regression and diagnostic tools

| Tool | Long-term purpose |
| --- | --- |
| `check-tui-latency.sh` | Linux PTY page-transition latency regression, with configurable cycles/thresholds and default loopback network-namespace isolation. Requires Perl, util-linux and namespace support; update its keys/rendered-label checks when the TUI changes. |
| `verify-capture.ps1` | Windows adapter/refcap/FlowLens capture-parity diagnostics with real traffic; see the [capture guide](../docs/research/capture-parity-verification.md). Not a unit test or a harmless host-independent smoke command. |
| `tls-eval-runtime.ps1` | Offline current-source TLS/domain accounting and resource evaluation against a generated ledger. |
| `tls-eval-stress.ps1` + `tls-eval-stress.cs` | Repeatable offline PCAP stress suites with an independent expected-state oracle. Retain the wrapper and generator together. |

The [TLS evaluation contract](../docs/tls-evaluation.md) states synthetic-traffic,
architecture and memory-layout limitations. These tools are not release benchmarks;
changes to the production state contract require reviewing the stress oracle too.

The capture tool's host-independent regression test now lives in `tests/capture`
and runs in Windows CI. From the repository root:

```powershell
pwsh -NoProfile -File tests/capture/verify-capture.Tests.ps1
```
