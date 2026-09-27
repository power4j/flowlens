# Offline TLS evaluation

Two source tools exercise outbound-domain handling without network access or
packet capture. They are development evaluations, not release benchmarks.
Both wrappers require PowerShell 7.6 or newer, Rust (default toolchain `1.96.0`), and the
platform's Rust/libpcap build dependencies. On Windows, install the MSVC tools,
Npcap SDK, and Npcap Runtime; on Linux, install libpcap development libraries.
See [development](development.md) for build prerequisites. The wrappers were
verified on Windows x86-64. Linux and macOS execution is designed to work but
has not been verified here.

Run either script by absolute path from any working directory. Supply a new,
explicit output directory; an existing path is rejected before a build or run.
For example, in PowerShell:

```powershell
& 'D:\path\to\flowlens\scripts\tls-eval-runtime.ps1' -OutputDirectory 'D:\results\tls runtime' -Profile smoke
& 'D:\path\to\flowlens\scripts\tls-eval-stress.ps1' -OutputDirectory 'D:\results\tls stress'
```

The scripts locate the repository through their own paths and build the current
source with Cargo. Use `-Toolchain 1.96.0` to select an installed toolchain;
`CARGO_TARGET_DIR` is honored. They take the example executable path from
Cargo's build messages, so the target directory may contain spaces. A failed
build, example run, or ledger comparison ends with a nonzero exit.

`tls-eval-runtime.ps1` paces synthetic ClientHello traffic through the parser,
FlowTable, and Stats. Its default `smoke` profile lasts about four seconds;
`windows` and `acceptance` are longer profiles. `-Seconds` overrides the five
phase durations (idle, fixed, growth, reuse, cooldown), for example
`-Seconds 0,1,1,1,1`. `checkpoints.jsonl` compares actual domains and byte
totals with an input ledger at each checkpoint, and records FlowTable resource
usage and production snapshot cost. `process-samples.jsonl` contains one-second
OS memory/CPU samples; `run.json` includes the executable hash, exit status,
and timing scope. Compare runs with the same rates, phase durations, snapshot
settings, toolchain, and host. OS samples can miss brief memory peaks.

`tls-eval-stress.ps1` generates nine legal offline PCAP suites and an
independent expected-state ledger, then runs each suite three times by default.
Its `results.json` records the comparison of every frame, final domain/byte
totals, state conservation, and resource limits. `corpus/contract.json`
explains the limits and fixture construction. `-Repeats 1` can shorten a local
check. This oracle assumes the 24-byte `Segment` reservation layout used by a
64-bit process; the wrapper rejects 32-bit PowerShell. Compare `results.json`
across revisions for correctness and the reported raw, metadata, and active
peaks, while keeping the fixture contract and architecture consistent.

The stress budget assumes a native 64-bit Rust build on the same host as
PowerShell; it is not a cross-compilation test.

Neither script requires old frozen reports, a browser, SSH, a network adapter,
or a privileged capture session. The example fixtures use documentation IP
addresses and synthetic domain names; they are not host configuration.
