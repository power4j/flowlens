# Development

This document covers source development and CI reproduction. User installation and runtime usage are documented in [`README.md`](../README.md) and [`README_CN.md`](../README_CN.md).

## Toolchain

- Rust toolchain: see [`rust-toolchain.toml`](../rust-toolchain.toml) (`edition = "2024"`).
- Linux release builds: Zig `0.16.0` and `cargo-zigbuild` `0.23.0`, targeting `x86_64` and `aarch64` with glibc `2.28`.
- Version bumps: `cargo-edit` `0.13.13`.
- Linux development checks: libpcap development headers and libraries (not required by the release helper).
- Windows: MSVC build tools and Npcap SDK `1.16`.
- macOS: native `x86_64` or Apple Silicon host with the system libpcap.

Npcap SDK is a Windows build dependency only. The SDK provides `wpcap.lib` and `Packet.lib`; Npcap Runtime remains an end-user prerequisite and is not bundled by FlowLens.

## Local checks

```bash
cargo fmt --all -- --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
```

## Optional static Linux distribution build

**Normal development needs no Zig or static libpcap build.** Continue to use the local checks above with the system libpcap development package. Static linking is an explicit release-helper invocation, used by CI for Linux distribution artifacts; it is not a Cargo default or feature.

To reproduce the optional CI build, install Zig, `cargo-zigbuild`, pkg-config, make, flex, bison, curl, Python 3 and xz. Run the release helper from the repository root:

```bash
bash scripts/build-linux-release.sh x86_64-unknown-linux-gnu.2.28
bash scripts/build-linux-release.sh aarch64-unknown-linux-gnu.2.28
```

The helper checksum-verifies libpcap 1.10.7, builds its static archive with Zig's glibc `2.28` target, and invokes `cargo zigbuild --release --locked`. It does not install system libraries or require a target-distribution libpcap development package, including for cross-builds. Ordinary Linux interfaces are enabled; optional D-Bus, RDMA, Bluetooth, USB, netmap, vendor and remote capture backends are disabled to avoid external runtime dependencies.

Outputs are `target/<architecture>-unknown-linux-gnu/release/flowlens` and `LICENSE`. The packaged `LICENSE` retains the project license and appends libpcap notices. Bundled libpcap updates require rebuilding FlowLens; update the pinned source version and checksum together.

### Native dependency cache

The Build Test and Release workflows use a separate exact-key cache for `target/native/<target>/install`, including `libpcap.a`, headers, pkg-config metadata, and upstream license. The key includes the target/glibc baseline, Zig version, source version/checksum and configure flags (via the helper hash), OS identity and flex/bison/make versions. No fallback `restore-keys` are used for this cache. Rust target caches exclude this native installation.

On a hit, the helper verifies its build key and file checksums, checks the archive, and relocates pkg-config paths to the current checkout. Missing, incompatible or damaged contents cause a rebuild. On a miss, it downloads the checksum-pinned source and compiles it once. The `pcap` Rust package is cleaned on every static build because its rlib embeds the native archive; other Rust dependencies can remain cached. Final ELF and real capture checks run even on cache hits. This cache is a build optimization, not an artifact trust boundary.

Verify the ELF contract before packaging:

```bash
bash scripts/verify-linux-binary.sh target/x86_64-unknown-linux-gnu/release/flowlens x86_64
bash scripts/verify-linux-binary.sh target/aarch64-unknown-linux-gnu/release/flowlens aarch64
```

Distribution binaries must have no dynamic libpcap dependency or runtime search path, use dynamic glibc with a maximum symbol version of `2.28`, and match their architecture and ELF interpreter. Plain `cargo build --release` is only for local development or same-host testing; ordinary source builds may still dynamically link the system libpcap.

## Windows build

Set `LIBPCAP_LIBDIR` to the target architecture's `Lib` directory from Npcap SDK `1.16`:

```powershell
$env:LIBPCAP_LIBDIR = 'path-to-npcap-sdk\Lib\x64'
$env:RUSTFLAGS = '-C target-feature=+crt-static'

cargo test --locked
cargo build --release --locked
```

The release binary is `target\release\flowlens.exe`. The Windows Release workflow verifies that the executable does not depend on the dynamic VC Runtime and still declares the external `wpcap.dll` dependency.

## CI boundaries

The CI checks run on Linux, Windows, and native macOS runners for pull requests and pushes to `main`:

- Rust formatting;
- `cargo check --locked`;
- `cargo test --locked`;
- Clippy with warnings denied;
- macOS `x86_64` and `arm64` release builds;
- macOS `flowlens --help` and `refcap --help` smoke tests.

The macOS jobs use `macos-15-intel` for `x86_64` (`x86_64-apple-darwin`) and `macos-15` for `arm64` (`aarch64-apple-darwin`). They build and test on native runners rather than cross-compiling. The jobs explicitly use the system `libpcap` with `LIBPCAP_LIBDIR=/usr/lib` and explicit `MACOSX_DEPLOYMENT_TARGET` values matching Rust 1.96.0 defaults (`10.12` for Intel, `11.0` for Apple Silicon); Homebrew libpcap is not required by CI. Binary audits reject non-system library paths and verify the deployment target. The workflow prints the SDK, `libpcap`, and binary linkage information to make runner-specific dependency failures diagnosable.

The source-validation macOS CI jobs do not run real network capture, long-running traffic tests, or performance benchmarks. The `Build Test` workflow packages and uploads unsigned macOS trial artifacts separately from the validation jobs. Signing, notarization, installer integration, minimum-version compatibility, and complete runtime validation remain separate follow-up work because they depend on credentials, host permissions, adapters, traffic generators, representative systems, and system load.

## On-demand test builds

The `Build Test` workflow creates distribution-shaped binaries for manual testing without changing the Cargo version, creating a tag, or creating a Release. Select a branch or commit and choose `all`, `linux`, `linux-macos`, `windows`, or `macos` in the GitHub Actions page. Artifacts are retained for 14 days and include a short commit identifier in their names.

The `macos` option creates native `aarch64` and `x86_64` archives from `macos-15` and `macos-15-intel` runners. These archives contain the unsigned `flowlens` binary and `LICENSE` and are for trial validation, not formal macOS release support.

The workflow can also be started with GitHub CLI:

```bash
gh workflow run build-test.yml --ref <branch> -f platform=all -f static_libpcap=true
```

The `static_libpcap` boolean controls **Linux only**, defaults to `true`, and leaves macOS/Windows unchanged. Set it to `false` to compare a dynamic system-libpcap build; this mode installs `libpcap-dev`, audits dynamic linkage, and runs loopback capture on the build runner rather than the no-libpcap distribution matrix. These dynamic trial artifacts still need the matching system libpcap at runtime and are not the formal Linux release policy.

```bash
gh workflow run build-test.yml --ref <branch> -f platform=linux -f static_libpcap=false
```

By default, Linux artifacts use static libpcap and the dynamic glibc `2.28` baseline for both `x86_64` and `aarch64`. The same binary is tested without system libpcap in Debian 12, Ubuntu 24.04, Fedora 43 and Rocky Linux 8 containers, including root capture, expected non-root denial, and non-root capture with only `CAP_NET_RAW`. Select `linux-macos` to validate both Linux architectures and both macOS architectures without rebuilding Windows. Windows artifacts for `x86_64` and `aarch64` use static VC Runtime linking and still require Npcap Runtime on the test machine.

## Release development

The Release workflow uses `cargo-edit` for `major`, `minor`, and `patch` bumps. Before pushing the version commit and annotated tag, it builds and validates Linux, Windows, and macOS artifacts for `x86_64` and `aarch64`. A failed macOS build or binary check blocks the release transaction. The maintainer checklist is in [`release-checklist.md`](release-checklist.md).

The macOS Release archives contain the unsigned, unnotarized `flowlens` binary and `LICENSE`. The workflow verifies the Mach-O architecture, system-only library linkage, CLI help, embedded version, and two-file archive shape. Test-build and Release workflows set explicit `MACOSX_DEPLOYMENT_TARGET` values matching Rust 1.96.0 defaults (`10.12` for Intel, `11.0` for Apple Silicon) and run root loopback capture on native macOS 15 runners; this does not establish support for older systems or complete capture/attribution behavior. Publishing these archives makes experimental builds available for manual download; it does not make macOS a supported platform or enable macOS in `install.sh`.

After a Release is published, the manually dispatched `release-smoke.yml` workflow downloads the selected macOS architecture, verifies it against `SHA256SUMS`, checks the archive and Mach-O metadata, and runs `flowlens --help` and `flowlens --version` on the matching native runner.
