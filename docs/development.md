# Development

This document covers source development and CI reproduction. User installation and runtime usage are documented in [`README.md`](../README.md) and [`README_CN.md`](../README_CN.md).

## Toolchain

- Rust toolchain: see [`rust-toolchain.toml`](../rust-toolchain.toml) (`edition = "2024"`).
- Linux release builds: Zig `0.16.0` and `cargo-zigbuild` `0.23.0`, targeting `x86_64` and `aarch64` with glibc `2.28`.
- Version bumps: `cargo-edit` `0.13.13`.
- Linux: libpcap development headers and libraries.
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

## Linux distribution build

Install Zig, `cargo-zigbuild`, and the libpcap development package first. The distribution target uses the glibc `2.28` baseline:

```bash
cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.28
cargo zigbuild --release --locked --target aarch64-unknown-linux-gnu.2.28
```

For an `aarch64` cross-build on Ubuntu, enable the foreign architecture and install its libpcap package, then point pkg-config at the target directory:

```bash
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install --yes libpcap-dev:amd64 libpcap-dev:arm64
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig
```

The output binary is:

```text
target/<target-architecture>-unknown-linux-gnu/release/flowlens
```

Check the ELF dependencies before treating the binary as a distribution artifact:

```bash
readelf -d target/<target-architecture>-unknown-linux-gnu/release/flowlens
readelf --version-info target/<target-architecture>-unknown-linux-gnu/release/flowlens
```

The binary may depend on the target system's glibc and libpcap. Static linking is used for Rust code and other dependencies where it is appropriate; glibc and libpcap remain explicit Linux runtime prerequisites.

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

The macOS jobs use `macos-15-intel` for `x86_64` (`x86_64-apple-darwin`) and `macos-15` for `arm64` (`aarch64-apple-darwin`). They build and test on native runners rather than cross-compiling. The jobs use the system `libpcap`; Homebrew is not required by CI. The workflow prints the SDK, `libpcap`, and binary linkage information to make runner-specific dependency failures diagnosable.

The macOS CI jobs do not run real network capture, long-running traffic tests, or performance benchmarks. The `Build Test` workflow packages and uploads unsigned macOS trial artifacts separately from the validation jobs. Signing, notarization, installer integration, minimum-version compatibility, and complete runtime validation remain separate follow-up work because they depend on credentials, host permissions, adapters, traffic generators, representative systems, and system load.

## On-demand test builds

The `Build Test` workflow creates distribution-shaped binaries for manual testing without changing the Cargo version, creating a tag, or creating a Release. Select a branch or commit and choose `all`, `linux`, `windows`, or `macos` in the GitHub Actions page. Artifacts are retained for 14 days and include a short commit identifier in their names.

The `macos` option creates native `aarch64` and `x86_64` archives from `macos-15` and `macos-15-intel` runners. These archives contain only the unsigned `flowlens` binary and are for trial validation, not formal macOS release support.

The workflow can also be started with GitHub CLI:

```bash
gh workflow run build-test.yml --ref <branch> -f platform=all
```

Linux artifacts use the glibc `2.28` baseline for both `x86_64` and `aarch64`. Windows artifacts for `x86_64` and `aarch64` use static VC Runtime linking and still require Npcap Runtime on the test machine.

## Release development

The Release workflow uses `cargo-edit` for `major`, `minor`, and `patch` bumps. Before pushing the version commit and annotated tag, it builds and validates Linux, Windows, and macOS artifacts for `x86_64` and `aarch64`. A failed macOS build or binary check blocks the release transaction. The maintainer checklist is in [`release-checklist.md`](release-checklist.md).

The macOS Release archives contain only the unsigned, unnotarized `flowlens` binary. The workflow verifies the Mach-O architecture, system libpcap linkage, CLI help, embedded version, and single-file archive shape. It does not set `MACOSX_DEPLOYMENT_TARGET`, claim a minimum supported macOS version, or run real packet capture. Publishing these archives makes experimental builds available for manual download; it does not make macOS a supported platform or enable macOS in `install.sh`.

After a Release is published, the manually dispatched `release-smoke.yml` workflow downloads the selected macOS architecture, verifies it against `SHA256SUMS`, checks the archive and Mach-O metadata, and runs `flowlens --help` and `flowlens --version` on the matching native runner.
