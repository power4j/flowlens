# Development

This document covers source development and CI reproduction. User installation and runtime usage are documented in [`README.md`](../README.md) and [`README_CN.md`](../README_CN.md).

## Toolchain

- Rust toolchain: see [`rust-toolchain.toml`](../rust-toolchain.toml) (`edition = "2024"`).
- Linux release builds: Zig `0.16.0` and `cargo-zigbuild` `0.23.0`, targeting `x86_64` and `aarch64` with glibc `2.28`.
- Version bumps: `cargo-edit` `0.13.13`.
- Linux: libpcap development headers and libraries.
- Windows: MSVC build tools and Npcap SDK `1.16`.

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

The macOS jobs do not upload artifacts and do not run real network capture, long-running traffic tests, or performance benchmarks. Artifact packaging, signing, notarization, installer integration, and Release publication remain separate follow-up work. Those checks are manual release-readiness activities because they depend on host permissions, adapters, traffic generators, Npcap behavior, and system load.

## On-demand test builds

The `Build Test` workflow creates distribution-shaped binaries for manual testing without changing the Cargo version, creating a tag, or creating a Release. Select a branch or commit and choose `all`, `linux`, or `windows` in the GitHub Actions page. Artifacts are retained for 14 days and include a short commit identifier in their names.

The current `Build Test` workflow creates Linux and Windows artifacts only. macOS validation is currently limited to the dedicated build/test surface in `ci.yml`; adding macOS trial artifacts is a separate follow-up.

The workflow can also be started with GitHub CLI:

```bash
gh workflow run build-test.yml --ref <branch> -f platform=all
```

Linux artifacts use the glibc `2.28` baseline for both `x86_64` and `aarch64`. Windows artifacts for `x86_64` and `aarch64` use static VC Runtime linking and still require Npcap Runtime on the test machine.

## Release development

The Release workflow currently publishes Linux and Windows artifacts only; macOS Release packaging is intentionally out of scope for the initial CI feasibility phase.

The Release workflow uses `cargo-edit` for `major`, `minor`, and `patch` bumps. It builds and validates Linux `x86_64`/`aarch64` and Windows `x86_64`/`aarch64` artifacts before pushing the version commit and annotated tag. The maintainer checklist is in [`release-checklist.md`](release-checklist.md).

## macOS CI rollout

The macOS jobs should initially be observed without adding them to branch protection as required checks. After 3–5 successful runs across pull requests and pushes to `main`, confirm that runner availability, system `libpcap`, native tests, and binary smoke tests are stable. Then add both `validate-macos-arm64` and `validate-macos-x86_64` to the repository branch protection rules as required checks.

This rollout only establishes that GitHub can build and test the two native macOS targets. It does not claim runtime support, packet-capture permissions, a minimum supported macOS version, signed distribution, or installer compatibility.
