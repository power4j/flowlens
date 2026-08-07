# Development

This document covers source development and CI reproduction. User installation and runtime usage are documented in [`README.md`](../README.md) and [`README_CN.md`](../README_CN.md).

## Toolchain

- Rust `1.96.0` (`edition = "2024"` and the current stable application baseline).
- Linux release builds: Zig `0.16.0` and `cargo-zigbuild` `0.23.0`.
- Version bumps: `cargo-edit` `0.13.13`.
- Linux: libpcap development headers and libraries.
- Windows: MSVC build tools and Npcap SDK `1.16`.

Npcap SDK is a Windows build dependency only. The SDK provides `wpcap.lib` and `Packet.lib`; Npcap Runtime remains an end-user prerequisite and is not bundled by FlowLens.

## Local checks

```bash
cargo +1.96.0 fmt --all -- --check
cargo +1.96.0 check --locked
cargo +1.96.0 test --locked
cargo +1.96.0 clippy --locked --all-targets --all-features -- -D warnings
```

## Linux distribution build

Install Zig, `cargo-zigbuild`, and the libpcap development package first. The distribution target uses the glibc `2.28` baseline:

```bash
cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.28
```

The output binary is:

```text
target/x86_64-unknown-linux-gnu/release/flowlens
```

Check the ELF dependencies before treating the binary as a distribution artifact:

```bash
readelf -d target/x86_64-unknown-linux-gnu/release/flowlens
readelf --version-info target/x86_64-unknown-linux-gnu/release/flowlens
```

The binary may depend on the target system's glibc and libpcap. Static linking is used for Rust code and other dependencies where it is appropriate; glibc and libpcap remain explicit Linux runtime prerequisites.

## Windows build

Set `LIBPCAP_LIBDIR` to the x64 `Lib` directory from Npcap SDK `1.16`:

```powershell
$env:LIBPCAP_LIBDIR = 'path-to-npcap-sdk\Lib\x64'
$env:RUSTFLAGS = '-C target-feature=+crt-static'

cargo +1.96.0 test --locked
cargo +1.96.0 build --release --locked
```

The release binary is `target\release\flowlens.exe`. The Windows Release workflow verifies that the executable does not depend on the dynamic VC Runtime and still declares the external `wpcap.dll` dependency.

## CI boundaries

The required CI checks run on Linux and Windows for pull requests and pushes to `main`:

- Rust formatting;
- `cargo check --locked`;
- `cargo test --locked`;
- Clippy with warnings denied.

CI does not run real network capture, long-running traffic tests, or performance benchmarks. Those checks are manual release-readiness activities because they depend on host permissions, adapters, traffic generators, Npcap behavior, and system load.

## On-demand test builds

The `Build Test` workflow creates distribution-shaped binaries for manual testing without changing the Cargo version, creating a tag, or creating a Release. Select a branch or commit and choose `all`, `linux`, or `windows` in the GitHub Actions page. Artifacts are retained for 14 days and include a short commit identifier in their names.

The workflow can also be started with GitHub CLI:

```bash
gh workflow run build-test.yml --ref <branch> -f platform=all
```

The Linux artifact uses the glibc `2.28` baseline. The Windows artifact uses static VC Runtime linking and still requires Npcap Runtime on the test machine.

## Release development

The Release workflow uses `cargo-edit` for `major`, `minor`, and `patch` bumps. It builds and validates both platform artifacts before pushing the version commit and annotated tag. The maintainer checklist is in [`release-checklist.md`](release-checklist.md).
