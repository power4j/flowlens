# Release Checklist

This checklist records the manual checks around the GitHub Release workflow. The workflow itself performs the version bump, builds all platform artifacts, pushes the version metadata, and creates a Draft Release.

## Before triggering Release

- [ ] `main` contains the intended source changes and has no uncommitted changes.
- [ ] Required CI checks are green on the intended `main` commit.
- [ ] `CHANGELOG.md` has a complete `[Unreleased]` entry for this release.
- [ ] `LICENSE`, Cargo SPDX metadata, and both READMEs state the same license for the release.
- [ ] The bump type is selected intentionally: `patch`, `minor`, or `major`.
- [ ] The expected version is strictly greater than the current Cargo version.
- [ ] Linux `x86_64` and `aarch64` manual smoke checks completed on supported hosts: start-up, interface discovery, capture, and representative output.
- [ ] Windows `x86_64` manual smoke checks completed on a supported host: Npcap detection, interface discovery, capture, and representative output.
- [ ] Windows `aarch64` manual smoke checks completed, or the release-specific exception below is explicitly applicable; cross-build and binary/dependency audits remain required in either case.
- [ ] Linux `x86_64` and `aarch64` distribution audits confirm the glibc `2.28` baseline, static libpcap linkage, and no runtime search path; no-system-libpcap capture smoke checks are green.
- [ ] macOS `x86_64` and `aarch64` native CI builds, system-only linkage/deployment-target audits, basic CLI checks, and root loopback capture checks are green.
- [ ] The Release Notes identify macOS archives as unsigned, unnotarized, experimental, and not fully runtime-tested.
- [ ] Any known platform limitation or incomplete boundary test is ready to state in the Release Notes.

Real traffic and performance checks are manual. They are not required CI jobs and are not silently replaced by a passing unit-test job.

## Current Unreleased exception: Windows ARM64

The maintainer approved a real-hardware capture-validation exception on **2026-10-01** for the next release containing the current Unreleased installer/static-libpcap changes. No Windows ARM64 machine is available. Retain the ARM64 archive and its existing build policy; this is an accepted validation gap, not a passed runtime test or a standing waiver for later releases.

- Build Test run `36811074001`, at source commit `a338366ff6250d9c69862a0e2e2146eb1b1f88cd`, passed the Windows x64/ARM64 builds and dependency audits. Both packages passed independent checksums, PE architecture, archive-shape and license checks.
- Windows x64 physical-interface capture parity passed on that source commit. This does not establish ARM64 runtime behavior.
- ARM64 Npcap runtime detection, interface discovery, capture and representative output remain **unverified on real hardware**. Do not check these off as passed or substitute emulation for hardware evidence.
- Record the resulting release version here when it is selected. Revisit the exception if Windows implementation changes; do not reuse it automatically for another release.

The Release Notes must include this limitation prominently:

> Windows ARM64 archives passed cross-build and binary/dependency audits. Capture on Windows ARM64 real hardware has not been validated.

## After Draft Release creation

- [ ] The Draft Release tag is the expected annotated `vX.Y.Z` tag.
- [ ] The Release name is exactly `vX.Y.Z`.
- [ ] Linux assets are named `flowlens-vX.Y.Z-linux-x86_64.tar.gz` and `flowlens-vX.Y.Z-linux-aarch64.tar.gz`.
- [ ] Windows assets are named `flowlens-vX.Y.Z-windows-x86_64.zip` and `flowlens-vX.Y.Z-windows-aarch64.zip`.
- [ ] Experimental macOS assets are named `flowlens-vX.Y.Z-macos-x86_64.tar.gz` and `flowlens-vX.Y.Z-macos-aarch64.tar.gz`.
- [ ] Each archive contains only its corresponding `flowlens` or `flowlens.exe` binary and `LICENSE`. Linux `LICENSE` retains the canonical project license and appends the bundled libpcap license/copyright notices; Windows/macOS use the canonical project license.
- [ ] The tagged source archives are available from the Release page and contain the same canonical `LICENSE` file.
- [ ] `SHA256SUMS` is present and covers all release archives.
- [ ] The generated Release Notes have been reviewed and edited.
- [ ] The `pre-release` option is selected when the release is not considered stable.
- [ ] The Npcap Runtime prerequisite is stated for Windows releases.
- [ ] Any Windows ARM64 real-hardware validation exception is stated explicitly in the Release Notes; binary audits must not be described as runtime validation.
- [ ] Linux Release Notes state the dynamic glibc `2.28` baseline, bundled libpcap version, and root or `CAP_NET_RAW` capture requirement. New static-libpcap archives do not require a system libpcap package; older dynamic archives and ordinary source builds may still require it.
- [ ] The macOS signing, notarization, minimum-version, capture-permission, and runtime-validation limits are stated.
- [ ] The Draft Release is published manually after the text and assets are verified.

## After publishing

- [ ] `flowlens --version` and `flowlens.exe --version` report `X.Y.Z`.
- [ ] Optional: run `install.sh --version vX.Y.Z` in a temporary directory, then uninstall. This check does not block publishing.
- [ ] Run the macOS Release smoke workflow for both `x86_64` and `aarch64`.
- [ ] The GitHub Release, tag, Cargo metadata, and Release Notes use the same version.
- [ ] The `[Unreleased]` entry in `CHANGELOG.md` is renamed to `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] A new empty `[Unreleased]` section is added to `CHANGELOG.md`.
- [ ] The changelog update is committed separately if it was not included before the release.

## Recovery after tag push

If the version commit or `vX.Y.Z` tag has already been pushed, do not rerun the complete bump workflow. The version is occupied. Recover by creating or updating the Draft Release for the existing tag, or by rerunning only the failed Release job when the workflow run supports it.
