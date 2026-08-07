# Release Checklist

This checklist records the manual checks around the GitHub Release workflow. The workflow itself performs the version bump, builds both platform artifacts, pushes the version metadata, and creates a Draft Release.

## Before triggering Release

- [ ] `main` contains the intended source changes and has no uncommitted changes.
- [ ] Required CI checks are green on the intended `main` commit.
- [ ] `CHANGELOG.md` has a complete `[Unreleased]` entry for this release.
- [ ] The bump type is selected intentionally: `patch`, `minor`, or `major`.
- [ ] The expected version is strictly greater than the current Cargo version.
- [ ] Linux manual smoke check completed on a supported host: start-up, interface discovery, capture, and representative output.
- [ ] Windows manual smoke check completed on a supported host: Npcap detection, interface discovery, capture, and representative output.
- [ ] Any known platform limitation or incomplete boundary test is ready to state in the Release Notes.

Real traffic and performance checks are manual. They are not required CI jobs and are not silently replaced by a passing unit-test job.

## After Draft Release creation

- [ ] The Draft Release tag is the expected annotated `vX.Y.Z` tag.
- [ ] The Release name is exactly `vX.Y.Z`.
- [ ] Assets are named `flowlens-vX.Y.Z-linux-x86_64.tar.gz` and `flowlens-vX.Y.Z-windows-x86_64.zip`.
- [ ] Each archive contains only its corresponding `flowlens` or `flowlens.exe` binary.
- [ ] `SHA256SUMS` is present and covers both archives.
- [ ] The generated Release Notes have been reviewed and edited.
- [ ] The `pre-release` option is selected when the release is not considered stable.
- [ ] The Npcap Runtime prerequisite is stated for Windows releases.
- [ ] The Linux glibc `2.28` and libpcap prerequisites are stated for Linux releases.
- [ ] The Draft Release is published manually after the text and assets are verified.

## After publishing

- [ ] `flowlens --version` and `flowlens.exe --version` report `X.Y.Z`.
- [ ] The GitHub Release, tag, Cargo metadata, and Release Notes use the same version.
- [ ] The `[Unreleased]` entry in `CHANGELOG.md` is renamed to `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] A new empty `[Unreleased]` section is added to `CHANGELOG.md`.
- [ ] The changelog update is committed separately if it was not included before the release.

## Recovery after tag push

If the version commit or `vX.Y.Z` tag has already been pushed, do not rerun the complete bump workflow. The version is occupied. Recover by creating or updating the Draft Release for the existing tag, or by rerunning only the failed Release job when the workflow run supports it.
