# Disposable Linux system-install regression

`test-system-install.sh` exercises public `bash install.sh` system installation
using a real, already downloaded and verified published Linux binary. It does
not build FlowLens, fetch the latest public release or run the full fixture
suite. Run it **only inside disposable Docker containers on an explicitly
authorized Linux test host**, never directly as root on a host or developer
machine. This test is opt-in and is not wired into CI.

## Prerequisites, prepared by the outer operator

- Confirm **no bind mounts or host-directory mounts**; copy the checkout,
  archive, original `SHA256SUMS` and optional baseline installer into the
  container. `/.dockerenv` and the explicit opt-in guard do not prove no binds.
- Use an isolated Docker bridge network, allow `NET_RAW` and `SETFCAP`, drop
  `NET_ADMIN`, and disable `no-new-privileges`.
- Prepare a Debian/Ubuntu container with Bash, curl, Python 3, CA certificates,
  `runuser`, GNU coreutils, tar, awk, sed, `ldd`, apt-get, apt-cache and dpkg-query.
  **Leave setcap absent**: the installer must bootstrap `libcap2-bin` (setcap,
  getcap, capsh). The test does not perform initial apt setup itself.
- Mount an independent, executable, **container-only tmpfs at `/test-tmp`**,
  on a different filesystem from `/usr/local/bin` and `/usr/local/share`.
- Start without `/usr/local/bin/flowlens` or
  `/usr/local/share/flowlens/install-manifest`, including symlinks. Supply no
  `FLOWLENS_VERSION`, `FLOWLENS_INSTALL_DIR`, `FLOWLENS_NO_MODIFY_PATH`,
  `FLOWLENS_FORCE` or `FLOWLENS_SETCAP` overrides.
- Keep **HOME unchanged**. The test never sets, unsets, replaces or derives paths
  from HOME; nobody capture uses `runuser --preserve-environment`. Make the
  copied checkout and `scripts/smoke-capture.py` readable/traversable by nobody.

## Invocation — only inside the prepared disposable container

Supply a standard `flowlens-vX.Y.Z-linux-(x86_64|aarch64).tar.gz` matching the
container architecture and its original release `SHA256SUMS`. The test rechecks
the checksum and serves that version and original sums from a random localhost
HTTP port. Only API_BASE/DOWNLOAD_BASE are changed in a temporary installer copy;
an exact reverse comparison verifies the rest is unchanged. Synthetic latest
JSON selects the supplied release, not a changing public latest release.

```bash
FLOWLENS_DISPOSABLE_INSTALL_TEST=1 bash tests/install/test-system-install.sh "$ARCHIVE" "$SHA256SUMS"
```

For baseline red/current green, use **two independent fresh containers**. The
optional third argument is a copied pre-fix installer. Expected baseline red
identifies missing default setcap bootstrap / CAP_NET_RAW, not command-not-found.

```bash
FLOWLENS_DISPOSABLE_INSTALL_TEST=1 bash tests/install/test-system-install.sh "$ARCHIVE" "$SHA256SUMS" /work/pre-fix-install.sh
```

Coverage: inert dry-run; default libcap2-bin bootstrap, only `cap_net_raw=ep`
and manifest true; real nobody loopback UDP capture; SETFCAP-denied reinstall;
manifest-publication fault with cross-filesystem TMPDIR and preservation of
binary SHA/inode, manifest SHA and caps; capture after both failures; capability
removal and denied capture; default reinstall recovery; `--no-setcap` with
manifest false/denied capture; default system uninstall and no staging/rollback
leftovers. The existing smoke script supplies up to eight seconds of traffic per
successful capture, unchanged. Failures name the scenario and print relevant
logs; the private fixed-`/tmp` mktemp directory is printed at startup.

The installer alone uninstalls its real container-local system binary/manifest.
The test has no recursive cleanup; its trap only stops its own mirror PID.
**Destroy the container from outside on success or failure** to discard retained
test files and logs. Local `bash -n`, ShellCheck and `git diff --check` are static
checks only, not installation-test evidence.
