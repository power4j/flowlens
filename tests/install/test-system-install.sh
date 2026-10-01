#!/usr/bin/env bash
# Real system paths, exclusively inside an authorized disposable Linux container.
set -euo pipefail
SCENARIO=preflight LOG='' MIRROR_LOG=''
fail() {
  printf 'FAIL [%s]: %s\n' "$SCENARIO" "$*" >&2
  local log
  for log in "$LOG" "$MIRROR_LOG"; do
    if [[ -n "$log" && -f "$log" ]]; then printf '\n--- %s ---\n' "$log" >&2; cat "$log" >&2; fi
  done
  exit 1
}
check() { "$@" || fail "assertion failed: $*"; }
run() {
  local expected="$1" actual=0; shift
  "$@" >"$LOG" 2>&1 || actual=$?
  [[ "$actual" == "$expected" ]] || fail "expected exit $expected, got $actual: $*"
}
no_staging() {
  local file
  for file in /usr/local/bin/flowlens.{new,rollback}.* \
    /usr/local/share/flowlens/install-manifest.{new,rollback}.* \
    /tmp/flowlens-install.* /test-tmp/flowlens-install.*; do
    [[ ! -e "$file" && ! -L "$file" ]] || fail "installer staging/rollback path remains: $file"
  done
}

[[ $# -ge 2 && $# -le 3 ]] || fail 'usage: bash tests/install/test-system-install.sh ARCHIVE SHA256SUMS [INSTALLER]'
check test "$(uname -s)" = Linux
check test "$(id -u)" = 0
[[ -f /.dockerenv ]] || fail 'refusing execution outside a Docker container'
[[ "${FLOWLENS_DISPOSABLE_INSTALL_TEST:-}" == 1 ]] || fail 'FLOWLENS_DISPOSABLE_INSTALL_TEST=1 is required'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHIVE="$1" SUMS="$2" INSTALLER="${3:-$ROOT/install.sh}"
BINARY=/usr/local/bin/flowlens MANIFEST=/usr/local/share/flowlens/install-manifest
for file in "$BINARY" "$MANIFEST"; do
  [[ ! -e "$file" && ! -L "$file" ]] || fail "refusing an existing installation: $file"
done
for tool in bash curl python3 runuser sha256sum stat grep mktemp cat sleep \
  tar awk sed cp mv ln mkdir chmod ldd apt-get apt-cache dpkg-query; do
  command -v "$tool" >/dev/null 2>&1 || fail "container prerequisite missing: $tool"
done
if command -v setcap >/dev/null 2>&1 || [[ -e /usr/sbin/setcap || -e /sbin/setcap ]]; then
  fail 'setcap must be absent initially to test automatic libcap2-bin bootstrap'
fi
for name in FLOWLENS_VERSION FLOWLENS_INSTALL_DIR FLOWLENS_NO_MODIFY_PATH FLOWLENS_FORCE FLOWLENS_SETCAP; do
  [[ -z "${!name:-}" ]] || fail "container must not supply installer override $name"
done
for file in "$ARCHIVE" "$SUMS" "$INSTALLER" "$ROOT/scripts/smoke-capture.py"; do
  [[ -f "$file" && -r "$file" ]] || fail "required readable file missing: $file"
done
ASSET="${ARCHIVE##*/}"
[[ "$ASSET" =~ ^flowlens-(v[0-9]+\.[0-9]+\.[0-9]+)-linux-(x86_64|aarch64)\.tar\.gz$ ]] || fail 'invalid release archive basename'
VERSION="${BASH_REMATCH[1]}" ARCH="${BASH_REMATCH[2]}"
case "$(uname -m)" in
  x86_64) HOST_ARCH=x86_64 ;;
  aarch64|arm64) HOST_ARCH=aarch64 ;;
  *) fail 'unsupported container architecture' ;;
esac
check test "$ARCH" = "$HOST_ARCH"

# The outer operator, not /.dockerenv, must establish absence of host binds.
python3 - "$ARCHIVE" "$SUMS" "$ASSET" <<'PY' || fail 'container prerequisites or archive checksum verification failed'
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
required = (1 << 13) | (1 << 31)  # NET_RAW and SETFCAP
for field in ("CapBnd", "CapEff"):
    assert int(status[field], 16) & required == required, field + " needs NET_RAW and SETFCAP"
assert not int(status["CapBnd"], 16) & (1 << 12), "NET_ADMIN must be dropped"
assert int(status["NoNewPrivs"]) == 0, "no-new-privileges must be disabled"
assert os.path.realpath("/test-tmp") == "/test-tmp", "/test-tmp must not be a symlink"
mounts = [line.split(" - ") for line in Path("/proc/self/mountinfo").read_text().splitlines()]
mount = [parts for parts in mounts if parts[0].split()[4] == "/test-tmp"]
assert len(mount) == 1 and mount[0][1].split()[0] == "tmpfs", "/test-tmp needs its own tmpfs"
assert "noexec" not in mount[0][0].split()[5].split(","), "/test-tmp must allow execution"
for directory in ("/usr/local/bin", "/usr/local/share"):
    assert os.stat("/test-tmp").st_dev != os.stat(directory).st_dev, "TMPDIR must be a different filesystem"
with tempfile.NamedTemporaryFile(dir="/test-tmp", prefix="flowlens-exec-probe.", delete=False) as probe:
    probe.write(b"#!/bin/sh\nexit 0\n")
os.chmod(probe.name, 0o755)
subprocess.run([probe.name], check=True)  # Retained until container destruction.
archive, sums, asset = sys.argv[1:]
expected = [line.partition("  ")[0] for line in Path(sums).read_text().splitlines()
            if line.partition("  ")[2] == asset]
digest = hashlib.sha256()
with open(archive, "rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
assert expected == [digest.hexdigest()], "SHA256SUMS must list the archive once with its exact SHA-256"
print("PASS: supplied release archive checksum verified")
PY

WORK="$(mktemp -d /tmp/flowlens-system-install.XXXXXX)"
RUNTIME="$WORK/install.sh" MIRROR_LOG="$WORK/mirror.log"
printf 'Test logs: %s\n' "$WORK"
SCENARIO=loopback-mirror
python3 - "$WORK" "$ARCHIVE" "$SUMS" "$VERSION" "$ASSET" "$INSTALLER" >"$MIRROR_LOG" 2>&1 <<'PY' &
import functools
import http.server
import json
import shutil
import sys
from pathlib import Path

work, archive, sums, version, asset, installer = sys.argv[1:]
work = Path(work)
public = work / "public"
release = public / "power4j/flowlens/releases/download" / version
release.mkdir(parents=True)
shutil.copyfile(archive, release / asset)
shutil.copyfile(sums, release / "SHA256SUMS")
latest = public / "repos/power4j/flowlens/releases/latest"
latest.parent.mkdir(parents=True)
latest.write_text(json.dumps({"tag_name": version, "prerelease": False, "draft": False}))
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(public))
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
original = Path(installer).read_bytes()
patched, replacements = original, []
for name, url in (("API_BASE", "https://api.github.com"), ("DOWNLOAD_BASE", "https://github.com")):
    old = f'{name}="{url}"'.encode()
    new = f'{name}="http://127.0.0.1:{server.server_port}"'.encode()
    assert original.count(old) == 1, "expected one installer base URL assignment: " + name
    patched = patched.replace(old, new, 1)
    replacements.append((old, new))
restored = patched
for old, new in replacements:
    restored = restored.replace(new, old, 1)
assert restored == original, "installer changed beyond API_BASE/DOWNLOAD_BASE"
(work / "install.sh").write_bytes(patched)
print("Only API_BASE and DOWNLOAD_BASE changed", flush=True)
(work / "mirror-port").write_text(str(server.server_port))
server.serve_forever()
PY
MIRROR_PID=$!
# No filesystem cleanup: the outer operator destroys the container.
stop_mirror() { kill "$MIRROR_PID" 2>/dev/null || true; wait "$MIRROR_PID" 2>/dev/null || true; }
trap stop_mirror EXIT
for _ in 1 2 3 4 5; do
  [[ ! -s "$WORK/mirror-port" ]] || break
  kill -0 "$MIRROR_PID" 2>/dev/null || fail 'mirror setup failed'
  sleep 1
done
[[ -s "$WORK/mirror-port" ]] || fail 'mirror did not become ready'

capture() {
  LOG="$WORK/$SCENARIO-capture.log"
  run 0 runuser --preserve-environment -u nobody -- python3 "$ROOT/scripts/smoke-capture.py" "$BINARY" lo "$@"
  cat "$LOG"
}
unchanged_install() {
  check test "$(sha256sum "$BINARY")" = "$OLD_BINARY"
  check test "$(stat -c %i "$BINARY")" = "$OLD_INODE"
  check test "$(sha256sum "$MANIFEST")" = "$OLD_MANIFEST"
  check test "$(getcap "$BINARY")" = "$BINARY cap_net_raw=ep"
  if grep -Eq 'installed FlowLens|CAP_NET_RAW was granted' "$LOG"; then fail 'failed installation printed success'; fi
  no_staging
}

SCENARIO=dry-run LOG="$WORK/dry-run.log"
run 0 env TMPDIR=/tmp bash "$RUNTIME" --dry-run
[[ ! -e "$BINARY" && ! -L "$BINARY" && ! -e "$MANIFEST" && ! -L "$MANIFEST" ]] || fail 'dry-run published system files'
if command -v setcap >/dev/null 2>&1 || [[ -e /usr/sbin/setcap || -e /sbin/setcap ]]; then fail 'dry-run bootstrapped setcap'; fi
no_staging
printf 'PASS [%s]\n' "$SCENARIO"

SCENARIO=default-system-install LOG="$WORK/default-system-install.log"
run 0 env TMPDIR=/tmp bash "$RUNTIME"
# Before getcap/capsh use, make the pre-fix red report missing default bootstrap.
command -v setcap >/dev/null 2>&1 || fail 'default system install did not bootstrap setcap (libcap2-bin); CAP_NET_RAW cannot be granted'
command -v getcap >/dev/null 2>&1 || fail 'default system install did not bootstrap getcap (libcap2-bin); cannot verify CAP_NET_RAW'
command -v capsh >/dev/null 2>&1 || fail 'libcap2-bin bootstrap did not provide capsh'
check test "$(dpkg-query -W -f='${Status}' libcap2-bin)" = 'install ok installed'
check test "$(getcap "$BINARY")" = "$BINARY cap_net_raw=ep"
check grep -Fxq 'setcap=true' "$MANIFEST"
check test "$("$BINARY" --version)" = "flowlens ${VERSION#v}"
no_staging
LOG="$WORK/nobody-identity.log"
run 0 runuser --preserve-environment -u nobody -- python3 - <<'PY'
import os
from pathlib import Path
assert os.getuid() != 0, "capture must not run as root"
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
for field in ("CapEff", "CapPrm", "CapAmb"):
    assert int(status[field], 16) == 0, "nobody inherited capabilities: " + field
PY
capture
printf 'PASS [%s]: libcap2-bin, only CAP_NET_RAW, real nobody loopback capture\n' "$SCENARIO"
OLD_BINARY="$(sha256sum "$BINARY")" OLD_INODE="$(stat -c %i "$BINARY")" OLD_MANIFEST="$(sha256sum "$MANIFEST")"

SCENARIO=missing-setfcap LOG="$WORK/missing-setfcap.log"
# Positional arguments are intentionally expanded by capsh's child shell.
# shellcheck disable=SC2016
run 1 env TMPDIR=/tmp capsh --drop=cap_setfcap -- -c 'exec bash "$1" --version "$2"' test-system-install "$RUNTIME" "$VERSION"
check grep -Fq 'failed to setcap' "$LOG"
unchanged_install
capture
printf 'PASS [%s]: original SHA/inode/manifest/caps and capture preserved\n' "$SCENARIO"

SCENARIO=manifest-rollback LOG="$WORK/manifest-rollback.log"
mkdir "$WORK/fault-bin"
cat >"$WORK/fault-bin/mv" <<'SH'
#!/usr/bin/env bash
source_path='' destination=''
for argument; do source_path="$destination"; destination="$argument"; done
case "$source_path:$destination" in
  /usr/local/share/flowlens/install-manifest.new.*:/usr/local/share/flowlens/install-manifest)
    printf 'Injected failure: refusing new manifest publication\n' >&2; exit 1 ;;
esac
exec /usr/bin/mv "$@"
SH
chmod 0755 "$WORK/fault-bin/mv"
run 1 env TMPDIR=/test-tmp PATH="$WORK/fault-bin:$PATH" bash "$RUNTIME" --version "$VERSION"
check grep -Fq 'Injected failure: refusing new manifest publication' "$LOG"
check grep -Fq 'failed to publish manifest' "$LOG"
unchanged_install
capture
printf 'PASS [%s]: cross-filesystem TMPDIR rollback preserves inode/caps/manifest/capture\n' "$SCENARIO"

SCENARIO=removed-capability LOG="$WORK/removed-capability.log"
run 0 setcap -r "$BINARY"
check test -z "$(getcap "$BINARY")"
capture denied
printf 'PASS [%s]: nobody capture denied\n' "$SCENARIO"

SCENARIO=default-reinstall LOG="$WORK/default-reinstall.log"
run 0 env TMPDIR=/tmp bash "$RUNTIME"
check test "$(getcap "$BINARY")" = "$BINARY cap_net_raw=ep"
check grep -Fxq 'setcap=true' "$MANIFEST"
no_staging
capture
printf 'PASS [%s]: capabilities and nobody capture restored\n' "$SCENARIO"

SCENARIO=no-setcap LOG="$WORK/no-setcap.log"
run 0 env TMPDIR=/tmp bash "$RUNTIME" --no-setcap
check test -z "$(getcap "$BINARY")"
check grep -Fxq 'setcap=false' "$MANIFEST"
no_staging
capture denied
printf 'PASS [%s]: empty caps, manifest false, nobody capture denied\n' "$SCENARIO"

SCENARIO=system-uninstall LOG="$WORK/system-uninstall.log"
run 0 env TMPDIR=/tmp bash "$RUNTIME" --uninstall
[[ ! -e "$BINARY" && ! -L "$BINARY" && ! -e "$MANIFEST" && ! -L "$MANIFEST" ]] || fail 'uninstall left system files'
no_staging
printf 'PASS [%s]: system binary/manifest removed; no staging/rollback leftovers\n' "$SCENARIO"
printf 'PASS: system-install scenarios completed for %s (not the full installer fixture suite)\n' "$ASSET"
