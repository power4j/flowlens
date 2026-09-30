#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
printf '#!/bin/sh\nexit 0\n' > "$work/flowlens"
cat > "$work/bin/readelf" <<'MOCK'
#!/usr/bin/env bash
set -eu
[[ ${MOCK_FAIL:-0} == 0 ]] || exit 1
case "$1" in
    -hW) printf '  Machine: %s\n' "$MOCK_MACHINE" ;;
    -lW) printf '      [Requesting program interpreter: %s]\n' "$MOCK_INTERPRETER" ;;
    -dW) printf '%s\n' "$MOCK_DYNAMIC" ;;
    --version-info) printf 'Name: GLIBC_%s\n' "$MOCK_GLIBC" ;;
    *) exit 2 ;;
esac
MOCK
chmod +x "$work/bin/readelf" "$work/flowlens"
export MOCK_MACHINE MOCK_INTERPRETER MOCK_DYNAMIC MOCK_GLIBC MOCK_FAIL
passed=0
reset() {
    MOCK_MACHINE='Advanced Micro Devices X86-64'
    MOCK_INTERPRETER=/lib64/ld-linux-x86-64.so.2
    MOCK_DYNAMIC=' 0x1 (NEEDED) Shared library: [libc.so.6]'
    MOCK_GLIBC=2.28
    MOCK_FAIL=0
}
check() {
    local name=$1 expected=$2 arch=${3:-x86_64} status=0
    PATH="$work/bin:$PATH" bash "$root/scripts/verify-linux-binary.sh" "$work/flowlens" "$arch" "${@:4}" > "$work/output" 2>&1 || status=$?
    if [[ $status != "$expected" ]]; then
        cat "$work/output"
        echo "FAIL: $name (exit=$status, expected=$expected)" >&2
        exit 1
    fi
    passed=$((passed + 1))
    echo "PASS: $name"
}
reset; check 'x86_64 static pcap with dynamic glibc' 0
reset; MOCK_MACHINE=AArch64; MOCK_INTERPRETER=/lib/ld-linux-aarch64.so.1; check 'aarch64' 0 aarch64
reset; MOCK_DYNAMIC+=$'\n 0x1 (NEEDED) Shared library: [libpcap.so.0.8]'; check 'static rejects dynamic pcap' 1 x86_64 static
reset; MOCK_DYNAMIC+=$'\n 0x1 (NEEDED) Shared library: [libpcap.so.0.8]'; check 'dynamic accepts pcap' 0 x86_64 dynamic
reset; check 'dynamic rejects missing pcap' 1 x86_64 dynamic
reset; check 'invalid linkage option rejected' 2 x86_64 invalid
reset; MOCK_DYNAMIC+=$'\n 0x1 (RUNPATH) Library runpath: [/work/native/lib]'; check 'build-directory RUNPATH rejected' 1
reset; MOCK_DYNAMIC+=$'\n 0x1 (RPATH) Library rpath: [/tmp/lib]'; check 'RPATH rejected' 1
reset; MOCK_GLIBC=2.29; check 'newer glibc rejected' 1
reset; MOCK_DYNAMIC=''; check 'fully static/missing libc rejected' 1
reset; MOCK_MACHINE=AArch64; check 'wrong architecture rejected' 1
reset; MOCK_INTERPRETER=/lib/ld-musl-x86_64.so.1; check 'wrong interpreter rejected' 1
reset; MOCK_FAIL=1; check 'readelf failure rejected' 1
printf '\n%d passed, 0 failed\n' "$passed"
