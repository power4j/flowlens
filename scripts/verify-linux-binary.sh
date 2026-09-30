#!/usr/bin/env bash
# Check the ELF contract, without executing a possibly cross-compiled binary.
set -euo pipefail
binary=$1
linkage=${3:-static}
case "$linkage" in
    static|dynamic) ;;
    *) echo 'Expected static or dynamic libpcap linkage' >&2; exit 2 ;;
esac
case "$2" in
    x86_64) machine='Advanced Micro Devices X86-64'; interpreter=/lib64/ld-linux-x86-64.so.2 ;;
    aarch64) machine=AArch64; interpreter=/lib/ld-linux-aarch64.so.1 ;;
    *) echo 'Expected x86_64 or aarch64' >&2; exit 2 ;;
esac
test -x "$binary"
actual=$(readelf -hW "$binary" | awk -F: '/Machine:/ { sub(/^[[:space:]]*/, "", $2); print $2 }')
test "$actual" = "$machine"
readelf -lW "$binary" | grep -F "Requesting program interpreter: $interpreter]"
dynamic=$(readelf -dW "$binary")
printf '%s\n' "$dynamic" | grep -F 'Shared library: [libc.so.6]'
if printf '%s\n' "$dynamic" | grep -Eq '\((RPATH|RUNPATH)\)'; then
    echo 'Unexpected runtime search path' >&2
    exit 1
fi
if printf '%s\n' "$dynamic" | grep -Eq '\(NEEDED\).*Shared library: \[libpcap\.so'; then
    test "$linkage" = dynamic
else
    test "$linkage" = static
fi
max_glibc=$(readelf --version-info "$binary" | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -V | tail -1)
test "$(printf '%s\n' "$max_glibc" 2.28 | sort -V | tail -1)" = 2.28
printf 'Linux binary audit passed: arch=%s, max_glibc=%s, %s libpcap\n' "$2" "$max_glibc" "$linkage"
