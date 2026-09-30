#!/usr/bin/env bash
# Audit a single-architecture macOS release binary against its build baseline.
set -euo pipefail

fail() {
    printf 'macOS binary audit: %s\n' "$1" >&2
    exit 1
}

normalize_version() {
    local version=$1
    [[ $version =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || return 1
    while [[ $version == *.0 ]]; do
        version=${version%.0}
    done
    printf '%s\n' "$version"
}

if [[ $# -ne 3 ]]; then
    printf 'Usage: %s binary expected-arch(x86_64|arm64) expected-deployment-target\n' "$0" >&2
    exit 2
fi
binary=$1
expected_arch=$2
expected_target=$3
case $expected_arch in
    x86_64|arm64) ;;
    *) fail "unsupported expected architecture: $expected_arch" ;;
esac
expected_version=$(normalize_version "$expected_target") || fail "invalid deployment target: $expected_target"
[[ -f $binary && -x $binary ]] || fail "binary is not executable: $binary"
case $binary in
    /*) ;;
    *) binary=./$binary ;;
esac

file_output=$(file -b "$binary") || fail 'file failed'
[[ $file_output =~ ^Mach-O\ 64-bit\ executable\ (x86_64|arm64)([[:space:],]|$) ]] || fail "not a single-architecture Mach-O executable: $file_output"
[[ ${BASH_REMATCH[1]} == "$expected_arch" ]] || fail "architecture mismatch: expected $expected_arch, got $file_output"
printf 'Architecture: %s\n' "$expected_arch"

dependencies=$(otool -L "$binary") || fail 'otool -L failed'
first_line=1
has_pcap=0
while IFS= read -r dependency; do
    if [[ $first_line == 1 ]]; then
        first_line=0
        continue
    fi
    dependency=${dependency#"${dependency%%[![:space:]]*}"}
    [[ -n $dependency ]] || continue
    dependency=${dependency%% \(*}
    case $dependency in
        */../*|*/./*) fail "non-system dependency: $dependency" ;;
        /usr/lib/*|/System/Library/Frameworks/*) ;;
        *) fail "non-system dependency: $dependency" ;;
    esac
    case $dependency in
        /usr/lib/libpcap*.dylib) has_pcap=1 ;;
    esac
done <<< "$dependencies"
[[ $has_pcap == 1 ]] || fail 'missing system libpcap dependency (/usr/lib/libpcap*.dylib)'

load_commands=$(otool -l "$binary") || fail 'otool -l failed'
deployment_target=$(printf '%s\n' "$load_commands" | awk '
    $1 == "cmd" { command = $2 }
    command == "LC_BUILD_VERSION" && $1 == "minos" { print $2 }
    command == "LC_VERSION_MIN_MACOSX" && $1 == "version" { print $2 }
')
[[ -n $deployment_target && $deployment_target != *$'\n'* ]] || fail 'expected exactly one macOS deployment target load command'
actual_version=$(normalize_version "$deployment_target") || fail "invalid binary deployment target: $deployment_target"
printf 'Deployment target: %s (expected %s)\n' "$deployment_target" "$expected_target"
[[ $actual_version == "$expected_version" ]] || fail "deployment target mismatch: expected $expected_target, got $deployment_target"

"$binary" --help >/dev/null || fail 'binary --help failed'
"$binary" --version || fail 'binary --version failed'
printf 'macOS binary audit passed\n'
