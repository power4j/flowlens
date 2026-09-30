#!/usr/bin/env bash
# Linux-runnable fixtures: no macOS tools or system permission changes required.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERIFY_SH=$ROOT/scripts/verify-macos-binary.sh
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/flowlens-macos-binary-test.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT
PASS=0
FAIL=0
mkdir -p "$WORKDIR/bin" "$WORKDIR/release with spaces"
export MOCK_DIR=$WORKDIR

cat > "$WORKDIR/bin/file" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == -b && -f $2 ]]
cat "$MOCK_DIR/file.txt"
MOCK
cat > "$WORKDIR/bin/otool" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && -f $2 ]]
printf '%s:\n' "$2"
case $1 in
    -L) cat "$MOCK_DIR/dependencies.txt" ;;
    -l) cat "$MOCK_DIR/commands.txt" ;;
    *) exit 2 ;;
esac
MOCK
cat > "$WORKDIR/release with spaces/flowlens" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_DIR/calls.txt"
case ${1:-} in
    --help) printf 'FlowLens help\n'; [[ ${MOCK_FAIL:-} != help ]] ;;
    --version) printf 'flowlens 0.7.2\n'; [[ ${MOCK_FAIL:-} != version ]] ;;
    *) exit 2 ;;
esac
MOCK
# Only disposable fixture files are made executable.
chmod +x "$WORKDIR/bin/file" "$WORKDIR/bin/otool" "$WORKDIR/release with spaces/flowlens"

build_version() {
    cat > "$WORKDIR/commands.txt" <<EOF
Load command 0
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 1
    minos $1
      sdk 15.5
   ntools 1
     tool 3
  version 1115.7.3
Load command 1
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 0.0
EOF
}

legacy_version() {
    cat > "$WORKDIR/commands.txt" <<EOF
Load command 0
      cmd LC_VERSION_MIN_MACOSX
  cmdsize 16
  version $1
      sdk 15.5
Load command 1
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 0.0
EOF
}

reset_fixture() {
    printf 'Mach-O 64-bit executable x86_64, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>\n' > "$WORKDIR/file.txt"
    cat > "$WORKDIR/dependencies.txt" <<'EOF'
    /usr/lib/libpcap.A.dylib (compatibility version 1.0.0, current version 1.0.0)
    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation (compatibility version 150.0.0, current version 3500.0.0)
EOF
    build_version 15.0
    MOCK_FAIL=
    export MOCK_FAIL
}

run_case() {
    local name=$1 expected_status=$2 needle=$3
    local arch=${4:-x86_64} target=${5:-15.0} status=0 calls expected_calls
    : > "$WORKDIR/calls.txt"
    # The mock PATH applies only to this process, not to the host or other tests.
    PATH="$WORKDIR/bin:$PATH" bash "$VERIFY_SH" \
        "$WORKDIR/release with spaces/flowlens" "$arch" "$target" > "$WORKDIR/output.txt" 2>&1 || status=$?
    calls=$(cat "$WORKDIR/calls.txt")
    expected_calls=
    if [[ $expected_status == 0 || $MOCK_FAIL == version ]]; then
        expected_calls=$'--help\n--version'
    elif [[ $MOCK_FAIL == help ]]; then
        expected_calls=--help
    fi
    if [[ $status == "$expected_status" ]] && grep -Fq -- "$needle" "$WORKDIR/output.txt" && [[ $calls == "$expected_calls" ]]; then
        PASS=$((PASS + 1))
        printf 'ok: %s\n' "$name"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL: %s (status %s, expected %s; calls %s)\n' "$name" "$status" "$expected_status" "$calls"
        cat "$WORKDIR/output.txt"
    fi
}

printf 'FlowLens macOS binary mock tests\n'
reset_fixture
run_case 'x86_64 LC_BUILD_VERSION succeeds and runs both CLI probes' 0 'Deployment target: 15.0 (expected 15.0)'
reset_fixture
printf 'Mach-O 64-bit executable arm64\n' > "$WORKDIR/file.txt"
build_version 15.0.0
run_case 'arm64 accepts minos 15.0.0 as 15.0' 0 'Deployment target: 15.0.0 (expected 15.0)' arm64
reset_fixture
run_case 'minos 15.0 accepts expected 15.0.0' 0 'Deployment target: 15.0 (expected 15.0.0)' x86_64 15.0.0
reset_fixture
legacy_version 15.0.0
run_case 'LC_VERSION_MIN_MACOSX succeeds' 0 'Deployment target: 15.0.0 (expected 15.0)'

for dependency in \
    /opt/homebrew/opt/libpcap/lib/libpcap.1.dylib \
    /usr/local/lib/libpcap.dylib \
    @rpath/libpcap.dylib \
    @loader_path/libpcap.dylib \
    /Users/runner/work/flowlens/target/release/libextra.dylib \
    /Library/Frameworks/Extra.framework/Extra \
    /usr/lib/../../opt/homebrew/lib/libextra.dylib; do
    reset_fixture
    printf '    %s (compatibility version 1.0.0, current version 1.0.0)\n' "$dependency" >> "$WORKDIR/dependencies.txt"
    run_case "rejects $dependency even with system pcap present" 1 "non-system dependency: $dependency"
done

reset_fixture
printf '    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n' > "$WORKDIR/dependencies.txt"
run_case 'rejects missing pcap' 1 'missing system libpcap dependency'
reset_fixture
printf 'Mach-O 64-bit executable arm64\n' > "$WORKDIR/file.txt"
run_case 'rejects architecture mismatch' 1 'architecture mismatch'
reset_fixture
printf 'Mach-O universal binary with 2 architectures: [x86_64] [arm64]\n' > "$WORKDIR/file.txt"
run_case 'rejects universal binary' 1 'not a single-architecture Mach-O executable'
reset_fixture
build_version 14.0
run_case 'rejects LC_BUILD_VERSION target mismatch' 1 'deployment target mismatch: expected 15.0, got 14.0'
reset_fixture
legacy_version 15.1
run_case 'rejects LC_VERSION_MIN_MACOSX target mismatch' 1 'deployment target mismatch: expected 15.0, got 15.1'
reset_fixture
printf 'Load command 0\n      cmd LC_SOURCE_VERSION\n  version 15.0\n' > "$WORKDIR/commands.txt"
run_case 'rejects absent deployment command' 1 'expected exactly one macOS deployment target load command'
reset_fixture
MOCK_FAIL=help
run_case 'rejects failed --help and does not run --version' 1 'binary --help failed'
reset_fixture
MOCK_FAIL=version
run_case 'rejects failed --version' 1 'binary --version failed'

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL == 0 ]]
