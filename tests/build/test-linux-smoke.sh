#!/usr/bin/env bash
# Both failures must be rejected before attempting any capture or file capabilities.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
cat > "$work/bin/ldconfig" <<'MOCK'
#!/usr/bin/env bash
[[ ${MOCK_QUERY_FAIL:-0} == 0 ]] || exit 7
printf 'libpcap.so.1 => /lib/libpcap.so.1\n'
for ((i=0; i<10000; i++)); do printf 'libfixture.so.%s => /lib/libfixture.so.%s\n' "$i" "$i"; done
MOCK
chmod +x "$work/bin/ldconfig"
status=0
PATH="$work/bin:$PATH" bash "$root/scripts/smoke-linux-release.sh" unused > "$work/output" 2>&1 || status=$?
[[ $status == 1 ]]
grep -F 'must not provide a system libpcap' "$work/output"
status=0
MOCK_QUERY_FAIL=1 PATH="$work/bin:$PATH" bash "$root/scripts/smoke-linux-release.sh" unused > "$work/output" 2>&1 || status=$?
[[ $status == 7 ]]
printf '2 passed, 0 failed\n'
