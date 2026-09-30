#!/usr/bin/env bash
# Run only in a disposable Linux container, with python3/util-linux/libcap installed.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cache=$(ldconfig -p)
if [[ $cache == *libpcap* ]]; then
    echo 'Smoke environment must not provide a system libpcap' >&2
    exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
cp "$1" "$work/flowlens"
chmod 755 "$work/flowlens"
"$work/flowlens" --help >/dev/null
"$work/flowlens" --version
python3 "$root/scripts/smoke-capture.py" "$work/flowlens" lo
setpriv --reuid=10001 --regid=10001 --clear-groups python3 "$root/scripts/smoke-capture.py" "$work/flowlens" lo denied
setcap cap_net_raw=ep "$work/flowlens"
getcap "$work/flowlens" | grep -F 'cap_net_raw=ep'
setpriv --reuid=10001 --regid=10001 --clear-groups python3 "$root/scripts/smoke-capture.py" "$work/flowlens" lo
