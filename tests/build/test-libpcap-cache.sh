#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/checkout with spaces"
cp "$root/scripts/build-linux-release.sh" "$work/helper.sh"
cd "$work/checkout with spaces"
printf 'project license\n' > LICENSE
prefix="$PWD/target/native/x86_64-unknown-linux-gnu/install"
mkdir -p "$prefix/include/pcap" "$prefix/lib/pkgconfig" target/x86_64-unknown-linux-gnu/release
for tool in zig flex bison make; do
    cat > "$work/bin/$tool" <<'MOCK'
#!/usr/bin/env bash
if [[ $1 == ar ]]; then exit 0; fi
printf 'fixture-tool-1\n'
MOCK
    chmod +x "$work/bin/$tool"
done
cat > "$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
exit 42
MOCK
cat > "$work/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CARGO_LOG"
MOCK
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH" CARGO_LOG="$work/cargo.log"
key=$(bash "$work/helper.sh" x86_64-unknown-linux-gnu.2.28 --cache-key)
[[ $key == libpcap-x86_64-unknown-linux-gnu-glibc2.28-zig* ]]
[[ ! -e $prefix/build-key ]]
seed() {
    mkdir -p "$prefix/lib/pkgconfig" "$prefix/include/pcap"
    printf 'archive\n' > "$prefix/lib/libpcap.a"
    printf 'header\n' > "$prefix/include/pcap/pcap.h"
    printf 'upstream license\n' > "$prefix/LICENSE"
    # shellcheck disable=SC2016
    printf 'prefix="/old/checkout"\nlibdir="/old/checkout/lib"\nName: libpcap\nDescription: cache fixture\nVersion: 1.10.7\nLibs: -L${libdir} -lpcap\nCflags: -I${prefix}/include\n' > "$prefix/lib/pkgconfig/libpcap.pc"
    printf '%s\n' "$key" > "$prefix/build-key"
    (cd "$prefix" && find include lib LICENSE -type f -print0 | sort -z | xargs -0 sha256sum > contents.sha256)
}
seed
bash "$work/helper.sh" x86_64-unknown-linux-gnu.2.28 > "$work/output"
grep -F 'cache HIT:' "$work/output"
escaped_prefix=${prefix// /\\ }
grep -Fx "prefix=$escaped_prefix" "$prefix/lib/pkgconfig/libpcap.pc"
# The pkg-config variable must remain literal.
# shellcheck disable=SC2016
grep -Fx 'libdir=${prefix}/lib' "$prefix/lib/pkgconfig/libpcap.pc"
flags=$(PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig" pkg-config --libs-only-L --static libpcap)
python3 - "$flags" "$prefix" <<'PY'
import shlex
import sys
assert shlex.split(sys.argv[1]) == ['-L' + sys.argv[2] + '/lib']
PY
grep -Fx 'clean --package pcap --release --target x86_64-unknown-linux-gnu' "$CARGO_LOG"
grep -F 'upstream license' target/x86_64-unknown-linux-gnu/release/LICENSE
(cd "$prefix" && sha256sum -c contents.sha256 >/dev/null)
bash "$work/helper.sh" x86_64-unknown-linux-gnu.2.28 > "$work/output"
grep -F 'cache HIT:' "$work/output"
miss() {
    local status=0
    bash "$work/helper.sh" x86_64-unknown-linux-gnu.2.28 > "$work/output" 2>&1 || status=$?
    [[ $status == 42 ]]
    grep -F 'cache MISS:' "$work/output"
}
printf 'changed\n' > "$prefix/build-key"
miss
seed
rm "$prefix/include/pcap/pcap.h"
miss
seed
printf 'corrupt archive\n' > "$prefix/lib/libpcap.a"
miss
seed
printf 'dynamic library\n' > "$prefix/lib/libpcap.so.1"
miss
seed
new_key=$(bash "$work/helper.sh" aarch64-unknown-linux-gnu.2.28 --cache-key)
[[ $new_key != "$key" ]]
printf '# recipe changed\n' >> "$work/helper.sh"
new_key=$(bash "$work/helper.sh" x86_64-unknown-linux-gnu.2.28 --cache-key)
[[ $new_key != "$key" ]]
miss
printf '9 passed, 0 failed\n'