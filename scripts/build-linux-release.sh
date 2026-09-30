#!/usr/bin/env bash
# Distribution builds only: static libpcap, dynamic glibc 2.28.
set -euo pipefail
case "${1:-}" in
    x86_64-unknown-linux-gnu.2.28) arch=x86_64 ;;
    aarch64-unknown-linux-gnu.2.28) arch=aarch64 ;;
    *) echo "Usage: $0 {x86_64,aarch64}-unknown-linux-gnu.2.28" >&2; exit 2 ;;
esac
target="${arch}-unknown-linux-gnu"
root=$(pwd)
native="$root/target/native/$target"
prefix="$native/install"
version=1.10.7
checksum=68fa62cffb974f4275641ce14c2e2d75739251f30e00e6a0900903b247d76a03
# The exact native cache key includes the source pin, all build flags, compiler,
# target baseline and tools/environment that can affect generated C sources.
recipe=$(sha256sum "${BASH_SOURCE[0]}" | cut -d ' ' -f1)
zig_version=$(zig version)
fingerprint=$({
    printf '%s\n' "$1" "$recipe" "$zig_version"
    cat /etc/os-release
    flex --version
    bison --version
    make --version
} | sha256sum | cut -d ' ' -f1)
key="libpcap-$target-glibc2.28-zig$zig_version-$fingerprint"
case "${2:-}" in
    --cache-key) printf '%s\n' "$key"; exit 0 ;;
    '') ;;
    *) echo 'Unknown build option' >&2; exit 2 ;;
esac
mkdir -p "$native"
cache_valid() {
    [[ -s $prefix/lib/libpcap.a && -s $prefix/include/pcap/pcap.h && -s $prefix/LICENSE && -s $prefix/lib/pkgconfig/libpcap.pc ]] || return 1
    [[ $(cat "$prefix/build-key" 2>/dev/null) == "$key" ]] || return 1
    [[ -z $(find "$prefix/lib" -name '*.so*' -print -quit) ]] || return 1
    (cd "$prefix" && sha256sum -c contents.sha256 >/dev/null 2>&1) || return 1
    zig ar t "$prefix/lib/libpcap.a" >/dev/null 2>&1
}
if cache_valid; then
    echo "libpcap cache HIT: $key"
else
    echo "libpcap cache MISS: $key"
    # This is only the helper's task-owned native installation directory.
    rm -rf "$prefix"
    mkdir -p "$prefix"
    archive="$native/libpcap-$version.tar.xz"
    if [[ ! -f $archive ]]; then
        curl -fSL --connect-timeout 20 --max-time 180 --retry 3 "https://www.tcpdump.org/release/libpcap-$version.tar.xz" -o "$archive"
    fi
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
    work=$(mktemp -d "$native/build.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    tar -xJf "$archive" -C "$work"
    cd "$work/libpcap-$version"
    # Do not compile this archive against the runner's newer glibc headers/libraries.
    unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH CFLAGS CPPFLAGS CXXFLAGS LDFLAGS LIBS
    CC="zig cc -target ${arch}-linux-gnu.2.28 -mcpu=baseline" \
    AR='zig ar' RANLIB='zig ranlib' CFLAGS='-O2 -fPIC' ./configure \
        --build="$(./config.guess)" --host="$target" --prefix="$prefix" --libdir="$prefix/lib" \
        --with-pcap=linux --disable-shared --without-libnl --disable-dbus --disable-rdma \
        --disable-bluetooth --disable-usb --disable-netmap --without-dag --without-septel \
        --without-snf --without-turbocap --without-dpdk --disable-remote
    make -j"$(nproc)"
    make install
    cp LICENSE "$prefix/LICENSE"
    printf '%s\n' "$key" > "$prefix/build-key"
    cd "$root"
fi
# Relocate both absolute fields after restoring from a different checkout.
python3 - "$prefix" <<'PY'
import pathlib
import sys
prefix = pathlib.Path(sys.argv[1])
pc = prefix / 'lib/pkgconfig/libpcap.pc'
escaped_prefix = str(prefix).replace('\\', '\\\\').replace(' ', '\\ ')
lines = pc.read_text().splitlines()
pc.write_text('\n'.join(
    'prefix=' + escaped_prefix if line.startswith('prefix=') else
    'libdir=${prefix}/lib' if line.startswith('libdir=') else line
    for line in lines
) + '\n')
PY
(cd "$prefix" && find include lib LICENSE -type f -print0 | sort -z | xargs -0 sha256sum > contents.sha256)
# LIBPCAP_LIBDIR bypasses the pcap crate's pkg-config static-link selection.
unset LIBPCAP_LIBDIR LIBPCAP_NO_PKG_CONFIG LIBPCAP_DYNAMIC PKG_CONFIG_ALL_STATIC PKG_CONFIG_ALL_DYNAMIC PKG_CONFIG_SYSROOT_DIR SYSROOT
export LIBPCAP_STATIC=1 LIBPCAP_VER="$version" PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig" PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
test -s "$prefix/lib/libpcap.a"
test "$(pkg-config --modversion libpcap)" = "$version"
# pcap embeds archive members in its rlib; do not reuse them after rebuilding libpcap.
cargo clean --package pcap --release --target "$target"
cargo zigbuild --release --locked --target "$1"
# Preserve upstream notices without changing the installer's two-file archive format.
cp LICENSE "target/$target/release/LICENSE"
printf '\n\n===== Bundled libpcap %s license =====\n\n' "$version" >> "target/$target/release/LICENSE"
cat "$prefix/LICENSE" >> "target/$target/release/LICENSE"
