#!/usr/bin/env bash
# FlowLens installer fixture tests.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${ROOT}/install.sh"
FIXTURES="${ROOT}/tests/install/fixtures"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/flowlens-install-test.XXXXXX")"
WORKDIR="$(cd "${WORKDIR}" && pwd)"
FIXTURE_MV="$(command -v mv)"
export FIXTURE_MV
PASS=0
FAIL=0
SERVER_PID=""

cleanup() {
  stop_server
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

fail() {
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n' "$1"
}

pass() {
  PASS=$((PASS + 1))
  printf 'ok: %s\n' "$1"
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local name="$3"
  if [ "${actual}" = "${expected}" ]; then
    pass "${name}"
  else
    fail "${name}: expected '${expected}', got '${actual}'"
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local name="$3"
  case "${haystack}" in
    *"${needle}"*) pass "${name}" ;;
    *) fail "${name}: missing '${needle}'"; printf '%s\n' "${haystack}" ;;
  esac
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local name="$3"
  case "${haystack}" in
    *"${needle}"*) fail "${name}: unexpected '${needle}'" ;;
    *) pass "${name}" ;;
  esac
}

assert_file() {
  if [ -f "$1" ]; then
    pass "$2"
  else
    fail "$2: missing $1"
  fi
}

assert_not_file() {
  if [ -f "$1" ]; then
    fail "$2: unexpected $1"
  else
    pass "$2"
  fi
}

python_bin() {
  local candidate base
  candidate="$(command -v python3 2>/dev/null || true)"
  if [ -n "${candidate}" ]; then
    case "${candidate}" in
      *shims*) ;;
      *) printf '%s\n' "${candidate}"; return ;;
    esac
  fi
  if [ -n "${USERPROFILE:-}" ]; then
    base="${USERPROFILE//\\//}"
    candidate="${base}/.pyenv/pyenv-win/versions/3.13.7/python.exe"
    if [ -f "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return
    fi
  fi
  command -v python3 || command -v python
}

install_fake_uname() {
  local os="$1"
  local arch="$2"
  mkdir -p "${WORKDIR}/bin"
  cat > "${WORKDIR}/bin/uname" <<EOF
#!/bin/sh
if [ "\$1" = "-s" ]; then echo "${os}"; exit 0; fi
if [ "\$1" = "-m" ]; then echo "${arch}"; exit 0; fi
echo "${os}"
EOF
  chmod +x "${WORKDIR}/bin/uname"
}

run_installer() {
  local out_file="$1"
  local script="$2"
  shift 2
  set +e
  (
    cd "${WORKDIR}"
    HOME="${TEST_HOME}"
    export HOME
    # PATH change is confined to this subshell.
    # shellcheck disable=SC2030
    PATH="${WORKDIR}/bin:${PATH}"
    export PATH
    SHELL="/bin/bash"
    export SHELL
    bash "${script}" "$@"
  ) >"${out_file}" 2>&1
  echo "$?"
  set -e
}

json_parse() {
  awk -f "${ROOT}/install-json.awk" "$1"
}

start_server() {
  local mode="$1"
  local port_file="${WORKDIR}/port"
  local pid_file="${WORKDIR}/server.pid"
  local waited=0
  rm -f "${port_file}" "${pid_file}"
  "${PYTHON}" -u "${ROOT}/tests/install/http_server.py" \
    --root "${WORKDIR}/www" --mode "${mode}" --port-file "${port_file}" --pid-file "${pid_file}" \
    >/dev/null 2>"${WORKDIR}/server.err" &
  SERVER_BASH_PID=$!
  while [ "${waited}" -lt 15 ]; do
    if [ -s "${port_file}" ] && [ -s "${pid_file}" ]; then
      break
    fi
    if ! kill -0 "${SERVER_BASH_PID}" >/dev/null 2>&1; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  SERVER_PORT=""
  SERVER_PID=""
  if [ -s "${port_file}" ]; then
    SERVER_PORT="$(tr -d '[:space:]' < "${port_file}")"
  fi
  if [ -s "${pid_file}" ]; then
    SERVER_PID="$(tr -d '[:space:]' < "${pid_file}")"
  fi
  if [ -z "${SERVER_PORT}" ] || [ -z "${SERVER_PID}" ]; then
    fail "http fixture server started"
    printf 'python=%s\n' "${PYTHON}"
    if [ -f "${WORKDIR}/server.err" ]; then
      cat "${WORKDIR}/server.err" || true
    fi
    return 1
  fi
  pass "http fixture server started on ${SERVER_PORT}"
}

stop_server() {
  if [ -n "${SERVER_BASH_PID:-}" ]; then
    kill "${SERVER_BASH_PID}" >/dev/null 2>&1 || true
    SERVER_BASH_PID=""
  fi
  SERVER_PID=""
}

make_test_installer() {
  prepare_runtime_mocks
  SYSTEM_BIN="${WORKDIR}/system/bin"
  SYSTEM_MANIFEST="${WORKDIR}/system/share/flowlens"
  # Keep shell expressions literal in the fixture's permission check.
  # shellcheck disable=SC2016
  sed -e "s#https://api.github.com#http://127.0.0.1:${SERVER_PORT}#g" \
      -e "s#https://github.com#http://127.0.0.1:${SERVER_PORT}#g" \
      -e "s#/usr/local/bin#${SYSTEM_BIN}#g" \
      -e "s#/usr/local/share/flowlens#${SYSTEM_MANIFEST}#g" \
      -e 's/\[ -w "${MANIFEST_DIR}" \]/[ "${FIXTURE_MANIFEST_WRITABLE:-1}" -eq 1 ] \&\& [ -w "${MANIFEST_DIR}" ]/' \
      -e "s#/etc/os-release#${WORKDIR}/os-release#g" \
      -e "s#/usr/sbin /sbin#${WORKDIR}/tools#g" \
      -e "s#command -v apt-get#test -x ${WORKDIR}/bin/apt-get#g" \
      -e "s#command -v apt-cache#test -x ${WORKDIR}/bin/apt-cache#g" \
      -e "s#command -v dnf#test -x ${WORKDIR}/bin/dnf#g" \
      -e "s#command -v yum#test -x ${WORKDIR}/bin/yum#g" \
      -e 's/command -v "${name}" 2>\/dev\/null/test -x "${FIXTURE_RUNTIME_ROOT}\/bin\/${name}" \&\& printf "%s\\n" "${FIXTURE_RUNTIME_ROOT}\/bin\/${name}"/' \
      "${INSTALL_SH}" > "${WORKDIR}/install.sh"
}

assert_command_line() {
  if grep -Fqx "  $2" "$1"; then pass "$3"; else fail "$3: no standalone $2"; cat "$1"; fi
}

prepare_runtime_mocks() {
  FIXTURE_RUNTIME_ROOT="${WORKDIR}"
  export FIXTURE_RUNTIME_ROOT
  mkdir -p "${WORKDIR}/bin"
  printf 'ID=debian\n' > "${WORKDIR}/os-release"
  : > "${WORKDIR}/runtime-present"
  : > "${WORKDIR}/libpcap.so.0.8"
  : > "${WORKDIR}/packages.log"
  printf "installer stdin must remain unread\n" > "${WORKDIR}/script-stdin"
  cat > "${WORKDIR}/bin/ldd" <<'EOF'
#!/bin/sh
[ "${FIXTURE_REQUIRE_C_LOCALE:-0}" -eq 0 ] || [ "${LC_ALL:-}" = C ] || { echo 'localized loader output'; exit 1; }
[ "${FIXTURE_LOADER_FAIL:-0}" -eq 0 ] || { echo 'wrong ELF architecture'; exit 1; }
if [ -f "${FIXTURE_RUNTIME_ROOT}/runtime-present" ] && [ "${FIXTURE_UNRESOLVED:-0}" -eq 0 ]; then
  printf 'libpcap.so.0.8 => %s/libpcap.so.0.8 (0x1234)\n' "${FIXTURE_RUNTIME_ROOT}"
else
  echo 'libpcap.so.0.8 => not found'
fi
EOF
  cat > "${WORKDIR}/bin/apt-cache" <<'EOF'
#!/bin/sh
[ "${FIXTURE_REQUIRE_C_LOCALE:-0}" -eq 0 ] || [ "${LC_ALL:-}" = C ] || { echo 'Localized-Candidate: 1.10.5'; exit 1; }
printf 'Candidate: %s\n' "${FIXTURE_APT_CANDIDATE:-1.10.5}"
EOF
  cat > "${WORKDIR}/bin/package-manager" <<'EOF'
#!/bin/sh
# The installer must supply /dev/null, not its script.
if IFS= read -r line; then echo "consumed stdin: ${line}" >> "${FIXTURE_RUNTIME_ROOT}/packages.log"; exit 99; fi
printf '%s %s frontend=%s\n' "$(basename "$0")" "$*" "${DEBIAN_FRONTEND:-}" >> "${FIXTURE_RUNTIME_ROOT}/packages.log"
[ "${FIXTURE_PACKAGE_FAIL:-}" != "$1" ] || exit 1
[ "$1" = install ] || exit 0
[ "${FIXTURE_PACKAGE_NO_RUNTIME:-0}" -eq 1 ] || touch "${FIXTURE_RUNTIME_ROOT}/runtime-present"
case "$*" in
  *libcap*)
    [ "${FIXTURE_PACKAGE_NO_SETCAP:-0}" -eq 1 ] && exit 0
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" > "%s/setcap.args"\n' "${FIXTURE_RUNTIME_ROOT}" > "${FIXTURE_RUNTIME_ROOT}/bin/setcap"
    chmod +x "${FIXTURE_RUNTIME_ROOT}/bin/setcap"
    ;;
esac
EOF
  local manager
  for manager in apt-get dnf yum; do
    cp "${WORKDIR}/bin/package-manager" "${WORKDIR}/bin/${manager}"
  done
  chmod +x "${WORKDIR}/bin/ldd" "${WORKDIR}/bin/apt-cache" "${WORKDIR}/bin/apt-get" "${WORKDIR}/bin/dnf" "${WORKDIR}/bin/yum"
}

prepare_assets() {
  mkdir -p "${WORKDIR}/www/v0.3.0" "${WORKDIR}/pack"
  cp "${FIXTURES}/api/latest-pretty.json" "${WORKDIR}/www/latest.json"
  printf '%s\n' '#!/bin/sh' 'echo flowlens-fixture' > "${WORKDIR}/pack/flowlens"
  chmod 0755 "${WORKDIR}/pack/flowlens"
  tar -C "${WORKDIR}/pack" -czf "${WORKDIR}/www/v0.3.0/flowlens-v0.3.0-linux-x86_64.tar.gz" flowlens
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "${WORKDIR}/www/v0.3.0/flowlens-v0.3.0-linux-x86_64.tar.gz" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "${WORKDIR}/www/v0.3.0/flowlens-v0.3.0-linux-x86_64.tar.gz" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "${digest}" "flowlens-v0.3.0-linux-x86_64.tar.gz" > "${WORKDIR}/www/v0.3.0/SHA256SUMS"
}

require_installer() {
  if [ ! -f "${INSTALL_SH}" ]; then
    fail "install.sh exists"
    printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
    exit 1
  fi
  pass "install.sh exists"
}

test_json_fixtures() {
  local out tag prerelease draft
  out="$(json_parse "${FIXTURES}/api/latest-compact.json")" || fail "parse compact JSON"
  tag="$(printf '%s\n' "${out}" | awk -F= '$1=="tag_name"{print $2}')"
  prerelease="$(printf '%s\n' "${out}" | awk -F= '$1=="prerelease"{print $2}')"
  draft="$(printf '%s\n' "${out}" | awk -F= '$1=="draft"{print $2}')"
  assert_eq "${tag}" "v0.3.0" "compact JSON tag_name"
  assert_eq "${prerelease}" "false" "compact JSON prerelease"
  assert_eq "${draft}" "false" "compact JSON draft"

  out="$(json_parse "${FIXTURES}/api/latest-pretty.json")" || fail "parse pretty JSON"
  tag="$(printf '%s\n' "${out}" | awk -F= '$1=="tag_name"{print $2}')"
  assert_eq "${tag}" "v0.3.0" "pretty JSON tag_name"

  out="$(json_parse "${FIXTURES}/api/latest-reordered.json")" || fail "parse reordered JSON"
  tag="$(printf '%s\n' "${out}" | awk -F= '$1=="tag_name"{print $2}')"
  assert_eq "${tag}" "v0.3.0" "reordered JSON tag_name"

  out="$(json_parse "${FIXTURES}/api/latest-forged-body.json")" || fail "parse forged-body JSON"
  tag="$(printf '%s\n' "${out}" | awk -F= '$1=="tag_name"{print $2}')"
  prerelease="$(printf '%s\n' "${out}" | awk -F= '$1=="prerelease"{print $2}')"
  assert_eq "${tag}" "v0.3.0" "forged-body JSON ignores string field"
  assert_eq "${prerelease}" "false" "forged-body JSON prerelease"

  if json_parse "${FIXTURES}/api/latest-missing-draft.json" >/dev/null 2>&1; then
    fail "missing draft is rejected"
  else
    pass "missing draft is rejected"
  fi
  if json_parse "${FIXTURES}/api/latest-duplicate-tag.json" >/dev/null 2>&1; then
    fail "duplicate tag_name is rejected"
  else
    pass "duplicate tag_name is rejected"
  fi
  if json_parse "${FIXTURES}/api/latest-wrong-type.json" >/dev/null 2>&1; then
    fail "wrong boolean type is rejected"
  else
    pass "wrong boolean type is rejected"
  fi
  if json_parse "${FIXTURES}/api/latest-trailing-garbage.json" >/dev/null 2>&1; then
    fail "trailing garbage is rejected"
  else
    pass "trailing garbage is rejected"
  fi
  if json_parse "${FIXTURES}/api/latest-truncated.json" >/dev/null 2>&1; then
    fail "truncated JSON is rejected"
  else
    pass "truncated JSON is rejected"
  fi
}

test_help_exits_zero() {
  local out status
  out="${WORKDIR}/help.out"
  status="$(run_installer "${out}" "${INSTALL_SH}" --help)"
  assert_eq "${status}" "0" "--help exits 0"
  assert_contains "$(cat "${out}")" "Usage" "--help prints usage"
}

test_invalid_version_exits_2() {
  local version status out
  for version in v0.3 v0.3.0-rc1 0.3.0 v00.3.0 v0.03.0 v0.3.0.1 v2147483648.0.0; do
    out="${WORKDIR}/bad-version.out"
    status="$(run_installer "${out}" "${INSTALL_SH}" --version "${version}" --install-dir "${WORKDIR}/bin-install")"
    assert_eq "${status}" "2" "--version ${version} exits 2"
  done
}

test_old_version_exits_2() {
  local out status
  out="${WORKDIR}/old-version.out"
  status="$(run_installer "${out}" "${INSTALL_SH}" --version v0.2.0 --install-dir "${WORKDIR}/bin-install")"
  assert_eq "${status}" "2" "--version v0.2.0 exits 2"
  assert_contains "$(cat "${out}")" "v0.3.0" "--version v0.2.0 mentions minimum version"
}

test_conflicting_dir_flags_exit_2() {
  local out status
  out="${WORKDIR}/conflict.out"
  status="$(run_installer "${out}" "${INSTALL_SH}" --system --install-dir "${WORKDIR}/bin-install")"
  assert_eq "${status}" "2" "--system with --install-dir exits 2"
  status="$(FLOWLENS_INSTALL_DIR="${WORKDIR}/env-bin" run_installer "${out}" "${INSTALL_SH}" --system)"
  assert_eq "${status}" "2" "--system with FLOWLENS_INSTALL_DIR exits 2"
  status="$(run_installer "${out}" "${INSTALL_SH}" --user --system)"
  assert_eq "${status}" "2" "--user --system exits 2"
  status="$(run_installer "${out}" "${INSTALL_SH}" --system --user --uninstall)"
  assert_eq "${status}" "2" "--system --user --uninstall exits 2"
}

test_uninstall_rejects_version() {
  local out status
  out="${WORKDIR}/uninstall-version.out"
  status="$(run_installer "${out}" "${INSTALL_SH}" --uninstall --version v0.3.0)"
  assert_eq "${status}" "2" "--uninstall --version exits 2"
}

test_unsupported_os_exits_3_before_network() {
  local out status
  out="${WORKDIR}/bad-os.out"
  install_fake_uname FreeBSD x86_64
  status="$(run_installer "${out}" "${INSTALL_SH}" --version v0.3.0 --install-dir "${WORKDIR}/bin-install")"
  assert_eq "${status}" "3" "unsupported OS exits 3"
}

test_macos_exits_3_before_network() {
  local arch out status
  for arch in x86_64 arm64; do
    out="${WORKDIR}/macos-${arch}.out"
    install_fake_uname Darwin "${arch}"
    status="$(run_installer "${out}" "${INSTALL_SH}" --version v0.3.0 --install-dir "${WORKDIR}/bin-install")"
    assert_eq "${status}" "3" "macOS ${arch} exits 3"
    assert_contains "$(cat "${out}")" "experimental" "macOS ${arch} explains experimental status"
  done
}

test_http_404() {
  local out status
  out="${WORKDIR}/http-404.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.4.0 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "4" "HTTP 404 exits 4"
  assert_contains "$(cat "${out}")" "404" "HTTP 404 mentions status"
}

test_http_403_rate_limit() {
  local out status
  : > "${WORKDIR}/www/force_403"
  out="${WORKDIR}/http-403.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --install-dir "${WORKDIR}/opt/bin")"
  rm -f "${WORKDIR}/www/force_403"
  assert_eq "${status}" "4" "HTTP 403 rate limit exits 4"
  assert_contains "$(cat "${out}")" "rate limit" "HTTP 403 mentions rate limit"
}

test_dry_run_install() {
  local out status
  out="${WORKDIR}/dry-run.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0 --install-dir "${WORKDIR}/opt/bin" --dry-run)"
  assert_eq "${status}" "0" "dry-run install exits 0"
  assert_not_file "${WORKDIR}/opt/bin/flowlens" "dry-run does not write binary"
  assert_not_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "dry-run does not write manifest"
  assert_contains "$(cat "${out}")" "dry-run" "dry-run reports actions"
  assert_contains "$(cat "${out}")" "glibc 2.28" "dry-run mentions glibc 2.28"
  assert_contains "$(cat "${out}")" "libpcap" "dry-run mentions libpcap"
  assert_contains "$(cat "${out}")" "CAP_NET_RAW" "dry-run mentions CAP_NET_RAW"
  assert_contains "$(cat "${out}")" "--setcap" "dry-run mentions --setcap"
}

test_install_and_uninstall() {
  local out status
  out="${WORKDIR}/install.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "install exits 0"
  assert_file "${WORKDIR}/opt/bin/flowlens" "install writes binary"
  assert_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "install writes manifest"
  assert_file "${TEST_HOME}/.bashrc" "default bash PATH file is created"
  assert_contains "$(cat "${TEST_HOME}/.bashrc")" "flowlens installer" "PATH marker is written"
  assert_command_line "${out}" "source '${TEST_HOME}/.bashrc'" "source hint is standalone"
  assert_contains "$(cat "${out}")" "glibc 2.28" "install mentions glibc 2.28"
  assert_contains "$(cat "${out}")" "libpcap" "install mentions libpcap"
  assert_contains "$(cat "${out}")" "CAP_NET_RAW" "install mentions CAP_NET_RAW"
  assert_contains "$(cat "${out}")" "--setcap" "install mentions --setcap"
  chmod a-x "${WORKDIR}/opt/bin/flowlens" 2>/dev/null || true
  out="${WORKDIR}/uninstall.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "uninstall exits 0"
  assert_not_file "${WORKDIR}/opt/bin/flowlens" "uninstall removes binary"
  assert_not_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "uninstall removes manifest"
}

test_no_modify_path_prints_hint() {
  local out status
  out="${WORKDIR}/no-path.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0 --install-dir "${WORKDIR}/opt/bin" --no-modify-path)"
  assert_eq "${status}" "0" "--no-modify-path install exits 0"
  assert_contains "$(cat "${out}")" "PATH was not modified" "--no-modify-path mentions PATH"
  assert_contains "$(cat "${out}")" "${WORKDIR}/opt/bin" "--no-modify-path names install dir"
  assert_command_line "${out}" "export PATH='${WORKDIR}/opt/bin':\$PATH" "PATH hint is standalone"
  chmod a-x "${WORKDIR}/opt/bin/flowlens" 2>/dev/null || true
  status="$(run_installer "${WORKDIR}/no-path-uninstall.out" "${WORKDIR}/install.sh" --uninstall --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "--no-modify-path uninstall exits 0"
}

write_sums_for() {
  local archive="$1"
  local version="$2"
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "${archive}" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "${archive}" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "${digest}" "flowlens-${version}-linux-x86_64.tar.gz" > "${WORKDIR}/www/${version}/SHA256SUMS"
}

install_fake_setcap() {
  local exit_code="$1"
  cat > "${WORKDIR}/bin/setcap" <<EOF
#!/bin/sh
printf '%s\n' "\$*" > "${WORKDIR}/setcap.args"
exit ${exit_code}
EOF
  chmod +x "${WORKDIR}/bin/setcap"
}

test_sha256_mismatch_exits_5() {
  local out status
  mkdir -p "${WORKDIR}/www/v0.3.4"
  cat "${WORKDIR}/www/v0.3.0/flowlens-v0.3.0-linux-x86_64.tar.gz" > "${WORKDIR}/www/v0.3.4/flowlens-v0.3.4-linux-x86_64.tar.gz"
  printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  flowlens-v0.3.4-linux-x86_64.tar.gz\n' > "${WORKDIR}/www/v0.3.4/SHA256SUMS"
  out="${WORKDIR}/bad-hash.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.4 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "5" "SHA-256 mismatch exits 5"
  assert_not_file "${WORKDIR}/opt/bin/flowlens" "SHA-256 mismatch does not install binary"
}

test_archive_extra_file_exits_5() {
  local out status
  mkdir -p "${WORKDIR}/pack-extra" "${WORKDIR}/www/v0.3.1"
  printf '%s\n' '#!/bin/sh' 'echo flowlens-fixture' > "${WORKDIR}/pack-extra/flowlens"
  printf 'x\n' > "${WORKDIR}/pack-extra/extra.txt"
  chmod 0755 "${WORKDIR}/pack-extra/flowlens"
  tar -C "${WORKDIR}/pack-extra" -czf "${WORKDIR}/www/v0.3.1/flowlens-v0.3.1-linux-x86_64.tar.gz" flowlens extra.txt
  write_sums_for "${WORKDIR}/www/v0.3.1/flowlens-v0.3.1-linux-x86_64.tar.gz" v0.3.1
  out="${WORKDIR}/extra.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.1 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "5" "archive extra file exits 5"
}

test_gpl_archive_requires_license() {
  local out status
  mkdir -p "${WORKDIR}/pack-gpl" "${WORKDIR}/www/v0.7.1" "${WORKDIR}/www/v0.7.2"
  printf '%s\n' '#!/bin/sh' 'echo flowlens-fixture' > "${WORKDIR}/pack-gpl/flowlens"
  cp "${ROOT}/LICENSE" "${WORKDIR}/pack-gpl/LICENSE"
  chmod 0755 "${WORKDIR}/pack-gpl/flowlens"

  tar -C "${WORKDIR}/pack-gpl" -czf "${WORKDIR}/www/v0.7.1/flowlens-v0.7.1-linux-x86_64.tar.gz" flowlens LICENSE
  write_sums_for "${WORKDIR}/www/v0.7.1/flowlens-v0.7.1-linux-x86_64.tar.gz" v0.7.1
  out="${WORKDIR}/gpl-license.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --dry-run --version v0.7.1 --install-dir "${WORKDIR}/gpl/bin")"
  assert_eq "${status}" "0" "GPL archive with LICENSE is accepted"

  tar -C "${WORKDIR}/pack-gpl" -czf "${WORKDIR}/www/v0.7.2/flowlens-v0.7.2-linux-x86_64.tar.gz" flowlens
  write_sums_for "${WORKDIR}/www/v0.7.2/flowlens-v0.7.2-linux-x86_64.tar.gz" v0.7.2
  out="${WORKDIR}/gpl-missing-license.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --dry-run --version v0.7.2 --install-dir "${WORKDIR}/gpl/bin")"
  assert_eq "${status}" "5" "GPL archive without LICENSE exits 5"
}

test_archive_path_traversal_exits_5() {
  local out status
  mkdir -p "${WORKDIR}/pack-trav/sub" "${WORKDIR}/www/v0.3.2"
  printf '%s\n' '#!/bin/sh' 'echo flowlens-fixture' > "${WORKDIR}/pack-trav/sub/flowlens"
  chmod 0755 "${WORKDIR}/pack-trav/sub/flowlens"
  tar -C "${WORKDIR}/pack-trav" -czf "${WORKDIR}/www/v0.3.2/flowlens-v0.3.2-linux-x86_64.tar.gz" sub/flowlens
  write_sums_for "${WORKDIR}/www/v0.3.2/flowlens-v0.3.2-linux-x86_64.tar.gz" v0.3.2
  out="${WORKDIR}/trav.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.2 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "5" "archive path traversal exits 5"
}

test_setcap_non_linux_exits_2() {
  local out status
  install_fake_uname Darwin x86_64
  out="${WORKDIR}/setcap-darwin.out"
  status="$(run_installer "${out}" "${INSTALL_SH}" --setcap --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  install_fake_uname Linux x86_64
  assert_eq "${status}" "2" "--setcap on macOS exits 2"
}

test_setcap_missing_exits_6() {
  local out status
  rm -f "${WORKDIR}/bin/setcap"
  out="${WORKDIR}/setcap-missing.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --setcap --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "6" "--setcap without setcap gives dependency failure"
  assert_command_line "${out}" "sudo apt-get install -y libcap2-bin" "missing setcap gives standalone command"
}

test_setcap_failure_rolls_back() {
  local out status old
  rm -f "${WORKDIR}/bin/setcap"
  out="${WORKDIR}/setcap-base.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "base install before setcap failure"
  old="$(cat "${WORKDIR}/opt/bin/flowlens")"
  chmod a-x "${WORKDIR}/opt/bin/flowlens" 2>/dev/null || true
  install_fake_setcap 1
  out="${WORKDIR}/setcap-fail.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --setcap --force --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  rm -f "${WORKDIR}/bin/setcap"
  assert_eq "${status}" "1" "setcap failure exits 1"
  assert_eq "$(cat "${WORKDIR}/opt/bin/flowlens")" "${old}" "setcap failure keeps previous binary"
}

test_setcap_success_records_manifest() {
  local out status
  chmod a-x "${WORKDIR}/opt/bin/flowlens" 2>/dev/null || true
  install_fake_setcap 0
  out="${WORKDIR}/setcap-ok.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --setcap --force --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "--setcap install exits 0"
  assert_contains "$(cat "${TEST_HOME}/.local/share/flowlens/install-manifest")" "setcap=true" "manifest records setcap=true"
  assert_file "${WORKDIR}/setcap.args" "setcap was invoked"
  assert_contains "$(cat "${out}")" "CAP_NET_RAW" "--setcap install mentions CAP_NET_RAW"
  assert_not_contains "$(cat "${out}")" "Re-run with --setcap" "--setcap install does not ask to re-run --setcap"
  rm -f "${WORKDIR}/bin/setcap"
}

test_manifest_publish_failure_rolls_back() {
  local out status old
  assert_file "${WORKDIR}/opt/bin/flowlens" "rollback test has an installed binary"
  old="$(cat "${WORKDIR}/opt/bin/flowlens")"
  chmod a-x "${WORKDIR}/opt/bin/flowlens" 2>/dev/null || true
  cat > "${WORKDIR}/bin/mv" <<'EOF'
#!/bin/sh
dest="$1"
for dest do :; done
case "$dest" in
  */install-manifest)
    exit 1
    ;;
esac
"${FIXTURE_MV}" "$@"
EOF
  chmod +x "${WORKDIR}/bin/mv"
  out="${WORKDIR}/rb.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --force --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  rm -f "${WORKDIR}/bin/mv"
  assert_eq "${status}" "1" "manifest publish failure exits 1"
  assert_contains "$(cat "${out}")" "failed to publish manifest" "failure reaches manifest publication"
  assert_eq "$(cat "${WORKDIR}/opt/bin/flowlens")" "${old}" "manifest publish failure restores binary"
}

install_fake_privileges() {
  cat > "${WORKDIR}/bin/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-u" ]; then printf '%s\n' "${FIXTURE_UID:-1001}"; exit 0; fi
exit 1
EOF
  cat > "${WORKDIR}/bin/sudo" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${FIXTURE_SUDO_LOG}"
[ "$1" = "-n" ] || exit 99
[ "${FIXTURE_SUDO_FAIL:-0}" -eq 0 ] || exit 1
shift
"$@"
EOF
  chmod +x "${WORKDIR}/bin/id" "${WORKDIR}/bin/sudo"
  FIXTURE_SUDO_LOG="${WORKDIR}/sudo.log"
  export FIXTURE_SUDO_LOG
  : > "${FIXTURE_SUDO_LOG}"
}

test_system_sudo_n_fails_closed() {
  local out status scope
  install_fake_privileges
  # A writable binary directory must not hide a manifest directory that needs sudo.
  mkdir -p "${SYSTEM_BIN}"
  out="${WORKDIR}/system.out"
  for scope in default explicit; do
    if [ "${scope}" = default ]; then
      status="$(FIXTURE_SUDO_FAIL=1 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
    else
      status="$(FIXTURE_SUDO_FAIL=1 run_installer "${out}" "${WORKDIR}/install.sh" --system --version v0.3.0)"
    fi
    assert_eq "${status}" "6" "${scope} system install without sudo -n exits 6"
    assert_contains "$(cat "${out}")" "sudo -n failed" "${scope} system install explains noninteractive failure"
    assert_contains "$(cat "${out}")" "sudo bash install.sh" "${scope} system install gives sudo direction"
    assert_contains "$(cat "${out}")" "--user" "${scope} system install gives user direction"
  done
  assert_eq "$(cat "${FIXTURE_SUDO_LOG}")" "$(printf '%s\n' '-n true' '-n true')" "sudo is only called noninteractively"
  assert_not_file "${SYSTEM_BIN}/flowlens" "sudo failure does not install system binary"
  assert_not_file "${TEST_HOME}/.local/bin/flowlens" "sudo failure does not fall back to user install"
  status="$(FIXTURE_SUDO_FAIL=1 run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "6" "default uninstall requires system privileges"
  assert_contains "$(cat "${out}")" "sudo bash install.sh --uninstall" "uninstall privilege failure gives system command"
  assert_contains "$(cat "${out}")" "original user without sudo" "uninstall privilege failure gives user direction"
}

test_system_scope_and_manifest_publication() {
  local out status old_binary old_manifest
  local TEST_HOME="${WORKDIR}/system-home"
  mkdir -p "${TEST_HOME}"
  : > "${FIXTURE_SUDO_LOG}"
  out="${WORKDIR}/system-install.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "default system install exits 0"
  assert_file "${SYSTEM_BIN}/flowlens" "default install writes system binary"
  assert_file "${SYSTEM_MANIFEST}/install-manifest" "default install writes system manifest"
  assert_not_file "${TEST_HOME}/.local/bin/flowlens" "default install does not write user binary"
  assert_not_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "default install does not write user manifest"
  assert_not_file "${TEST_HOME}/.bashrc" "system install does not modify shell PATH"
  assert_contains "$(cat "${out}")" "sudo flowlens" "system launch hint gives command"
  assert_contains "$(cat "${out}")" "sudo '${SYSTEM_BIN}/flowlens'" "system launch hint gives absolute fallback"
  assert_contains "$(cat "${SYSTEM_MANIFEST}/install-manifest")" "binary_path=${SYSTEM_BIN}/flowlens" "system manifest records system binary"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "/install-manifest ${SYSTEM_MANIFEST}/install-manifest.new." "manifest is staged then copied with privileges"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "-n chmod 0644 ${SYSTEM_MANIFEST}/install-manifest.new." "manifest permissions are set with privileges"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "-n mv -f ${SYSTEM_MANIFEST}/install-manifest.new." "manifest publication uses privileged atomic rename"
  old_binary="$(cat "${SYSTEM_BIN}/flowlens")"
  old_manifest="$(cat "${SYSTEM_MANIFEST}/install-manifest")"
  mkdir -p "${WORKDIR}/pack-update" "${WORKDIR}/www/v0.3.5"
  printf '%s\n' '#!/bin/sh' 'echo flowlens-updated-fixture' > "${WORKDIR}/pack-update/flowlens"
  tar -C "${WORKDIR}/pack-update" -czf "${WORKDIR}/www/v0.3.5/flowlens-v0.3.5-linux-x86_64.tar.gz" flowlens
  write_sums_for "${WORKDIR}/www/v0.3.5/flowlens-v0.3.5-linux-x86_64.tar.gz" v0.3.5
  # Model a protected system manifest directory even on hosts without Unix permissions.
  cat > "${WORKDIR}/bin/mv" <<'EOF'
#!/bin/sh
case "$*" in
  *install-manifest.new.*) exit 1 ;;
esac
"${FIXTURE_MV}" "$@"
EOF
  chmod +x "${WORKDIR}/bin/mv"
  : > "${FIXTURE_SUDO_LOG}"
  status="$(FIXTURE_MANIFEST_WRITABLE=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.5)"
  rm -f "${WORKDIR}/bin/mv"
  assert_eq "${status}" "1" "privileged manifest publication failure exits 1"
  assert_contains "$(cat "${out}")" "failed to publish manifest" "privileged failure reaches manifest publication"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "-n cp -p ${SYSTEM_BIN}/flowlens" "binary rollback snapshot preserves ownership and mode with privileges"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "-n cp -p ${SYSTEM_MANIFEST}/install-manifest" "manifest rollback snapshot preserves ownership and mode with privileges"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "/rollback-binary ${SYSTEM_BIN}/flowlens" "privileged rollback restores binary"
  assert_contains "$(cat "${FIXTURE_SUDO_LOG}")" "/rollback-manifest ${SYSTEM_MANIFEST}/install-manifest" "privileged rollback restores manifest"
  assert_file "${SYSTEM_BIN}/flowlens" "privileged rollback retains installed binary"
  assert_file "${SYSTEM_MANIFEST}/install-manifest" "privileged rollback retains installed manifest"
  assert_eq "$(cat "${SYSTEM_BIN}/flowlens")" "${old_binary}" "privileged rollback restores original binary content after upgrade"
  assert_eq "$(cat "${SYSTEM_MANIFEST}/install-manifest")" "${old_manifest}" "privileged rollback restores original manifest content after upgrade"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "0" "default uninstall exits 0"
  assert_not_file "${SYSTEM_BIN}/flowlens" "default uninstall removes system binary"
  assert_not_file "${SYSTEM_MANIFEST}/install-manifest" "default uninstall removes system manifest"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --system --version v0.3.0)"
  assert_eq "${status}" "0" "explicit --system install exits 0"
  assert_file "${SYSTEM_BIN}/flowlens" "explicit --system writes system binary"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --system --uninstall)"
  assert_eq "${status}" "0" "explicit --system uninstall exits 0"
  assert_not_file "${SYSTEM_BIN}/flowlens" "explicit --system uninstall removes system binary"
}

test_user_scope_and_custom_dirs() {
  local out status
  local TEST_HOME="${WORKDIR}/user home"
  mkdir -p "${TEST_HOME}"
  out="${WORKDIR}/user-install.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --user --version v0.3.0)"
  assert_eq "${status}" "0" "--user install exits 0"
  assert_file "${TEST_HOME}/.local/bin/flowlens" "--user writes user binary"
  assert_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "--user writes user manifest"
  assert_contains "$(cat "${TEST_HOME}/.bashrc")" "flowlens installer" "--user updates shell PATH"
  assert_contains "$(cat "${out}")" "sudo '${TEST_HOME}/.local/bin/flowlens'" "user launch hint quotes absolute path with spaces"
  assert_contains "$(cat "${out}")" "does not control sudo" "user launch hint distinguishes sudo PATH"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "0" "default uninstall with only a user copy exits 0"
  assert_file "${TEST_HOME}/.local/bin/flowlens" "default uninstall retains user copy"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --user --uninstall)"
  assert_eq "${status}" "0" "--user uninstall exits 0"
  assert_not_file "${TEST_HOME}/.local/bin/flowlens" "--user uninstall removes user binary"
  assert_not_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "--user uninstall removes user manifest"
  assert_not_contains "$(cat "${TEST_HOME}/.bashrc")" "flowlens installer" "--user uninstall removes managed PATH block"
  status="$(FLOWLENS_INSTALL_DIR="${WORKDIR}/env-bin" run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "standalone environment directory install exits 0"
  assert_file "${WORKDIR}/env-bin/flowlens" "environment directory overrides implicit system default"
  assert_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "custom directory keeps user manifest"
  status="$(FLOWLENS_INSTALL_DIR="${WORKDIR}/env-bin" run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "0" "environment directory uninstall exits 0"
  assert_not_file "${WORKDIR}/env-bin/flowlens" "environment directory uninstall removes custom binary"
  status="$(FLOWLENS_INSTALL_DIR="${WORKDIR}/env-bin" run_installer "${out}" "${WORKDIR}/install.sh" --install-dir "${WORKDIR}/cli-bin" --dry-run --version v0.3.0)"
  assert_eq "${status}" "0" "custom CLI directory with environment override exits 0"
  assert_contains "$(cat "${out}")" "to ${WORKDIR}/cli-bin/flowlens" "CLI directory takes precedence over environment"
  status="$(FLOWLENS_INSTALL_DIR="${WORKDIR}/env-bin" run_installer "${out}" "${WORKDIR}/install.sh" --user --dry-run --version v0.3.0)"
  assert_eq "${status}" "0" "--user allows environment directory"
  assert_contains "$(cat "${out}")" "to ${WORKDIR}/env-bin/flowlens" "--user preserves environment directory"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --user --install-dir "relative bin" --dry-run --version v0.3.0)"
  assert_eq "${status}" "0" "--user allows custom relative directory"
  assert_contains "$(cat "${out}")" "sudo '${WORKDIR}/relative bin/flowlens'" "custom relative directory launch hint uses absolute path"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --user --install-dir "${WORKDIR}/user's bin" --dry-run --version v0.3.0)"
  assert_eq "${status}" "0" "custom directory with apostrophe exits 0"
  assert_contains "$(cat "${out}")" "sudo '${WORKDIR}/user'\\''s bin/flowlens'" "launch hint safely quotes apostrophe"
}

test_old_user_install_detection() {
  local out status old_binary old_manifest old_path
  local caller_home="${WORKDIR}/caller home"
  local TEST_HOME="${caller_home}"
  mkdir -p "${TEST_HOME}" "${WORKDIR}/root-home"
  out="${WORKDIR}/migration.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --user --version v0.3.0)"
  assert_eq "${status}" "0" "migration fixture installs user copy"
  old_binary="$(cat "${caller_home}/.local/bin/flowlens")"
  old_manifest="$(cat "${caller_home}/.local/share/flowlens/install-manifest")"
  old_path="$(cat "${caller_home}/.bashrc")"
  cat > "${WORKDIR}/bin/getent" <<EOF
#!/bin/sh
printf '%s\n' "\$*" > "${WORKDIR}/getent.args"
printf '%s\n' 'fixture-user:x:1001:1001::${caller_home}:/bin/bash'
EOF
  chmod +x "${WORKDIR}/bin/getent"
  TEST_HOME="${WORKDIR}/root-home"
  status="$(FIXTURE_UID=0 SUDO_USER=fixture-user SUDO_UID=1001 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "sudo caller system install exits 0"
  assert_eq "$(cat "${WORKDIR}/getent.args")" "passwd fixture-user" "sudo caller home is resolved through account lookup"
  assert_contains "$(cat "${out}")" "${caller_home}/.local/bin/flowlens may shadow" "warning names original user's copy despite root HOME"
  assert_contains "$(cat "${out}")" "bash install.sh --user --uninstall" "managed copy warning gives precise cleanup command"
  assert_contains "$(cat "${out}")" "original user, without sudo" "managed copy cleanup runs without sudo"
  assert_command_line "${out}" "sudo '${SYSTEM_BIN}/flowlens' --version" "managed cleanup version check is standalone"
  assert_command_line "${out}" "sudo '${SYSTEM_BIN}/flowlens'" "managed cleanup launch check is standalone"
  assert_command_line "${out}" "command -v flowlens" "resolution check is standalone"
  assert_eq "$(cat "${caller_home}/.local/bin/flowlens")" "${old_binary}" "system install retains old user binary"
  assert_eq "$(cat "${caller_home}/.local/share/flowlens/install-manifest")" "${old_manifest}" "system install retains old user manifest"
  assert_eq "$(cat "${caller_home}/.bashrc")" "${old_path}" "system install retains old user PATH block"
  status="$(FIXTURE_UID=0 SUDO_USER=fixture-user SUDO_UID=9999 run_installer "${out}" "${WORKDIR}/install.sh" --dry-run --version v0.3.0)"
  assert_eq "${status}" "0" "unresolved sudo caller does not block system install"
  assert_contains "$(cat "${out}")" "could not resolve the sudo caller's home" "sudo caller account UID must match"
  assert_not_contains "$(cat "${out}")" "bash install.sh --user --uninstall" "unresolved caller does not receive guessed cleanup command"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "0" "system uninstall after migration fixture exits 0"
  assert_file "${caller_home}/.local/bin/flowlens" "system uninstall preserves old user copy"
  TEST_HOME="${caller_home}"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --user --uninstall)"
  assert_eq "${status}" "0" "original user can clean up managed old copy"
  printf '#!/bin/sh\ntouch "%s"\n' "${WORKDIR}/old-binary-executed" > "${caller_home}/.local/bin/flowlens"
  chmod +x "${caller_home}/.local/bin/flowlens"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "system install with unmanaged user copy exits 0"
  assert_contains "$(cat "${out}")" "${caller_home}/.local/bin/flowlens may shadow" "ordinary user install also detects old copy"
  assert_contains "$(cat "${out}")" "review and remove it manually" "unmanaged old copy gets manual cleanup guidance"
  assert_not_contains "$(cat "${out}")" "bash install.sh --user --uninstall" "unmanaged copy is not described as uninstallable"
  assert_file "${caller_home}/.local/bin/flowlens" "unmanaged old binary is retained"
  assert_not_file "${WORKDIR}/old-binary-executed" "old user binary is never executed"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "0" "system cleanup after unmanaged fixture exits 0"
  rm -f "${WORKDIR}/bin/getent" "${WORKDIR}/bin/id" "${WORKDIR}/bin/sudo"
}

test_runtime_dependencies() {
  local out="${WORKDIR}/runtime.out" status manager old_binary old_manifest
  install_fake_privileges
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "present runtime needs no setup"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "present runtime does not touch packages"
  assert_command_line "${out}" "sudo flowlens" "default capture command is standalone"
  assert_not_contains "$(cat "${out}")" "sudo setcap" "default install does not require manual capability grant"
  assert_contains "$(cat "${SYSTEM_MANIFEST}/install-manifest")" "setcap=false" "default install grants no capability"
  old_binary="$(cat "${SYSTEM_BIN}/flowlens")"
  old_manifest="$(cat "${SYSTEM_MANIFEST}/install-manifest")"

  rm -f "${WORKDIR}/runtime-present"
  mkdir -p "${WORKDIR}/www/v0.3.9" "${WORKDIR}/bad-pack"
  cp "${WORKDIR}/pack/flowlens" "${WORKDIR}/bad-pack/flowlens"
  : > "${WORKDIR}/bad-pack/extra"
  tar -C "${WORKDIR}/bad-pack" -czf "${WORKDIR}/www/v0.3.9/flowlens-v0.3.9-linux-x86_64.tar.gz" flowlens extra
  printf 'bad-checksum  flowlens-v0.3.9-linux-x86_64.tar.gz\n' > "${WORKDIR}/www/v0.3.9/SHA256SUMS"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.9)"
  assert_eq "${status}" "5" "bad checksum blocks dependency setup"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "bad checksum cannot change packages"
  write_sums_for "${WORKDIR}/www/v0.3.9/flowlens-v0.3.9-linux-x86_64.tar.gz" v0.3.9
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.9)"
  assert_eq "${status}" "5" "invalid archive blocks dependency setup"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "invalid archive cannot change packages"
  cp "${SYSTEM_BIN}/flowlens" "${WORKDIR}/saved-binary"
  printf 'user modified binary\n' > "${SYSTEM_BIN}/flowlens"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "7" "failed overwrite preflight blocks dependency setup"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "failed preflight cannot change packages"
  cp "${WORKDIR}/saved-binary" "${SYSTEM_BIN}/flowlens"

  for manager in apt-get dnf yum; do
    : > "${WORKDIR}/packages.log"
    rm -f "${WORKDIR}/runtime-present"
    if [ "${manager}" = apt-get ]; then
      printf 'ID=ubuntu\nID_LIKE=debian\n' > "${WORKDIR}/os-release"
    else
      printf 'ID=rocky\nID_LIKE="rhel centos fedora"\n' > "${WORKDIR}/os-release"
      [ "${manager}" != yum ] || rm -f "${WORKDIR}/bin/dnf"
    fi
    status="$(LC_ALL=POSIX FIXTURE_REQUIRE_C_LOCALE=1 FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0 < "${WORKDIR}/script-stdin")"
    assert_eq "${status}" "0" "${manager} provisions missing runtime with localized tool output"
    if [ "${manager}" = apt-get ]; then
      assert_contains "$(cat "${WORKDIR}/packages.log")" "apt-get update frontend=noninteractive" "apt refresh is noninteractive"
      assert_contains "$(cat "${WORKDIR}/packages.log")" "apt-get install -y libpcap0.8t64 frontend=noninteractive" "apt selects modern runtime"
    else
      assert_contains "$(cat "${WORKDIR}/packages.log")" "${manager} install -y libpcap" "RPM runtime package"
    fi
    assert_not_contains "$(cat "${WORKDIR}/packages.log")" "libcap" "default setup does not bootstrap setcap"
    assert_not_contains "$(cat "${WORKDIR}/packages.log")" "consumed stdin" "package setup cannot consume script stdin"
  done
  prepare_runtime_mocks
  rm -f "${WORKDIR}/runtime-present"
  status="$(FIXTURE_UID=0 FIXTURE_APT_CANDIDATE='(none)' run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "legacy apt runtime installs"
  assert_contains "$(cat "${WORKDIR}/packages.log")" "install -y libpcap0.8 frontend" "legacy apt name selected"
  assert_not_contains "$(cat "${WORKDIR}/packages.log")" "-dev" "no development packages"

  prepare_runtime_mocks
  rm -f "${WORKDIR}/bin/setcap" "${WORKDIR}/runtime-present"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --setcap --version v0.3.0)"
  assert_eq "${status}" "0" "system --setcap bootstraps missing tool and runtime"
  assert_contains "$(cat "${WORKDIR}/packages.log")" "install -y libpcap0.8t64 libcap2-bin" "only requested capability tool bootstrapped"
  assert_contains "$(cat "${out}")" "CAP_NET_RAW was granted" "successful capability grant reported"
  assert_command_line "${out}" "'${SYSTEM_BIN}/flowlens'" "capability install recommends non-root absolute executable"
  assert_not_contains "$(cat "${out}")" "  sudo flowlens" "capability install does not recommend sudo capture"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "upgrade without --setcap uses default policy"
  assert_contains "$(cat "${SYSTEM_MANIFEST}/install-manifest")" "setcap=false" "upgrade does not persist capability request"
  old_manifest="$(cat "${SYSTEM_MANIFEST}/install-manifest")"

  prepare_runtime_mocks
  printf 'ID=fedora\n' > "${WORKDIR}/os-release"
  rm -f "${WORKDIR}/bin/setcap"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --setcap --version v0.3.0)"
  assert_eq "${status}" "0" "RPM --setcap bootstraps missing tool only"
  assert_contains "$(cat "${WORKDIR}/packages.log")" "dnf install -y libcap" "RPM capability package is libcap"
  assert_not_contains "$(cat "${WORKDIR}/packages.log")" "libpcap" "present runtime is not reinstalled for --setcap"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "0" "restore default capture policy after RPM capability fixture"
  old_manifest="$(cat "${SYSTEM_MANIFEST}/install-manifest")"
  prepare_runtime_mocks
  rm -f "${WORKDIR}/runtime-present"
  for manager in user custom; do
    if [ "${manager}" = user ]; then
      status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --user --version v0.3.0)"
    else
      status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --install-dir "${WORKDIR}/custom" --version v0.3.0)"
    fi
    assert_eq "${status}" "6" "${manager} scope refuses missing runtime even as root"
    assert_command_line "${out}" "sudo apt-get install -y libpcap0.8t64" "${manager} gives manual dependency command"
    assert_eq "$(cat "${WORKDIR}/packages.log")" "" "${manager} scope never changes packages"
  done
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --dry-run --setcap --version v0.3.0)"
  assert_eq "${status}" "0" "missing dependencies dry-run succeeds without changes"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "dry-run never calls package mutations"
  assert_not_contains "$(cat "${out}")" "was granted" "dry-run does not claim capability granted"
  status="$(FIXTURE_SUDO_FAIL=1 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "6" "writable directories still require package privileges"
  assert_command_line "${out}" "sudo bash install.sh" "dependency privilege guidance is standalone"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "privilege failure never runs package manager"
  for manager in update install; do
    status="$(FIXTURE_UID=0 FIXTURE_PACKAGE_FAIL="${manager}" run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
    assert_eq "${status}" "6" "apt ${manager} failure prevents publication"
    assert_eq "$(cat "${SYSTEM_BIN}/flowlens")" "${old_binary}" "package failure preserves previous binary"
    assert_eq "$(cat "${SYSTEM_MANIFEST}/install-manifest")" "${old_manifest}" "package failure preserves previous manifest"
    assert_not_contains "$(cat "${out}")" "installed FlowLens" "package failure never claims success"
    assert_command_line "${out}" "sudo apt-get install -y libpcap0.8t64" "package failure gives manual command"
  done
  status="$(FIXTURE_UID=0 FIXTURE_UNRESOLVED=1 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "6" "package success with unresolved SONAME prevents publication"
  assert_contains "$(cat "${out}")" "Required libpcap.so.0.8 is still unavailable" "exact missing SONAME reported"
  assert_not_contains "$(cat "${out}")" "installed FlowLens" "unresolved runtime never claims success"
  assert_eq "$(cat "${SYSTEM_MANIFEST}/install-manifest")" "${old_manifest}" "unresolved runtime leaves manifest unchanged"
  : > "${WORKDIR}/packages.log"
  status="$(FIXTURE_UID=0 FIXTURE_LOADER_FAIL=1 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "6" "incompatible artifact loader fails safely"
  assert_command_line "${out}" "getconf GNU_LIBC_VERSION" "glibc diagnostic is standalone"
  assert_command_line "${out}" "uname -m" "architecture diagnostic is standalone"
  assert_command_line "${out}" "ldd --version" "loader diagnostic is standalone"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "wrong architecture does not change packages"
  rm -f "${WORKDIR}/runtime-present" "${WORKDIR}/bin/setcap"
  printf 'ID=unknown\n' > "${WORKDIR}/os-release"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "6" "unsupported distribution requires manual setup"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "unsupported distro does not use available manager"
  assert_contains "$(cat "${out}")" "package manager" "unsupported distro manual guidance"
  printf 'ID=debian\n' > "${WORKDIR}/os-release"
  rm -f "${WORKDIR}/bin/apt-cache"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --version v0.3.0)"
  assert_eq "${status}" "6" "missing manager tooling fails closed"
  assert_command_line "${out}" "sudo dnf install -y libpcap" "unknown manager RPM example uses RPM package"
  assert_command_line "${out}" "sudo apt-get install -y libpcap0.8t64" "unknown manager gives modern apt install command"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "missing manager never changes packages"
  status="$(FIXTURE_UID=0 run_installer "${out}" "${WORKDIR}/install.sh" --uninstall)"
  assert_eq "${status}" "0" "uninstall ignores missing runtime and tools"
  assert_eq "$(cat "${WORKDIR}/packages.log")" "" "uninstall never changes packages"
  prepare_runtime_mocks
  rm -f "${WORKDIR}/bin/id" "${WORKDIR}/bin/sudo" "${WORKDIR}/bin/setcap"
}

main() {
  printf 'FlowLens installer tests\n'
  TEST_HOME="${WORKDIR}/home"
  mkdir -p "${TEST_HOME}"
  require_installer
  slice="${FLOWLENS_TEST_SLICE:-all}"
  if [ "${slice}" != "unit" ]; then
    PYTHON="$(python_bin)"
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "unit" ]; then
    test_json_fixtures
    test_help_exits_zero
    test_invalid_version_exits_2
    test_old_version_exits_2
    test_conflicting_dir_flags_exit_2
    test_uninstall_rejects_version
    test_unsupported_os_exits_3_before_network
    test_macos_exits_3_before_network
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "http" ]; then
    prepare_assets
    install_fake_uname Linux x86_64
    start_server ok
    make_test_installer
    test_http_404
    test_http_403_rate_limit
    test_dry_run_install
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "fail" ]; then
    if [ "${slice}" = "fail" ]; then
      prepare_assets
      install_fake_uname Linux x86_64
      start_server ok
      make_test_installer
    fi
    test_install_and_uninstall
    test_no_modify_path_prints_hint
    test_sha256_mismatch_exits_5
    test_archive_extra_file_exits_5
    test_gpl_archive_requires_license
    test_archive_path_traversal_exits_5
    test_setcap_non_linux_exits_2
    test_setcap_missing_exits_6
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "setcap" ]; then
    if [ "${slice}" = "setcap" ]; then
      prepare_assets
      install_fake_uname Linux x86_64
      start_server ok
      make_test_installer
    fi
    test_setcap_failure_rolls_back
    test_setcap_success_records_manifest
    test_manifest_publish_failure_rolls_back
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "scope" ]; then
    if [ "${slice}" = "scope" ]; then
      prepare_assets
      install_fake_uname Linux x86_64
      start_server ok
      make_test_installer
    fi
    test_system_sudo_n_fails_closed
    test_system_scope_and_manifest_publication
    test_user_scope_and_custom_dirs
    test_old_user_install_detection
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "deps" ]; then
    if [ "${slice}" = "deps" ]; then
      prepare_assets
      install_fake_uname Linux x86_64
      start_server ok
      make_test_installer
    fi
    test_runtime_dependencies
  fi
  stop_server
  printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
  if [ "${FAIL}" -ne 0 ]; then
    exit 1
  fi
}

main "$@"
