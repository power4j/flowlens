#!/usr/bin/env bash
# FlowLens installer fixture tests.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${ROOT}/install.sh"
FIXTURES="${ROOT}/tests/install/fixtures"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/flowlens-install-test.XXXXXX")"
PASS=0
FAIL=0
SERVER_PID=""

cleanup() {
  if [ -n "${SERVER_PID}" ]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
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
    *) fail "${name}: missing '${needle}'" ;;
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
  local launcher raw
  if command -v python3 >/dev/null 2>&1; then
    launcher="$(command -v python3)"
  else
    launcher="$(command -v python)"
  fi
  raw="$("${launcher}" -c 'import sys; print(sys.executable)')"
  printf '%s\n' "${raw}" | tr '\\' '/'
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
    PATH="${WORKDIR}/bin:${PATH}"
    export PATH
    SHELL="${SHELL:-/bin/bash}"
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
  rm -f "${port_file}" "${pid_file}"
  "${PYTHON}" -u "${ROOT}/tests/install/http_server.py"     --root "${WORKDIR}/www" --mode "${mode}" --port-file "${port_file}" --pid-file "${pid_file}"     >/dev/null 2>"${WORKDIR}/server.err" &
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -s "${port_file}" ] && [ -s "${pid_file}" ]; then
      break
    fi
    sleep 0.1
  done
  SERVER_PORT="$(tr -d '[:space:]' < "${port_file}" 2>/dev/null || true)"
  SERVER_PID="$(tr -d '[:space:]' < "${pid_file}" 2>/dev/null || true)"
  if [ -z "${SERVER_PORT}" ] || [ -z "${SERVER_PID}" ]; then
    fail "http fixture server started"
    if [ -f "${WORKDIR}/server.err" ]; then
      printf '%s
' "$(cat "${WORKDIR}/server.err")"
    fi
    return 1
  fi
  pass "http fixture server started on ${SERVER_PORT}"
}

stop_server() {
  if [ -n "${SERVER_PID}" ]; then
    taskkill //F //PID "${SERVER_PID}" >/dev/null 2>&1 || kill "${SERVER_PID}" >/dev/null 2>&1 || true
    SERVER_PID=""
  fi
}

make_test_installer() {
  sed -e "s#https://api.github.com#http://127.0.0.1:${SERVER_PORT}#g" \
      -e "s#https://github.com#http://127.0.0.1:${SERVER_PORT}#g" \
      "${INSTALL_SH}" > "${WORKDIR}/install.sh"
}

prepare_assets() {
  mkdir -p "${WORKDIR}/www" "${WORKDIR}/pack"
  cp "${FIXTURES}/api/latest-pretty.json" "${WORKDIR}/www/latest.json"
  printf '%s\n' '#!/bin/sh' 'echo flowlens-fixture' > "${WORKDIR}/pack/flowlens"
  chmod 0755 "${WORKDIR}/pack/flowlens"
  tar -C "${WORKDIR}/pack" -czf "${WORKDIR}/www/flowlens-v0.3.0-linux-x86_64.tar.gz" flowlens
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "${WORKDIR}/www/flowlens-v0.3.0-linux-x86_64.tar.gz" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "${WORKDIR}/www/flowlens-v0.3.0-linux-x86_64.tar.gz" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "${digest}" "flowlens-v0.3.0-linux-x86_64.tar.gz" > "${WORKDIR}/www/SHA256SUMS"
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
  out="${WORKDIR}/uninstall.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "uninstall exits 0"
  assert_not_file "${WORKDIR}/opt/bin/flowlens" "uninstall removes binary"
  assert_not_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "uninstall removes manifest"
}

main() {
  printf 'FlowLens installer tests\n'
  PYTHON="$(python_bin)"
  TEST_HOME="${WORKDIR}/home"
  mkdir -p "${TEST_HOME}"
  require_installer
  test_json_fixtures
  test_help_exits_zero
  test_invalid_version_exits_2
  test_old_version_exits_2
  test_conflicting_dir_flags_exit_2
  test_uninstall_rejects_version
  test_unsupported_os_exits_3_before_network
  prepare_assets
  install_fake_uname Linux x86_64
  start_server ok
  make_test_installer
  test_http_404
  test_http_403_rate_limit
  test_dry_run_install
  test_install_and_uninstall
  stop_server
  printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
  if [ "${FAIL}" -ne 0 ]; then
    exit 1
  fi
}

main "$@"
