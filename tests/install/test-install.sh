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
  sed -e "s#https://api.github.com#http://127.0.0.1:${SERVER_PORT}#g" \
      -e "s#https://github.com#http://127.0.0.1:${SERVER_PORT}#g" \
      "${INSTALL_SH}" > "${WORKDIR}/install.sh"
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
  chmod a-x "${WORKDIR}/opt/bin/flowlens" 2>/dev/null || true
  out="${WORKDIR}/uninstall.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --uninstall --install-dir "${WORKDIR}/opt/bin")"
  assert_eq "${status}" "0" "uninstall exits 0"
  assert_not_file "${WORKDIR}/opt/bin/flowlens" "uninstall removes binary"
  assert_not_file "${TEST_HOME}/.local/share/flowlens/install-manifest" "uninstall removes manifest"
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

test_setcap_missing_exits_2() {
  local out status saved
  # shellcheck disable=SC2031
  saved="${PATH}"
  PATH="${WORKDIR}/bin:/usr/bin:/bin"
  export PATH
  rm -f "${WORKDIR}/bin/setcap"
  out="${WORKDIR}/setcap-missing.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --setcap --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  PATH="${saved}"
  export PATH
  assert_eq "${status}" "2" "--setcap without setcap exits 2"
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
/usr/bin/mv "$@"
EOF
  chmod +x "${WORKDIR}/bin/mv"
  out="${WORKDIR}/rb.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --force --version v0.3.0 --install-dir "${WORKDIR}/opt/bin")"
  rm -f "${WORKDIR}/bin/mv"
  assert_eq "${status}" "1" "manifest publish failure exits 1"
  assert_eq "$(cat "${WORKDIR}/opt/bin/flowlens")" "${old}" "manifest publish failure restores binary"
}

test_system_sudo_n_fails_closed() {
  local out status
  if [ -w /usr/local/bin ]; then
    pass "--system sudo -n skipped because /usr/local/bin is writable"
    return
  fi
  cat > "${WORKDIR}/bin/sudo" <<'EOF'
#!/bin/sh
if [ "$1" = "-n" ]; then
  exit 1
fi
sleep 30
exit 1
EOF
  chmod +x "${WORKDIR}/bin/sudo"
  out="${WORKDIR}/system.out"
  status="$(run_installer "${out}" "${WORKDIR}/install.sh" --system --version v0.3.0)"
  rm -f "${WORKDIR}/bin/sudo"
  assert_eq "${status}" "6" "--system without sudo -n exits 6"
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
    test_sha256_mismatch_exits_5
    test_archive_extra_file_exits_5
    test_archive_path_traversal_exits_5
    test_setcap_non_linux_exits_2
    test_setcap_missing_exits_2
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
    test_system_sudo_n_fails_closed
  fi
  if [ "${slice}" = "all" ] || [ "${slice}" = "http" ] || [ "${slice}" = "fail" ] || [ "${slice}" = "setcap" ]; then
    stop_server
  fi
  printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
  if [ "${FAIL}" -ne 0 ]; then
    exit 1
  fi
}

main "$@"
