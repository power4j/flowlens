#!/usr/bin/env bash
# FlowLens installer. Compatible with Bash 3.2+.
set -eu

FLOWLENS_REPO="power4j/flowlens"
MIN_VERSION="v0.3.0"
MAX_COMPONENT=2147483647
API_BASE="https://api.github.com"
DOWNLOAD_BASE="https://github.com"
PATH_BEGIN="# >>> flowlens installer >>>"
PATH_END="# <<< flowlens installer <<<"
PATH_MARKER="flowlens-installer"

usage() {
  cat <<'EOF'
Usage:
  bash install.sh [options]

Options:
  --version VERSION      Install an exact version, for example v0.3.0
  --install-dir DIR      Install into DIR
  --system               Install into /usr/local/bin
  --force                Allow overwrite or downgrade of installer-owned files
  --dry-run              Report actions without committing an install
  --no-modify-path       Do not modify shell PATH files
  --setcap               Set CAP_NET_RAW on Linux after install
  --uninstall            Remove an installer-owned install
  --help                 Show this help and exit
EOF
}

die() {
  local code="$1"
  shift
  printf '%s\n' "$*" >&2
  exit "${code}"
}

log() {
  printf '%s\n' "$*"
}


is_true() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "${value}" in
    1|true) return 0 ;;
    0|false|'') return 1 ;;
    *) die 2 "invalid boolean value: $1" ;;
  esac
}

abspath() {
  local target="$1"
  local dir base
  case "${target}" in
    /*) printf '%s\n' "${target}"; return ;;
  esac
  dir="$(cd "$(dirname "${target}")" && pwd)"
  base="$(basename "${target}")"
  printf '%s/%s\n' "${dir}" "${base}"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    die 1 "sha256sum or shasum is required"
  fi
}

validate_component() {
  local value="$1"
  case "${value}" in
    ''|*[!0-9]*) return 1 ;;
    0) return 0 ;;
    0*) return 1 ;;
  esac
  if [ "${#value}" -gt 10 ]; then
    return 1
  fi
  if [ "${#value}" -eq 10 ] && [ "${value}" \> "${MAX_COMPONENT}" ]; then
    return 1
  fi
  if [ "${value}" -gt "${MAX_COMPONENT}" ] 2>/dev/null; then
    return 1
  fi
  return 0
}

is_valid_version() {
  local version="$1"
  local major minor patch
  case "${version}" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) return 1 ;;
  esac
  major="${version#v}"
  major="${major%%.*}"
  minor="${version#v${major}.}"
  minor="${minor%%.*}"
  patch="${version#v${major}.${minor}.}"
  [ "${version}" = "v${major}.${minor}.${patch}" ] || return 1
  validate_component "${major}" || return 1
  validate_component "${minor}" || return 1
  validate_component "${patch}" || return 1
  return 0
}

version_cmp() {
  local left="$1"
  local right="$2"
  local lmaj lmin lpat rmaj rmin rpat
  lmaj="${left#v}"; lmaj="${lmaj%%.*}"
  lmin="${left#v${lmaj}.}"; lmin="${lmin%%.*}"
  lpat="${left#v${lmaj}.${lmin}.}"
  rmaj="${right#v}"; rmaj="${rmaj%%.*}"
  rmin="${right#v${rmaj}.}"; rmin="${rmin%%.*}"
  rpat="${right#v${rmaj}.${rmin}.}"
  if [ "${lmaj}" -lt "${rmaj}" ]; then echo lt; return; fi
  if [ "${lmaj}" -gt "${rmaj}" ]; then echo gt; return; fi
  if [ "${lmin}" -lt "${rmin}" ]; then echo lt; return; fi
  if [ "${lmin}" -gt "${rmin}" ]; then echo gt; return; fi
  if [ "${lpat}" -lt "${rpat}" ]; then echo lt; return; fi
  if [ "${lpat}" -gt "${rpat}" ]; then echo gt; return; fi
  echo eq
}

parse_release_json() {
  awk -f /dev/stdin "$1" <<'AWK'
# Strict GitHub Release JSON object parser for Bash 3.2 installers.
# Reads one JSON object and prints:
#   tag_name=...
#   prerelease=true|false
#   draft=true|false
{
  if (NR > 1) data = data "\n"
  data = data $0
}

END {
  n = length(data)
  i = 1
  tag_name = ""
  prerelease = ""
  draft = ""
  seen_tag = 0
  seen_pre = 0
  seen_draft = 0
  if (n == 0) fail("empty input")
  skip_ws()
  if (!parse_object(1)) fail("top-level object required")
  skip_ws()
  if (i <= n) fail("trailing garbage")
  if (!seen_tag || !seen_pre || !seen_draft) fail("missing required field")
  print "tag_name=" tag_name
  print "prerelease=" prerelease
  print "draft=" draft
}

function fail(msg) {
  print "json parse error: " msg > "/dev/stderr"
  exit 1
}

function skip_ws(   c) {
  while (i <= n) {
    c = substr(data, i, 1)
    if (c == " " || c == "\t" || c == "\n" || c == "\r") i++
    else return
  }
}

function peek() {
  if (i > n) return ""
  return substr(data, i, 1)
}

function parse_object(is_top,   first, key, c) {
  skip_ws()
  if (peek() != "{") return 0
  i++
  first = 1
  skip_ws()
  if (peek() == "}") {
    i++
    return 1
  }
  while (i <= n) {
    if (!first) {
      skip_ws()
      if (peek() != ",") return 0
      i++
      skip_ws()
    }
    first = 0
    if (!parse_string()) return 0
    key = parsed_string
    skip_ws()
    if (peek() != ":") return 0
    i++
    skip_ws()
    if (is_top && (key == "tag_name" || key == "prerelease" || key == "draft")) {
      if (!parse_required_field(key)) return 0
    } else if (!parse_value()) {
      return 0
    }
    skip_ws()
    c = peek()
    if (c == "}") {
      i++
      return 1
    }
    if (c != ",") return 0
  }
  return 0
}

function parse_required_field(key,   c) {
  if (key == "tag_name") {
    if (seen_tag) fail("duplicate tag_name")
    if (!parse_string()) fail("tag_name must be a string")
    tag_name = parsed_string
    seen_tag = 1
    return 1
  }
  if (key == "prerelease") {
    if (seen_pre) fail("duplicate prerelease")
    c = peek()
    if (c != "t" && c != "f") fail("prerelease must be a boolean")
    if (!parse_boolean()) fail("prerelease must be a boolean")
    prerelease = parsed_bool
    seen_pre = 1
    return 1
  }
  if (key == "draft") {
    if (seen_draft) fail("duplicate draft")
    c = peek()
    if (c != "t" && c != "f") fail("draft must be a boolean")
    if (!parse_boolean()) fail("draft must be a boolean")
    draft = parsed_bool
    seen_draft = 1
    return 1
  }
  return 0
}

function parse_value(   c) {
  c = peek()
  if (c == "\"") return parse_string()
  if (c == "{") return parse_object(0)
  if (c == "[") return parse_array()
  if (c == "t" || c == "f") return parse_boolean()
  if (c == "n") return parse_null()
  if (c == "-" || (c >= "0" && c <= "9")) return parse_number()
  return 0
}

function parse_array(   first, c) {
  if (peek() != "[") return 0
  i++
  skip_ws()
  if (peek() == "]") {
    i++
    return 1
  }
  first = 1
  while (i <= n) {
    if (!first) {
      skip_ws()
      if (peek() != ",") return 0
      i++
      skip_ws()
    }
    first = 0
    if (!parse_value()) return 0
    skip_ws()
    c = peek()
    if (c == "]") {
      i++
      return 1
    }
    if (c != ",") return 0
  }
  return 0
}

function parse_string(   c, hex, j, code, out) {
  if (peek() != "\"") return 0
  i++
  out = ""
  while (i <= n) {
    c = substr(data, i, 1)
    i++
    if (c == "\"") {
      parsed_string = out
      return 1
    }
    if (c == "\\") {
      if (i > n) return 0
      c = substr(data, i, 1)
      i++
      if (c == "\"" || c == "\\" || c == "/") out = out c
      else if (c == "b") out = out "\b"
      else if (c == "f") out = out "\f"
      else if (c == "n") out = out "\n"
      else if (c == "r") out = out "\r"
      else if (c == "t") out = out "\t"
      else if (c == "u") {
        hex = substr(data, i, 4)
        if (hex !~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/) return 0
        i += 4
        code = hex_value(hex)
        if (code < 128) out = out sprintf("%c", code)
        else out = out "\\u" hex
      } else return 0
    } else {
      if (c == "\n" || c == "\r" || c == "\t") return 0
      out = out c
    }
  }
  return 0
}

function hex_value(hex,   v, k, ch, d) {
  v = 0
  for (k = 1; k <= 4; k++) {
    ch = substr(hex, k, 1)
    if (ch >= "0" && ch <= "9") d = ch + 0
    else if (ch >= "a" && ch <= "f") d = 10 + index("abcdef", ch) - 1
    else if (ch >= "A" && ch <= "F") d = 10 + index("ABCDEF", ch) - 1
    else return -1
    v = v * 16 + d
  }
  return v
}

function parse_boolean() {
  if (substr(data, i, 4) == "true") {
    i += 4
    parsed_bool = "true"
    return 1
  }
  if (substr(data, i, 5) == "false") {
    i += 5
    parsed_bool = "false"
    return 1
  }
  return 0
}

function parse_null() {
  if (substr(data, i, 4) == "null") {
    i += 4
    return 1
  }
  return 0
}

function parse_number(   c, started) {
  if (peek() == "-") i++
  if (peek() == "0") {
    i++
    c = peek()
    if (c >= "0" && c <= "9") return 0
  } else if (peek() >= "1" && peek() <= "9") {
    while (peek() >= "0" && peek() <= "9") i++
  } else return 0
  if (peek() == ".") {
    i++
    if (peek() < "0" || peek() > "9") return 0
    while (peek() >= "0" && peek() <= "9") i++
  }
  c = peek()
  if (c == "e" || c == "E") {
    i++
    c = peek()
    if (c == "+" || c == "-") i++
    if (peek() < "0" || peek() > "9") return 0
    while (peek() >= "0" && peek() <= "9") i++
  }
  return 1
}
AWK
}

header_value() {
  local file="$1"
  local name="$2"
  awk -v n="${name}" '
    BEGIN { nl = tolower(n) }
    {
      line = $0
      sub(/\r$/, "", line)
      pos = index(line, ":")
      if (pos < 1) next
      key = substr(line, 1, pos - 1)
      val = substr(line, pos + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      if (tolower(key) == nl) { print val; exit }
    }
  ' "${file}"
}

http_get() {
  local url="$1"
  local headers="$2"
  local body="$3"
  local status curl_ec
  if ! command -v curl >/dev/null 2>&1; then
    die 1 "curl is required"
  fi
  set +e
  status="$(curl -sS -L --connect-timeout 5 --max-time 20 --retry 0 --no-keepalive -D "${headers}" -o "${body}" -w '%{http_code}' "${url}")"
  curl_ec=$?
  set -e
  HTTP_STATUS="${status}"
  HTTP_CURL_EC="${curl_ec}"
  return 0
}

fail_http() {
  local url="$1"
  local what="$2"
  local remaining reset
  if [ "${HTTP_CURL_EC}" -ne 0 ]; then
    die 4 "${what} failed: curl exit ${HTTP_CURL_EC} for ${url}"
  fi
  if [ "${HTTP_STATUS}" = "404" ]; then
    die 4 "${what} returned 404: version not found or no stable Release"
  fi
  if [ "${HTTP_STATUS}" = "403" ]; then
    remaining="$(header_value "${TMP_DIR}/headers" "X-RateLimit-Remaining")"
    reset="$(header_value "${TMP_DIR}/headers" "X-RateLimit-Reset")"
    if [ "${remaining}" = "0" ]; then
      if [ -n "${reset}" ]; then
        die 4 "GitHub API unauthenticated rate limit reached; retry after ${reset}"
      fi
      die 4 "GitHub API unauthenticated rate limit reached"
    fi
  fi
  die 4 "${what} failed with HTTP ${HTTP_STATUS}"
}

cleanup() {
  if [ -n "${TMP_BIN:-}" ] && [ -f "${TMP_BIN}" ]; then
    rm -f "${TMP_BIN}"
  fi
  if [ -n "${TMP_MANIFEST:-}" ] && [ -f "${TMP_MANIFEST}" ]; then
    rm -f "${TMP_MANIFEST}"
  fi
  if [ -n "${TMP_PATH_FILE:-}" ] && [ -f "${TMP_PATH_FILE}" ]; then
    rm -f "${TMP_PATH_FILE}"
  fi
  if [ -n "${TMP_DIR:-}" ] && [ -d "${TMP_DIR}" ]; then
    rm -rf "${TMP_DIR}"
  fi
}

priv() {
  if [ "${USE_SUDO:-0}" -eq 1 ]; then
    sudo -n "$@"
  else
    "$@"
  fi
}

prepare_privileges() {
  USE_SUDO=0
  if [ "${WANT_SYSTEM}" -ne 1 ]; then
    return
  fi
  if [ "$(id -u)" -eq 0 ]; then
    return
  fi
  if [ -d "${INSTALL_DIR}" ] && [ -w "${INSTALL_DIR}" ]; then
    return
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    die 6 "system install needs write access to ${INSTALL_DIR}"
  fi
  if ! sudo -n true >/dev/null 2>&1; then
    die 6 "system install needs write access to ${INSTALL_DIR}; sudo -n failed"
  fi
  USE_SUDO=1
}

rollback_install() {
  if [ -f "${TMP_DIR}/rollback-binary" ]; then
    priv mv -f "${TMP_DIR}/rollback-binary" "${BINARY_PATH}" || true
  fi
  if [ -f "${TMP_DIR}/rollback-manifest" ]; then
    priv mv -f "${TMP_DIR}/rollback-manifest" "${MANIFEST_PATH}" || true
  fi
  if [ -f "${TMP_DIR}/rollback-path" ] && [ -n "${PATH_FILE:-}" ]; then
    priv mv -f "${TMP_DIR}/rollback-path" "${PATH_FILE}" || true
  fi
}

detect_platform() {
  local uname_s uname_m
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"
  case "${uname_s}" in
    Linux) PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *) die 3 "unsupported platform: ${uname_s}" ;;
  esac
  case "${uname_m}" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) die 3 "unsupported architecture: ${uname_m}" ;;
  esac
}

parse_args() {
  WANT_HELP=0
  WANT_UNINSTALL=0
  WANT_SYSTEM=0
  WANT_FORCE=0
  WANT_DRY_RUN=0
  WANT_NO_MODIFY_PATH=0
  WANT_SETCAP=0
  ARG_VERSION=""
  ARG_INSTALL_DIR=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help) WANT_HELP=1; shift ;;
      --uninstall) WANT_UNINSTALL=1; shift ;;
      --system) WANT_SYSTEM=1; shift ;;
      --force) WANT_FORCE=1; shift ;;
      --dry-run) WANT_DRY_RUN=1; shift ;;
      --no-modify-path) WANT_NO_MODIFY_PATH=1; shift ;;
      --setcap) WANT_SETCAP=1; shift ;;
      --version)
        [ "$#" -ge 2 ] || die 2 "--version requires a value"
        ARG_VERSION="$2"
        shift 2
        ;;
      --install-dir)
        [ "$#" -ge 2 ] || die 2 "--install-dir requires a value"
        ARG_INSTALL_DIR="$2"
        shift 2
        ;;
      *) die 2 "unknown argument: $1" ;;
    esac
  done
}

apply_env() {
  if [ -z "${ARG_VERSION}" ] && [ -n "${FLOWLENS_VERSION:-}" ]; then
    ARG_VERSION="${FLOWLENS_VERSION}"
  fi
  if [ -z "${ARG_INSTALL_DIR}" ] && [ -n "${FLOWLENS_INSTALL_DIR:-}" ]; then
    ARG_INSTALL_DIR="${FLOWLENS_INSTALL_DIR}"
  fi
  if [ "${WANT_NO_MODIFY_PATH}" -eq 0 ] && [ -n "${FLOWLENS_NO_MODIFY_PATH:-}" ]; then
    if is_true "${FLOWLENS_NO_MODIFY_PATH}"; then
      WANT_NO_MODIFY_PATH=1
    fi
  fi
  if [ "${WANT_FORCE}" -eq 0 ] && [ -n "${FLOWLENS_FORCE:-}" ]; then
    if is_true "${FLOWLENS_FORCE}"; then
      WANT_FORCE=1
    fi
  fi
  if [ "${WANT_SETCAP}" -eq 0 ] && [ -n "${FLOWLENS_SETCAP:-}" ]; then
    if is_true "${FLOWLENS_SETCAP}"; then
      WANT_SETCAP=1
    fi
  fi
}

validate_args() {
  if [ "${WANT_UNINSTALL}" -eq 1 ]; then
    if [ -n "${ARG_VERSION}" ] || [ -n "${FLOWLENS_VERSION:-}" ]; then
      die 2 "--uninstall cannot be combined with --version or FLOWLENS_VERSION"
    fi
    if [ "${WANT_SETCAP}" -eq 1 ] || [ -n "${FLOWLENS_SETCAP:-}" ]; then
      die 2 "--uninstall cannot be combined with --setcap or FLOWLENS_SETCAP"
    fi
    if [ "${WANT_NO_MODIFY_PATH}" -eq 1 ] || [ -n "${FLOWLENS_NO_MODIFY_PATH:-}" ]; then
      die 2 "--uninstall cannot be combined with --no-modify-path or FLOWLENS_NO_MODIFY_PATH"
    fi
  fi
  if [ "${WANT_SYSTEM}" -eq 1 ] && [ -n "${ARG_INSTALL_DIR}" ]; then
    die 2 "--system cannot be combined with --install-dir or FLOWLENS_INSTALL_DIR"
  fi
  if [ -n "${ARG_VERSION}" ]; then
    if ! is_valid_version "${ARG_VERSION}"; then
      die 2 "invalid version: ${ARG_VERSION}"
    fi
    if [ "$(version_cmp "${ARG_VERSION}" "${MIN_VERSION}")" = "lt" ]; then
      die 2 "version ${ARG_VERSION} is older than FlowLens asset naming change; lowest installable version is ${MIN_VERSION}"
    fi
  fi
}

resolve_dirs() {
  HOME_DIR="${HOME}"
  [ -n "${HOME_DIR}" ] || die 1 "HOME is not set"
  if [ "${WANT_SYSTEM}" -eq 1 ]; then
    INSTALL_DIR="/usr/local/bin"
    MANIFEST_DIR="/usr/local/share/flowlens"
  elif [ -n "${ARG_INSTALL_DIR}" ]; then
    INSTALL_DIR="${ARG_INSTALL_DIR}"
    MANIFEST_DIR="${HOME_DIR}/.local/share/flowlens"
  else
    INSTALL_DIR="${HOME_DIR}/.local/bin"
    MANIFEST_DIR="${HOME_DIR}/.local/share/flowlens"
  fi
  BINARY_PATH="${INSTALL_DIR}/flowlens"
  MANIFEST_PATH="${MANIFEST_DIR}/install-manifest"
}

choose_path_file() {
  local shell_name
  shell_name="$(basename "${SHELL:-}")"
  PATH_FILE=""
  case "${shell_name}" in
    bash)
      if [ -f "${HOME_DIR}/.bash_profile" ]; then
        PATH_FILE="${HOME_DIR}/.bash_profile"
      elif [ -f "${HOME_DIR}/.profile" ]; then
        PATH_FILE="${HOME_DIR}/.profile"
      else
        PATH_FILE="${HOME_DIR}/.bashrc"
      fi
      ;;
    zsh)
      if [ -f "${HOME_DIR}/.zprofile" ]; then
        PATH_FILE="${HOME_DIR}/.zprofile"
      else
        PATH_FILE="${HOME_DIR}/.zshrc"
      fi
      ;;
  esac
}

should_modify_path() {
  if [ "${WANT_NO_MODIFY_PATH}" -eq 1 ]; then
    return 1
  fi
  if [ "${WANT_SYSTEM}" -eq 1 ]; then
    return 1
  fi
  if [ -z "${PATH_FILE}" ]; then
    return 1
  fi
  case ":${PATH}:" in
    *:"${INSTALL_DIR}":*) return 1 ;;
  esac
  return 0
}

read_manifest_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="${key}" '
    $1==k { print substr($0, index($0, "=") + 1); found=1 }
    END { if (!found) exit 1 }
  ' "${file}"
}

validate_manifest_file() {
  local file="$1"
  local version install_dir binary_path digest path_file marker setcap_val mf_version
  mf_version="$(read_manifest_value "${file}" manifest_version)" || return 1
  [ "${mf_version}" = "1" ] || return 1
  version="$(read_manifest_value "${file}" version)" || return 1
  install_dir="$(read_manifest_value "${file}" install_dir)" || return 1
  binary_path="$(read_manifest_value "${file}" binary_path)" || return 1
  digest="$(read_manifest_value "${file}" binary_sha256)" || return 1
  path_file="$(read_manifest_value "${file}" path_file)" || return 1
  marker="$(read_manifest_value "${file}" path_marker)" || return 1
  setcap_val="$(read_manifest_value "${file}" setcap)" || return 1
  is_valid_version "${version}" || return 1
  [ "${binary_path}" = "${install_dir}/flowlens" ] || return 1
  [ "${marker}" = "${PATH_MARKER}" ] || return 1
  case "${digest}" in
    *[!0-9a-fA-F]*|'') return 1 ;;
  esac
  [ "${#digest}" -eq 64 ] || return 1
  case "${setcap_val}" in
    true|false) ;;
    *) return 1 ;;
  esac
  MF_VERSION="${version}"
  MF_INSTALL_DIR="${install_dir}"
  MF_BINARY_PATH="${binary_path}"
  MF_DIGEST="${digest}"
  MF_PATH_FILE="${path_file}"
  MF_SETCAP="${setcap_val}"
  return 0
}

write_manifest_file() {
  local dest="$1"
  local version="$2"
  local digest="$3"
  local path_file="$4"
  local setcap_val="$5"
  cat > "${dest}" <<EOF
manifest_version=1
version=${version}
install_dir=${INSTALL_DIR}
binary_path=${BINARY_PATH}
binary_sha256=${digest}
path_file=${path_file}
path_marker=${PATH_MARKER}
setcap=${setcap_val}
EOF
}

write_path_block() {
  local dest="$1"
  local original="$2"
  if [ -f "${original}" ]; then
    cat "${original}" > "${dest}"
    if grep -F -q "${PATH_BEGIN}" "${dest}" 2>/dev/null; then
      return 0
    fi
    printf '\n' >> "${dest}"
  else
    : > "${dest}"
  fi
  cat >> "${dest}" <<EOF
${PATH_BEGIN}
export PATH="${INSTALL_DIR}:\$PATH"
${PATH_END}
EOF
}

remove_path_block() {
  local dest="$1"
  local original="$2"
  awk -v b="${PATH_BEGIN}" -v e="${PATH_END}" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "${original}" > "${dest}"
}

fetch_version() {
  local parsed tag prerelease draft
  if [ -n "${ARG_VERSION}" ]; then
    VERSION="${ARG_VERSION}"
    return
  fi
  http_get "${API_BASE}/repos/${FLOWLENS_REPO}/releases/latest" "${TMP_DIR}/headers" "${TMP_DIR}/latest.json"
  if [ "${HTTP_CURL_EC}" -ne 0 ] || [ "${HTTP_STATUS}" != "200" ]; then
    fail_http "${API_BASE}/repos/${FLOWLENS_REPO}/releases/latest" "GitHub API"
  fi
  parsed="$(parse_release_json "${TMP_DIR}/latest.json")" || die 4 "GitHub API returned invalid JSON"
  tag="$(printf '%s\n' "${parsed}" | awk -F= '$1=="tag_name"{print $2}')"
  prerelease="$(printf '%s\n' "${parsed}" | awk -F= '$1=="prerelease"{print $2}')"
  draft="$(printf '%s\n' "${parsed}" | awk -F= '$1=="draft"{print $2}')"
  is_valid_version "${tag}" || die 4 "GitHub API tag_name is not a supported version: ${tag}"
  if [ "$(version_cmp "${tag}" "${MIN_VERSION}")" = "lt" ]; then
    die 4 "latest version ${tag} is older than minimum ${MIN_VERSION}"
  fi
  if [ "${prerelease}" != "false" ] || [ "${draft}" != "false" ]; then
    die 4 "latest Release is not a stable published version"
  fi
  VERSION="${tag}"
}

download_assets() {
  local expected actual line hash name
  ASSET_NAME="flowlens-${VERSION}-${PLATFORM}-${ARCH}.tar.gz"
  ASSET_URL="${DOWNLOAD_BASE}/${FLOWLENS_REPO}/releases/download/${VERSION}/${ASSET_NAME}"
  SUMS_URL="${DOWNLOAD_BASE}/${FLOWLENS_REPO}/releases/download/${VERSION}/SHA256SUMS"
  http_get "${ASSET_URL}" "${TMP_DIR}/asset-headers" "${TMP_DIR}/${ASSET_NAME}"
  if [ "${HTTP_CURL_EC}" -ne 0 ] || [ "${HTTP_STATUS}" != "200" ]; then
    fail_http "${ASSET_URL}" "asset download"
  fi
  http_get "${SUMS_URL}" "${TMP_DIR}/sums-headers" "${TMP_DIR}/SHA256SUMS"
  if [ "${HTTP_CURL_EC}" -ne 0 ] || [ "${HTTP_STATUS}" != "200" ]; then
    fail_http "${SUMS_URL}" "SHA256SUMS download"
  fi
  expected=""
  while IFS= read -r line; do
    hash="${line%%  *}"
    name="${line#*  }"
    if [ "${name}" = "${ASSET_NAME}" ]; then
      expected="${hash}"
      break
    fi
  done < "${TMP_DIR}/SHA256SUMS"
  [ -n "${expected}" ] || die 5 "${ASSET_NAME} is not listed in SHA256SUMS"
  actual="$(sha256_file "${TMP_DIR}/${ASSET_NAME}")"
  [ "${actual}" = "${expected}" ] || die 5 "SHA-256 mismatch for ${ASSET_NAME}"
}

extract_asset() {
  local list count
  mkdir -p "${TMP_DIR}/extract"
  list="$(tar -tzf "${TMP_DIR}/${ASSET_NAME}")" || die 5 "invalid archive"
  count="$(printf '%s\n' "${list}" | awk 'NF{c++} END{print c+0}')"
  [ "${count}" = "1" ] || die 5 "archive must contain only flowlens"
  case "${list}" in
    flowlens|./flowlens) ;;
    *) die 5 "archive contains unexpected path: ${list}" ;;
  esac
  tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "${TMP_DIR}/extract" || die 5 "failed to extract archive"
  [ -f "${TMP_DIR}/extract/flowlens" ] || die 5 "extracted binary is missing"
  chmod 0755 "${TMP_DIR}/extract/flowlens"
  NEW_DIGEST="$(sha256_file "${TMP_DIR}/extract/flowlens")"
}

preflight_install() {
  local existing_digest
  if [ ! -d "${INSTALL_DIR}" ]; then
    if [ "${WANT_DRY_RUN}" -eq 1 ]; then
      log "dry-run: would create ${INSTALL_DIR}"
    else
      priv mkdir -p "${INSTALL_DIR}" || die 6 "install path is not writable: ${INSTALL_DIR}"
    fi
  fi
  if [ "${WANT_DRY_RUN}" -eq 0 ] && [ "${USE_SUDO:-0}" -eq 0 ] && [ ! -w "${INSTALL_DIR}" ]; then
    die 6 "install path is not writable: ${INSTALL_DIR}"
  fi
  if [ -e "${BINARY_PATH}" ]; then
    if [ -L "${BINARY_PATH}" ]; then
      die 7 "refusing to replace a symlink: ${BINARY_PATH}"
    fi
    if [ -f "${MANIFEST_PATH}" ]; then
      validate_manifest_file "${MANIFEST_PATH}" || die 7 "existing manifest is invalid"
      existing_digest="$(sha256_file "${BINARY_PATH}")"
      if [ "${existing_digest}" != "${MF_DIGEST}" ] && [ "${WANT_FORCE}" -eq 0 ]; then
        die 7 "existing binary digest does not match manifest; use --force to overwrite"
      fi
      if [ "$(version_cmp "${MF_VERSION}" "${VERSION}")" = "gt" ] && [ "${WANT_FORCE}" -eq 0 ]; then
        die 7 "installed version ${MF_VERSION} is newer than ${VERSION}; use --force to downgrade"
      fi
    else
      if [ "${WANT_FORCE}" -eq 0 ]; then
        die 7 "target exists without an installer manifest: ${BINARY_PATH}"
      fi
    fi
  fi
}

commit_install() {
  local tmp_bin tmp_manifest tmp_path setcap_val path_file_out
  setcap_val="false"
  path_file_out=""
  choose_path_file
  if should_modify_path; then
    path_file_out="${PATH_FILE}"
  fi
  if [ "${WANT_SETCAP}" -eq 1 ]; then
    setcap_val="true"
  fi
  if [ "${WANT_DRY_RUN}" -eq 1 ]; then
    log "dry-run: would install ${VERSION} to ${BINARY_PATH}"
    if [ "${WANT_SETCAP}" -eq 1 ]; then
      log "dry-run: would run setcap cap_net_raw+ep ${BINARY_PATH}"
    fi
    if [ -n "${path_file_out}" ]; then
      log "dry-run: would update PATH in ${path_file_out}"
    fi
    return
  fi
  priv mkdir -p "${MANIFEST_DIR}" || die 6 "manifest directory is not writable: ${MANIFEST_DIR}"
  TMP_BIN="${INSTALL_DIR}/flowlens.new.$$"
  TMP_MANIFEST="${MANIFEST_DIR}/install-manifest.new.$$"
  tmp_bin="${TMP_BIN}"
  tmp_manifest="${TMP_MANIFEST}"
  priv cp "${TMP_DIR}/extract/flowlens" "${tmp_bin}"
  priv chmod 0755 "${tmp_bin}"
  write_manifest_file "${tmp_manifest}" "${VERSION}" "${NEW_DIGEST}" "${path_file_out}" "${setcap_val}"
  if [ -n "${path_file_out}" ]; then
    TMP_PATH_FILE="${path_file_out}.flowlens.new.$$"
    tmp_path="${TMP_PATH_FILE}"
    write_path_block "${tmp_path}" "${path_file_out}"
  else
    tmp_path=""
  fi
  if [ -f "${BINARY_PATH}" ]; then
    cp "${BINARY_PATH}" "${TMP_DIR}/rollback-binary" || die 1 "failed to snapshot existing binary"
  fi
  if [ -f "${MANIFEST_PATH}" ]; then
    cp "${MANIFEST_PATH}" "${TMP_DIR}/rollback-manifest" || die 1 "failed to snapshot existing manifest"
  fi
  if [ -n "${path_file_out}" ] && [ -f "${path_file_out}" ]; then
    cp "${path_file_out}" "${TMP_DIR}/rollback-path" || die 1 "failed to snapshot PATH file"
  fi
  if ! priv mv -f "${tmp_bin}" "${BINARY_PATH}"; then
    die 1 "failed to publish binary"
  fi
  TMP_BIN=""
  if [ "${WANT_SETCAP}" -eq 1 ]; then
    if ! priv setcap cap_net_raw+ep "${BINARY_PATH}"; then
      rollback_install
      die 1 "failed to setcap ${BINARY_PATH}"
    fi
  fi
  if ! priv mv -f "${tmp_manifest}" "${MANIFEST_PATH}"; then
    rollback_install
    die 1 "failed to publish manifest"
  fi
  TMP_MANIFEST=""
  if [ -n "${tmp_path}" ]; then
    if ! priv mv -f "${tmp_path}" "${path_file_out}"; then
      rollback_install
      die 1 "failed to publish PATH file"
    fi
    TMP_PATH_FILE=""
  fi
  log "installed FlowLens ${VERSION} to ${BINARY_PATH}"
}

do_install() {
  detect_platform
  if [ "${WANT_SETCAP}" -eq 1 ] && [ "${PLATFORM}" != "linux" ]; then
    die 2 "--setcap is only supported on Linux"
  fi
  if [ "${WANT_SETCAP}" -eq 1 ] && ! command -v setcap >/dev/null 2>&1; then
    die 2 "--setcap requires the setcap command"
  fi
  if [ "${PLATFORM}" = "macos" ]; then
    log "macOS is reserved; current Releases have no macOS assets"
  fi
  resolve_dirs
  prepare_privileges
  fetch_version
  download_assets
  extract_asset
  preflight_install
  commit_install
}

do_uninstall() {
  local existing_digest tmp_path
  choose_path_file
  if [ ! -f "${MANIFEST_PATH}" ]; then
    if [ -e "${BINARY_PATH}" ]; then
      die 7 "target exists without an installer manifest: ${BINARY_PATH}"
    fi
    log "nothing to uninstall"
    return
  fi
  validate_manifest_file "${MANIFEST_PATH}" || die 8 "existing manifest is invalid"
  if [ -f "${MF_BINARY_PATH}" ]; then
    existing_digest="$(sha256_file "${MF_BINARY_PATH}")"
    if [ "${existing_digest}" != "${MF_DIGEST}" ] && [ "${WANT_FORCE}" -eq 0 ]; then
      die 8 "binary digest does not match manifest; refusing to delete"
    fi
  fi
  if [ "${WANT_DRY_RUN}" -eq 1 ]; then
    log "dry-run: would remove ${MF_BINARY_PATH}"
    log "dry-run: would remove ${MANIFEST_PATH}"
    return
  fi
  if [ -f "${MF_BINARY_PATH}" ]; then
    priv rm -f "${MF_BINARY_PATH}" || die 8 "failed to remove ${MF_BINARY_PATH}"
  fi
  if [ -n "${MF_PATH_FILE}" ] && [ -f "${MF_PATH_FILE}" ]; then
    tmp_path="${MF_PATH_FILE}.flowlens.uninstall.$$"
    remove_path_block "${tmp_path}" "${MF_PATH_FILE}"
    priv mv -f "${tmp_path}" "${MF_PATH_FILE}"
  fi
  priv rm -f "${MANIFEST_PATH}" || die 8 "failed to remove manifest"
  log "uninstalled FlowLens"
}

main() {
  parse_args "$@"
  if [ "${WANT_HELP}" -eq 1 ]; then
    usage
    exit 0
  fi
  apply_env
  validate_args
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/flowlens-install.XXXXXX")"
  trap cleanup EXIT
  if [ "${WANT_UNINSTALL}" -eq 1 ]; then
    resolve_dirs
    prepare_privileges
    do_uninstall
    exit 0
  fi
  do_install
}

main "$@"
