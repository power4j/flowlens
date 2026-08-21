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
