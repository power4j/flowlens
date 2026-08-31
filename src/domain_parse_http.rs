//! HTTP/1.x request Host-header domain parser.
//!
//! Parses the HTTP/1.x request line + headers from plaintext TCP payloads
//! with [`httparse`] and extracts the Host header. RFC 9110 §7.2 makes the
//! Host header name case-insensitive; [`httparse`] keeps the wire form
//! without normalizing, so the comparison uses [`str::eq_ignore_ascii_case`].
//!
//! Behavior contract:
//! - After [`Status::Complete`], scan the headers for the first Host
//!   (case-insensitively) and return the UTF-8 decoded value; invalid UTF-8
//!   and empty Host values return `None`.
//! - [`Status::Partial`] (incomplete payload) returns `None`; the parser is
//!   stateless, and whether later payloads are retried is up to the capture
//!   layer's flow table.
//! - HTTP responses (`HTTP/1.1 200 ...`) are token errors in [`httparse`] (`Err(Token)`),
//!   naturally falling into the failure branch returning `None`, matching
//!   the parse-requests-only (outbound) semantics.
//! - Non-HTTP bytes, empty payloads and parse errors all return `None`.
//!
//! Called by [`CompositeDomainParser`] on the non-TLS branch.
//!
//! [`CompositeDomainParser`]: crate::domain_parse_composite::CompositeDomainParser
//! [`Status::Complete`]: httparse::Status::Complete
//! [`Status::Partial`]: httparse::Status::Partial

use std::sync::Arc;

use httparse::{EMPTY_HEADER, Request, Status};

use crate::domain_parse::DomainParser;

/// Maximum number of headers accepted in a single parse.
///
/// Why 64: it is [`httparse`]'s default cap (`parse_headers_iter` returns
/// `Err(TooManyHeaders)` when full). Real HTTP/1.x requests put Host among
/// the first few headers, so 64 covers typical browser/curl requests;
/// anything beyond is treated as a parse failure returning `None`.
///
/// [`httparse`]'s [`EMPTY_HEADER`] is `Header<'static>`, so 64 preallocated
/// stack slots cost about 1KB (two usizes per slot) — acceptable on a
/// 1CPU/1GB server.
const MAX_HEADERS: usize = 64;

/// Domain parser for HTTP/1.x requests.
///
/// Parses requests only (method SP path SP HTTP-version CRLF ... CRLF);
/// HTTP responses make [`httparse`] fail and fall into the `None` branch.
/// That is how this parser implements "match the outbound direction only":
/// inbound HTTP response bytes never yield a domain, and the capture layer's
/// direction filter provides the outer guard — this parser does not repeat
/// the direction check.
pub struct HttpDomainParser;

impl HttpDomainParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HttpDomainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainParser for HttpDomainParser {
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>> {
        // Reject empty payloads up front to skip the needless stack allocation; mirrors the tls module.
        if tcp_payload.is_empty() {
            return None;
        }

        let mut headers = [EMPTY_HEADER; MAX_HEADERS];
        let mut req = Request::new(&mut headers);

        // Accept Complete only: Partial (incomplete payload) and any Err
        // (non-HTTP request, HTTP response, malformed token, >64 headers)
        // all fall through to None.
        let _consumed = match req.parse(tcp_payload) {
            Ok(Status::Complete(n)) => n,
            _ => return None,
        };

        // `req.headers` is shrunk to the N slots actually filled after a
        // successful parse (see parse_headers_iter_uninit in the httparse
        // source), so iterating it directly is safe.
        //
        // httparse keeps header names in wire form (no lower-casing), hence
        // [`str::eq_ignore_ascii_case`]; it also trims leading/trailing
        // whitespace off header values while parsing, so no extra trim here.
        let host_value = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .map(|h| h.value)?;

        if host_value.is_empty() {
            return None;
        }

        str::from_utf8(host_value).ok().map(Arc::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── success paths ────────────────────────────────────────────────

    #[test]
    fn parses_host_from_get_request() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let domain = HttpDomainParser::new()
            .parse_domain(req)
            .expect("应从 GET 请求提取 Host");
        assert_eq!(domain.as_ref(), "example.com");
    }

    #[test]
    fn parses_host_from_post_request() {
        let body = b"hello world";
        let req = format!(
            "POST /api/submit HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body.len()
        );

        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(body);

        let domain = HttpDomainParser::new()
            .parse_domain(&bytes)
            .expect("应从 POST 请求提取 Host");
        assert_eq!(domain.as_ref(), "api.example.com");
    }

    #[test]
    fn parses_host_with_other_headers_present() {
        let req = b"GET /index.html HTTP/1.1\r\n\
                    Accept: */*\r\n\
                    Accept-Language: en-US\r\n\
                    User-Agent: flowlens-test/1.0\r\n\
                    Host: example.com\r\n\
                    Connection: keep-alive\r\n\
                    \r\n";

        let domain = HttpDomainParser::new()
            .parse_domain(req)
            .expect("应在多个 header 中找到 Host");
        assert_eq!(domain.as_ref(), "example.com");
    }

    #[test]
    fn parses_host_preserving_case_and_trailing_form() {
        // No extra normalization: case, trailing dot and port suffix are kept verbatim.
        let req = b"GET / HTTP/1.1\r\nHost: Example.COM.:8080\r\n\r\n";

        let domain = HttpDomainParser::new()
            .parse_domain(req)
            .expect("应返回 Host 头的原始值");
        assert_eq!(domain.as_ref(), "Example.COM.:8080");
    }

    // ── Host header name is case-insensitive (HTTP spec) ─────────────

    #[test]
    fn matches_host_header_case_insensitively() {
        // httparse keeps header names in wire form, so this parser compares
        // with eq_ignore_ascii_case. Covers the three common spellings.
        for name in ["Host", "host", "HOST"] {
            let req = format!("{name}: example.com\r\n");
            let buf = format!("GET / HTTP/1.1\r\n{req}\r\n");
            let domain = HttpDomainParser::new()
                .parse_domain(buf.as_bytes())
                .unwrap_or_else(|| panic!("应匹配大小写变体：{name}"));
            assert_eq!(domain.as_ref(), "example.com");
        }
    }

    // ── failure paths ────────────────────────────────────────────────

    #[test]
    fn returns_none_for_partial_first_packet() {
        // The payload holds the request line + partial headers, missing the \r\n\r\n terminator.
        let req = b"GET / HTTP/1.1\r\nHost: example.com";

        assert!(HttpDomainParser::new().parse_domain(req).is_none());
    }

    #[test]
    fn returns_none_for_request_without_host() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(req).is_none());
    }

    #[test]
    fn returns_none_for_http_1_0_request_without_host() {
        // HTTP/1.0 allows requests without Host (RFC 1945) and httparse
        // still parses them; this parser returns None for a missing Host.
        let req = b"GET / HTTP/1.0\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(req).is_none());
    }

    #[test]
    fn returns_none_for_http_response() {
        // Outbound responses must not be treated as a Host source — this parser only recognizes the request-line format.
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(resp).is_none());
    }

    #[test]
    fn returns_none_for_non_http_bytes() {
        // TLS ClientHello bytes, random binary and plain text must not be treated as HTTP requests.
        let tls_bytes = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03";
        assert!(HttpDomainParser::new().parse_domain(tls_bytes).is_none());

        let binary = b"\xff\xfe\xfd\xfc";
        assert!(HttpDomainParser::new().parse_domain(binary).is_none());

        let text = b"not a request line at all";
        assert!(HttpDomainParser::new().parse_domain(text).is_none());
    }

    #[test]
    fn returns_none_for_empty_payload() {
        assert!(HttpDomainParser::new().parse_domain(&[]).is_none());
    }

    #[test]
    fn returns_none_for_truncated_request_line() {
        // A handful of bytes — not even a complete request line.
        assert!(HttpDomainParser::new().parse_domain(b"GET / HT").is_none());
    }

    #[test]
    fn returns_none_for_empty_host_header() {
        // The Host header is present but empty — an empty string is not a valid domain, so return None.
        let req = b"GET / HTTP/1.1\r\nHost:\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(req).is_none());
    }

    #[test]
    fn returns_none_for_too_many_headers() {
        // Exceeding MAX_HEADERS (64) should make httparse return TooManyHeaders -> None.
        let mut buf: Vec<u8> = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 1) {
            buf.extend_from_slice(format!("X-Custom-{i}: v\r\n").as_bytes());
        }
        buf.extend_from_slice(b"Host: example.com\r\n\r\n");

        assert!(HttpDomainParser::new().parse_domain(&buf).is_none());
    }
}
