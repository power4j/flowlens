//! Composite domain parser: routes TLS / HTTP by the first payload byte.
//!
//! `payload[0] == 0x16` (TLS handshake ContentType) goes to
//! [`TlsDomainParser`]; everything else goes to [`HttpDomainParser`] — an
//! HTTP request line starts with an ASCII method (G/P/H/D/C/O/T, ...), which
//! never collides with 0x16.
//!
//! Why first-byte routing instead of a chain (try TLS, fall back to HTTP):
//! 1. Performance: HTTP requests are never handed to tls-parser (and vice
//!    versa); exactly one parser runs per parse.
//! 2. Clarity: the routing rule maps 1:1 to the wire format.
//! 3. Predictability: no reliance on parser failure behavior (tls-parser
//!    may panic or return unstable errors on some HTTP bytes).
//!
//! Bytes that are neither TLS nor HTTP (any binary other than a 0x16
//! prefix) land in the HTTP parser and httparse returns None;
//! connection-level bounded retries are governed by the capture layer's
//! flow table.

use std::sync::Arc;

use crate::domain_parse::DomainParser;
use crate::domain_parse_http::HttpDomainParser;
use crate::domain_parse_tls::TlsDomainParser;

/// Wire value of TLS ContentType=Handshake (RFC 8446 §5.1).
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/// Composite TLS + HTTP domain parser.
///
/// The production path (`CaptureSource::open`) uses this type as the default
/// parser, combined with [`crate::flow_table::FlowTable`] for
/// connection-level caching and bounded retries.
pub struct CompositeDomainParser {
    tls: TlsDomainParser,
    http: HttpDomainParser,
}

impl CompositeDomainParser {
    pub fn new() -> Self {
        Self {
            tls: TlsDomainParser::new(),
            http: HttpDomainParser::new(),
        }
    }
}

impl Default for CompositeDomainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainParser for CompositeDomainParser {
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>> {
        if tcp_payload.is_empty() {
            return None;
        }
        if tcp_payload[0] == TLS_HANDSHAKE_CONTENT_TYPE {
            self.tls.parse_domain(tcp_payload)
        } else {
            self.http.parse_domain(tcp_payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_parse_tls::test_fixtures::*;

    // ── routing branches ────────────────────────────────────────────

    #[test]
    fn routes_tls_payload_to_tls_parser() {
        let record = tls_client_hello_with_sni("example.com");

        let domain = CompositeDomainParser::new()
            .parse_domain(&record)
            .expect("TLS payload 应由 TLS 分支解析");
        assert_eq!(domain.as_ref(), "example.com");
    }

    #[test]
    fn routes_http_payload_to_http_parser() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let domain = CompositeDomainParser::new()
            .parse_domain(req)
            .expect("HTTP payload 应由 HTTP 分支解析");
        assert_eq!(domain.as_ref(), "example.com");
    }

    // ── failure paths ───────────────────────────────────────────────

    #[test]
    fn returns_none_for_non_tls_non_http_payload() {
        // 0xAA is neither a TLS handshake nor an HTTP request line; httparse fails to parse -> None
        let binary: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        assert!(CompositeDomainParser::new().parse_domain(binary).is_none());
    }

    #[test]
    fn returns_none_for_ech_tls_payload() {
        // A TLS ClientHello with an ECH extension is handled by the TLS branch
        // and returns None (tls-parser recognizes ECH and drops the outer SNI).
        let record = tls_client_hello_with_ech();

        assert!(CompositeDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_empty_payload() {
        assert!(CompositeDomainParser::new().parse_domain(&[]).is_none());
    }

    #[test]
    fn returns_none_for_application_data_record() {
        // TLS ApplicationData starting with 0x17 is not a handshake -> HTTP branch -> httparse fails
        let record = tls_record(0x17, &[0x01, 0x02, 0x03, 0x04]);
        assert!(CompositeDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_http_response() {
        // An HTTP response (outbound responses are not a Host source) starts
        // with H(0x48), not 0x16 -> HTTP branch; httparse rejects the
        // response-line format -> None.
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(CompositeDomainParser::new().parse_domain(resp).is_none());
    }
}
