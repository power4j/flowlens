//! TLS ClientHello domain parser.
//!
//! Identifies TLS handshake ClientHello records in TCP payloads and extracts
//! the SNI with [`tls_parser`]. When an ECH extension
//! (encrypted_server_name / encrypted_client_hello) is present the parser
//! returns `None` (the real SNI cannot be decrypted, so the flow falls back
//! to NoDomain).
//!
//! Called by [`CompositeDomainParser`] on the TLS handshake ContentType branch.
//!
//! [`CompositeDomainParser`]: crate::domain_parse_composite::CompositeDomainParser

use std::sync::Arc;

use tls_parser::{TlsExtension, parse_tls_extensions, parse_tls_handshake_client_hello};

use crate::domain_parse::{DomainParseResult, DomainParser, DomainReason, HelloObservation};

/// RFC 9849 `encrypted_client_hello` extension type code.
///
/// tls-parser 0.12 only registers the draft-ietf-tls-esni code
/// [`DRAFT_ENCRYPTED_SERVER_NAME_TYPE`] (0xFFCE) and does not recognize the
/// RFC 9849 code 0xFE0D. Real-world ECH traffic (modern browsers) uses
/// 0xFE0D, which parses into the [`TlsExtension::Unknown`] branch, so the
/// type code has to be compared by hand.
const RFC9849_ECH_EXTENSION_TYPE: u16 = 0xFE0D;

/// draft-ietf-tls-esni `encrypted_server_name` extension type code.
///
/// tls-parser 0.12 registers this code point and parses it into
/// [`TlsExtension::EncryptedServerName`]. If truncated extension data makes
/// parsing fail, the whole extensions list fails to parse (it does not fall
/// back to `Unknown`) and the caller gets `None` — matching the contract
/// that parse errors return `None`.
const DRAFT_ENCRYPTED_SERVER_NAME_TYPE: u16 = 0xFFCE;

/// Domain parser for TLS ClientHello records.
///
/// Behavior contract:
/// - Handles only TLS handshake ClientHello (ContentType=22, HandshakeType=0x01).
/// - Returns `None` when an ECH extension is detected (the
///   `EncryptedServerName` variant, `Unknown(0xFFCE)` or `Unknown(0xFE0D)`),
///   even if an outer SNI is also present.
/// - Otherwise returns the first `host_name` SNI entry.
/// - Non-ClientHello records (ApplicationData etc.), missing SNI, parse
///   errors and truncated bytes all return `None`.
pub struct TlsDomainParser;

impl TlsDomainParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TlsDomainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainParser for TlsDomainParser {
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>> {
        self.parse_result(tcp_payload).adopted_domain()
    }

    fn supports_streams(&self) -> bool {
        true
    }

    fn parse_result(&self, input: &[u8]) -> DomainParseResult {
        use DomainParseResult::{NeedMore, Rejected};
        if input.is_empty() {
            return NeedMore;
        }
        if input[0] != 22 {
            return Rejected(DomainReason::NonTargetProtocol);
        }
        // Only handshake bodies are combined. The bounded capture buffer reserves
        // space for this temporary copy before invoking the parser.
        let mut handshake = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let remaining = &input[offset..];
            if remaining.len() < 5 {
                return NeedMore;
            }
            if remaining[0] != 22 || remaining[1] != 3 || remaining[2] > 4 {
                return Rejected(DomainReason::Malformed);
            }
            let length = usize::from(u16::from_be_bytes([remaining[3], remaining[4]]));
            if length == 0 {
                return Rejected(DomainReason::Malformed);
            }
            if remaining.len() < 5 + length {
                return NeedMore;
            }
            handshake.reserve_exact(length);
            handshake.extend_from_slice(&remaining[5..5 + length]);
            offset += 5 + length;
            if handshake.len() < 4 {
                continue;
            }
            if handshake[0] != 1 {
                return Rejected(DomainReason::NonTargetProtocol);
            }
            let message_length = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if message_length > 64 * 1024 {
                return Rejected(DomainReason::PerFlowBudget);
            }
            if handshake.len() >= 4 + message_length {
                return parse_hello(&handshake[..4 + message_length]);
            }
        }
        NeedMore
    }
}

fn parse_hello(handshake: &[u8]) -> DomainParseResult {
    let malformed = || DomainParseResult::Rejected(DomainReason::Malformed);
    let Ok((rest, hello)) = parse_tls_handshake_client_hello(&handshake[4..]) else {
        return malformed();
    };
    if !rest.is_empty() {
        return malformed();
    }
    let Some(ext_bytes) = hello.ext else {
        return DomainParseResult::Complete(HelloObservation::default());
    };
    // tls-parser's many0 parser can accept a valid prefix of a malformed list.
    // Validate every extension's declared boundary and require full consumption.
    let mut offset = 0;
    let mut types = std::collections::HashSet::new();
    while offset < ext_bytes.len() {
        let Some(header) = ext_bytes.get(offset..offset + 4) else {
            return malformed();
        };
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if !types.insert(kind) || offset + 4 + length > ext_bytes.len() {
            return malformed();
        }
        if kind == 0 {
            let body = &ext_bytes[offset + 4..offset + 4 + length];
            if body.len() < 2
                || usize::from(u16::from_be_bytes([body[0], body[1]])) != body.len() - 2
            {
                return malformed();
            }
            let mut cursor = 2;
            let mut names = std::collections::HashSet::new();
            while cursor < body.len() {
                let Some(header) = body.get(cursor..cursor + 3) else {
                    return malformed();
                };
                let name_len = usize::from(u16::from_be_bytes([header[1], header[2]]));
                if !names.insert(header[0]) || name_len == 0 || cursor + 3 + name_len > body.len() {
                    return malformed();
                }
                cursor += 3 + name_len;
            }
        }
        offset += 4 + length;
    }
    let Ok((rest, extensions)) = parse_tls_extensions(ext_bytes) else {
        return malformed();
    };
    if !rest.is_empty() {
        return malformed();
    }
    let sni = extract_sni(&extensions);
    if extensions.iter().any(|ext| matches!(ext, TlsExtension::SNI(entries)
        if entries.iter().any(|(kind, name)| kind.0 == 0 && (name.is_empty() || std::str::from_utf8(name).is_err())))) {
        return malformed();
    }
    DomainParseResult::Complete(HelloObservation {
        observed_sni: sni,
        ech_extension_present: types.contains(&RFC9849_ECH_EXTENSION_TYPE),
        esni_extension_present: types.contains(&DRAFT_ENCRYPTED_SERVER_NAME_TYPE),
    })
}

/// Extract the first `host_name` SNI entry from the extensions; skip invalid UTF-8.
fn extract_sni(extensions: &[TlsExtension<'_>]) -> Option<Arc<str>> {
    for ext in extensions {
        if let TlsExtension::SNI(entries) = ext {
            for (name_type, name) in entries {
                if name_type.0 == 0
                    && let Ok(hostname) = std::str::from_utf8(name)
                {
                    return Some(Arc::from(hostname));
                }
            }
        }
    }
    None
}

/// Shared TLS ClientHello wire-format builders (test fixtures).
///
/// Builds TLS record bytes by hand so tests need no external pcap files. All
/// fixtures use a TLS 1.2 ClientHello skeleton (SNI/ECH fields sit at the
/// same offsets in TLS 1.3). Shared by this module's tests,
/// `domain_parse_composite::tests` and `capture::tests::perf_benches` — any
/// TLS wire-format construction goes through this module instead of being
/// copied in three places.
#[cfg(any(test, feature = "tls-eval-observe"))]
#[allow(dead_code)]
pub mod test_fixtures {
    /// Build a TLS record: `content_type(1) | version(2) | length(2) | payload`.
    pub fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + payload.len());
        record.push(content_type);
        record.extend_from_slice(&[0x03, 0x01]); // record version: TLS 1.0
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    /// Build a TLS record with ContentType=Handshake(0x16); the payload is a handshake message.
    pub fn tls_record_handshake(handshake_msg: &[u8]) -> Vec<u8> {
        tls_record(0x16, handshake_msg)
    }

    /// Build a handshake message: `msg_type(1) | length(3) | body`.
    pub fn handshake_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(msg_type);
        msg.push((len >> 16) as u8);
        msg.push((len >> 8) as u8);
        msg.push(len as u8);
        msg.extend_from_slice(body);
        msg
    }

    /// Build a ClientHello body (the payload of handshake type=0x01), with an
    /// optional SNI and extra extensions.
    pub fn client_hello_body(sni: Option<&str>, extra_extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        // version: TLS 1.2
        body.extend_from_slice(&[0x03, 0x03]);
        // random: 32 zero bytes
        body.extend_from_slice(&[0u8; 32]);
        // session_id: empty
        body.push(0x00);
        // cipher_suites: a single suite
        body.extend_from_slice(&[0x00, 0x02]); // length=2
        body.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
        // compression_methods: null
        body.push(0x01); // length=1
        body.push(0x00); // null

        // assemble the extensions
        let mut extensions_buf = Vec::new();
        if let Some(name) = sni {
            extensions_buf.extend_from_slice(&sni_extension(name));
        }
        for ext in extra_extensions {
            extensions_buf.extend_from_slice(ext);
        }

        if !extensions_buf.is_empty() {
            body.extend_from_slice(&(extensions_buf.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions_buf);
        }

        // wrap into a handshake msg (type=0x01)
        handshake_msg(0x01, &body)
    }

    /// Build an SNI extension (type=0x0000, a single host_name entry).
    pub fn sni_extension(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let name_len = name.len();
        let list_len = 1 + 2 + name_len; // name_type + name_length + name
        let ext_data_len = 2 + list_len; // server_name_list_length + list

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // type: server_name
        ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes()); // server_name_list_length
        ext.push(0x00); // name_type: host_name
        ext.extend_from_slice(&(name_len as u16).to_be_bytes());
        ext.extend_from_slice(name);
        ext
    }

    /// Build an arbitrary extension: `type(2) | length(2) | data`.
    pub fn build_raw_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut ext = Vec::with_capacity(4 + data.len());
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(data);
        ext
    }

    /// Build valid draft-ietf-tls-esni EncryptedServerName data.
    ///
    /// Field order (from the tls-parser source, parse_tls_extension_encrypted_server_name):
    /// ciphersuite(2) | group(2) | key_share<2+> | record_digest<2+> | encrypted_sni<2+>
    pub fn valid_draft_ech_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x01]); // ciphersuite
        data.extend_from_slice(&[0x00, 0x17]); // group: x25519
        data.extend_from_slice(&[0x00, 0x01, 0xAA]); // key_share: len=1
        data.extend_from_slice(&[0x00, 0x01, 0xBB]); // record_digest: len=1
        data.extend_from_slice(&[0x00, 0x01, 0xCC]); // encrypted_sni: len=1
        data
    }

    /// Build a complete TLS ClientHello handshake record carrying an SNI (convenience wrapper).
    pub fn tls_client_hello_with_sni(name: &str) -> Vec<u8> {
        let body = client_hello_body(Some(name), &[]);
        tls_record_handshake(&body)
    }

    /// Build a complete TLS ClientHello handshake record with an ECH extension
    /// (RFC 9849 0xFE0D).
    ///
    /// Used to exercise the ECH path — the outer SNI is the cover domain
    /// "cover.example". For the draft code point (0xFFCE) or custom bytes,
    /// combine `client_hello_body` + `build_raw_extension` directly.
    pub fn tls_client_hello_with_ech() -> Vec<u8> {
        let ech_ext = build_raw_extension(0xFE0D, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let body = client_hello_body(Some("cover.example"), &[ech_ext]);
        tls_record_handshake(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;

    // ── success paths ────────────────────────────────────────────────

    #[test]
    fn parses_sni_from_client_hello_with_sni() {
        let record = tls_record_handshake(&client_hello_body(Some("example.com"), &[]));

        let domain = TlsDomainParser::new()
            .parse_domain(&record)
            .expect("应从 ClientHello 提取 SNI");
        assert_eq!(domain.as_ref(), "example.com");
    }

    #[test]
    fn parses_long_sni_from_client_hello() {
        let name = "very-long-subdomain.example.invalid";
        let record = tls_record_handshake(&client_hello_body(Some(name), &[]));

        let domain = TlsDomainParser::new()
            .parse_domain(&record)
            .expect("应提取较长的 SNI");
        assert_eq!(domain.as_ref(), name);
    }

    #[test]
    fn parses_sni_when_other_extensions_present() {
        let renegotiation = build_raw_extension(0xFF01, &[0x00]);
        let record =
            tls_record_handshake(&client_hello_body(Some("example.com"), &[renegotiation]));

        let domain = TlsDomainParser::new()
            .parse_domain(&record)
            .expect("应跳过非 SNI/ECH extension 并提取 SNI");
        assert_eq!(domain.as_ref(), "example.com");
    }

    // ── ECH paths ────────────────────────────────────────────────────

    #[test]
    fn returns_none_for_draft_encrypted_server_name_extension() {
        let ech = build_raw_extension(0xFFCE, &valid_draft_ech_data());
        let record = tls_record_handshake(&client_hello_body(Some("cover.example"), &[ech]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_rfc9849_ech_extension() {
        let ech = build_raw_extension(0xFE0D, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let record = tls_record_handshake(&client_hello_body(Some("cover.example"), &[ech]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn ech_takes_precedence_over_sni() {
        // RFC 9849 §4: ECH clients should also send an outer SNI as cover.
        // The parser must drop the outer SNI whenever ECH is present.
        let ech = build_raw_extension(0xFE0D, &[0x00, 0x01, 0x02]);
        let record = tls_record_handshake(&client_hello_body(Some("cover.example"), &[ech]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    // ── failure paths ────────────────────────────────────────────────

    #[test]
    fn returns_none_for_client_hello_without_extensions() {
        let record = tls_record_handshake(&client_hello_body(None, &[]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_client_hello_with_extensions_but_no_sni() {
        let renegotiation = build_raw_extension(0xFF01, &[0x00]);
        let record = tls_record_handshake(&client_hello_body(None, &[renegotiation]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_application_data_record() {
        let record = tls_record(0x17, &[0x01, 0x02, 0x03, 0x04]);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_alert_record() {
        let record = tls_record(0x15, &[0x01, 0x00]);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_empty_payload() {
        assert!(TlsDomainParser::new().parse_domain(&[]).is_none());
    }

    #[test]
    fn returns_none_for_truncated_record_header() {
        assert!(TlsDomainParser::new().parse_domain(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn returns_none_for_truncated_handshake_body() {
        // The record header declares a 64-byte payload but only 5 bytes follow.
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x40];
        record.extend_from_slice(&[0x01, 0x00, 0x00, 0x3F, 0x03]);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_non_tls_payload() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert!(TlsDomainParser::new().parse_domain(payload).is_none());
    }

    #[test]
    fn returns_none_for_non_handshake_record_with_handshake_bytes_in_payload() {
        // An ApplicationData payload that happens to start with 0x01 must not be treated as a ClientHello.
        let payload = [0x01, 0x00, 0x00, 0x10, 0x03, 0x03, 0x00, 0x00];
        let record = tls_record(0x17, &payload);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }
}
