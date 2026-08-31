use std::sync::Arc;

/// L7 domain parser interface (the capture layer's trait seam).
///
/// Implementations extract the target domain from TCP payloads (e.g. TLS
/// ClientHello, plaintext HTTP/1.x requests). The capture layer calls this
/// interface only for outbound packets that carry a payload; the parsed
/// result is passed through to the aggregation layer via
/// [`crate::capture::Flow::domain`], and the raw payload never leaves the
/// capture layer.
///
/// Production paths use [`CompositeDomainParser`]; tests may inject a custom
/// implementation of this trait (e.g. `capture::tests::RecordingParser`) to
/// control parsing behavior.
///
/// [`CompositeDomainParser`]: crate::domain_parse_composite::CompositeDomainParser
pub trait DomainParser: Send + Sync {
    /// Parse the target domain from TCP payload bytes; return `None` when parsing fails.
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>>;
}
