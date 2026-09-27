use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum DomainKind {
    Ordinary,
    PublicSni,
}

/// A visible client name and its statistical identity; no destination proof.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DomainName {
    name: Arc<str>,
    kind: DomainKind,
}

impl DomainName {
    pub fn new(name: Arc<str>, kind: DomainKind) -> Self {
        Self { name, kind }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> DomainKind {
        self.kind
    }
}

impl From<Arc<str>> for DomainName {
    fn from(name: Arc<str>) -> Self {
        Self::new(name, DomainKind::Ordinary)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HelloObservation {
    pub observed_sni: Option<Arc<str>>,
    pub ech_extension_present: bool,
    pub esni_extension_present: bool,
}

impl HelloObservation {
    pub fn visible_name(&self) -> Option<DomainName> {
        self.observed_sni.clone().map(|name| {
            DomainName::new(
                name,
                if self.ech_extension_present || self.esni_extension_present {
                    DomainKind::PublicSni
                } else {
                    DomainKind::Ordinary
                },
            )
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DomainReason {
    NoSni,
    NonTargetProtocol,
    Malformed,
    OverlapConflict,
    GapAtDeadline,
    HandshakeTimeout,
    PerFlowBudget,
    GlobalBudgetEvicted,
    ClosedBeforeHello,
    GenerationReplaced,
    ObservationTimeout,
    GenerationAmbiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainParseResult {
    NeedMore,
    Complete(HelloObservation),
    Rejected(DomainReason),
}

impl DomainParseResult {
    pub fn adopted_domain(&self) -> Option<Arc<str>> {
        match self {
            Self::Complete(hello)
                if !hello.ech_extension_present && !hello.esni_extension_present =>
            {
                hello.observed_sni.clone()
            }
            _ => None,
        }
    }
}

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

    fn parse_result(&self, payload: &[u8]) -> DomainParseResult {
        match self.parse_domain(payload) {
            Some(domain) => DomainParseResult::Complete(HelloObservation {
                observed_sni: Some(domain),
                ..HelloObservation::default()
            }),
            None => DomainParseResult::Rejected(DomainReason::NonTargetProtocol),
        }
    }

    /// Compatibility for existing single-packet parser injections.
    fn supports_streams(&self) -> bool {
        false
    }
}
