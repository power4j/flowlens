//! 复合域名解析器（04 票）：按首字节路由 TLS / HTTP。
//!
//! `payload[0] == 0x16`（TLS handshake ContentType）走 [`TlsDomainParser`]；
//! 否则走 [`HttpDomainParser`]——HTTP 请求行以 ASCII method（G/P/H/D/C/O/T 等）
//! 开头，绝不与 0x16 冲突。
//!
//! 选首字节路由而非链式（TLS 失败再试 HTTP）的理由：
//! 1. 性能：HTTP 请求不会被 tls-parser 尝试（反之亦然），每次解析仅一个 parser
//!    被调用；
//! 2. 清晰：路由规则与 wire format 对应；
//! 3. 可预测：不依赖 parser 实现的失败行为（例如 tls-parser 对部分 HTTP
//!    字节可能 panic 或返回不确定错误）。
//!
//! 非 TLS 非 HTTP 的字节（任意 0x16 之外的二进制）会落到 HTTP parser，由
//! httparse 返回 None（与 spec Q12 "首包解析失败标记 NoDomain" 一致）。

use std::sync::Arc;

use crate::domain_parse::DomainParser;
use crate::domain_parse_http::HttpDomainParser;
use crate::domain_parse_tls::TlsDomainParser;

/// TLS ContentType=Handshake 的 wire 值（RFC 8446 §5.1）。
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/// TLS + HTTP 复合域名解析器。
///
/// 生产路径（`CaptureSource::open`）使用此类型作为默认 parser，配合
/// [`crate::flow_table::FlowTable`] 实现"每连接首包解析一次"。
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

    // ── 路由分支 ─────────────────────────────────────────────────────

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

    // ── 失败路径 ─────────────────────────────────────────────────────

    #[test]
    fn returns_none_for_non_tls_non_http_payload() {
        // 0xAA 非 TLS handshake 也不构成 HTTP 请求行，httparse 解析失败 → None
        let binary: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        assert!(CompositeDomainParser::new().parse_domain(binary).is_none());
    }

    #[test]
    fn returns_none_for_ech_tls_payload() {
        // ECH extension 的 TLS ClientHello 由 TLS 分支处理并返回 None
        // （tls-parser 已识别 ECH 并丢弃外层 SNI，见 02 票测试）。
        let record = tls_client_hello_with_ech();

        assert!(CompositeDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_empty_payload() {
        assert!(CompositeDomainParser::new().parse_domain(&[]).is_none());
    }

    #[test]
    fn returns_none_for_application_data_record() {
        // 0x17 起始的 TLS ApplicationData 不是 handshake → HTTP 分支 → httparse 失败
        let record = tls_record(0x17, &[0x01, 0x02, 0x03, 0x04]);
        assert!(CompositeDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_http_response() {
        // HTTP 响应（出站方向不应作 Host 源）首字节 H(0x48) 非 0x16 → HTTP 分支
        // httparse 对响应行格式解析失败 → None。
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(CompositeDomainParser::new().parse_domain(resp).is_none());
    }
}
