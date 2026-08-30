//! HTTP/1.x 请求 Host 头域名解析器（03 票）。
//!
//! 从明文 TCP payload 用 [`httparse`] 解析 HTTP/1.x 请求行 + Headers，提取 Host 头。
//! HTTP Host 头在 RFC 9110 §7.2 中规定为大小写不敏感，[`httparse`] 保留 wire 形式
//! 不做归一（已对照源码确认），故此处用 [`str::eq_ignore_ascii_case`] 比对。
//!
//! 行为契约：
//! - [`Status::Complete`] 后遍历 headers 找首个 Host（大小写不敏感），命中即返回
//!   UTF-8 解码结果；无效 UTF-8、空 Host 值返回 `None`。
//! - [`Status::Partial`]（当前 payload 不完整）返回 `None`；解析器本身无状态，
//!   是否对后续 payload 重试由 capture 层流表控制。
//! - HTTP 响应（`HTTP/1.1 200 ...`）会被 [`httparse`] 视为 token 错误（`Err(Token)`），
//!   自然落到失败分支返回 `None`，匹配"只解析请求，匹配出站方向"。
//! - 非 HTTP 字节、空 payload、解析错误统一返回 `None`。
//!
//! 04 票起由 [`CompositeDomainParser`] 在非 TLS 分支调用。
//!
//! [`CompositeDomainParser`]: crate::domain_parse_composite::CompositeDomainParser
//! [`Status::Complete`]: httparse::Status::Complete
//! [`Status::Partial`]: httparse::Status::Partial

use std::sync::Arc;

use httparse::{EMPTY_HEADER, Request, Status};

use crate::domain_parse::DomainParser;

/// 单次解析最多接受的 header 数量。
///
/// 选 64 的依据：[`httparse`] 默认上限（`parse_headers_iter` 满即返回
/// `Err(TooManyHeaders)`）；真实 HTTP/1.x 请求 Host 通常在前几个 header，64 足够
/// 覆盖常规浏览器/curl 请求；超出按解析失败返回 `None`（与 spec Q12 一致）。
///
/// [`httparse`] 的 [`EMPTY_HEADER`] 是 `Header<'static>`，栈上预分配 64 个槽位
/// 约 1KB（每槽 2 个 usize），对 1CPU/1GB 服务器可接受。
const MAX_HEADERS: usize = 64;

/// HTTP/1.x 请求的域名解析器。
///
/// 仅解析请求（method SP path SP HTTP-version CRLF ... CRLF），HTTP 响应会让
/// [`httparse`] 失败并落到 `None` 分支——这是本解析器"只匹配出站方向"的语义实现
/// 点：入站方向的 HTTP 响应字节不会得到域名，由 capture 层的方向过滤（01 票）兜
/// 底，本解析器不重复判断方向。
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
        // 快速拒绝空 payload，避免无谓的栈分配；与 tls 模块对齐。
        if tcp_payload.is_empty() {
            return None;
        }

        let mut headers = [EMPTY_HEADER; MAX_HEADERS];
        let mut req = Request::new(&mut headers);

        // 只接收 Complete：Partial（当前 payload 不完整）、任何 Err（非
        // HTTP 请求、HTTP 响应、畸形 token、超出 64 header）都落到 None。
        let _consumed = match req.parse(tcp_payload) {
            Ok(Status::Complete(n)) => n,
            _ => return None,
        };

        // `req.headers` 在解析成功后被 shrink 到实际填充的 N 个（见 httparse 源
        // 码 parse_headers_iter_uninit），可直接遍历。
        //
        // httparse 保留 header name 的 wire 形式（不 lower-case），故用
        // [`str::eq_ignore_ascii_case`]；它也在解析时 trim 过 header value 的前
        // 后空白，此处不再重复 trim。
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

    // ── 成功路径 ────────────────────────────────────────────────────────

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
        // spec: 不做额外归一——大小写、trailing dot、port 后缀一律保留原始形式。
        let req = b"GET / HTTP/1.1\r\nHost: Example.COM.:8080\r\n\r\n";

        let domain = HttpDomainParser::new()
            .parse_domain(req)
            .expect("应返回 Host 头的原始值");
        assert_eq!(domain.as_ref(), "Example.COM.:8080");
    }

    // ── Host 头大小写不敏感（HTTP 规范） ──────────────────────────────

    #[test]
    fn matches_host_header_case_insensitively() {
        // httparse 保留 header name 的 wire 形式，本解析器用 eq_ignore_ascii_case
        // 比对。覆盖三种常见写法。
        for name in ["Host", "host", "HOST"] {
            let req = format!("{name}: example.com\r\n");
            let buf = format!("GET / HTTP/1.1\r\n{req}\r\n");
            let domain = HttpDomainParser::new()
                .parse_domain(buf.as_bytes())
                .unwrap_or_else(|| panic!("应匹配大小写变体：{name}"));
            assert_eq!(domain.as_ref(), "example.com");
        }
    }

    // ── 失败路径 ───────────────────────────────────────────────────────

    #[test]
    fn returns_none_for_partial_first_packet() {
        // payload 只含请求行 + 部分 header，缺 \r\n\r\n 终结符。
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
        // HTTP/1.0 允许无 Host（RFC 1945），httparse 仍解析成功；本解析器按"无
        // Host"返回 None。
        let req = b"GET / HTTP/1.0\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(req).is_none());
    }

    #[test]
    fn returns_none_for_http_response() {
        // 出站方向的响应不应被当 Host 源——本解析器只识别请求行格式。
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(resp).is_none());
    }

    #[test]
    fn returns_none_for_non_http_bytes() {
        // TLS ClientHello 字节、随机二进制、纯文本都不应被当成 HTTP 请求。
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
        // 只有几个字节，连请求行都不完整。
        assert!(HttpDomainParser::new().parse_domain(b"GET / HT").is_none());
    }

    #[test]
    fn returns_none_for_empty_host_header() {
        // Host 头存在但值为空——空字符串不是合法域名，按 None 处理。
        let req = b"GET / HTTP/1.1\r\nHost:\r\n\r\n";

        assert!(HttpDomainParser::new().parse_domain(req).is_none());
    }

    #[test]
    fn returns_none_for_too_many_headers() {
        // 超出 MAX_HEADERS（64）应让 httparse 返回 TooManyHeaders -> None。
        let mut buf: Vec<u8> = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 1) {
            buf.extend_from_slice(format!("X-Custom-{i}: v\r\n").as_bytes());
        }
        buf.extend_from_slice(b"Host: example.com\r\n\r\n");

        assert!(HttpDomainParser::new().parse_domain(&buf).is_none());
    }
}
