# FlowLens 与 netwatch 的 TLS 流量解析对比

调研日期：2026-09-27。

比较基线：FlowLens 0.7.1，当前工作区提交 `86dbec935127f69147e76ccee4b05f77054a674e`；netwatch 0.32.5，远端 main 提交 `c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9`。netwatch 源码通过临时目录中的只读 Git checkout 核查，以下远端链接固定到该提交。

这是源码、现有测试和协议规范的静态比较，未运行实流量实验、吞吐基准或双方测试套件。测试部分描述已有覆盖，不代表本次执行通过。建议是后续设计方向，本次没有改变解析行为。

## 主要结论

双方都使用 `tls-parser 0.12` 解析 ClientHello；差异主要来自解析前后的处理链路。FlowLens 提取 SNI，用于出站域名流量统计。netwatch 在此之上增加 ALPN、JA4、QUIC Initial 解析，以及使用客户端导出密钥的 TLS/QUIC 应用数据解密。

netwatch 的能力更广，但其 TCP TLS 路径仍然以单个 TCP payload 为输入，没有提供完整的 TCP 字节流、TLS record 和握手消息重组。不能因其具备 stream tracking 或 TLS decryption 就推断它解决了跨包 ClientHello 的识别问题。对 FlowLens 最直接的收益是提高域名识别的覆盖和可解释性：结构化结果、有界握手重组、连接代次，以及 QUIC Initial 支持。

## 技术对照

| 维度 | FlowLens 当前实现 | netwatch 当前实现 | 对我们的含义 |
| --- | --- | --- | --- |
| 抓包长度 | pcap snaplen 65,535 | pcap snaplen 65,535；协议分类另外裁到 4,096 字节 | 抓到完整网络帧不等于重组出完整 ClientHello；扩大 snaplen 不能解决 TCP 分段 |
| 解析基础 | `tls-parser 0.12`；首字节 `0x16` 路由 TLS | 同版本解析库；协议分类器链；TLS 还快速检查 record version 主字节 | 不必为了借鉴能力更换解析库 |
| 结果模型 | `Option<Arc<str>>`，仅成功域名 | `AppProtocol::Tls { sni, alpn, ech, ja4 }`；QUIC 有独立变体 | 协议已识别、没有域名、数据不完整应能分别表达 |
| TCP 分类重试 | 每个流表条目最多解析 3 次，每次输入当前包 payload | 第一个长度至少 16 字节的 payload 触发分类；TCP 分类失败也锁定结果 | 我们的重试有优势，但两者都不能把分片拼成 ClientHello |
| TLS 分帧 | 一次 `parse_tls_plaintext`，忽略返回的剩余输入 | TLS 分类和 Hello 字段提取同样解析一个 record | 需要分别处理 TCP 分段、多 record 和跨 record 握手消息 |
| ECH | 识别 `0xFE0D` 及旧 ESNI `0xFFCE`，返回无域名 | 检查 `0xFE0D`；保留可见 SNI，并附 `ech` 标记 | 将“观察到的 SNI”和“可用于目标域名归属的 SNI”分开 |
| QUIC | UDP 不进入域名解析/流表 | v1/v2 Initial 密钥派生、去头部保护、AEAD 解密、CRYPTO 分片缓存，再解析裸 TLS 握手 | 能扩展到 QUIC 域名识别，不要求用户提供会话密钥 |
| TLS 应用数据解密 | 没有 | keylog 驱动；TLS 1.3 三种常见 AEAD；TLS 1.2 部分 AES-GCM/ChaCha20-Poly1305 套件 | 适合客户端配合的诊断场景，对默认域名统计不是前置条件 |
| 连接生命周期 | 五元组缓存，65,536 条、5 分钟空闲过期；不跟踪 SYN/FIN/RST | 新 SYN/序号和关闭状态可触发新 stream generation | 重组缓冲和旧域名不能跨连接复用 |
| 存储成本 | 域名解析无 payload 缓存，原始 payload 不离开 capture 层 | 保存 stream segments/解密结果；stream 数据总预算 256 MiB；QUIC 跨包 CRYPTO 缓存每流上限 16 KiB | 借鉴必要状态即可，无需照搬包留存与解密存储体系 |

本地依据：[解析接口](../../src/domain_parse.rs)、[TLS 解析](../../src/domain_parse_tls.rs)、[协议路由](../../src/domain_parse_composite.rs)、[捕获入口](../../src/capture/parser.rs)、[流表](../../src/flow_table.rs)。远端依据：[结果模型](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/mod.rs#L36-L97)、[分类和握手提取](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/tls.rs#L38-L292)、[stream 处理](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/collectors/packets/mod.rs#L591-L893)。

## 应特别注意的实现边界

### TCP 重试不等于重组

FlowLens 的链路是当前 TCP payload → `CompositeDomainParser` → `TlsDomainParser` → 流表缓存。首次失败后，第二次收到的是第二个包自身的 payload，并没有前一个包的字节。因此将一个 ClientHello 分成 A/B 两段时，A 因不完整失败，B 又通常不是以 TLS record 头开始；三次重试不能恢复 A+B。

netwatch 的 TCP 分类也有这个限制，而且 `app_protocol_attempted` 在分类返回 `None` 时即设为 true。它提取解密需要的 client/server random 时会继续检查后续握手 payload，但这条路径仍没有重组，也不会自动修复已锁定的 TLS 分类结果。

证据：FlowLens `src/capture/parser.rs:352–388`、`src/domain_parse_tls.rs:65–81`；netwatch [分类锁定与 Hello 提取](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/collectors/packets/mod.rs#L769-L823)。netwatch 注释中的分片占比不是本次验证的测量结论，不应据此判断修复价值。

### 有 TLS 解密能力，不代表完整恢复应用会话

netwatch 从 ClientHello 获取 client random，从 ServerHello 获取协商密码套件；TLS 1.2 还需要 server random。keylog 按 client random 索引秘密，使用 `ring` 完成密钥派生和 AEAD 解密。TLS 1.3 使用 application traffic secrets；TLS 1.2 使用 `CLIENT_RANDOM` master secret。

实际捕获路径对每个 TCP payload 调用一次 `try_decrypt_tls_record`。它要求 payload 从 `0x17` record 头开始且这个 record 已完整存在，跨 TCP 段则直接返回；同 payload 后续 records 没有被循环处理。代码通过向前搜索最多跳过 16 个 record 序号来恢复部分解密进度，这不能补回缺失字节，也不等于 TCP 乱序重组。

实现支持观察到的 TLS 1.3 KeyUpdate 后更新密钥；缺失 KeyUpdate 后的密钥代次恢复、0-RTT、TLS 1.2 CBC 不在这条实现的支持范围内。keylog 尚未到达时可以在后续记录重试，但没有证据表明此前漏解的记录会被重新回放。没有客户端导出秘密，就不能依靠这些代码解密普通 TLS 应用数据。

证据：[记录解密及其边界](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/collectors/packets/mod.rs#L947-L1132)、[捕获调用点](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/collectors/packets/mod.rs#L1660-L1705)、[keylog 与密码学实现](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/tls_decrypt.rs)。

### QUIC Initial 的域名提取可以独立实现

QUIC Initial 的密钥来自公开的版本 salt 与 DCID，通过 HKDF 派生；去除头部保护并解开 Initial 后，可从 CRYPTO frames 得到 TLS ClientHello。因此，读取 QUIC Initial 中未被 ECH 隐藏的 SNI 不需要 SSLKEYLOGFILE。这与解密 QUIC 1-RTT 应用数据是不同能力。[RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2)

netwatch 代码支持 v1/v2 的 packet type、salt 和 HKDF labels，并在 stream tracker 合并多包 CRYPTO 数据。`dpi/quic.rs` 顶部仍有“未支持 v2/多包”的旧注释，不能据此判断当前能力。实际依据是 [版本分支](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/quic.rs#L39-L93)、[Initial 解析与解密](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/quic.rs#L682-L696)、[跨包缓存](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/collectors/packets/mod.rs#L825-L893)。

借鉴时要补足连续性判断：现有跨包缓存按 offset 写入并以零扩容，未单独记录收到的区间；不能把缓冲区长度当作已收到的连续长度。这是从源码得出的设计风险提示，本次没有复现错误 SNI。我们的实现应追踪 gaps、重叠、重传、连接身份与超时，并在获得完整连续握手后提交结果。

### ECH 扩展存在，不等于真实 ECH 已生效

RFC 9849 的 GREASE ECH 允许客户端在没有 ECH 配置时发送形似 ECH 的扩展；它不改变普通 TLS 握手的安全属性。因此仅看到扩展，不能断言可见 SNI 一定是掩护名称，也不能确认 ECH 已被服务器接受。[RFC 9849 §6.2](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.2)、[§10.1](https://www.rfc-editor.org/rfc/rfc9849.html#section-10.1)

FlowLens 一律丢弃相关 SNI 的策略避免把真实 ECH 的 outer name 算作目标域名，但会牺牲部分 GREASE ECH 的识别覆盖。netwatch 的 `sni + ech` 数据模型保留了更多观测信息，不过源码注释把两者都解释成“内层名字不可见”也过于绝对。

建议保留 `observed_sni` 与 `ech_extension_present`，另由域名归属策略判断是否采纳；不要直接命名成 `ech_enabled` 或把可见 SNI 自动加入“真实目标域名”排名。默认保守策略可以继续保留，同时报告无法确认归属的原因。

### ClientHello 元数据不等于协商结果

netwatch TLS 分类器保存的是 ClientHello 的第一个 ALPN，JA4 使用最高非 GREASE 的 supported version。它们分别表示客户端提出的协议和支持能力，不能直接当作最终 ALPN 或协商 TLS 版本。[TLS 分类器](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/tls.rs#L220-L290)

JA4 对 cipher/extension 列表做 GREASE 过滤、排序及摘要，并包含协议类型、版本、SNI 存在与 ALPN 提示。它适合辅助比较客户端协议栈，不应成为确定的进程身份或恶意流量结论。[JA4 实现](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/ja4.rs#L130-L185)

## 对 FlowLens 的建议顺序

| 顺序 | 建议 | 预期价值与验收重点 |
| --- | --- | --- |
| 1 | 将域名解析结果从单一 `Option` 扩成可区分“成功、需要更多数据、已识别但无可采纳域名、非目标协议、格式错误”的结果；记录 ECH 等原因 | 为重组和覆盖率测量提供基础。缺失分片不要直接消耗终局失败次数；ECH/no-SNI 不必重复解析三次 |
| 2 | 实现只面向握手初期的有界 TCP/record/handshake 重组，并跟踪连接代次 | 解决分段和跨 record ClientHello；按 TCP seq 处理乱序、重传和重叠，设置每流/全局字节预算、超时与淘汰，解析完成立即释放 payload |
| 3 | 添加 QUIC v1/v2 Initial → CRYPTO → ClientHello → SNI 路径 | 扩大 QUIC 域名覆盖；复用裸 ClientHello 的扩展提取逻辑。先做握手元数据，1-RTT 解密不是前置条件 |
| 4 | 在确有展示或诊断用途时增加 offered ALPN、客户端版本能力、可选 JA4 | 让用户理解协议栈差异；字段语义明确，指纹不取代本项目的进程归属证据 |
| 5 | 将 SSLKEYLOGFILE 解密作为可选诊断功能单独评估 | 客户端配合、记录序号、密钥更新、明文留存和应用协议解析都增加复杂度。先解决 record 重组，再考虑这条路线 |

1/2 可以组成一个受控的实现阶段。既有捕获层边界值得保留：原始 payload 不进入聚合层，只输出域名、协议元数据、识别状态及必要计数。无需为提取 SNI 留存整个连接的应用数据。

重组预算应基于 fixtures 和实际捕获测量确定，不能直接把 netwatch 的 16 KiB 当成协议上限。QUIC 的连接身份还需考虑 DCID/Retry；若暂不处理连接迁移，应明确说明覆盖边界。

同时需要核对域名统计口径：当前域名解析成功前的包没有回填；成功后的出站无 payload 包也在查表前返回，入站则会查表恢复 domain。它目前不能解释为完整连接的所有字节。[捕获路径](../../src/capture/parser.rs) 的相关位置是 339–388 行；[域名累加](../../src/stats/mod.rs) 的 581–590 行会跳过没有 domain 的记录。新增重组会延后识别时点，应同时决定识别前计数是否回填，并避免重复计数。

## 验证建议

FlowLens 已有完整 SNI、旧/新 ECH 扩展、无 SNI、截断输入和非握手输入测试；流表重试测试使用注入的 `RecordingParser` 模拟先失败后成功，不能证明真实 TLS 分片可恢复。见 `src/domain_parse_tls.rs:251` 起及 `src/capture/mod.rs:426`。

netwatch 有真实 Python ssl ClientHello fixture、JA4/GREASE 测试、RFC 8448 TLS 1.3 密钥与密文向量、TLS 1.2 PRF/AEAD 测试，以及实抓解密示例。这种“标准向量 + 真实客户端 fixture + 捕获链路实验”的组合值得借鉴。见 [TLS 测试](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/tls.rs#L296)、[解密测试](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/src/dpi/tls_decrypt.rs#L960)、[TLS 1.3 实验](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/examples/tls_decrypt_live.rs)、[QUIC 实验](https://github.com/matthart1983/netwatch/blob/c354da5a7e99bd8f6f5ee07d99acabb4d75cc0d9/examples/quic_decrypt_test.rs)。

后续实现至少应验证：

- 同一个 ClientHello 按多个切分点分成 TCP segments，包含乱序、重传、重叠与永久缺口。
- 一个 payload 包含多个 TLS records；一个握手消息跨 records；record 头本身被分段。
- 连接四元组复用、新 SYN、FIN/RST、超时和缓冲预算耗尽，不串用旧域名或旧握手。
- ECH 扩展存在/不存在、可见 SNI 保留、保守归属策略，以及畸形扩展不会制造成功结果。
- QUIC v1/v2 Initial 标准向量、多包 CRYPTO 连续性、重复片段、未知版本和 AEAD 认证失败。
- 重组释放后的内存、捕获丢包指标，以及按明确分母报告的连接识别率和字节覆盖率。

本次只新增研究文档；没有运行仓库要求的四项 Rust 代码检查，因为没有修改代码。后续实现仍须完整执行 `cargo fmt --all -- --check`、`cargo check --locked`、`cargo test --locked`、`cargo clippy --locked --all-targets --all-features -- -D warnings`。
