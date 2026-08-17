# 0013 - 进程归属升级为「独占/共享」包容式分级记账

状态：已接受（2026-08-17，grilling 会话共识）
关联：`CONTEXT.md` 词汇表需随本 ADR 落地同步修订（见「词汇表影响」）。

## 背景

- 现状：`ProcessIdentity::{Attributed, Unattributed}` 二元模型（`src/stats.rs`），未归属字节单行累计，进程维度统计自启动以来只增不减。
- 痛点：未归属绝对值必然随时间膨胀（实测约 95h 后占总流量 3.2%），挤入 topN，观感差。核心诉求：**把未归属桶的量消化到进程头上，同时不伪造精度**。
- 前提共识：操作系统只能提供当前/近期连接归属，快照时效、PID 复用、短连接快速消失、抓包/处理延迟不可全消，**接受无法 100% 归属**。
- 实测成分（`temp/tui-diagnostics` 2026-08-11 run 末次快照）：lookup miss 字节中 **89% 无候选 / 11% 多候选**；最终未归属损失构成约 **50% pending 超时 / 41% probe not-found / 9% 多候选 / 0% capacity 溢出**。结论：多候选拆分原料有限（~9%），历史区间追回才是消化主力，追不回的必须保留在未归属。

## 决策

### 1. 记账模型：记录层守恒 + 包容式投影

- 每个已终结字节恰好产生一条归属记录，取值四类之一：**独占 / 共享 / 系统 / 未归属**。
- 守恒等式（已结算口径）：`总计 = 独占 + 共享 + 系统 + 未归属`。
- 进程视图是包容式（inclusive）投影：共享字节**全额计入每个候选进程**，因此进程行字节求和可以大于接口总流量。此语义必须在 UI 提示与文档中声明，消费方不得对进程行求和当作总量。
- 在途流量（待识别，≤1s pending 窗口）不计入四桶，由进程页边框 `?` 指示器展示（现有 `pending_status_title` 机制保留）。实时完整视角：`在途 + 独占 + 共享 + 系统 + 未归属 = 总计`。

### 2. 分类规则

| 通道 | 判定 | 去向 |
|---|---|---|
| 独占 Exclusive | 当前快照/探测唯一命中；或历史区间唯一命中（evidence 记 `history`，不单列通道） | 进程行独占字节 |
| 共享 Shared | 多候选并发（lookup/probe ambiguous 且终局未消解） | **每个候选进程全额计入**，不均分、不拆分 |
| 系统 System | 无本地套接字的协议流量（ICMP 等 `local_socket: None`） | 独立摘要行，不参与 topN |
| 未归属 Unattributed | 历史追回失败 + 从未被任何一代快照观测到的短连接 + capacity 溢出 | 独立摘要行，不参与 topN |

### 3. 历史归属引擎

- socket→PID 区间日志（valid_from/valid_to）：保留 15 分钟，容量 8192 条，最旧淘汰（内存约 1–2MB）。
- **PID 启动时间硬门槛**：Linux 读 /proc stat 字段 22，Windows 读进程创建时间；候选 PID 的启动时间无法验证早于流起始时间 → 降级未归属，绝不归属（防 PID 复用错误归属；错误归属比未知更有害）。
- 迟到探测结果**不回改**已终结统计，仅影响该连接后续数据包。
- 现有 pending 机制（1s 窗口 / 1024 容量 / 3 次探测重试）保持不变。

### 4. 统计口径

- 进程维度窗口化，复用 IP 维度 epoch bucket 机制（`src/stats.rs` `IpWindowState`），窗口参数与 IP 维度一致。
- topN 按 `独占 + 共享` 总量排序。

### 5. TUI（用户可见文案一律英文，遵循 CONTEXT.md「用户可见文案」）

进程页采用 top 命令式布局：固定摘要区在上、主表独立滚动，单区块、边框保留在途指示器：

```
┌ Processes ──────────────────────────────────── ?  1.50 KB ┐
│ Total 10.0G = Exclusive 9.2G + Shared 0.3G +              │
│              System 2.4M + Unattributed 0.5G              │
│ System        Recv 2.1 M    Sent 0.3 M    Total 2.4 M     │
│ Unattributed  Recv 0.4 G    Sent 0.1 G    Total 0.5 G     │
│───────────────────────────────────────────────────────────│
│ Process      PID   Recv    Sent    Total   A  Last seen    │
│ chrome.exe   4012  1.1 G   0.9 G   2.0 G   S  14:32:05    │
│ svchost.exe  884   180 M   12 M    192 M   M  14:31:58    │
│ ...（topN 滚动区，按 Exclusive+Shared 总量排序）           │
└───────────────────────────────────────────────────────────┘
```

- 摘要行不设时间列（聚合行 last-seen 无信息量）。
- 摘要区是标签行而非表格列，守恒行与分区行使用完整单词（Exclusive/Shared/System/Unattributed），可读性优先；极简约束仅适用于表格列的列头与列值。
- 紧凑模式摘要压缩为两行：守恒行 + Unattributed 行（System 数值已在守恒行内）。
- 新增列极简：列头单字母 `A`（Attribution 首字母压缩），值 `S` = single（该行全部字节独占）、`M` = mixed（含共享字节，含纯共享行）。列表页不出现完整单词；`S`/`M` 仅作引导，图例与构成明细在进程详情页 `Attribution` 区域说明。
- 进程详情页顶部新增 `Attribution` 区域：Exclusive / Shared（列出 shared_with 伙伴，按进程统计身份 pid+path）/ Total (incl. shared)。

### 6. 报表 schema（加法变更，不破坏兼容）

- JSON 每进程新增：
  `"attribution": { "exclusive": {"recv","sent"}, "shared": {"recv","sent"}, "shared_with": [进程身份...], "evidence": ["snapshot"|"probe"|"history"] }`
- plain/TSV 在 `Total` 后加 `Attr` 列，值 `single` / `mixed`（报表供机器消费，保留完整单词，不受 TUI 极简约束）。
- `evidence` 目前仅覆盖独占通道（snapshot / probe / history）；共享通道的构成由 `shared_with` 表达，不单独追踪证据来源。
- `<unattributed traffic>` 行名保留；新增 `<system traffic (no socket)>` 行。

## 验收

- 单测合入门槛：PID 复用拒绝归属；迟到探测不回改；记录层守恒恒等式恒成立；共享字节只产生一条记录但投影到多个进程。
- refcap 回放 + 过夜真机 diagnostics 采集，对比改造前后窗口口径未归属占比。
- 成功判据：窗口口径未归属占比 ≤1%，且未归属不出现在 topN。

## 实施切分（每刀独立可合入、可回退）

1. **通道化**：stats 独占/共享双通道 + 守恒摘要 + System/Unattributed 摘要行 + Attr 列 + 详情 Attribution 区 + 报表字段。
2. **进程窗口化**：复用 IP epoch 机制，窗口口径与累计口径并列。
3. **历史引擎**：区间日志 + 历史追回 + PID 启动时间门槛 + 共享判定接入。

## 词汇表影响（CONTEXT.md，落地时修订）

- **未归属流量**：多候选不再属于未归属（改归共享归属）；无套接字流量移出为系统流量。
- **新增**：独占归属流量、共享归属流量、系统流量。
- **待识别流量**：维持现义（在途瞬态），补充其与四桶终态的关系描述。
- **进程详情**：补充归属构成（独占/共享/共享伙伴）。

## 后果

- 正面：topN 不再被未归属行骚扰（移出排名 + 窗口化根治膨胀）；歧义流量诚实呈现为共享而非均分（无伪精度）；历史引擎追回曾被观测的短连接；成分数据可解释。
- 代价：进程求和 ≠ 接口总量（需持续声明）；区间日志常驻 1–2MB；进程维度 stats 路径需窗口化重构；JSON 消费方需理解 inclusive 语义。
