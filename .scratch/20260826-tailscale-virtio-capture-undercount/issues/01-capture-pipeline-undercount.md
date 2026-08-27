# Tailscale 文件传输在 Red Hat VirtIO 网卡上严重少计流量

Type: task
Status: resolved
Branch: `fix/tailscale-virtio-capture-accounting`
Reported: 2026-08-26

## 现象

在 Windows 10 虚拟机上通过 Tailscale Taildrop 发送 1 GB 以上文件时，Windows 任务管理器显示 `Red Hat VirtIO Ethernet Adapter` 实时发送约 59.1 Mbps；FlowLens 监控同一物理网卡时，概览页累计流量仅约 1.45 MB。

## 现有证据

- `temp/20260826-tailscale-issue/win10-misc/win-proc-1.png`
- `temp/20260826-tailscale-issue/win10-misc/flowlens-1.png`
- `temp/20260826-tailscale-issue/win10-misc/flowlens-20260826T054258Z695370100-13064.log`
- `temp/20260826-tailscale-issue/result-1/`（无效验证：Windows「以太网」计数器与 Npcap `WAN Miniport (Network Monitor)` 错配）
- 报告方确认 IPv4 地址由路由器固定分配，多次测试结果一致。
- 诊断日志的传输窗口（序号 4 到 11）中，`pcap_received` 增加 269,214，约为 7,678 包/秒；`pcap_dropped` 和 `pcap_if_dropped` 增量均为 0。
- 同一窗口中，`lookup_hits` 仅增加 142。接口总量在进程归属前记录，因此进程查找失败不能解释接口总量严重少计。

## 当前判断

原始诊断日志表明 Npcap 已收到高频数据包，且没有报告驱动丢包。丢失位置仍可能位于抓包读取之后、`Flow` 生成之前，优先检查严格解析失败和本机地址判定失败。

`result-1` 不能用于判断产品缺陷。诊断脚本读取了不存在的 `Get-NetAdapter.Description` 字段，随后选择首个非 Loopback Npcap 设备，造成 Windows「以太网」计数器与 `WAN Miniport (Network Monitor)` 捕获设备错配。正确设备已确认为：

- 描述：`Red Hat VirtIO Ethernet Adapter`
- Npcap 名称：`\Device\NPF_{8A8121CE-B85E-4602-BB53-05412604BE26}`

诊断脚本已改为按 `Get-NetAdapter.InterfaceGuid` 与 Npcap 名称中的 GUID 精确匹配；零匹配或多匹配时立即终止，不再按枚举顺序选择设备。

## 红灯验证

在受影响的 `win-misc` 主机上，使用当前分支构建的 `flowlens.exe` 与 `refcap.exe`：

```powershell
.\scripts\verify-capture.ps1 -ManualMode -DurationSec 45 -Interface '\Device\NPF_{8A8121CE-B85E-4602-BB53-05412604BE26}' -OutputDir .\result-2
```

在 30 秒窗口内执行 Tailscale 文件传输。预期当前版本返回非零退出码，并显示：

- `flowlens/refcap-IP` 显著低于 0.9；
- Npcap `dropped` 与 `if_dropped` 为 0 或接近 0。

## 最小缺失证据

现有材料没有保存原始帧，也没有 `refcap` 分类数据，因此无法在开发机上重放并让同一个测试随代码修复由红转绿。至少需要以下一种材料：

1. 上述验证脚本生成的完整目录；
2. 传输高峰期间同一 Npcap 设备的 5–10 秒 `.pcapng`，并记录当时本机全部 IPv4/IPv6 地址。

## 候选原因

1. `etherparse::PacketHeaders` 拒绝 VirtIO/Npcap 提供的卸载或合并帧，当前 `.ok()` 将原因静默转换为 `None`。
2. Tailscale 外层数据包使用的源/目标地址不在 FlowLens 启动时采集的 `local_ips` 快照中，导致被当作与本机无关的包过滤。
3. 数据链路类型或链路层封装与当前解析分支不完全匹配。
4. 已确认诊断工具曾将 Windows 计数器网卡与 Npcap 捕获设备错配；此项只解释 `result-1`，不解释原始截图。

## 完成条件

- 有一个可重复的红灯验证，能够在修复后转绿。
- 新增回归测试，覆盖实际触发缺陷的数据包结构或地址变化条件。
- 实施最小修复，不改变无关统计语义。
- `cargo fmt --all -- --check`、`cargo check --locked`、`cargo test --locked`、`cargo clippy --locked --all-targets --all-features -- -D warnings` 全部通过。

## Comments

- 2026-08-26：创建缺陷分支并整理现有证据。当前等待可重放数据包或受影响主机上的 capture-parity 报告。

- 2026-08-26：构建 FlowLens 0.5.0 与 refcap，并生成现场诊断包：`temp/20260826-tailscale-issue/flowlens-tailscale-diagnostic-kit-20260826.zip`。

- 2026-08-26：修复 `verify-capture.ps1` 在 `-ManualMode` 下错误要求 `iperf3.exe` 的前置校验；新增 `scripts/verify-capture.Tests.ps1` 回归检查并更新诊断包。

- 2026-08-26：检查 `result-1`，确认报告比较了 Windows「以太网」计数器与 Npcap `WAN Miniport (Network Monitor)`，该结果无效。正确 Npcap 设备为 `\Device\NPF_{8A8121CE-B85E-4602-BB53-05412604BE26}`。

- 2026-08-26：诊断脚本改为按接口 GUID 双向精确映射 Npcap 设备与 Windows 计数器；删除「首个非 Loopback 设备」选择逻辑，并覆盖自动选择、显式选择、无匹配和 `-ManualMode` 工具校验。

- 2026-08-26：复核发现显式 `\Device\NPF_Loopback` 不具备物理网卡 GUID；保留 Loopback 采集能力，但不再伪造 Windows 网卡计数器，计数器显示为不可用。


- 2026-08-27：复核 `result-3`，FlowLens 已读取 237,550,079 字节，其中 237,468,353 字节（99.97%）被判定为非本地 IPv4；解析错误仅 44,492 字节。当前首要假设收敛为启动时 `local_ips` 快照不包含 VirtIO 上实际承载 Tailscale 外层报文的端点地址。

- 2026-08-27：增加启动时本地 IP 快照和非本地 IPv4/IPv6 端点样本诊断。样本有界保存，并在长流量过程中周期刷新，避免只记录传输开始前的后台报文。等待 `result-4` 对比 `capture.local_ips` 与 `capture.non_local_ipv4_samples`。

- 2026-08-27：复核 `result-4`，确认 FlowLens 已读取 667,488 个数据包、625,757,801 字节，其中 667,245 个非本地 IPv4 数据包占 625,726,471 字节；端点样本主要为 `10.11.12.31 <-> 10.11.12.250`。其中 `10.11.12.31` 是测试机 VirtIO 地址；`capture.local_ips` 包含 Tailscale 地址 `100.127.185.26`，但不包含本机的 `10.11.12.31`。因此根因收敛为 Npcap `Device.addresses` 的本机地址列表不完整，而非抓包丢包或解析吞吐不足。

- 2026-08-27：实施最小修复：Windows 启动时通过 `GetAdaptersAddresses` 读取系统所有已配置单播 IPv4/IPv6 地址，与 Npcap 设备地址集合合并；保留原有 Npcap 地址，避免改变接口选择和其他平台行为。新增 IPv4/IPv6 `SOCKET_ADDRESS` 解析测试，以及覆盖「Npcap 缺少 VirtIO 地址、原生地址补齐」的回归测试。开发机上的 Windows 原生查询已验证 API 可返回本机 IPv4；测试机应由该 API 补充 `10.11.12.31`。

- 2026-08-27：复核 `temp/20260826-tailscale-issue/result-6`，在实际 Tailscale 文件传输场景下验证通过：`refcap/adapter = 100.0%`、`flowlens/refcap-IP = 93.3%`，`Capture layer OK`、`Pipeline layer OK` 和 `OVERALL` 均为 `True`；`capture.local_ips` 已包含 `10.11.12.31`，且主要流量已归属 `tailscaled.exe`。
