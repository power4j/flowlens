# FlowLens

[English](README.md) | 简体中文

FlowLens 是面向资源受限 Linux 和 Windows 主机的命令行网络流量分析工具，用于查看网卡流量，并以尽力而为的方式提供进程、IP 和出站域名归属信息。

![FlowLens 概览](assets/screen/ui-overview.png)

## 支持平台

| 平台 | 运行前置条件 |
| --- | --- |
| Linux `x86_64` | glibc `2.28` 或更新版本、libpcap，以及 root 权限或 `CAP_NET_RAW` |
| Windows `x86_64` | 已安装 [Npcap Runtime](https://npcap.com/) 的 Windows 系统 |

Linux 和 Windows 均属于支持平台。「支持平台」表示核心功能和基本稳定性达到最低验收线，不表示所有边界情况都已完成穷尽测试。

## 安装

从 [GitHub Releases](https://github.com/power4j/flowlens/releases/latest) 下载对应平台的压缩包，解压其中唯一的可执行文件即可。

### Linux

如果系统尚未安装 libpcap 运行库，请先安装：

```bash
# Debian 或 Ubuntu
sudo apt install libpcap0.8

# RHEL 兼容发行版
sudo dnf install libpcap
```

以 root 身份运行 FlowLens，或者为可执行文件授予 `CAP_NET_RAW`：

```bash
sudo ./flowlens
# 或
sudo setcap cap_net_raw+ep ./flowlens
./flowlens
```

### Windows

启动 FlowLens 前请安装 [Npcap](https://npcap.com/)。Windows 压缩包只包含 `flowlens.exe`，不包含 Npcap Runtime。

FlowLens 启动时会检查 `wpcap.dll`。如果缺少 Npcap Runtime，程序会在打开抓包设备前报告错误。

## 使用

不指定网卡，直接启动前台 TUI：

```bash
./flowlens
```

直接打开指定网卡：

```bash
./flowlens eth0
```

将定时生成的 plain 文本快照写入文件：

```bash
./flowlens eth0 --output /tmp/stats.txt
```

将 JSON Lines 流写入标准输出：

```bash
./flowlens eth0 --format json
```

将 JSON 快照写入文件：

```bash
./flowlens eth0 --format json --output /tmp/stats.json
```

限制每个 top-N 列表的条目数：

```bash
./flowlens eth0 --top-n 3
```

将进程归属诊断信息以 JSONL 格式写入默认 `.log` 文件：

```bash
./flowlens eth0 --format json --diagnostics
```

指定诊断输出文件：

```bash
./flowlens eth0 --diagnostics --diagnostics-output /tmp/flowlens-diagnostics.jsonl
```

TUI 模式下诊断信息同样只写入该文件，不写入终端屏幕。

完整参数列表请运行 `flowlens --help` 查看。

## 可查看的信息

- 入站、出站和合计流量。
- 进程名称、PID、流量总量和尽力而为的可执行文件身份。
- 远端 IP 地址排行。
- 本机主动发起的 TCP 连接中，从 TLS SNI 或明文 HTTP `Host` 头识别出的出站域名。
- TUI、plain 文本、JSON 和 JSON Lines 输出。

## 已知限制

进程归属采用尽力而为策略。权限、网络命名空间、容器、WSL 代理路径、端口复用和进程表时序都可能使部分流量进入 `<unattributed traffic>`。

出站域名统计覆盖 TCP TLS ClientHello SNI 和明文 HTTP/1.x `Host` 头，不覆盖 QUIC/HTTP3、入站发起的连接、加密 SNI 和无法解析的 payload。

loopback 抓包可能同时显示同一传输的入站和出站流量。这是操作系统的抓包语义，不表示公网传输实际发生了两次。

Linux 和 Windows 的进程归属及抓包行为可能存在差异。每个版本的 Release Notes 会说明平台前置条件和已知限制。

## 许可证

FlowLens 使用 [Apache License 2.0](LICENSE) 许可证。

开发和源码构建说明见 [`docs/development.md`](docs/development.md)。
