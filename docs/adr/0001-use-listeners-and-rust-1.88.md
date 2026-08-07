# 使用 listeners 并将 MSRV 提高到 Rust 1.88

FlowLens 使用 `listeners 0.6` 作为进程查询基础，不自行维护 Linux 和 Windows 的系统 API 实现。FlowLens 主要交付预编译应用，低编译器版本不会提高目标机兼容性；`listeners 0.6.0` 已验证可在 Rust 1.88 编译，但不能在 Rust 1.85 编译，因此将 MSRV 提高到 Rust 1.88。Linux 运行兼容性仍由 glibc 2.28 和 libpcap 基线独立保障。

`listeners` 应封装在 FlowLens 的进程查询接口后，通过 `get_all()` 建立包含本机 IP、端口和协议的索引。项目锁定依赖版本并持续使用 Rust 1.88 验证 MSRV；依赖升级确有需要时可以提高 MSRV。

查询不到的 TCP/UDP 本机 socket 流量可以先进入短窗口待归属队列。后续进程表刷新找到唯一 PID 时，流量提交到对应进程；超时、歧义、刷新失败、陈旧进程表或队列溢出时，流量提交到「未归属流量」。该机制只处理尚未提交的待归属记录，已经提交到进程或未归属流量的历史统计不做追溯修改。

Rust 1.88 基线已由 ADR 0011 取代；当前应用基线为 Rust 1.96.0。
