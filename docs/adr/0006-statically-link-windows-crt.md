# Windows 发布制品静态链接 VC Runtime

Windows `x86_64` 和 `aarch64` Release 制品使用 MSVC 目标并启用 `crt-static`，将 VC Runtime 静态链接进 `flowlens.exe`，减少用户侧运行库安装要求。Npcap Runtime 不静态链接或随制品重新分发；当前程序依赖 `wpcap.dll`，Npcap 仍是运行前置条件。发布构建必须检查最终 PE 依赖，确认静态 CRT 配置生效。
