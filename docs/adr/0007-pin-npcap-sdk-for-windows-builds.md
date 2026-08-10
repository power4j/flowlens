# 固定并校验 Windows 构建使用的 Npcap SDK

Windows Release 构建从 Npcap 官方地址下载固定版本的 SDK，并在使用前校验 SHA-256；构建按目标架构选择 `Lib\x64` 或 `Lib\ARM64` 下的 `wpcap.lib` 和 `Packet.lib` 等编译输入。SDK 只提供编译输入，不进入最终制品。Windows 用户仍需自行安装 Npcap Runtime，Release 不重新分发 SDK 或 Runtime。固定并校验 SDK 可以让构建结果可追溯，同时保持运行时依赖和第三方分发责任清晰。
