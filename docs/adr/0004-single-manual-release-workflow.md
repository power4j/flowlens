# 使用单一手动 Release 工作流完成版本发布

FlowLens 将日常 CI 与发布工作流分开：日常 CI 负责 PR 和 `main` push 检查，发布工作流仅允许在 `main` 上手动触发，并在同一次运行中完成版本 bump、版本提交、`vX.Y.Z` tag 推送、跨平台构建和 Draft Release 创建。这样避免依赖由默认 `GITHUB_TOKEN` 推送的 tag 再触发另一个工作流，也避免版本升级和制品发布分散后产生重复或不一致。Release 工作流使用固定的 GitHub Actions concurrency group，并关闭 `cancel-in-progress`：当前发布完成后，最多执行一个等待中的发布；GitHub 不保证多个等待任务的 FIFO 顺序，新的等待任务可能替换旧任务。
