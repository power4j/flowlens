# TUI 主题按终端能力自动选择，并支持会话级切换

FlowLens 的 TUI 以语义角色而非页面类别或色相获取样式。内置主题为 FlowLens Dark、ANSI 16 和 Mono；三个主题覆盖同一组角色，用户可通过 `--theme` 或设置浮层选择。`Auto` 是选择策略，不是第四套主题：它在启动时依据 `NO_COLOR`、`COLORTERM` 与 `TERM` 解析为一个内置主题。完整的用户配置和角色参考见 [TUI themes](../themes.md)。

自动选择优先级为：非空 `NO_COLOR` 选择 Mono；值为 `truecolor` 或 `24bit` 的 `COLORTERM` 选择 FlowLens Dark；`TERM=dumb` 选择 Mono；包含 `256color` 的 `TERM` 选择 FlowLens Dark；`ansi`、`linux`、`screen`、`xterm` 与 `vt*` 选择 ANSI 16；其他值选择 FlowLens Dark。`COLORTERM` 与 `TERM` 忽略首尾空白并按不区分大小写比较，空 `NO_COLOR` 不影响检测。环境变量无法可靠区分所有真彩色和 256 色终端，因此默认偏向常见的真彩色终端，用户可明确选择 ANSI 16。

ANSI 16 使用终端默认背景和 ANSI 色槽，实际 RGB 由终端宿主决定。Mono 不使用颜色，依靠反显、粗体和既有行标记表达状态。ANSI 16 的数据行选择保留单元格的方向和端点前景色，使用粗体和行标记；Mono 数据行使用反显和粗体。这样低色深终端仍可区分数据和交互状态。

设置浮层由小写 `o` 打开，`Esc` 或 `o` 关闭；用方向键或 `j`／`k` 选择 Theme 项，用左右键或 `h`／`l` 切换。选择仅在当前会话有效，切换网卡后仍保留。主题文件只在启动时读取，不会被设置浮层改写或由程序自动生成。渲染状态由会话状态持有，不使用进程级活动调色板。
