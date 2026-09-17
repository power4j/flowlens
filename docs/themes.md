# TUI themes

FlowLens themes control only the interactive foreground TUI. They do not change captured traffic, plain-text output, JSON output, or JSON Lines output.

Use `--theme` to select a built-in theme or load a JSON theme file:

```bash
flowlens --theme auto
flowlens eth0 --theme dark
flowlens eth0 --theme ansi16
flowlens eth0 --theme mono
flowlens eth0 --theme ./my-theme.json
```

`--theme` is rejected when `--output` or `--format json` selects a non-interactive mode. Theme-file errors are written to standard error and FlowLens exits with a non-zero status before checking capture prerequisites or opening a capture device.

## Built-in themes

| ID | Display name | Color model | Background behavior |
| --- | --- | --- | --- |
| `dark` | FlowLens Dark | RGB, ANSI names, or terminal default colors | Uses the selected FlowLens Dark colors. |
| `ansi16` | ANSI 16 | ANSI color names or terminal default colors | Uses the terminal's default background and ANSI palette. |
| `mono` | Mono | Terminal default colors only | Uses the terminal's default foreground and background. |

FlowLens Dark is FlowLens's fixed custom dark theme. In ANSI 16, the terminal host determines the actual RGB values for ANSI color names. Mono does not use hue to communicate meaning.

## Automatic selection

`auto` is the default. It is resolved once when the TUI starts, in this order:

1. A present, non-empty `NO_COLOR` selects Mono.
2. `COLORTERM=truecolor` or `COLORTERM=24bit` selects FlowLens Dark.
3. `TERM=dumb` selects Mono.
4. A `TERM` value containing `256color` selects FlowLens Dark.
5. `TERM` equal to `ansi`, `linux`, `screen`, or `xterm`, or beginning with `vt`, selects ANSI 16.
6. All other values select FlowLens Dark.

`COLORTERM` and `TERM` ignore leading and trailing whitespace and case. An empty `NO_COLOR` is ignored. An explicit built-in theme or file theme overrides automatic selection, including a non-empty `NO_COLOR`.

## Session selection

Press `o` in the TUI to open Settings. Select `Theme` with the arrow keys or `j` and `k`; change it with the left and right arrow keys or `h` and `l`. Press `Esc` or `o` to close Settings.

The available choices are `Auto`, FlowLens Dark, ANSI 16, Mono, and, when loaded at startup, the JSON theme file. `Auto` displays the resolved built-in name, for example `Auto (ANSI 16)`. A selection applies immediately, remains in effect when switching network interfaces, and ends when the process exits. FlowLens does not write a configuration file or modify the loaded JSON file.

## JSON theme files

A JSON theme file inherits one built-in theme and overrides individual semantic roles. Relative paths are resolved from the current working directory.

```json
{
  "name": "My Dark",
  "base": "dark",
  "colors": {
    "ui.border": "#3D4C5F",
    "data.local_endpoint": "#16C60C"
  }
}
```

`base` is required and must be `dark`, `ansi16`, or `mono`. `name` is optional; an omitted or empty name uses the file stem in Settings. `colors` is optional and may be empty. A file always inherits omitted roles from its declared `base`, never from the current session theme.

Each value must be one of the following strings:

- `#RRGGBB`
- `default`, meaning the terminal default foreground or background
- `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `gray`, `dark_gray`, `light_red`, `light_green`, `light_yellow`, `light_blue`, `light_magenta`, `light_cyan`, or `white`

`dark` accepts all listed values. `ansi16` accepts `default` and ANSI names, but rejects RGB values. `mono` accepts only `default`. Unknown top-level fields, unknown role keys, non-string values, invalid color values, and invalid `base` values are errors. FlowLens does not silently fall back to a built-in theme, chain theme files, discover themes from a directory, reload files while running, or download themes.

## Role reference

Roles identify UI meaning. Equal defaults do not merge role responsibilities: a custom theme can override each listed key independently. `default` is a terminal color, not a missing value or an inherited value. Every Mono role defaults to `default`.

| Role | FlowLens Dark | ANSI 16 | Meaning |
| --- | --- | --- | --- |
| `ui.page_bg` | `#0B1118` | `default` | Page background. |
| `ui.panel_bg` | `#0B1118` | `default` | Panel background. |
| `ui.popup_bg` | `#131D29` | `default` | Popup background. |
| `ui.text` | `#D8E0E8` | `default` | Ordinary UI text. |
| `ui.title` | `#F4F7FA` | `default` | Panel titles. |
| `ui.header` | `#93A2B4` | `dark_gray` | Table headers. |
| `ui.label` | `#93A2B4` | `dark_gray` | Field labels. |
| `ui.secondary` | `#93A2B4` | `dark_gray` | Supplementary UI text. |
| `ui.placeholder` | `#93A2B4` | `dark_gray` | Missing-value and empty-state text. |
| `ui.border` | `#3D4C5F` | `gray` | Structural borders and separators. |
| `ui.focus_border` | `#93A2B4` | `gray` | Border of the current operable panel. |
| `ui.active_tab_fg` | `#F4F7FA` | `default` | Active navigation text. |
| `ui.inactive_tab_fg` | `#93A2B4` | `dark_gray` | Inactive navigation text. |
| `ui.active_tab_bg` | `#1C2C3D` | `default` | Active navigation background. |
| `ui.selection_bg` | `#1C2C3D` | `default` | Selected row background. |
| `ui.key` | `#D8E0E8` | `default` | Shortcut keys. |
| `ui.setting_label` | `#D8E0E8` | `default` | Settings item names. |
| `ui.hint` | `#93A2B4` | `dark_gray` | Action hints. |
| `ui.setting_value` | `#F4F7FA` | `default` | Settings values. |
| `feedback.warning` | `#F5BA45` | `yellow` | Explicit warnings and tracking-paused text. |
| `feedback.error` | `#F18BA0` | `red` | Explicit error text. |
| `brand.foreground` | `#B9A0F7` | `magenta` | FlowLens product name. |
| `data.inbound` | `#F5BA45` | `yellow` | Received and inbound values, markers, and chart fills. |
| `data.outbound` | `#43C6E8` | `cyan` | Sent and outbound values, markers, and chart fills. |
| `data.local_endpoint` | `#16C60C` | `light_green` | Local address in connection details. |
| `data.remote_endpoint` | `#D8E0E8` | `default` | Remote address in connection details. |
| `data.identity` | `#D8E0E8` | `default` | Process names, domains, PIDs, and ports. |
| `data.protocol` | `#D8E0E8` | `default` | Protocol text. |
| `data.address_family` | `#D8E0E8` | `default` | Address-family text. |
| `data.attribution` | `#D8E0E8` | `default` | Attribution category text. |
| `data.total` | `#F4F7FA` | `default` | Bidirectional totals, connection bytes, and attribution totals. |
| `data.time` | `#93A2B4` | `dark_gray` | Time and freshness fields. |
| `chart.track` | `#253443` | `default` | Unfilled traffic-bar track. |
| `chart.combined` | `#93A2B4` | `gray` | Combined traffic-bar fill. |

For an IP page that represents a single direction, `Total` uses `data.inbound` or `data.outbound`. Process and domain totals use `data.total` because they combine directions. Protocol, address family, and attribution category use ordinary data text; they do not imply warnings.

## Fixed interaction styling

Theme files set colors only. They cannot configure bold, reverse video, or the `> ` row marker.

| State | FlowLens Dark | ANSI 16 | Mono |
| --- | --- | --- | --- |
| Selected data row | Selection background, bold, and `> `; preserves cell foreground colors. | Selection background (terminal default by default), bold, and `> `; preserves cell foreground colors. | Reverse video, bold, and `> `. |
| Active navigation | Active foreground and background, bold. | Reverse video and bold when using the default background. | Reverse video and bold. |
| Operable panel | Focus border and existing row marker. | Bold focus border and existing row marker. | Bold border and existing row marker. |

The marker and modifiers keep selections and focus identifiable when terminal colors are unavailable or have low contrast.
