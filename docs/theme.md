# TUI themes

FlowLens themes control only the interactive foreground TUI. They do not affect captured traffic, plain-text output, JSON output, or JSON Lines output. `--theme` is rejected in a non-interactive mode, including `--output` and `--format json`.

## Select a theme

Use `--theme` when starting the TUI:

```bash
# Registered built-in theme.
flowlens --theme ansi16

# Named user theme: ~/.flowlens/themes/ocean.json.
flowlens --theme ocean

# Exact file path, relative to the startup working directory.
flowlens eth0 --theme ./my-theme.json
```

FlowLens ships the following built-in themes:

| ID | Display name | Profile | Behavior |
| --- | --- | --- | --- |
| `dark` | FlowLens Dark | `truecolor` | Uses FlowLens RGB colors. |
| `signal-deck` | Signal Deck | `truecolor` | Uses a layered blue-black surface with focused cyan, orange traffic, and a purple brand accent. |
| `ansi16` | ANSI 16 | `ansi16` | Uses the terminal default background and ANSI color slots. |
| `mono` | Mono | `mono` | Uses terminal default colors and fixed text styles. |

`auto` is the default when `--theme` is omitted. It is a selection strategy, not a fourth theme. At TUI startup, it chooses a built-in in this order:

1. A present, non-empty `NO_COLOR` selects Mono.
2. `COLORTERM=truecolor` or `COLORTERM=24bit` selects Signal Deck.
3. `TERM=dumb` selects Mono.
4. A `TERM` value containing `256color` selects Signal Deck.
5. `TERM` equal to `ansi`, `linux`, `screen`, or `xterm`, or beginning with `vt`, selects ANSI 16.
6. All other values select Signal Deck.

`COLORTERM` and `TERM` ignore leading and trailing whitespace and case. An empty `NO_COLOR` has no effect. An explicit built-in or file theme takes precedence over Auto.

### Name and path resolution

FlowLens resolves a `--theme` value in this fixed order:

1. An omitted value or `auto` keeps Auto and does not look in the user theme directory.
2. An exact registered built-in ID selects that built-in.
3. An explicit path loads that exact file.
4. Any other short name loads one file from the user theme directory.

`--theme ocean` therefore selects a built-in named `ocean` when one is registered. Otherwise, it reads exactly `~/.flowlens/themes/ocean.json` on Linux, or `%USERPROFILE%\.flowlens\themes\ocean.json` on Windows. FlowLens does not enumerate the directory.

A value is an explicit path when it is absolute, contains `/` or `\`, begins with `./`, `../`, or `~`, or has a file extension. Relative explicit paths use the working directory from which FlowLens started. Prefix a no-extension filename with `./` to force path handling. Only `~/` and `~\` expand from the current user's home directory. `~custom.json` is a literal explicit relative path and does not need a home directory. File extensions are not restricted for explicit paths.

### Session behavior

Press `o` in the TUI to open Settings. Select `Theme` with the arrow keys or `j` and `k`; change it with the left and right arrow keys or `h` and `l`. Press `Esc` or `o` to close Settings.

Settings offers Auto, every registered built-in, and an external theme that was successfully loaded at startup. Auto displays its resolved built-in, for example `Auto (Signal Deck)`. A change applies immediately and remains selected when switching network interfaces or resetting displayed data.

FlowLens validates the catalog, detects Auto, and reads an external file only at startup. It then retains an in-memory validated theme snapshot. Rendering and Settings changes perform no file or environment reads; FlowLens does not write settings, generate theme files, or hot-reload a changed file. The snapshot is discarded when the process exits.

## Theme JSON v1

The authoring schema is [theme-v1.schema.json](../themes/theme-v1.schema.json), Draft 2020-12. It checks JSON shape and closed fields; FlowLens also validates role completeness, built-in bases, and color capability at runtime. `$schema`, `version: 1`, and `name` are optional. A missing `version` means v1. `$schema` never triggers a network request and does not choose the runtime format.

Every file uses exactly one v1 form:

| Form | Required fields | Rules |
| --- | --- | --- |
| Complete theme | `profile`, `colors` | `profile` is `truecolor`, `ansi16`, or `mono`; `base` is absent; `colors` contains all 34 roles. Every built-in uses this form. |
| Override | `base` | `base` names a registered built-in; `colors` may be partial, empty, or omitted. It inherits the base profile and every omitted role. |

Complete examples are the tracked built-in files: [FlowLens Dark](../themes/dark.json), [Signal Deck](../themes/signal-deck.json), [ANSI 16](../themes/ansi16.json), and [Mono](../themes/mono.json).

An override can change only the roles it needs:

```json
{
  "$schema": "./theme-v1.schema.json",
  "version": 1,
  "name": "Warm Dark",
  "base": "dark",
  "colors": {
    "ui.title": "#F0C674"
  }
}
```

For editor validation, `$schema` is a path relative to the JSON file. The built-in files use `"./theme-v1.schema.json"` because the schema is in the same `themes/` directory. For a standalone user theme, copy or otherwise place the schema at that relative location, or adjust the relative path to the schema's actual location. The editor can load the local schema; FlowLens ignores the field at runtime.

Existing valid override files in the form `{name?, base, colors?}` remain valid. An absent or empty `name` uses the explicit file's stem in Settings. `colors` may be absent or empty. Accepted color names remain case-sensitive.

An override cannot inherit from an external file or another override. `base` is intentionally a string in the schema, so the schema stays independent of the current catalog; FlowLens verifies that it names a registered built-in.

### Profiles and color values

The `profile` determines which color values a complete theme accepts. An override uses its base theme's profile.

| Profile | Accepted values |
| --- | --- |
| `truecolor` | `#RRGGBB`, `default`, and ANSI color names. |
| `ansi16` | `default` and ANSI color names; RGB is rejected. |
| `mono` | `default` only. |

`default` means the terminal default color. ANSI color names are `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `gray`, `dark_gray`, `light_red`, `light_green`, `light_yellow`, `light_blue`, `light_magenta`, `light_cyan`, and `white`. In ANSI 16, the terminal host determines their RGB values. Mono uses no hue to communicate meaning.

## Roles and fixed styles

Roles describe UI meaning. Equal defaults do not merge responsibilities: each role can be overridden independently. `default` is a terminal color, not a missing or inherited value. Every Mono role is `default`. Signal Deck's canonical role values are in [signal-deck.json](../themes/signal-deck.json).

| Role | FlowLens Dark | ANSI 16 | Meaning |
| --- | --- | --- |
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

For a single-direction IP page, `Total` uses `data.inbound` or `data.outbound`. Process and domain totals use `data.total` because they combine directions. Protocol, address family, and attribution category use ordinary data text; they do not imply warnings.

Theme files set colors only. They cannot configure bold, reverse video, or the `> ` row marker.

| State | Truecolor (FlowLens Dark and Signal Deck) | ANSI 16 | Mono |
| --- | --- | --- | --- |
| Selected data row | Selection background, bold, and `> `; preserves cell foreground colors. | Selection background when configured, bold, and `> `; preserves cell foreground colors. | Reverse video, bold, and `> `. |
| Active navigation | Active foreground and background, bold. | Reverse video and bold when using the default background. | Reverse video and bold. |
| Operable panel | Focus-border color, bold, and existing row marker. | Bold focus border and existing row marker. | Bold border and existing row marker. |

Every profile renders the operable-panel focus border in bold. Truecolor themes apply the `ui.focus_border` color. The marker and modifiers preserve selection and focus when terminal colors are unavailable or low contrast.

## Validate and publish a built-in

Run this local-schema validation from the repository root after editing the schema or built-in JSON files:

```bash
npx --yes ajv-cli@5 validate -s themes/theme-v1.schema.json -d themes/dark.json -d themes/signal-deck.json -d themes/ansi16.json -d themes/mono.json --spec=draft2020
```

The command validates local files. If `ajv-cli` is not already cached, `npx` may access the network to install it; use an installed CLI when validation must run offline.

To add a built-in, add one complete JSON file under `themes/` and one ID-to-JSON registration in `src/theme/catalog.rs`. The catalog registration makes it selectable through the CLI, Settings, and override `base` without a separate UI list. Built-in JSON is embedded with `include_str!`, so released binaries remain a single executable with no adjacent theme-resource lookup. Adding a built-in does not change Auto's explicit default mapping.

## Errors and recovery

Invalid JSON, unknown top-level fields or roles, non-string or malformed colors, an incomplete complete theme, an incompatible profile value, or an unknown base are configuration errors. FlowLens writes one English stderr message beginning with `Theme configuration error:` and exits with a non-zero status before Npcap checks, interface discovery, diagnostics output, capture setup, or TUI construction.

The message identifies the built-in ID or external path. JSON syntax errors include a line and column when available; field errors identify the field, and where relevant the role and value. Correct the reported file or select a known built-in such as `--theme dark`, then start FlowLens again. FlowLens does not silently fall back to Auto or edit the file.
