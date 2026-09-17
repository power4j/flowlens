//! Semantic TUI themes and startup-only theme-file parsing.
use ratatui::style::{Color, Modifier, Style};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuiltinTheme {
    Dark,
    Ansi16,
    Mono,
}
impl BuiltinTheme {
    pub(crate) const ALL: [Self; 3] = [Self::Dark, Self::Ansi16, Self::Mono];
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Dark => "FlowLens Dark",
            Self::Ansi16 => "ANSI 16",
            Self::Mono => "Mono",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value {
            "dark" => Some(Self::Dark),
            "ansi16" => Some(Self::Ansi16),
            "mono" => Some(Self::Mono),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ThemeSelection {
    Auto,
    Builtin(BuiltinTheme),
    File,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ColorTier {
    Monochrome,
    Sixteen,
    Truecolor,
}
pub(crate) fn tier_from_env(
    colorterm: Option<&str>,
    term: &str,
    no_color: Option<&str>,
) -> ColorTier {
    if no_color.is_some_and(|value| !value.is_empty()) {
        return ColorTier::Monochrome;
    }
    if colorterm.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "truecolor" | "24bit"
        )
    }) {
        return ColorTier::Truecolor;
    }
    let term = term.trim().to_ascii_lowercase();
    if term == "dumb" {
        return ColorTier::Monochrome;
    }
    if term.contains("256color") {
        return ColorTier::Truecolor;
    }
    if matches!(term.as_str(), "ansi" | "linux" | "screen" | "xterm") || term.starts_with("vt") {
        return ColorTier::Sixteen;
    }
    ColorTier::Truecolor
}
pub(crate) fn detect_tier() -> ColorTier {
    let term = std::env::var("TERM").unwrap_or_default();
    tier_from_env(
        std::env::var("COLORTERM").ok().as_deref(),
        &term,
        std::env::var("NO_COLOR").ok().as_deref(),
    )
}
pub(crate) fn detected_theme(tier: ColorTier) -> BuiltinTheme {
    match tier {
        ColorTier::Truecolor => BuiltinTheme::Dark,
        ColorTier::Sixteen => BuiltinTheme::Ansi16,
        ColorTier::Monochrome => BuiltinTheme::Mono,
    }
}

macro_rules! roles { ($($name:ident),+ $(,)?) => { #[derive(Clone, Copy, Debug, Eq, PartialEq)] pub(crate) struct ThemeColors { $(pub(crate) $name: Color,)+ } }; }
roles!(
    page_bg,
    panel_bg,
    popup_bg,
    text,
    title,
    header,
    label,
    secondary,
    placeholder,
    border,
    focus_border,
    active_tab_fg,
    inactive_tab_fg,
    active_tab_bg,
    selection_bg,
    key,
    setting_label,
    hint,
    setting_value,
    warning,
    error,
    brand,
    inbound,
    outbound,
    local_endpoint,
    remote_endpoint,
    identity,
    protocol,
    address_family,
    attribution,
    total,
    time,
    chart_track,
    chart_combined
);
#[derive(Clone, Debug)]
pub(crate) struct Theme {
    pub(crate) name: String,
    pub(crate) base: BuiltinTheme,
    pub(crate) colors: ThemeColors,
}
impl Theme {
    pub(crate) fn builtin(base: BuiltinTheme) -> Self {
        Self {
            name: base.label().to_string(),
            base,
            colors: builtin_colors(base),
        }
    }
    pub(crate) fn selection_style(&self) -> Style {
        match self.base {
            BuiltinTheme::Dark => Style::default()
                .bg(self.colors.selection_bg)
                .add_modifier(Modifier::BOLD),
            BuiltinTheme::Ansi16 => {
                let style = Style::default().add_modifier(Modifier::BOLD);
                if self.colors.selection_bg == Color::Reset {
                    style
                } else {
                    style.bg(self.colors.selection_bg)
                }
            }
            BuiltinTheme::Mono => {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            }
        }
    }
    pub(crate) fn active_tab_style(&self) -> Style {
        match self.base {
            BuiltinTheme::Dark => Style::default()
                .fg(self.colors.active_tab_fg)
                .bg(self.colors.active_tab_bg)
                .add_modifier(Modifier::BOLD),
            BuiltinTheme::Ansi16 => {
                let style = Style::default()
                    .fg(self.colors.active_tab_fg)
                    .add_modifier(Modifier::BOLD);
                if self.colors.active_tab_bg == Color::Reset {
                    style.add_modifier(Modifier::REVERSED)
                } else {
                    style.bg(self.colors.active_tab_bg)
                }
            }
            BuiltinTheme::Mono => Style::default()
                .fg(self.colors.active_tab_fg)
                .add_modifier(Modifier::REVERSED | Modifier::BOLD),
        }
    }
}
fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}
fn builtin_colors(base: BuiltinTheme) -> ThemeColors {
    let c = match base {
        BuiltinTheme::Dark => (
            rgb(11, 17, 24),
            rgb(19, 29, 41),
            rgb(216, 224, 232),
            rgb(244, 247, 250),
            rgb(147, 162, 180),
            rgb(61, 76, 95),
            rgb(28, 44, 61),
            rgb(245, 186, 69),
            rgb(241, 139, 160),
            rgb(185, 160, 247),
            rgb(245, 186, 69),
            rgb(67, 198, 232),
            rgb(22, 198, 12),
            rgb(37, 52, 67),
        ),
        BuiltinTheme::Ansi16 => (
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::DarkGray,
            Color::Gray,
            Color::Reset,
            Color::Yellow,
            Color::Red,
            Color::Magenta,
            Color::Yellow,
            Color::Cyan,
            Color::LightGreen,
            Color::Gray,
        ),
        BuiltinTheme::Mono => (
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
        ),
    };
    let (
        page_bg,
        popup_bg,
        text,
        title,
        secondary,
        border,
        selection_bg,
        warning,
        error,
        brand,
        inbound,
        outbound,
        local_endpoint,
        track,
    ) = c;
    ThemeColors {
        page_bg,
        panel_bg: page_bg,
        popup_bg,
        text,
        title,
        header: secondary,
        label: secondary,
        secondary,
        placeholder: secondary,
        border,
        focus_border: if base == BuiltinTheme::Ansi16 {
            Color::Gray
        } else {
            secondary
        },
        active_tab_fg: title,
        inactive_tab_fg: secondary,
        active_tab_bg: selection_bg,
        selection_bg,
        key: text,
        setting_label: text,
        hint: secondary,
        setting_value: title,
        warning,
        error,
        brand,
        inbound,
        outbound,
        local_endpoint,
        remote_endpoint: text,
        identity: text,
        protocol: text,
        address_family: text,
        attribution: text,
        total: title,
        time: secondary,
        chart_track: track,
        chart_combined: if base == BuiltinTheme::Ansi16 {
            Color::Gray
        } else {
            secondary
        },
    }
}
#[derive(Clone, Debug)]
pub(crate) struct ThemeState {
    pub(crate) selection: ThemeSelection,
    pub(crate) detected: BuiltinTheme,
    pub(crate) resolved: Theme,
    pub(crate) loaded_file: Option<Theme>,
}
impl ThemeState {
    pub(crate) fn auto() -> Self {
        let detected = detected_theme(detect_tier());
        Self {
            selection: ThemeSelection::Auto,
            detected,
            resolved: Theme::builtin(detected),
            loaded_file: None,
        }
    }
    pub(crate) fn with_selection(selection: ThemeSelection, loaded_file: Option<Theme>) -> Self {
        Self::with_detected(detected_theme(detect_tier()), selection, loaded_file)
    }
    fn with_detected(
        detected: BuiltinTheme,
        selection: ThemeSelection,
        loaded_file: Option<Theme>,
    ) -> Self {
        let mut state = Self {
            selection: ThemeSelection::Auto,
            detected,
            resolved: Theme::builtin(detected),
            loaded_file,
        };
        state.select(selection);
        state
    }
    pub(crate) fn select(&mut self, selection: ThemeSelection) {
        self.selection = selection.clone();
        self.resolved = match selection {
            ThemeSelection::Auto => Theme::builtin(self.detected),
            ThemeSelection::Builtin(base) => Theme::builtin(base),
            ThemeSelection::File => self
                .loaded_file
                .clone()
                .expect("file selection requires loaded theme"),
        };
    }
    pub(crate) fn choices(&self) -> Vec<ThemeSelection> {
        let mut choices = vec![ThemeSelection::Auto];
        choices.extend(BuiltinTheme::ALL.into_iter().map(ThemeSelection::Builtin));
        if self.loaded_file.is_some() {
            choices.push(ThemeSelection::File);
        }
        choices
    }
    pub(crate) fn selection_label(&self) -> String {
        match self.selection {
            ThemeSelection::Auto => format!("Auto ({})", self.detected.label()),
            ThemeSelection::Builtin(base) => base.label().to_string(),
            ThemeSelection::File => self
                .loaded_file
                .as_ref()
                .map(|theme| theme.name.clone())
                .unwrap_or_default(),
        }
    }
}
#[cfg(test)]
impl ThemeState {
    pub(crate) fn dark_for_test() -> Self {
        Self::with_detected(
            BuiltinTheme::Dark,
            ThemeSelection::Builtin(BuiltinTheme::Dark),
            None,
        )
    }

    pub(crate) fn for_test(
        detected: BuiltinTheme,
        selection: ThemeSelection,
        loaded_file: Option<Theme>,
    ) -> Self {
        Self::with_detected(detected, selection, loaded_file)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThemeFile {
    name: Option<String>,
    base: String,
    #[serde(default)]
    colors: serde_json::Map<String, serde_json::Value>,
}
pub(crate) fn load_theme(path: &Path) -> Result<Theme, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("Failed to read theme file {}: {error}", path.display()))?;
    let file: ThemeFile = serde_json::from_str(&contents)
        .map_err(|error| format!("Invalid theme file {}: {error}", path.display()))?;
    let base = BuiltinTheme::parse(&file.base).ok_or_else(|| {
        format!(
            "Invalid theme base `{}`; expected dark, ansi16, or mono",
            file.base
        )
    })?;
    let mut theme = Theme::builtin(base);
    theme.name = file
        .name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        });
    for (role, value) in file.colors {
        set_color(&mut theme.colors, &role, parse_color(value, base, &role)?)?;
    }
    Ok(theme)
}
fn parse_color(value: serde_json::Value, base: BuiltinTheme, role: &str) -> Result<Color, String> {
    let value = value
        .as_str()
        .ok_or_else(|| format!("Invalid color for `{role}`: expected a string"))?;
    let color = if value == "default" {
        Color::Reset
    } else if let Some(color) = ansi_color(value) {
        color
    } else if let Some(hex) = value.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("Invalid color `{value}` for `{role}`"));
        }
        Color::Rgb(
            u8::from_str_radix(&hex[0..2], 16).unwrap(),
            u8::from_str_radix(&hex[2..4], 16).unwrap(),
            u8::from_str_radix(&hex[4..6], 16).unwrap(),
        )
    } else {
        return Err(format!("Invalid color `{value}` for `{role}`"));
    };
    if base == BuiltinTheme::Mono && color != Color::Reset {
        return Err(format!(
            "Theme base mono only accepts `default` for `{role}`"
        ));
    }
    if base == BuiltinTheme::Ansi16 && matches!(color, Color::Rgb(..)) {
        return Err(format!(
            "Theme base ansi16 does not accept RGB color `{value}` for `{role}`"
        ));
    }
    Ok(color)
}
fn ansi_color(value: &str) -> Option<Color> {
    Some(match value {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" => Color::Gray,
        "dark_gray" => Color::DarkGray,
        "light_red" => Color::LightRed,
        "light_green" => Color::LightGreen,
        "light_yellow" => Color::LightYellow,
        "light_blue" => Color::LightBlue,
        "light_magenta" => Color::LightMagenta,
        "light_cyan" => Color::LightCyan,
        "white" => Color::White,
        _ => return None,
    })
}
macro_rules! set_roles { ($colors:expr,$role:expr,$color:expr,$($name:ident),+) => { match $role { $(stringify!($name)=>{$colors.$name=$color;Ok(())},)+ _=>Err(format!("Unknown theme color role `{}`",$role)) } }; }
fn set_color(colors: &mut ThemeColors, role: &str, color: Color) -> Result<(), String> {
    let role = match role {
        "ui.page_bg" => "page_bg",
        "ui.panel_bg" => "panel_bg",
        "ui.popup_bg" => "popup_bg",
        "ui.text" => "text",
        "ui.title" => "title",
        "ui.header" => "header",
        "ui.label" => "label",
        "ui.secondary" => "secondary",
        "ui.placeholder" => "placeholder",
        "ui.border" => "border",
        "ui.focus_border" => "focus_border",
        "ui.active_tab_fg" => "active_tab_fg",
        "ui.inactive_tab_fg" => "inactive_tab_fg",
        "ui.active_tab_bg" => "active_tab_bg",
        "ui.selection_bg" => "selection_bg",
        "ui.key" => "key",
        "ui.setting_label" => "setting_label",
        "ui.hint" => "hint",
        "ui.setting_value" => "setting_value",
        "feedback.warning" => "warning",
        "feedback.error" => "error",
        "brand.foreground" => "brand",
        "data.inbound" => "inbound",
        "data.outbound" => "outbound",
        "data.local_endpoint" => "local_endpoint",
        "data.remote_endpoint" => "remote_endpoint",
        "data.identity" => "identity",
        "data.protocol" => "protocol",
        "data.address_family" => "address_family",
        "data.attribution" => "attribution",
        "data.total" => "total",
        "data.time" => "time",
        "chart.track" => "chart_track",
        "chart.combined" => "chart_combined",
        _ => return Err(format!("Unknown theme color role `{role}`")),
    };
    set_roles!(
        colors,
        role,
        color,
        page_bg,
        panel_bg,
        popup_bg,
        text,
        title,
        header,
        label,
        secondary,
        placeholder,
        border,
        focus_border,
        active_tab_fg,
        inactive_tab_fg,
        active_tab_bg,
        selection_bg,
        key,
        setting_label,
        hint,
        setting_value,
        warning,
        error,
        brand,
        inbound,
        outbound,
        local_endpoint,
        remote_endpoint,
        identity,
        protocol,
        address_family,
        attribution,
        total,
        time,
        chart_track,
        chart_combined
    )
}
pub(crate) fn parse_cli_theme(value: &str) -> Result<(ThemeSelection, Option<Theme>), String> {
    match value {
        "auto" => Ok((ThemeSelection::Auto, None)),
        "dark" => Ok((ThemeSelection::Builtin(BuiltinTheme::Dark), None)),
        "ansi16" => Ok((ThemeSelection::Builtin(BuiltinTheme::Ansi16), None)),
        "mono" => Ok((ThemeSelection::Builtin(BuiltinTheme::Mono), None)),
        path => {
            let theme = load_theme(&PathBuf::from(path))?;
            Ok((ThemeSelection::File, Some(theme)))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn theme_path(label: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "flowlens-theme-{label}-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn load_fixture(label: &str, json: &str) -> Result<Theme, String> {
        let path = theme_path(label);
        std::fs::write(&path, json).unwrap();
        let result = load_theme(&path);
        std::fs::remove_file(path).unwrap();
        result
    }

    fn all_colors(colors: ThemeColors) -> [Color; 34] {
        [
            colors.page_bg,
            colors.panel_bg,
            colors.popup_bg,
            colors.text,
            colors.title,
            colors.header,
            colors.label,
            colors.secondary,
            colors.placeholder,
            colors.border,
            colors.focus_border,
            colors.active_tab_fg,
            colors.inactive_tab_fg,
            colors.active_tab_bg,
            colors.selection_bg,
            colors.key,
            colors.setting_label,
            colors.hint,
            colors.setting_value,
            colors.warning,
            colors.error,
            colors.brand,
            colors.inbound,
            colors.outbound,
            colors.local_endpoint,
            colors.remote_endpoint,
            colors.identity,
            colors.protocol,
            colors.address_family,
            colors.attribution,
            colors.total,
            colors.time,
            colors.chart_track,
            colors.chart_combined,
        ]
    }

    #[test]
    fn no_color_overrides_everything() {
        assert_eq!(
            tier_from_env(Some("truecolor"), "xterm-256color", Some("1")),
            ColorTier::Monochrome
        );
    }

    #[test]
    fn empty_no_color_is_ignored() {
        assert_eq!(tier_from_env(None, "xterm", Some("")), ColorTier::Sixteen);
    }

    #[test]
    fn colorterm_truecolor_wins_over_term() {
        assert_eq!(
            tier_from_env(Some(" TrueColor "), "linux", None),
            ColorTier::Truecolor
        );
        assert_eq!(
            tier_from_env(Some("24bit"), "xterm", None),
            ColorTier::Truecolor
        );
    }

    #[test]
    fn terminal_tiers_follow_the_documented_fallback_order() {
        assert_eq!(tier_from_env(None, "dumb", None), ColorTier::Monochrome);
        assert_eq!(
            tier_from_env(None, "screen-256color", None),
            ColorTier::Truecolor
        );
        for term in ["ansi", "linux", "screen", "xterm", "vt220"] {
            assert_eq!(
                tier_from_env(None, term, None),
                ColorTier::Sixteen,
                "{term}"
            );
        }
        assert_eq!(
            tier_from_env(Some("other"), "unrecognized", None),
            ColorTier::Truecolor
        );
    }

    #[test]
    fn explicit_selection_overrides_detected_theme_and_auto_restores_it() {
        let mut state = ThemeState::for_test(
            BuiltinTheme::Mono,
            ThemeSelection::Builtin(BuiltinTheme::Dark),
            None,
        );
        assert_eq!(state.resolved.base, BuiltinTheme::Dark);
        state.select(ThemeSelection::Auto);
        assert_eq!(state.resolved.base, BuiltinTheme::Mono);
        assert_eq!(state.selection_label(), "Auto (Mono)");
    }

    #[test]
    fn builtins_cover_the_approved_dark_and_ansi16_roles() {
        let dark = Theme::builtin(BuiltinTheme::Dark);
        assert_eq!(dark.colors.page_bg, Color::Rgb(11, 17, 24));
        assert_eq!(dark.colors.popup_bg, Color::Rgb(19, 29, 41));
        assert_eq!(dark.colors.local_endpoint, Color::Rgb(22, 198, 12));
        assert_eq!(dark.colors.total, Color::Rgb(244, 247, 250));
        assert_eq!(dark.colors.chart_track, Color::Rgb(37, 52, 67));

        let ansi = Theme::builtin(BuiltinTheme::Ansi16);
        assert_eq!(ansi.colors.inbound, Color::Yellow);
        assert_eq!(ansi.colors.outbound, Color::Cyan);
        assert_eq!(ansi.colors.local_endpoint, Color::LightGreen);
        assert_eq!(ansi.colors.warning, Color::Yellow);
        assert_eq!(ansi.colors.error, Color::Red);
        assert_eq!(ansi.colors.brand, Color::Magenta);
        assert_eq!(ansi.colors.focus_border, Color::Gray);
        assert_eq!(ansi.colors.chart_combined, Color::Gray);
        assert_eq!(ansi.colors.selection_bg, Color::Reset);
    }

    #[test]
    fn mono_builtin_has_no_colored_roles() {
        assert!(
            all_colors(Theme::builtin(BuiltinTheme::Mono).colors)
                .iter()
                .all(|color| *color == Color::Reset)
        );
    }

    #[test]
    fn selection_and_navigation_styles_follow_theme_rules_and_overrides() {
        let dark = Theme::builtin(BuiltinTheme::Dark);
        let dark_selection = dark.selection_style();
        assert_eq!(dark_selection.bg, Some(Color::Rgb(28, 44, 61)));
        assert!(dark_selection.add_modifier.contains(Modifier::BOLD));

        let mut ansi = Theme::builtin(BuiltinTheme::Ansi16);
        let ansi_selection = ansi.selection_style();
        assert_eq!(ansi_selection.bg, None);
        assert!(!ansi_selection.add_modifier.contains(Modifier::REVERSED));
        ansi.colors.selection_bg = Color::Blue;
        ansi.colors.active_tab_bg = Color::Yellow;
        assert_eq!(ansi.selection_style().bg, Some(Color::Blue));
        assert!(
            !ansi
                .selection_style()
                .add_modifier
                .contains(Modifier::REVERSED)
        );
        assert_eq!(ansi.active_tab_style().bg, Some(Color::Yellow));
        assert!(
            !ansi
                .active_tab_style()
                .add_modifier
                .contains(Modifier::REVERSED)
        );

        let mono = Theme::builtin(BuiltinTheme::Mono);
        assert!(
            mono.selection_style()
                .add_modifier
                .contains(Modifier::REVERSED)
        );
        assert!(
            mono.active_tab_style()
                .add_modifier
                .contains(Modifier::REVERSED)
        );
    }
    #[test]
    fn file_inherits_and_roles_are_independent() {
        let theme = load_fixture(
            "inherit",
            r##"{"base":"dark","colors":{"ui.title":"#010203","data.total":"#040506"}}"##,
        )
        .unwrap();
        assert_eq!(theme.colors.title, Color::Rgb(1, 2, 3));
        assert_eq!(theme.colors.total, Color::Rgb(4, 5, 6));
        assert_eq!(theme.colors.inbound, Color::Rgb(245, 186, 69));
    }
    #[test]
    fn rejects_invalid_theme_constraints() {
        assert!(
            load_fixture(
                "ansi-rgb",
                r##"{"base":"ansi16","colors":{"ui.border":"#000000"}}"##
            )
            .unwrap_err()
            .contains("does not accept RGB")
        );
    }

    #[test]
    fn rejects_unknown_fields_roles_and_invalid_base() {
        assert!(
            load_fixture("field", r#"{"base":"dark","unknown":true}"#)
                .unwrap_err()
                .contains("unknown field")
        );
        assert!(
            load_fixture("role", r#"{"base":"dark","colors":{"data.unknown":"red"}}"#)
                .unwrap_err()
                .contains("Unknown theme color role")
        );
        assert!(
            load_fixture("base", r#"{"base":"solarized"}"#)
                .unwrap_err()
                .contains("Invalid theme base")
        );
    }

    #[test]
    fn rejects_non_ascii_hex_and_non_default_mono_values_without_panicking() {
        assert!(
            load_fixture(
                "unicode",
                r##"{"base":"dark","colors":{"ui.border":"#€€€"}}"##
            )
            .unwrap_err()
            .contains("Invalid color")
        );
        assert!(
            load_fixture("mono", r#"{"base":"mono","colors":{"ui.text":"white"}}"#)
                .unwrap_err()
                .contains("only accepts `default`")
        );
    }

    #[test]
    fn file_theme_can_be_reselected_after_switching_to_auto() {
        let file = load_fixture(
            "choice",
            r##"{"name":"Session file","base":"dark","colors":{"ui.title":"#010203"}}"##,
        )
        .unwrap();
        let mut state =
            ThemeState::for_test(BuiltinTheme::Ansi16, ThemeSelection::File, Some(file));
        assert_eq!(state.selection_label(), "Session file");
        state.select(ThemeSelection::Auto);
        assert_eq!(state.selection_label(), "Auto (ANSI 16)");
        state.select(ThemeSelection::File);
        assert_eq!(state.resolved.colors.title, Color::Rgb(1, 2, 3));
    }
}
