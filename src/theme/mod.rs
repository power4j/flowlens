//! Resolved TUI themes and startup-only JSON loading.
mod catalog;
mod resolve;

use ratatui::style::{Color, Modifier, Style};
use resolve::Profile;
use std::{fmt, path::PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum Role {
    PageBg,
    PanelBg,
    PopupBg,
    Text,
    Title,
    Header,
    Label,
    Secondary,
    Placeholder,
    Border,
    FocusBorder,
    ActiveTabFg,
    InactiveTabFg,
    ActiveTabBg,
    SelectionBg,
    Key,
    SettingLabel,
    Hint,
    SettingValue,
    Warning,
    Error,
    Brand,
    Inbound,
    Outbound,
    LocalEndpoint,
    RemoteEndpoint,
    Identity,
    Protocol,
    AddressFamily,
    Attribution,
    Total,
    Time,
    ChartTrack,
    ChartCombined,
}
impl Role {
    const COUNT: usize = 34;
    const ALL: [Self; Self::COUNT] = [
        Self::PageBg,
        Self::PanelBg,
        Self::PopupBg,
        Self::Text,
        Self::Title,
        Self::Header,
        Self::Label,
        Self::Secondary,
        Self::Placeholder,
        Self::Border,
        Self::FocusBorder,
        Self::ActiveTabFg,
        Self::InactiveTabFg,
        Self::ActiveTabBg,
        Self::SelectionBg,
        Self::Key,
        Self::SettingLabel,
        Self::Hint,
        Self::SettingValue,
        Self::Warning,
        Self::Error,
        Self::Brand,
        Self::Inbound,
        Self::Outbound,
        Self::LocalEndpoint,
        Self::RemoteEndpoint,
        Self::Identity,
        Self::Protocol,
        Self::AddressFamily,
        Self::Attribution,
        Self::Total,
        Self::Time,
        Self::ChartTrack,
        Self::ChartCombined,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::PageBg => "ui.page_bg",
            Self::PanelBg => "ui.panel_bg",
            Self::PopupBg => "ui.popup_bg",
            Self::Text => "ui.text",
            Self::Title => "ui.title",
            Self::Header => "ui.header",
            Self::Label => "ui.label",
            Self::Secondary => "ui.secondary",
            Self::Placeholder => "ui.placeholder",
            Self::Border => "ui.border",
            Self::FocusBorder => "ui.focus_border",
            Self::ActiveTabFg => "ui.active_tab_fg",
            Self::InactiveTabFg => "ui.inactive_tab_fg",
            Self::ActiveTabBg => "ui.active_tab_bg",
            Self::SelectionBg => "ui.selection_bg",
            Self::Key => "ui.key",
            Self::SettingLabel => "ui.setting_label",
            Self::Hint => "ui.hint",
            Self::SettingValue => "ui.setting_value",
            Self::Warning => "feedback.warning",
            Self::Error => "feedback.error",
            Self::Brand => "brand.foreground",
            Self::Inbound => "data.inbound",
            Self::Outbound => "data.outbound",
            Self::LocalEndpoint => "data.local_endpoint",
            Self::RemoteEndpoint => "data.remote_endpoint",
            Self::Identity => "data.identity",
            Self::Protocol => "data.protocol",
            Self::AddressFamily => "data.address_family",
            Self::Attribution => "data.attribution",
            Self::Total => "data.total",
            Self::Time => "data.time",
            Self::ChartTrack => "chart.track",
            Self::ChartCombined => "chart.combined",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "ui.page_bg" => Self::PageBg,
            "ui.panel_bg" => Self::PanelBg,
            "ui.popup_bg" => Self::PopupBg,
            "ui.text" => Self::Text,
            "ui.title" => Self::Title,
            "ui.header" => Self::Header,
            "ui.label" => Self::Label,
            "ui.secondary" => Self::Secondary,
            "ui.placeholder" => Self::Placeholder,
            "ui.border" => Self::Border,
            "ui.focus_border" => Self::FocusBorder,
            "ui.active_tab_fg" => Self::ActiveTabFg,
            "ui.inactive_tab_fg" => Self::InactiveTabFg,
            "ui.active_tab_bg" => Self::ActiveTabBg,
            "ui.selection_bg" => Self::SelectionBg,
            "ui.key" => Self::Key,
            "ui.setting_label" => Self::SettingLabel,
            "ui.hint" => Self::Hint,
            "ui.setting_value" => Self::SettingValue,
            "feedback.warning" => Self::Warning,
            "feedback.error" => Self::Error,
            "brand.foreground" => Self::Brand,
            "data.inbound" => Self::Inbound,
            "data.outbound" => Self::Outbound,
            "data.local_endpoint" => Self::LocalEndpoint,
            "data.remote_endpoint" => Self::RemoteEndpoint,
            "data.identity" => Self::Identity,
            "data.protocol" => Self::Protocol,
            "data.address_family" => Self::AddressFamily,
            "data.attribution" => Self::Attribution,
            "data.total" => Self::Total,
            "data.time" => Self::Time,
            "chart.track" => Self::ChartTrack,
            "chart.combined" => Self::ChartCombined,
            _ => return None,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Theme {
    name: String,
    profile: Profile,
    roles: [Color; Role::COUNT],
}
impl Theme {
    fn new(name: String, profile: Profile, roles: [Color; Role::COUNT]) -> Self {
        Self {
            name,
            profile,
            roles,
        }
    }
    fn set(&mut self, role: Role, color: Color) {
        self.roles[role as usize] = color;
    }
    pub(crate) fn color(&self, role: Role) -> Color {
        self.roles[role as usize]
    }
    pub(crate) fn selection_style(&self) -> Style {
        match self.profile {
            Profile::Truecolor => Style::default()
                .bg(self.color(Role::SelectionBg))
                .add_modifier(Modifier::BOLD),
            Profile::Ansi16 => {
                let style = Style::default().add_modifier(Modifier::BOLD);
                if self.color(Role::SelectionBg) == Color::Reset {
                    style
                } else {
                    style.bg(self.color(Role::SelectionBg))
                }
            }
            Profile::Mono => Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
        }
    }
    pub(crate) fn active_tab_style(&self) -> Style {
        match self.profile {
            Profile::Truecolor => Style::default()
                .fg(self.color(Role::ActiveTabFg))
                .bg(self.color(Role::ActiveTabBg))
                .add_modifier(Modifier::BOLD),
            Profile::Ansi16 => {
                let style = Style::default()
                    .fg(self.color(Role::ActiveTabFg))
                    .add_modifier(Modifier::BOLD);
                if self.color(Role::ActiveTabBg) == Color::Reset {
                    style.add_modifier(Modifier::REVERSED)
                } else {
                    style.bg(self.color(Role::ActiveTabBg))
                }
            }
            Profile::Mono => Style::default()
                .fg(self.color(Role::ActiveTabFg))
                .add_modifier(Modifier::REVERSED | Modifier::BOLD),
        }
    }
}
#[cfg(test)]
impl Theme {
    pub(crate) fn dark_for_test() -> Self {
        ThemeSession::load(Some("dark")).unwrap().current().clone()
    }
}
#[derive(Debug)]
pub(crate) struct ThemeError {
    source: String,
    kind: ThemeErrorKind,
}
#[derive(Debug)]
enum ThemeErrorKind {
    Syntax {
        line: usize,
        column: usize,
        message: String,
    },
    Io(String),
    Field {
        field: String,
        value: Option<String>,
        reason: String,
    },
}
impl ThemeError {
    fn syntax(
        source: impl fmt::Display,
        line: usize,
        column: usize,
        message: impl fmt::Display,
    ) -> Self {
        Self {
            source: source.to_string(),
            kind: ThemeErrorKind::Syntax {
                line,
                column,
                message: message.to_string(),
            },
        }
    }
    fn source(source: impl fmt::Display, reason: impl fmt::Display) -> Self {
        Self {
            source: source.to_string(),
            kind: ThemeErrorKind::Io(reason.to_string()),
        }
    }
    fn field(
        source: impl fmt::Display,
        field: impl fmt::Display,
        reason: impl fmt::Display,
    ) -> Self {
        Self {
            source: source.to_string(),
            kind: ThemeErrorKind::Field {
                field: field.to_string(),
                value: None,
                reason: reason.to_string(),
            },
        }
    }
    fn field_value(
        source: impl fmt::Display,
        field: impl fmt::Display,
        value: impl fmt::Display,
        reason: impl fmt::Display,
    ) -> Self {
        Self {
            source: source.to_string(),
            kind: ThemeErrorKind::Field {
                field: field.to_string(),
                value: Some(value.to_string()),
                reason: reason.to_string(),
            },
        }
    }
}
impl fmt::Display for ThemeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: ", self.source)?;
        match &self.kind {
            ThemeErrorKind::Syntax {
                line,
                column,
                message,
            } => write!(formatter, "line {line}, column {column}: {message}"),
            ThemeErrorKind::Io(reason) => reason.fmt(formatter),
            ThemeErrorKind::Field {
                field,
                value,
                reason,
            } => {
                write!(formatter, "{field}")?;
                if let Some(value) = value {
                    write!(formatter, " `{value}`")?;
                }
                write!(formatter, ": {reason}")
            }
        }
    }
}
impl std::error::Error for ThemeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Choice {
    Auto,
    Builtin(usize),
    External,
}
#[derive(Clone)]
pub(crate) struct ThemeSession {
    themes: Vec<(&'static str, Theme)>,
    detected: usize,
    choice: Choice,
    external: Option<Theme>,
}
impl ThemeSession {
    pub(crate) fn load(request: Option<&str>) -> Result<Self, ThemeError> {
        let themes = catalog::builtins()?;
        let detected_id = detect();
        let detected = catalog::builtin_index(&themes, detected_id).ok_or_else(|| {
            ThemeError::source(
                "catalog",
                format!("Auto default `{detected_id}` is not registered"),
            )
        })?;
        let mut session = Self {
            themes,
            detected,
            choice: Choice::Auto,
            external: None,
        };
        if let Some(request) = request
            && request != "auto"
        {
            let ids = session.themes.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            let home = if ids.contains(&request) || !resolve::requires_home(request) {
                None
            } else {
                Some(runtime_home(request)?)
            };
            match resolve::resolve_source(request, &ids, home.as_deref())? {
                resolve::Source::Builtin(index) => session.choice = Choice::Builtin(index),
                resolve::Source::File(path) => {
                    session.external = Some(resolve::load_external(&path, &session.themes)?);
                    session.choice = Choice::External;
                }
            }
        }
        Ok(session)
    }
    pub(crate) fn current(&self) -> &Theme {
        match self.choice {
            Choice::Auto => &self.themes[self.detected].1,
            Choice::Builtin(index) => &self.themes[index].1,
            Choice::External => self
                .external
                .as_ref()
                .expect("external choice requires theme"),
        }
    }
    pub(crate) fn selection_label(&self) -> String {
        match self.choice {
            Choice::Auto => format!("Auto ({})", self.themes[self.detected].1.name),
            Choice::Builtin(index) => self.themes[index].1.name.clone(),
            Choice::External => self.external.as_ref().expect("external theme").name.clone(),
        }
    }
    pub(crate) fn next(&mut self) {
        self.advance(true);
    }
    pub(crate) fn previous(&mut self) {
        self.advance(false);
    }
    fn advance(&mut self, forward: bool) {
        let len = self.themes.len() + usize::from(self.external.is_some()) + 1;
        let index = match self.choice {
            Choice::Auto => 0,
            Choice::Builtin(index) => index + 1,
            Choice::External => self.themes.len() + 1,
        };
        let next = if forward {
            (index + 1) % len
        } else {
            (index + len - 1) % len
        };
        self.choice = if next == 0 {
            Choice::Auto
        } else if next <= self.themes.len() {
            Choice::Builtin(next - 1)
        } else {
            Choice::External
        };
    }
}
fn detect() -> &'static str {
    detect_from(
        std::env::var("NO_COLOR").ok().as_deref(),
        std::env::var("COLORTERM").ok().as_deref(),
        std::env::var("TERM").ok().as_deref(),
    )
}
fn detect_from(
    no_color: Option<&str>,
    color_term: Option<&str>,
    term: Option<&str>,
) -> &'static str {
    if no_color.is_some_and(|value| !value.is_empty()) {
        return "mono";
    }
    let color_term = color_term.unwrap_or_default().trim().to_ascii_lowercase();
    if matches!(color_term.as_str(), "truecolor" | "24bit") {
        return "dark";
    }
    let term = term.unwrap_or_default().trim().to_ascii_lowercase();
    if term == "dumb" {
        "mono"
    } else if term.contains("256color") {
        "dark"
    } else if matches!(term.as_str(), "ansi" | "linux" | "screen" | "xterm")
        || term.starts_with("vt")
    {
        "ansi16"
    } else {
        "dark"
    }
}
fn runtime_home(request: &str) -> Result<PathBuf, ThemeError> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or_else(|| ThemeError::source(request, "home directory is unavailable"))
}
#[cfg(test)]
impl ThemeSession {
    pub(crate) fn dark_for_test() -> Self {
        Self::load(Some("dark")).expect("embedded dark theme is valid")
    }
    pub(crate) fn auto_for_test() -> Self {
        let mut session = Self::dark_for_test();
        session.choice = Choice::Auto;
        session.detected = session
            .themes
            .iter()
            .position(|(id, _)| *id == "dark")
            .unwrap();
        session
    }
}
#[cfg(test)]
impl ThemeSession {
    pub(crate) fn with_role(mut self, role: Role, color: Color) -> Self {
        match self.choice {
            Choice::Auto => self.themes[self.detected].1.set(role, color),
            Choice::Builtin(index) => self.themes[index].1.set(role, color),
            Choice::External => self.external.as_mut().unwrap().set(role, color),
        }
        self
    }
    pub(crate) fn with_external(mut self, label: &str) -> Self {
        let mut theme = self.themes[0].1.clone();
        theme.name = label.to_owned();
        self.external = Some(theme);
        self
    }
    pub(crate) fn select_external_for_test(mut self) -> Self {
        self.choice = Choice::External;
        self
    }
    pub(crate) fn cycle_labels_for_test(&mut self) -> Vec<String> {
        let count = self.themes.len() + usize::from(self.external.is_some()) + 1;
        (0..count)
            .map(|_| {
                self.next();
                self.selection_label()
            })
            .collect()
    }
    pub(crate) fn builtin_labels_for_test(&self) -> Vec<String> {
        self.themes
            .iter()
            .map(|(_, theme)| theme.name.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn colors(session: &ThemeSession) -> [Color; Role::COUNT] {
        Role::ALL.map(|role| session.current().color(role))
    }

    fn assert_error(json: &str, field: &str, value: &str, reason: &str) {
        let error = resolve::parse_complete("fixture.json", json)
            .unwrap_err()
            .to_string();
        assert!(error.contains("fixture.json"), "{error}");
        assert!(error.contains(field), "{error}");
        assert!(error.contains(value), "{error}");
        assert!(error.contains(reason), "{error}");
    }

    fn assert_external_error(json: &str, field: &str, value: &str, reason: &str) {
        let path = std::env::temp_dir().join(format!(
            "flowlens-invalid-{field}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, json).unwrap();
        let error = resolve::load_external(&path, &catalog::builtins().unwrap())
            .unwrap_err()
            .to_string();
        std::fs::remove_file(path).unwrap();
        assert!(error.contains("flowlens-invalid-"), "{error}");
        assert!(error.contains(field), "{error}");
        assert!(error.contains(value), "{error}");
        assert!(error.contains(reason), "{error}");
    }

    #[test]
    fn auto_no_color_wins() {
        assert_eq!(
            detect_from(Some("1"), Some("truecolor"), Some("xterm-256color")),
            "mono"
        );
    }
    #[test]
    fn auto_empty_no_color_is_ignored() {
        assert_eq!(detect_from(Some(""), None, Some("xterm")), "ansi16");
    }
    #[test]
    fn auto_colorterm_truecolor_wins() {
        assert_eq!(
            detect_from(None, Some(" TrueColor "), Some("linux")),
            "dark"
        );
    }
    #[test]
    fn auto_colorterm_24bit_wins() {
        assert_eq!(detect_from(None, Some("24bit"), Some("dumb")), "dark");
    }
    #[test]
    fn auto_dumb_is_mono() {
        assert_eq!(detect_from(None, None, Some(" dumb ")), "mono");
    }
    #[test]
    fn auto_256color_is_dark() {
        assert_eq!(detect_from(None, None, Some("screen-256color")), "dark");
    }
    #[test]
    fn auto_known_ansi_terms() {
        for term in ["ansi", "linux", "screen", "xterm", "vt220"] {
            assert_eq!(detect_from(None, None, Some(term)), "ansi16");
        }
    }
    #[test]
    fn auto_unknown_defaults_to_dark() {
        assert_eq!(detect_from(None, Some("unknown"), Some("custom")), "dark");
    }
    #[test]
    fn path_classification_is_exact() {
        assert!(!resolve::explicit_path("dark"));
        assert!(resolve::explicit_path("x.json"));
        assert!(resolve::explicit_path("./x"));
        assert!(resolve::explicit_path("~/x"));
        assert!(resolve::explicit_path("~custom.json"));
        assert!(resolve::explicit_path("a/b"));
    }
    #[test]
    fn path_classification_accepts_backslash_home() {
        assert!(resolve::explicit_path("~\\theme.json"));
    }
    #[test]
    fn path_classification_accepts_absolute_path() {
        let path = std::env::temp_dir().join("theme");
        assert!(resolve::explicit_path(path.to_string_lossy().as_ref()));
    }
    #[test]
    fn source_resolution_is_ordered_and_home_is_injected() {
        let home = Path::new("C:/home/tester");
        let ids = ["dark", "ansi16", "mono"];
        assert!(matches!(
            resolve::resolve_source("dark", &ids, None),
            Ok(resolve::Source::Builtin(0))
        ));
        for name in ["./ocean", "../ocean", "folder/ocean", "ocean.json"] {
            assert!(
                matches!(
                    resolve::resolve_source(name, &ids, None),
                    Ok(resolve::Source::File(_))
                ),
                "{name}"
            );
        }
        assert_eq!(
            match resolve::resolve_source("~custom.json", &ids, None).unwrap() {
                resolve::Source::File(path) => path,
                _ => unreachable!(),
            },
            Path::new("~custom.json")
        );
        for name in ["~/ocean.json", "~\\ocean.json"] {
            assert_eq!(
                match resolve::resolve_source(name, &ids, Some(home)).unwrap() {
                    resolve::Source::File(path) => path,
                    _ => unreachable!(),
                },
                home.join("ocean.json")
            );
            assert!(
                resolve::resolve_source(name, &ids, None)
                    .unwrap_err()
                    .to_string()
                    .contains("home directory is unavailable")
            );
        }
        assert_eq!(
            match resolve::resolve_source("ocean", &ids, Some(home)).unwrap() {
                resolve::Source::File(path) => path,
                _ => unreachable!(),
            },
            home.join(".flowlens/themes/ocean.json")
        );
        for name in ["ocean", "~/ocean", "~\\ocean"] {
            assert!(
                resolve::resolve_source(name, &ids, None)
                    .unwrap_err()
                    .to_string()
                    .contains("home directory is unavailable")
            );
        }
    }
    #[test]
    fn malformed_syntax_reports_location() {
        let error = resolve::parse_complete("fixture", "{")
            .unwrap_err()
            .to_string();
        assert!(error.contains("fixture: line"));
        assert!(error.contains("column"));
    }
    #[test]
    fn complete_null_fields_are_rejected() {
        for field in ["base", "profile", "name", "version", "$schema"] {
            let json = format!(r#"{{"{field}":null,"profile":"truecolor","colors":{{}}}}"#);
            assert!(resolve::parse_complete("test", &json).is_err(), "{field}");
        }
    }

    #[test]
    fn complete_theme_errors_identify_values_roles_and_reason() {
        assert_error(
            r#"{"profile":"truecolor","colors":{"ui.text":3}}"#,
            "ui.text",
            "3",
            "expected a string",
        );
        assert_error(
            r#"{"profile":"truecolor","colors":{"ui.unknown":"red"}}"#,
            "colors",
            "ui.unknown",
            "unknown role",
        );
        assert_error(
            r##"{"profile":"ansi16","colors":{"ui.text":"#010203"}}"##,
            "ui.text",
            "#010203",
            "does not accept RGB",
        );
        assert_error(
            r#"{"profile":"mono","colors":{"ui.text":"white"}}"#,
            "ui.text",
            "white",
            "only accepts",
        );
        assert_error(
            r##"{"profile":"truecolor","colors":{"ui.text":"#€€"}}"##,
            "ui.text",
            "#€€",
            "invalid color",
        );
        assert_error(
            r#"{"version":2,"profile":"truecolor","colors":{}}"#,
            "version",
            "2",
            "unsupported version",
        );
        let missing =
            resolve::parse_complete("fixture.json", r#"{"profile":"truecolor","colors":{}}"#)
                .unwrap_err()
                .to_string();
        assert!(missing.contains("ui.page_bg"), "{missing}");
        let syntax = resolve::parse_complete("fixture.json", "{")
            .unwrap_err()
            .to_string();
        assert!(
            syntax.contains("fixture.json: line") && syntax.contains("column"),
            "{syntax}"
        );
    }

    #[test]
    fn shape_and_override_errors_preserve_source_field_value_and_reason() {
        assert_error(
            r#"{"unknown":true,"profile":"truecolor","colors":{}}"#,
            "unknown",
            "unknown",
            "unknown top-level field",
        );
        for colors in ["null", "3", "[]"] {
            let complete = format!(r#"{{"profile":"truecolor","colors":{colors}}}"#);
            assert_error(&complete, "colors", colors, "expected an object");
            let override_json = format!(r#"{{"base":"dark","colors":{colors}}}"#);
            assert_external_error(&override_json, "colors", colors, "expected an object");
        }
        for json in [
            r#"{"base":"dark","profile":"truecolor","colors":{}}"#,
            r#"{"colors":{}}"#,
        ] {
            let error = resolve::parse_complete("fixture.json", json)
                .unwrap_err()
                .to_string();
            assert!(error.contains("fixture.json"), "{error}");
            assert!(error.contains("profile/base"), "{error}");
            assert!(error.contains("complete theme requires"), "{error}");
        }
        assert_external_error(r#"{"base":null}"#, "base", "null", "must not be null");
        assert_external_error(
            r#"{"base":"dark","profile":null}"#,
            "profile",
            "null",
            "must not be null",
        );
        assert_external_error(
            r#"{"base":"dark","profile":"truecolor"}"#,
            "profile",
            "truecolor",
            "override cannot declare profile",
        );
        assert_external_error(r#"{"base":"ocean"}"#, "base", "ocean", "unknown built-in");
    }

    #[test]
    fn embedded_theme_values_and_fixed_styles_are_preserved() {
        let dark = ThemeSession::load(Some("dark")).unwrap();
        assert_eq!(
            dark.current().color(Role::LocalEndpoint),
            Color::Rgb(22, 198, 12)
        );
        assert_eq!(dark.current().color(Role::PageBg), Color::Rgb(11, 17, 24));
        assert!(
            dark.current()
                .selection_style()
                .add_modifier
                .contains(Modifier::BOLD)
        );
        let ansi = ThemeSession::load(Some("ansi16")).unwrap();
        assert_eq!(ansi.current().color(Role::Inbound), Color::Yellow);
        assert!(
            ThemeSession::load(Some("mono"))
                .unwrap()
                .current()
                .selection_style()
                .add_modifier
                .contains(Modifier::REVERSED)
        );
    }
    #[test]
    fn all_builtin_roles_and_fixed_styles_match_the_approved_palette() {
        let dark = [
            Color::Rgb(11, 17, 24),
            Color::Rgb(11, 17, 24),
            Color::Rgb(19, 29, 41),
            Color::Rgb(216, 224, 232),
            Color::Rgb(244, 247, 250),
            Color::Rgb(147, 162, 180),
            Color::Rgb(147, 162, 180),
            Color::Rgb(147, 162, 180),
            Color::Rgb(147, 162, 180),
            Color::Rgb(61, 76, 95),
            Color::Rgb(147, 162, 180),
            Color::Rgb(244, 247, 250),
            Color::Rgb(147, 162, 180),
            Color::Rgb(28, 44, 61),
            Color::Rgb(28, 44, 61),
            Color::Rgb(216, 224, 232),
            Color::Rgb(216, 224, 232),
            Color::Rgb(147, 162, 180),
            Color::Rgb(244, 247, 250),
            Color::Rgb(245, 186, 69),
            Color::Rgb(241, 139, 160),
            Color::Rgb(185, 160, 247),
            Color::Rgb(245, 186, 69),
            Color::Rgb(67, 198, 232),
            Color::Rgb(22, 198, 12),
            Color::Rgb(216, 224, 232),
            Color::Rgb(216, 224, 232),
            Color::Rgb(216, 224, 232),
            Color::Rgb(216, 224, 232),
            Color::Rgb(216, 224, 232),
            Color::Rgb(244, 247, 250),
            Color::Rgb(147, 162, 180),
            Color::Rgb(37, 52, 67),
            Color::Rgb(147, 162, 180),
        ];
        let ansi = [
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::DarkGray,
            Color::DarkGray,
            Color::DarkGray,
            Color::DarkGray,
            Color::Gray,
            Color::Gray,
            Color::Reset,
            Color::DarkGray,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::DarkGray,
            Color::Reset,
            Color::Yellow,
            Color::Red,
            Color::Magenta,
            Color::Yellow,
            Color::Cyan,
            Color::LightGreen,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::Reset,
            Color::DarkGray,
            Color::Gray,
            Color::Gray,
        ];
        let mono = [Color::Reset; Role::COUNT];
        for (id, expected) in [("dark", dark), ("ansi16", ansi), ("mono", mono)] {
            let session = ThemeSession::load(Some(id)).unwrap();
            assert_eq!(colors(&session), expected, "{id}");
            let selection = session.current().selection_style();
            let active = session.current().active_tab_style();
            let expected_selection = match id {
                "dark" => Style::default()
                    .bg(Color::Rgb(28, 44, 61))
                    .add_modifier(Modifier::BOLD),
                "ansi16" => Style::default().add_modifier(Modifier::BOLD),
                "mono" => Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
                _ => unreachable!(),
            };
            let expected_active = match id {
                "dark" => Style::default()
                    .fg(Color::Rgb(244, 247, 250))
                    .bg(Color::Rgb(28, 44, 61))
                    .add_modifier(Modifier::BOLD),
                "ansi16" => Style::default()
                    .fg(Color::Reset)
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD),
                "mono" => Style::default()
                    .fg(Color::Reset)
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD),
                _ => unreachable!(),
            };
            assert_eq!(selection, expected_selection, "{id} selection");
            assert_eq!(active, expected_active, "{id} active tab");
        }
        let mut ansi = ThemeSession::load(Some("ansi16")).unwrap();
        ansi.themes[1].1.set(Role::SelectionBg, Color::Blue);
        ansi.themes[1].1.set(Role::ActiveTabBg, Color::Yellow);
        assert_eq!(
            ansi.current().selection_style(),
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            ansi.current().active_tab_style(),
            Style::default()
                .fg(Color::Reset)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        );
    }
    #[test]
    fn catalog_registration_drives_selection_override_and_auto_defaults() {
        let entries = [
            catalog::Entry {
                id: "ocean",
                json: include_str!("../../themes/dark.json"),
            },
            catalog::Entry {
                id: "dark",
                json: include_str!("../../themes/dark.json"),
            },
            catalog::Entry {
                id: "ansi16",
                json: include_str!("../../themes/ansi16.json"),
            },
            catalog::Entry {
                id: "mono",
                json: include_str!("../../themes/mono.json"),
            },
        ];
        let themes = catalog::builtins_from(&entries).unwrap();
        assert_eq!(
            themes.len(),
            4,
            "every registration validates and joins the catalog"
        );
        let mut session = ThemeSession {
            themes,
            detected: 0,
            choice: Choice::Auto,
            external: None,
        };
        session.detected = catalog::builtin_index(&session.themes, "dark").unwrap();
        assert_eq!(
            session.current().color(Role::LocalEndpoint),
            Color::Rgb(22, 198, 12)
        );
        session.next();
        assert_eq!(session.choice, Choice::Builtin(0));

        let path = std::env::temp_dir().join(format!("flowlens-ocean-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r##"{"base":"ocean","colors":{"ui.title":"#010203"}}"##,
        )
        .unwrap();
        let external = resolve::load_external(&path, &session.themes).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(external.color(Role::Title), Color::Rgb(1, 2, 3));
        assert_eq!(detect_from(None, None, Some("xterm")), "ansi16");
    }
    #[test]
    fn external_complete_copy_and_name_fallbacks_preserve_theme_values() {
        let path =
            std::env::temp_dir().join(format!("flowlens-complete-{}.json", std::process::id()));
        std::fs::write(&path, include_str!("../../themes/dark.json")).unwrap();
        let builtins = catalog::builtins().unwrap();
        let external = resolve::load_external(&path, &builtins).unwrap();
        std::fs::remove_file(&path).unwrap();
        let builtin = ThemeSession::load(Some("dark")).unwrap();
        assert_eq!(Role::ALL.map(|role| external.color(role)), colors(&builtin));
        assert_eq!(
            external.selection_style(),
            builtin.current().selection_style()
        );
        assert_eq!(
            external.active_tab_style(),
            builtin.current().active_tab_style()
        );

        let expected_name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let complete_without_name =
            include_str!("../../themes/dark.json").replace("  \"name\": \"FlowLens Dark\",\n", "");
        let complete_with_empty_name = include_str!("../../themes/dark.json")
            .replace("\"name\": \"FlowLens Dark\"", "\"name\": \"\"");
        for json in [
            complete_without_name,
            complete_with_empty_name,
            r#"{"base":"dark","colors":{}}"#.to_owned(),
            r#"{"name":"","base":"dark","colors":{}}"#.to_owned(),
        ] {
            std::fs::write(&path, json).unwrap();
            assert_eq!(
                resolve::load_external(&path, &builtins).unwrap().name,
                expected_name
            );
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn catalog_registration_errors_include_id_context() {
        let cases = [
            (
                vec![catalog::Entry { id: "", json: "" }],
                "",
                "must not be empty",
            ),
            (
                vec![catalog::Entry {
                    id: "auto",
                    json: "",
                }],
                "auto",
                "reserved for automatic selection",
            ),
            (
                vec![
                    catalog::Entry {
                        id: "dark",
                        json: include_str!("../../themes/dark.json"),
                    },
                    catalog::Entry {
                        id: "dark",
                        json: "",
                    },
                ],
                "dark",
                "duplicate ID",
            ),
        ];
        for (entries, value, reason) in cases {
            let error = catalog::builtins_from(&entries).unwrap_err().to_string();
            assert_eq!(error, format!("catalog: id `{value}`: {reason}"));
        }
    }

    #[test]
    fn external_theme_cannot_be_used_as_an_override_base() {
        let parent = std::env::temp_dir().join(format!(
            "flowlens-external-parent-{}.json",
            std::process::id()
        ));
        let child = std::env::temp_dir().join(format!(
            "flowlens-external-child-{}.json",
            std::process::id()
        ));
        let builtins = catalog::builtins().unwrap();
        std::fs::write(&parent, r#"{"name":"external-parent","base":"dark"}"#).unwrap();
        assert_eq!(
            resolve::load_external(&parent, &builtins).unwrap().name,
            "external-parent"
        );
        std::fs::write(&child, r#"{"base":"external-parent"}"#).unwrap();
        let error = resolve::load_external(&child, &builtins)
            .unwrap_err()
            .to_string();
        std::fs::remove_file(parent).unwrap();
        std::fs::remove_file(child).unwrap();
        assert!(error.contains("external-parent"), "{error}");
        assert!(error.contains("unknown built-in"), "{error}");
    }
    #[test]
    fn override_inherits_catalog_builtin_and_rejects_bad_hex() {
        let path = std::env::temp_dir().join(format!("flowlens-theme-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r##"{"name":"Session","base":"dark","colors":{"ui.title":"#010203"}}"##,
        )
        .unwrap();
        let builtins = catalog::builtins().unwrap();
        let theme = resolve::load_external(&path, &builtins).unwrap();
        assert_eq!(theme.color(Role::Title), Color::Rgb(1, 2, 3));
        assert_eq!(theme.color(Role::Inbound), Color::Rgb(245, 186, 69));
        std::fs::write(
            &path,
            r##"{"base":"dark","colors":{"ui.title":"#zz0000"}}"##,
        )
        .unwrap();
        assert!(resolve::load_external(&path, &builtins).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn session_keeps_external_theme_after_file_is_removed() {
        let path = std::env::temp_dir().join(format!(
            "flowlens-theme-session-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r##"{"base":"dark","colors":{"ui.title":"#010203"}}"##,
        )
        .unwrap();
        let mut session = ThemeSession::load(Some(path.to_string_lossy().as_ref())).unwrap();
        std::fs::remove_file(path).unwrap();
        session.next();
        session.previous();
        assert_eq!(session.current().color(Role::Title), Color::Rgb(1, 2, 3));
    }
}
