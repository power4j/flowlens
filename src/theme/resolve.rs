use std::path::{Path, PathBuf};

use ratatui::style::Color;
use serde::Deserialize;

use super::{Role, Theme, ThemeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Profile {
    Truecolor,
    Ansi16,
    Mono,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTheme {
    #[serde(rename = "$schema")]
    _schema: Option<String>,
    version: Option<u8>,
    name: Option<String>,
    profile: Option<String>,
    base: Option<String>,
    #[serde(default)]
    colors: serde_json::Map<String, serde_json::Value>,
}

pub(super) fn parse_complete(id: &str, json: &str) -> Result<Theme, ThemeError> {
    let (wire, object) = decode(id, json)?;
    if object.contains_key("base") || !non_null(&object, "profile") || !non_null(&object, "colors")
    {
        return Err(ThemeError::field(
            id,
            "profile/base",
            "complete theme requires profile and no base",
        ));
    }
    let profile = profile(id, wire.profile.as_deref().unwrap())?;
    let mut colors = [Color::Reset; Role::COUNT];
    let mut seen = [false; Role::COUNT];
    for (name, value) in wire.colors {
        let role = role(id, &name)?;
        seen[role as usize] = true;
        colors[role as usize] = color(id, &name, value, profile)?;
    }
    if let Some(role) = Role::ALL.into_iter().find(|role| !seen[*role as usize]) {
        return Err(ThemeError::field_value(
            id,
            "colors",
            role.name(),
            "complete theme is missing this role",
        ));
    }
    Ok(Theme::new(
        wire.name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.to_owned()),
        profile,
        colors,
    ))
}

pub(super) fn load_external(
    path: &Path,
    builtins: &[(&'static str, Theme)],
) -> Result<Theme, ThemeError> {
    let source = path.display().to_string();
    let json = std::fs::read_to_string(path)
        .map_err(|error| ThemeError::source(source.clone(), error.to_string()))?;
    let (wire, object) = decode(&source, &json)?;
    if object.contains_key("base") {
        let base = wire
            .base
            .as_deref()
            .filter(|_| non_null(&object, "base"))
            .ok_or_else(|| {
                ThemeError::field_value(&source, "base", "null", "must be a non-null string")
            })?;
        if object.contains_key("profile") {
            return Err(ThemeError::field_value(
                &source,
                "profile",
                object["profile"].to_string(),
                "override cannot declare profile",
            ));
        }
        let entry = builtins
            .iter()
            .find(|(id, _)| *id == base)
            .ok_or_else(|| ThemeError::field_value(&source, "base", base, "unknown built-in"))?;
        let mut theme = entry.1.clone();
        for (name, value) in wire.colors {
            theme.set(
                role(&source, &name)?,
                color(&source, &name, value, theme.profile)?,
            );
        }
        theme.name = wire
            .name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
        Ok(theme)
    } else {
        let mut theme = parse_complete(&source, &json)?;
        if wire.name.is_none_or(|name| name.is_empty()) {
            theme.name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
        }
        Ok(theme)
    }
}

fn decode(
    source: &str,
    json: &str,
) -> Result<(WireTheme, serde_json::Map<String, serde_json::Value>), ThemeError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
        ThemeError::syntax(source, error.line(), error.column(), error.to_string())
    })?;
    let object = value
        .as_object()
        .cloned()
        .ok_or_else(|| ThemeError::field(source, "theme", "expected an object"))?;
    for (field, value) in &object {
        if !matches!(
            field.as_str(),
            "$schema" | "version" | "name" | "profile" | "base" | "colors"
        ) {
            return Err(ThemeError::field_value(
                source,
                field,
                value,
                "unknown top-level field",
            ));
        }
    }
    if let Some(colors) = object.get("colors")
        && !colors.is_object()
    {
        return Err(ThemeError::field_value(
            source,
            "colors",
            colors,
            "expected an object",
        ));
    }
    for field in ["$schema", "version", "name", "profile", "base"] {
        if object.get(field).is_some_and(serde_json::Value::is_null) {
            return Err(ThemeError::field_value(
                source,
                field,
                "null",
                "must not be null",
            ));
        }
    }
    let wire: WireTheme = serde_json::from_str(json).map_err(|error| {
        ThemeError::syntax(source, error.line(), error.column(), error.to_string())
    })?;
    if wire.version.is_some_and(|version| version != 1) {
        return Err(ThemeError::field_value(
            source,
            "version",
            wire.version.unwrap(),
            "unsupported version; expected 1",
        ));
    }
    Ok((wire, object))
}
fn non_null(object: &serde_json::Map<String, serde_json::Value>, field: &str) -> bool {
    object.get(field).is_some_and(|value| !value.is_null())
}
fn profile(source: &str, value: &str) -> Result<Profile, ThemeError> {
    match value {
        "truecolor" => Ok(Profile::Truecolor),
        "ansi16" => Ok(Profile::Ansi16),
        "mono" => Ok(Profile::Mono),
        _ => Err(ThemeError::field_value(
            source,
            "profile",
            value,
            "expected truecolor, ansi16, or mono",
        )),
    }
}
fn role(source: &str, value: &str) -> Result<Role, ThemeError> {
    Role::parse(value)
        .ok_or_else(|| ThemeError::field_value(source, "colors", value, "unknown role"))
}
fn color(
    source: &str,
    role: &str,
    value: serde_json::Value,
    profile: Profile,
) -> Result<Color, ThemeError> {
    let rendered = value.to_string();
    let value = value
        .as_str()
        .ok_or_else(|| ThemeError::field_value(source, role, rendered, "expected a string"))?;
    let parsed = if value == "default" {
        Color::Reset
    } else if let Some(color) = ansi(value) {
        color
    } else if let Some(hex) = value.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ThemeError::field_value(
                source,
                role,
                value,
                "invalid color",
            ));
        }
        let byte = |range| {
            u8::from_str_radix(&hex[range], 16)
                .map_err(|_| ThemeError::field(source, role, format!("invalid color `{value}`")))
        };
        Color::Rgb(byte(0..2)?, byte(2..4)?, byte(4..6)?)
    } else {
        return Err(ThemeError::field_value(
            source,
            role,
            value,
            "invalid color",
        ));
    };
    if profile == Profile::Mono && parsed != Color::Reset {
        return Err(ThemeError::field_value(
            source,
            role,
            value,
            "mono only accepts `default`",
        ));
    }
    if profile == Profile::Ansi16 && matches!(parsed, Color::Rgb(..)) {
        return Err(ThemeError::field_value(
            source,
            role,
            value,
            "ansi16 does not accept RGB",
        ));
    }
    Ok(parsed)
}
fn ansi(value: &str) -> Option<Color> {
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

#[derive(Debug)]
pub(super) enum Source {
    Builtin(usize),
    File(PathBuf),
}

pub(super) fn resolve_source(
    value: &str,
    builtin_ids: &[&str],
    home: Option<&Path>,
) -> Result<Source, ThemeError> {
    if let Some(index) = builtin_ids.iter().position(|id| *id == value) {
        return Ok(Source::Builtin(index));
    }
    if explicit_path(value) {
        return expand_home(value, home).map(Source::File);
    }
    let home = home.ok_or_else(|| ThemeError::source(value, "home directory is unavailable"))?;
    Ok(Source::File(
        home.join(".flowlens")
            .join("themes")
            .join(format!("{value}.json")),
    ))
}

pub(super) fn explicit_path(value: &str) -> bool {
    Path::new(value).is_absolute()
        || value.contains(['/', '\\'])
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('~')
        || Path::new(value).extension().is_some()
}

pub(super) fn requires_home(value: &str) -> bool {
    !explicit_path(value) || home_relative(value).is_some()
}

fn expand_home(value: &str, home: Option<&Path>) -> Result<PathBuf, ThemeError> {
    if let Some(rest) = home_relative(value) {
        let home =
            home.ok_or_else(|| ThemeError::source(value, "home directory is unavailable"))?;
        Ok(home.join(rest))
    } else {
        Ok(PathBuf::from(value))
    }
}

fn home_relative(value: &str) -> Option<&str> {
    value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
}
