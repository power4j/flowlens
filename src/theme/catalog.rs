use super::{Theme, ThemeError, resolve::parse_complete};

pub(super) struct Entry {
    pub(super) id: &'static str,
    pub(super) json: &'static str,
}

const ENTRIES: [Entry; 4] = [
    Entry {
        id: "dark",
        json: include_str!("../../themes/dark.json"),
    },
    Entry {
        id: "signal-deck",
        json: include_str!("../../themes/signal-deck.json"),
    },
    Entry {
        id: "ansi16",
        json: include_str!("../../themes/ansi16.json"),
    },
    Entry {
        id: "mono",
        json: include_str!("../../themes/mono.json"),
    },
];

pub(super) fn builtins() -> Result<Vec<(&'static str, Theme)>, ThemeError> {
    builtins_from(&ENTRIES)
}

pub(super) fn builtins_from(entries: &[Entry]) -> Result<Vec<(&'static str, Theme)>, ThemeError> {
    for (index, entry) in entries.iter().enumerate() {
        if entry.id.is_empty() {
            return Err(ThemeError::field_value(
                "catalog",
                "id",
                entry.id,
                "must not be empty",
            ));
        }
        if entry.id == "auto" {
            return Err(ThemeError::field_value(
                "catalog",
                "id",
                entry.id,
                "reserved for automatic selection",
            ));
        }
        if entry_index(&entries[..index], entry.id).is_some() {
            return Err(ThemeError::field_value(
                "catalog",
                "id",
                entry.id,
                "duplicate ID",
            ));
        }
    }
    entries
        .iter()
        .map(|entry| parse_complete(entry.id, entry.json).map(|theme| (entry.id, theme)))
        .collect()
}

pub(super) fn builtin_index(builtins: &[(&'static str, Theme)], id: &str) -> Option<usize> {
    builtins
        .iter()
        .position(|(builtin_id, _)| *builtin_id == id)
}

fn entry_index(entries: &[Entry], id: &str) -> Option<usize> {
    entries.iter().position(|entry| entry.id == id)
}
