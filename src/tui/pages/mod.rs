//! TUI page renderers.

pub(super) mod about;
pub(super) mod detail;
pub(super) mod domains;
pub(super) mod ips;
pub(super) mod overview;
pub(super) mod processes;
pub(super) mod settings;

pub(super) use about::*;
pub(super) use detail::*;
pub(super) use domains::*;
pub(super) use ips::*;
pub(super) use overview::*;
pub(super) use processes::*;
pub(super) use settings::*;
