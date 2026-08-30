//! `InstallScope` core — the event model and typed errors shared by every recorder backend.
//!
//! **The flight recorder for package installs.** This crate is the schema authority
//! (`Architecture.md` §3) and deliberately contains no I/O, no network, and no process control, so
//! both the strace backend (Phase 1) and the aya backend (Phase 2) produce byte-identical streams
//! for the same observations.
//!
//! `Rules.md` constraints enforced here by lint, not by convention:
//! - no LLM, cloud, or telemetry dependency anywhere (§1) — this crate depends only on `serde` and
//!   `thiserror`;
//! - no `.unwrap()` / `.expect()` outside tests (§2);
//! - typed errors via `thiserror`, never `anyhow` (§2).

#![forbid(unsafe_code)]
// Rules.md §2 bans unwrap/expect in *non-test* code. Tests are where a panic is the correct
// response to a broken invariant, so the deny is scoped rather than blanket.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
// Every public enum here is a wire format that will grow variants; callers are expected to match
// exhaustively today and update deliberately when the schema version bumps.
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod events;

pub use error::{CoreError, Result};
pub use events::{
    AddrFamily, Backend, DnsQuery, Event, EventMeta, FsRead, FsWrite, Heartbeat, HostInfo,
    IncompleteReason, NetConnect, Outcome, PathOrigin, Payload, ProcSpawn, SessionEnd,
    SessionStart, TracedPath, WriteKind, Zones, SCHEMA_VERSION,
};
