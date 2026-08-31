//! `InstallScope` recorder — backends that turn a real install into a schema v1 event stream.
//!
//! Phase 1 ships the strace backend (`Architecture.md`:35); Phase 2 adds aya, now that G1 has
//! passed.
//!
//! # Layering
//!
//! [`decode`], [`fdtable`], [`parser`], and [`session`] are **pure**: no I/O, no process control, no
//! platform assumptions. They compile and are tested on any host. Only [`strace`] spawns processes
//! and is therefore Linux-only.
//!
//! That split is deliberate. The parser is where correctness lives, so it must be testable
//! everywhere — including the Windows machine this was written on, where the recorder cannot run.
//!
//! # `Rules.md` constraints enforced here
//! - typed errors via `thiserror`, no `anyhow` (§2);
//! - no `.unwrap()`/`.expect()` outside tests, denied by lint (§2);
//! - a dead recording surfaces as PARTIAL, never as silence (§2) — see [`session`];
//! - no LLM, cloud, or telemetry dependency (§1).

// `unsafe` is denied rather than forbidden, so the aya backend can opt in with an explicit
// `#[allow]` and a safety comment per block. `forbid` cannot be overridden, and reading a
// `#[repr(C)]` record out of a perf buffer genuinely requires a pointer cast — there is no safe
// equivalent. Every other module in this crate remains unsafe-free, and the exception is one
// module wide rather than crate wide.
#![deny(unsafe_code)]
// Rules.md §2 bans unwrap/expect in *non-test* code; in tests a panic is the correct response to a
// broken invariant.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

pub mod clock;
pub mod decode;
pub mod fdtable;
pub mod merge;
pub mod parity;
pub mod parser;
pub mod session;
pub mod translate;

#[cfg(target_os = "linux")]
pub mod strace;

/// The aya eBPF backend. Requires Linux, the `aya-backend` feature, and a compiled eBPF object.
#[cfg(all(target_os = "linux", feature = "aya-backend"))]
pub mod aya;

pub use merge::{MergeStats, Merged, Merger};
pub use parser::{ParseStats, Parser, DEFAULT_EVENT_CAP};
pub use session::{summarize_stream, SessionWriter, StreamSummary};

/// Version stamped into every `session_start` event, so a recording always says what produced it.
pub const AGENT_VERSION: &str = concat!("installscope-recorder-", env!("CARGO_PKG_VERSION"));

/// Errors specific to running a recorder backend.
#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    /// The backend binary is not installed. Actionable message, because this is the most common
    /// first-run failure.
    #[error("{tool} not found on PATH; install it (Debian/Ubuntu: `apt-get install {tool}`)")]
    BackendMissing {
        /// The missing executable.
        tool: &'static str,
    },

    /// The command to record was empty.
    #[error("no command given to record")]
    EmptyCommand,

    /// Spawning the backend or the traced command failed.
    #[error("failed to spawn {what}: {source}")]
    Spawn {
        /// What was being spawned.
        what: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// I/O against the trace directory or event stream failed.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// The path involved.
        path: std::path::PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The backend produced no trace output at all, so nothing was recorded. Distinct from "recorded
    /// nothing interesting": this is a recorder failure and must render as PARTIAL.
    #[error("{backend} produced no trace output; nothing was recorded")]
    NoTraceOutput {
        /// Which backend produced nothing.
        backend: &'static str,
    },

    /// A core-level failure (serialization, schema) bubbled up.
    #[error(transparent)]
    Core(#[from] installscope_core::CoreError),

    /// This platform has no recorder backend. v1 is Linux-only by design (Scope.md:25); macOS and
    /// Windows are deferred with explicit promotion triggers (Scope.md:51-52).
    #[error(
        "recording is only supported on Linux in v1; see Scope.md for the macOS/Windows triggers"
    )]
    UnsupportedPlatform,
}

impl RecorderError {
    /// Attaches a path to an [`std::io::Error`].
    pub fn io(path: impl Into<std::path::PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Convenience alias for recorder operations.
pub type Result<T> = std::result::Result<T, RecorderError>;
