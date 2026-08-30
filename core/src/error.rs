//! Typed errors for the `InstallScope` core and recorder.
//!
//! `Rules.md` §2: `thiserror` in libraries, `anyhow` only at the CLI boundary. Nothing in this crate
//! or the recorder uses `.unwrap()`/`.expect()` outside tests, and clippy denies both.

use std::path::PathBuf;

/// Errors that can occur while modelling, serializing, or reading events.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A JSONL line was not valid JSON, or was valid JSON of the wrong shape.
    #[error("malformed event on line {line}: {source}")]
    MalformedEvent {
        /// 1-based line number within the stream.
        line: usize,
        /// The underlying deserialization failure.
        #[source]
        source: serde_json::Error,
    },

    /// The stream declares a schema version this build does not understand. Refusing is deliberate:
    /// silently reinterpreting an unknown schema would produce confident wrong evidence.
    #[error("unsupported schema_version {found}; this build understands {supported}")]
    UnsupportedSchemaVersion {
        /// Version found in the stream.
        found: u32,
        /// Version this build supports.
        supported: u32,
    },

    /// A recording ended without a `session_end` event, so its completeness cannot be established.
    /// The caller must render this as PARTIAL rather than as a clean result (Rules.md §2).
    #[error("recording has no session_end event; completeness unknown, must render as PARTIAL")]
    MissingSessionEnd,

    /// Serializing an event failed.
    #[error("failed to serialize event: {0}")]
    Serialize(#[from] serde_json::Error),

    /// I/O against an event stream or session directory failed.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// The path being read or written.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

impl CoreError {
    /// Attaches a path to an [`std::io::Error`], because "No such file or directory" without the
    /// path is a support ticket rather than a diagnostic.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Convenience alias used throughout the core crate.
pub type Result<T> = std::result::Result<T, CoreError>;
