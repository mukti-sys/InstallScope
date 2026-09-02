//! Typed errors for lockfile parsing.
//!
//! Every variant names what was wrong and where. A dependency review that fails with "invalid
//! lockfile" tells a maintainer nothing they can act on, and the alternative — parsing what can be
//! parsed and silently dropping the rest — would under-report what a PR introduces. So parsing is
//! strict and its failures are specific.

/// Why a lockfile could not be parsed.
#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    /// A `package-lock.json` was not valid JSON, or was JSON of the wrong shape.
    #[error("package-lock.json is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A `pnpm-lock.yaml` was not valid YAML, or was YAML of the wrong shape.
    #[error("pnpm-lock.yaml is not valid YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// The file declares a `lockfileVersion` this build does not know how to read.
    ///
    /// Refused rather than parsed on a best-effort basis. A future format may give an existing key a
    /// new meaning, and a report built on a misread key would be confidently wrong — the one output
    /// this product cannot produce.
    #[error(
        "{ecosystem} lockfileVersion {found} is not supported; this build reads {supported}. \
         Parsing it anyway risks misreading the dependency set, so it is refused."
    )]
    UnsupportedVersion {
        /// Which package manager the file came from.
        ecosystem: crate::model::Ecosystem,
        /// The version string as it appeared.
        found: String,
        /// What this build does support, for the error message.
        supported: &'static str,
    },

    /// The file parsed but had no `lockfileVersion` at all.
    ///
    /// Not defaulted to anything. The version determines how every key in the file is interpreted, so
    /// guessing it would mean guessing the dependency set.
    #[error("{ecosystem} lockfile has no lockfileVersion field; the format cannot be determined")]
    MissingVersion {
        /// Which package manager the file was expected to come from.
        ecosystem: crate::model::Ecosystem,
    },

    /// A structural expectation the format guarantees was not met.
    #[error("{ecosystem} lockfile (version {version}) is malformed at {location}: {detail}")]
    Malformed {
        /// Which package manager the file came from.
        ecosystem: crate::model::Ecosystem,
        /// Declared lockfile version, since the expectation depends on it.
        version: String,
        /// Where in the file, as a key path.
        location: String,
        /// What was expected instead.
        detail: String,
    },

    /// The path given is not a lockfile this build reads.
    ///
    /// `Scope.md`:41 refuses Yarn, Poetry and Cargo in v1. Refusing by name is the point: a
    /// half-working parser for a fourth format is worse than no parser at all.
    #[error(
        "{path} is not an in-scope lockfile. v1 reads package-lock.json and pnpm-lock.yaml only \
         (Scope.md:26)."
    )]
    UnsupportedEcosystem {
        /// The path that was offered.
        path: String,
    },

    /// I/O reading a lockfile from disk.
    #[error("cannot read lockfile at {path}: {source}")]
    Io {
        /// The path attempted.
        path: std::path::PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience alias for this crate.
pub type Result<T> = std::result::Result<T, LockfileError>;
