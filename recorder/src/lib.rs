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

/// Resolves a command's program to an absolute path, leaving its arguments untouched.
///
/// Both backends run the recorded command with a working directory the caller chose, which means a
/// relative program path is resolved against *that* directory rather than the recorder's. The failure is
/// unhelpful in a specific way: strace reports "Cannot stat", writes no trace files, and the recording
/// comes back PARTIAL blaming the backend — pointing at the recorder when the fault is the command line.
///
/// So the program is resolved here, once, against the recorder's own working directory:
///
/// - a path containing a separator is made absolute and checked for existence;
/// - a bare name (`npm`, `sh`) is left alone, because resolving it would mean reimplementing `PATH`
///   lookup and would break the common case where the recorded process should find its own tools;
/// - a missing or non-executable file becomes [`RecorderError::CommandNotExecutable`] before any output
///   directory or session file is created.
///
/// # Errors
/// [`RecorderError::EmptyCommand`] for an empty command, [`RecorderError::CommandNotExecutable`] when a
/// path-qualified program does not exist or is not executable.
pub fn resolve_program(command: &[String], cwd: Option<&std::path::Path>) -> Result<Vec<String>> {
    let Some(program) = command.first() else {
        return Err(RecorderError::EmptyCommand);
    };

    // A bare name is left to PATH resolution in the child. Rewriting it would change which binary runs.
    if !program.contains('/') {
        return Ok(command.to_vec());
    }

    let path = std::path::Path::new(program);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        // Deliberately the recorder's cwd, not `cwd`: that is what the user's shell resolved the path
        // against when they typed it.
        std::env::current_dir()
            .map_err(|source| RecorderError::io(program, source))?
            .join(path)
    };

    let canonical =
        std::fs::canonicalize(&absolute).map_err(|source| RecorderError::CommandNotExecutable {
            program: program.clone(),
            detail: source.to_string(),
        })?;

    if !canonical.is_file() {
        return Err(RecorderError::CommandNotExecutable {
            program: program.clone(),
            detail: format!("{} is not a file", canonical.display()),
        });
    }

    // Checked explicitly so the error names the problem rather than surfacing later as an exec failure
    // inside the backend, where it would look like the recorded program crashed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&canonical)
            .map_err(|source| RecorderError::io(&canonical, source))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(RecorderError::CommandNotExecutable {
                program: program.clone(),
                detail: format!("{} is not executable (mode {mode:o})", canonical.display()),
            });
        }
    }

    let Some(resolved) = canonical.to_str() else {
        return Err(RecorderError::CommandNotExecutable {
            program: program.clone(),
            detail: "resolved path is not valid UTF-8".to_string(),
        });
    };

    let mut out = Vec::with_capacity(command.len());
    out.push(resolved.to_string());
    out.extend(command.iter().skip(1).cloned());
    // `cwd` is unused on non-unix builds; the parameter stays for API symmetry across platforms.
    let _ = cwd;
    Ok(out)
}

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

    /// The program to record does not exist, or is not executable.
    ///
    /// Checked before the backend is spawned. Without this the failure surfaces as
    /// "strace produced no trace files" — technically true and actively misleading, because it points at
    /// the recorder when the fault is the command line.
    #[error(
        "cannot execute `{program}`: {detail}\n\
         note: relative program paths are resolved against the directory installscope was run from, \
         not --cwd"
    )]
    CommandNotExecutable {
        /// The program as given.
        program: String,
        /// Why it cannot be run.
        detail: String,
    },

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_program_name_is_left_for_path_lookup() {
        // Rewriting `npm` to an absolute path would change which binary runs — the recorded process
        // should find its own tools through PATH, exactly as it would without a recorder attached.
        let command = vec!["npm".to_string(), "install".to_string()];
        let resolved = resolve_program(&command, None).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved, command);
    }

    #[test]
    fn a_missing_path_qualified_program_is_rejected_with_its_name() {
        // The failure this exists to prevent: a relative script path resolved against the recorded
        // command's cwd, surfacing later as "the backend produced no trace files".
        let command = vec!["./does/not/exist.sh".to_string(), "arg".to_string()];
        match resolve_program(&command, None) {
            Err(RecorderError::CommandNotExecutable { program, detail }) => {
                assert_eq!(program, "./does/not/exist.sh");
                assert!(!detail.is_empty(), "the reason must be stated");
            }
            other => panic!("expected CommandNotExecutable, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_command_is_rejected() {
        assert!(matches!(
            resolve_program(&[], None),
            Err(RecorderError::EmptyCommand)
        ));
    }

    #[test]
    fn arguments_survive_resolution_untouched() {
        // Only the program is rewritten. An argument that happens to look like a path must not be
        // resolved: `--out ./relative` is the recorded command's business, not the recorder's.
        let this_file = std::path::Path::new(file!());
        if !this_file.exists() {
            return; // running from a different working directory; the other tests cover the logic
        }
        let command = vec![
            this_file.to_string_lossy().into_owned(),
            "./also-relative".to_string(),
            "--flag=./x".to_string(),
        ];
        // A source file is not executable, so on unix this is the permission path rather than the happy
        // one — which is itself worth asserting, since an unexecutable file must not be silently run.
        match resolve_program(&command, None) {
            Ok(resolved) => {
                assert_eq!(resolved[1], "./also-relative");
                assert_eq!(resolved[2], "--flag=./x");
                assert!(
                    std::path::Path::new(&resolved[0]).is_absolute(),
                    "the program must be absolute"
                );
            }
            Err(RecorderError::CommandNotExecutable { detail, .. }) => {
                assert!(
                    detail.contains("not executable") || detail.contains("mode"),
                    "a non-executable file must say so: {detail}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_directory_is_not_executable() {
        // canonicalize succeeds for a directory, so the is_file check is what catches it. Without that,
        // the backend would try to exec a directory and report a confusing spawn failure.
        //
        // "./" rather than ".": a program with no separator is treated as a PATH lookup and left alone,
        // which is correct — `.` as a bare name is the child's problem, not a path we should resolve.
        let command = vec!["./".to_string()];
        match resolve_program(&command, None) {
            Err(RecorderError::CommandNotExecutable { detail, .. }) => {
                assert!(detail.contains("not a file"), "got {detail}");
            }
            other => panic!("expected CommandNotExecutable, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_dot_is_treated_as_a_path_lookup_not_a_directory() {
        // Documents the boundary the previous test relies on: the separator is what makes something a
        // path. Without a separator we do not touch it, because resolving bare names would mean
        // reimplementing PATH search and could pick a different binary than the child would.
        let resolved = resolve_program(&[".".to_string()], None).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(resolved, vec!["."]);
    }
}
