//! Lockfile parsing and diffing — the trigger that decides whether anything gets recorded.
//!
//! PRD.md:30 calls the lockfile-diff trigger the adoption unlock: no habit change, no wrapped
//! commands, no daemon. It fires exactly when a pull request changes which packages will be installed.
//! This crate answers that question and nothing else.
//!
//! ```text
//! before.json ──┐
//!               ├──▶ parse ──▶ Lockfile ──┐
//! after.json  ──┘                         ├──▶ diff ──▶ LockfileDiff ──▶ should_record()
//!                                         │
//!                        (same shape for npm and pnpm)
//! ```
//!
//! # Two ecosystems, permanently
//!
//! `Scope.md`:26 puts npm and pnpm in v1 and `Scope.md`:41 refuses Yarn, Poetry and Cargo — "four
//! parsers in v1 = four half-finished ones". That is enforced structurally rather than by a check:
//! [`Ecosystem`] has two variants, so support for a third cannot be added by editing one match arm.
//!
//! # Why the parsers are strict
//!
//! A parser that skips what it does not understand reports a smaller dependency set than the one that
//! will be installed. That is the same failure shape as a recorder dying silently (PRD.md:58): the
//! output looks clean because evidence is missing. So an unknown `lockfileVersion` is an error, a
//! malformed file is an error, and a source this crate does not model becomes
//! [`Source::Unknown`] — which is classified as external, so it still gets recorded.
//!
//! # Why the formats were verified rather than remembered
//!
//! Every fixture under `tests/fixtures/` is real output from a real package manager, and three of the
//! formats do something a reader would not predict. npm `lockfileVersion: 1` hides an alias in the
//! *version* field. npm records a `file:` dependency as two entries that must be merged. pnpm resolves
//! `github:` specifiers to a codeload tarball URL and then uses that URL as the package key, so the
//! key contains `@` and `/` and cannot be split naively. `Rules.md` §5 asks for verified claims over
//! confident-looking ones; `tests/fixtures/README.md` records how each file was generated.

#![forbid(unsafe_code)]
// Rules.md §2 bans unwrap/expect in non-test code.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

pub mod diff;
pub mod error;
pub mod model;
pub mod npm;
pub mod pnpm;

pub use diff::{diff, Change, LockfileDiff};
pub use error::{LockfileError, Result};
pub use model::{Ecosystem, Groups, Identity, Lockfile, Package, Source};

/// Parses a lockfile, choosing the parser from the filename.
///
/// # Errors
/// [`LockfileError::UnsupportedEcosystem`] when the filename is not one of the two in scope, and
/// otherwise whatever the chosen parser reports.
pub fn parse(path: &str, text: &str) -> Result<Lockfile> {
    match Ecosystem::from_path(path) {
        Some(Ecosystem::Npm) => npm::parse(text),
        Some(Ecosystem::Pnpm) => pnpm::parse(text),
        None => Err(LockfileError::UnsupportedEcosystem {
            path: path.to_string(),
        }),
    }
}

/// Reads and parses a lockfile from disk.
///
/// # Errors
/// [`LockfileError::Io`] when the file cannot be read, and otherwise as [`parse`].
pub fn load(path: &std::path::Path) -> Result<Lockfile> {
    let text = std::fs::read_to_string(path).map_err(|source| LockfileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let name = path.to_str().unwrap_or_default();
    parse(name, &text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parser_is_chosen_by_filename() {
        let npm = parse(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"x"}}}"#,
        )
        .expect("npm parse");
        assert_eq!(npm.ecosystem, Ecosystem::Npm);

        let pnpm =
            parse("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\n").expect("pnpm parse");
        assert_eq!(pnpm.ecosystem, Ecosystem::Pnpm);
    }

    #[test]
    fn an_out_of_scope_lockfile_is_refused_by_name() {
        // Scope.md:41. Refusing loudly beats attempting a parse that would half-work.
        let err = parse("yarn.lock", "whatever").expect_err("must refuse");
        match err {
            LockfileError::UnsupportedEcosystem { path } => assert_eq!(path, "yarn.lock"),
            other => panic!("expected UnsupportedEcosystem, got {other}"),
        }
    }

    #[test]
    fn a_lockfile_in_a_subdirectory_is_still_recognised() {
        // Monorepos put lockfiles under apps/ and packages/. Matching on the full path would miss them.
        let parsed = parse(
            "apps/web/package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"x"}}}"#,
        )
        .expect("parse");
        assert_eq!(parsed.ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn a_missing_file_names_the_path_it_tried() {
        // "No such file or directory" with no path is a support ticket rather than a diagnostic.
        let err = load(std::path::Path::new(
            "definitely/not/here/package-lock.json",
        ))
        .expect_err("must fail");
        assert!(
            err.to_string().contains("definitely/not/here"),
            "the error must name the path: {err}"
        );
    }
}
