//! The shared model: one resolved package, however the lockfile spelled it.
//!
//! npm and pnpm describe the same fact — "version X of package Y will be installed from Z" — in six
//! different notations across the versions in scope. This module is the single shape everything
//! downstream sees, so the diff engine and the Action never branch on which package manager produced
//! the file.
//!
//! # Why the raw key is kept
//!
//! Every [`Package`] carries the lockfile key it came from. It is redundant with `name` and `version`
//! for a registry dependency and is deliberately kept anyway: when a report says "this dependency was
//! added", a maintainer needs to find the line in their own lockfile. A normalized name is not always
//! greppable — pnpm 5.4 writes `/@babel/code-frame/7.24.7` and pnpm 9.0 writes
//! `'@babel/code-frame@7.24.7'` for the same package.
//!
//! # Why identity is (name, version) rather than name
//!
//! One lockfile routinely resolves the same package at two versions. `npm install debug@4.3.4 ms@2.1.3`
//! produces `ms` at 2.1.3 at the tree root and `ms` at 2.1.2 nested under `debug` — verified, not
//! assumed; both fixtures in `tests/fixtures/` contain exactly that. Both are real installs that both
//! run their own install scripts. Keying on name alone would hide one of them, and hiding an install
//! that runs code is the failure direction this product cannot take.

use std::fmt;

/// Where a package's bytes come from.
///
/// # Why registry and tarball are one variant
///
/// npm records both a registry dependency and a direct tarball URL as a `resolved` URL plus an
/// `integrity` hash, with no field that distinguishes them. pnpm does distinguish, but only in some
/// versions and only for some source kinds. Inventing the distinction for npm would mean deciding it
/// from the URL's shape, which is a guess dressed as a fact — and the guess would be wrong in the
/// direction that matters, because calling `https://evil.example/x.tgz` a "registry dependency" is
/// exactly the reassurance this product must never manufacture.
///
/// So the parser reports what the file says: a URL and maybe a hash. A consumer holding the rule
/// catalog can ask whether the host is a registry; that question has an owner already
/// (`installscope_core::Catalog::is_registry_host`) and it is not this module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// Fetched over the network as a tarball.
    ///
    /// Covers a registry dependency, a direct tarball URL, and a git dependency that the package
    /// manager resolved to a tarball (pnpm does this for `github:` specifiers — verified against
    /// pnpm 5.4, 6.0 and 9.0 output).
    ///
    /// `url` is `None` for npm `lockfileVersion: 1` entries that predate `resolved`, and for pnpm
    /// registry entries, which record only the integrity hash and rely on the configured registry.
    Remote {
        /// Tarball URL, when the lockfile recorded one.
        url: Option<String>,
        /// Subresource integrity string (`sha512-…`), when the lockfile recorded one.
        integrity: Option<String>,
    },
    /// A git dependency the lockfile recorded as a git URL rather than resolving to a tarball.
    ///
    /// npm does this: `git+ssh://git@github.com/vercel/ms.git#1c6264b…`.
    Git {
        /// The git URL, normally including the resolved commit.
        url: String,
    },
    /// A directory on disk (`file:`), installed by copy or by symlink.
    Directory {
        /// The path as the lockfile recorded it, relative to the lockfile.
        path: String,
    },
    /// A workspace member linked into `node_modules`.
    ///
    /// Distinguished from [`Self::Directory`] because a workspace link is code from this repository
    /// rather than code arriving from outside it. A dependency-review tool that reported every
    /// workspace package as a new third-party dependency would cry wolf on every PR.
    Workspace {
        /// Path to the workspace member.
        path: String,
    },
    /// The lockfile said something this parser does not model.
    ///
    /// Carries the raw text rather than being dropped. An unrecognised source is still a package that
    /// will be installed and will run its scripts, so omitting it would under-report what a PR
    /// introduces — and it is classified [`Self::is_external`] for the same reason.
    Unknown {
        /// Whatever the lockfile did say.
        raw: String,
    },
}

impl Source {
    /// The integrity string, when this source has one.
    #[must_use]
    pub fn integrity(&self) -> Option<&str> {
        match self {
            Self::Remote { integrity, .. } => integrity.as_deref(),
            Self::Git { .. }
            | Self::Directory { .. }
            | Self::Workspace { .. }
            | Self::Unknown { .. } => None,
        }
    }

    /// The URL this source is fetched from, when it is fetched at all.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Remote { url, .. } => url.as_deref(),
            Self::Git { url } => Some(url),
            Self::Directory { .. } | Self::Workspace { .. } | Self::Unknown { .. } => None,
        }
    }

    /// True when installing this package fetches code from outside the repository.
    ///
    /// The question the lockfile-diff trigger actually asks. A workspace link and a `file:` directory
    /// are both the repository's own code; everything else arrives from elsewhere and is worth
    /// recording.
    #[must_use]
    pub const fn is_external(&self) -> bool {
        match self {
            // Unknown counts as external deliberately: under-recording a dependency that does run
            // code is worse than over-recording one that does not.
            Self::Remote { .. } | Self::Git { .. } | Self::Unknown { .. } => true,
            Self::Directory { .. } | Self::Workspace { .. } => false,
        }
    }

    /// Short label for reports.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Remote { .. } => "remote",
            Self::Git { .. } => "git",
            Self::Directory { .. } => "directory",
            Self::Workspace { .. } => "workspace",
            Self::Unknown { .. } => "unknown",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote { url: Some(url), .. } | Self::Git { url } => {
                write!(f, "{} {url}", self.kind())
            }
            Self::Remote { url: None, .. } => f.write_str("remote"),
            Self::Directory { path } | Self::Workspace { path } => {
                write!(f, "{} {path}", self.kind())
            }
            Self::Unknown { raw } => write!(f, "unknown {raw}"),
        }
    }
}

/// Which dependency group pulled a package in.
///
/// Recorded because a dev dependency still runs its install scripts in CI and on a developer's
/// machine, so it is in scope for recording — but a report that cannot tell the two apart cannot help
/// a maintainer judge blast radius.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Groups {
    /// Reachable only through the dev dependency graph.
    pub dev: bool,
    /// Installation is optional; a failure to install is not a failure to build.
    pub optional: bool,
}

impl Groups {
    /// A production, non-optional dependency.
    pub const PROD: Self = Self {
        dev: false,
        optional: false,
    };
}

impl fmt::Display for Groups {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.dev, self.optional) {
            (true, true) => f.write_str("dev, optional"),
            (true, false) => f.write_str("dev"),
            (false, true) => f.write_str("optional"),
            (false, false) => f.write_str("prod"),
        }
    }
}

/// One resolved package as a lockfile described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Package name as published, not as aliased.
    ///
    /// For `"ms-alias": "npm:ms@2.1.3"` this is `ms`, because `ms` is what gets downloaded and whose
    /// scripts run. The local name is preserved in [`Self::alias`].
    pub name: String,
    /// Resolved version.
    ///
    /// Empty when the lockfile did not record one — pnpm omits the version for a `file:` directory
    /// dependency in some versions. Empty rather than a placeholder, so a caller cannot mistake a
    /// fabricated value for a recorded one.
    pub version: String,
    /// The local name this package is installed under, when it differs from [`Self::name`].
    pub alias: Option<String>,
    /// Where the bytes come from.
    pub source: Source,
    /// Which dependency groups pulled it in.
    pub groups: Groups,
    /// True when the package declares an install script.
    ///
    /// `Some(false)` means the lockfile said there is none; `None` means the lockfile does not carry
    /// the information at all, which is the case for every pnpm version and for npm
    /// `lockfileVersion: 1`. The three states are distinct because "no install script" and "we cannot
    /// tell" support very different claims, and collapsing them would let the weaker one be read as
    /// the stronger.
    pub has_install_script: Option<bool>,
    /// The lockfile key this was parsed from, verbatim.
    pub key: String,
}

impl Package {
    /// The identity used for diffing: name and version.
    ///
    /// See the module docs for why the version is part of it.
    #[must_use]
    pub fn identity(&self) -> Identity {
        Identity {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }

    /// `name@version`, for display.
    #[must_use]
    pub fn label(&self) -> String {
        if self.version.is_empty() {
            self.name.clone()
        } else {
            format!("{}@{}", self.name, self.version)
        }
    }
}

/// A package identity: what to record, independent of where in the tree it sits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity {
    /// Published package name.
    pub name: String,
    /// Resolved version, or empty when the lockfile recorded none.
    pub version: String,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.version.is_empty() {
            f.write_str(&self.name)
        } else {
            write!(f, "{}@{}", self.name, self.version)
        }
    }
}

/// Which package manager produced a lockfile.
///
/// Two variants, permanently, until `Scope.md` says otherwise. Yarn, Poetry and Cargo are refused by
/// absence rather than by a runtime check: there is no variant to construct, so support cannot be
/// added by editing one match arm (`Scope.md`:41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// `package-lock.json`.
    Npm,
    /// `pnpm-lock.yaml`.
    Pnpm,
}

impl Ecosystem {
    /// Every ecosystem in scope, for callers that need to enumerate lockfile names.
    pub const ALL: &'static [Self] = &[Self::Npm, Self::Pnpm];

    /// The lockfile filename this ecosystem writes.
    #[must_use]
    pub const fn lockfile_name(self) -> &'static str {
        match self {
            Self::Npm => "package-lock.json",
            Self::Pnpm => "pnpm-lock.yaml",
        }
    }

    /// The package manager binary that consumes it.
    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
        }
    }

    /// Identifies an ecosystem from a lockfile path.
    ///
    /// Matches on the filename only, so a path in any directory works. Returns `None` for anything
    /// not in scope, which is what makes the trigger ignore a `yarn.lock` rather than mis-parse it.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
        Self::ALL
            .iter()
            .copied()
            .find(|ecosystem| ecosystem.lockfile_name() == file)
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.program())
    }
}

/// A parsed lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// Which package manager wrote it.
    pub ecosystem: Ecosystem,
    /// The `lockfileVersion` as it appeared, verbatim.
    ///
    /// Kept as text because npm writes a number (`3`) and pnpm writes a string (`'9.0'`), and a report
    /// that says "lockfileVersion 9" when the file says `'9.0'` is a small lie that costs trust.
    pub declared_version: String,
    /// Every package the lockfile resolves, sorted by key for deterministic output.
    pub packages: Vec<Package>,
}

impl Lockfile {
    /// Packages whose code arrives from outside this repository.
    #[must_use]
    pub fn external(&self) -> Vec<&Package> {
        self.packages
            .iter()
            .filter(|package| package.source.is_external())
            .collect()
    }

    /// Every entry for a package name.
    ///
    /// Plural because one lockfile can resolve the same name at several versions.
    #[must_use]
    pub fn entries_named(&self, name: &str) -> Vec<&Package> {
        self.packages
            .iter()
            .filter(|package| package.name == name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote() -> Source {
        Source::Remote {
            url: None,
            integrity: None,
        }
    }

    fn package(name: &str, version: &str, source: Source) -> Package {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            alias: None,
            source,
            groups: Groups::PROD,
            has_install_script: None,
            key: format!("node_modules/{name}"),
        }
    }

    #[test]
    fn only_workspace_and_directory_sources_are_internal() {
        // The classification the trigger depends on. Getting it backwards would either record the
        // repository's own code as a third-party dependency, or skip recording a real one.
        assert!(remote().is_external());
        assert!(Source::Git {
            url: "git+ssh://git@github.com/a/b.git#abc".to_string()
        }
        .is_external());
        assert!(Source::Unknown {
            raw: "???".to_string()
        }
        .is_external());

        assert!(!Source::Directory {
            path: "local-dir".to_string()
        }
        .is_external());
        assert!(!Source::Workspace {
            path: "packages/a".to_string()
        }
        .is_external());
    }

    #[test]
    fn only_remote_sources_carry_integrity() {
        assert_eq!(
            Source::Remote {
                url: Some("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz".to_string()),
                integrity: Some("sha512-abc".to_string()),
            }
            .integrity(),
            Some("sha512-abc")
        );
        assert_eq!(
            Source::Git {
                url: "git+ssh://x#abc".to_string()
            }
            .integrity(),
            None
        );
        assert_eq!(
            Source::Directory {
                path: "d".to_string()
            }
            .url(),
            None
        );
    }

    #[test]
    fn identity_includes_the_version() {
        // A lockfile that resolves ms at 2.1.2 and 2.1.3 describes two installs, not one.
        let older = package("ms", "2.1.2", remote());
        let newer = package("ms", "2.1.3", remote());
        assert_ne!(older.identity(), newer.identity());
        assert_eq!(newer.identity().to_string(), "ms@2.1.3");
    }

    #[test]
    fn an_alias_reports_the_published_name() {
        // `"ms-alias": "npm:ms@2.1.3"` downloads ms and runs ms's scripts. Reporting the alias as the
        // package name would make a finding untraceable to the package that caused it.
        let mut aliased = package("ms", "2.1.3", remote());
        aliased.alias = Some("ms-alias".to_string());
        assert_eq!(aliased.label(), "ms@2.1.3");
        assert_eq!(aliased.alias.as_deref(), Some("ms-alias"));
    }

    #[test]
    fn a_versionless_package_does_not_render_a_trailing_at() {
        // pnpm omits the version for some `file:` dependencies. "local-dir@" would look like a parse
        // bug in a report, and inventing "0.0.0" would be worse.
        let versionless = package(
            "local-dir",
            "",
            Source::Directory {
                path: "local-dir".to_string(),
            },
        );
        assert_eq!(versionless.label(), "local-dir");
        assert_eq!(versionless.identity().to_string(), "local-dir");
    }

    #[test]
    fn install_script_knowledge_has_three_states() {
        // "declares no install script" and "the lockfile does not say" support different claims.
        let mut subject = package("ms", "2.1.3", remote());
        assert_eq!(subject.has_install_script, None);
        subject.has_install_script = Some(false);
        assert_eq!(subject.has_install_script, Some(false));
        assert_ne!(subject.has_install_script, None);
    }

    #[test]
    fn groups_render_readably() {
        assert_eq!(Groups::PROD.to_string(), "prod");
        assert_eq!(
            Groups {
                dev: true,
                optional: false
            }
            .to_string(),
            "dev"
        );
        assert_eq!(
            Groups {
                dev: false,
                optional: true
            }
            .to_string(),
            "optional"
        );
        assert_eq!(
            Groups {
                dev: true,
                optional: true
            }
            .to_string(),
            "dev, optional"
        );
    }

    #[test]
    fn ecosystems_are_recognised_by_filename_in_any_directory() {
        assert_eq!(
            Ecosystem::from_path("package-lock.json"),
            Some(Ecosystem::Npm)
        );
        assert_eq!(
            Ecosystem::from_path("apps/web/package-lock.json"),
            Some(Ecosystem::Npm)
        );
        assert_eq!(
            Ecosystem::from_path("pnpm-lock.yaml"),
            Some(Ecosystem::Pnpm)
        );
        assert_eq!(
            Ecosystem::from_path(r"apps\web\pnpm-lock.yaml"),
            Some(Ecosystem::Pnpm)
        );
    }

    #[test]
    fn out_of_scope_lockfiles_are_not_recognised() {
        // Scope.md:41 refuses yarn, poetry and cargo in v1. The trigger must ignore them rather than
        // try to parse them, because a half-working parser is worse than none.
        for path in [
            "yarn.lock",
            "poetry.lock",
            "Cargo.lock",
            "bun.lockb",
            "package.json",
            "package-lock.json.bak",
            "not-a-package-lock.json",
        ] {
            assert_eq!(
                Ecosystem::from_path(path),
                None,
                "{path} must not be treated as an in-scope lockfile"
            );
        }
    }

    #[test]
    fn external_filters_out_repository_code() {
        let lockfile = Lockfile {
            ecosystem: Ecosystem::Npm,
            declared_version: "3".to_string(),
            packages: vec![
                package("ms", "2.1.3", remote()),
                package(
                    "local-a",
                    "0.1.0",
                    Source::Workspace {
                        path: "packages/local-a".to_string(),
                    },
                ),
            ],
        };
        let external = lockfile.external();
        assert_eq!(external.len(), 1);
        assert_eq!(external[0].name, "ms");
        assert_eq!(lockfile.entries_named("local-a").len(), 1);
    }
}
