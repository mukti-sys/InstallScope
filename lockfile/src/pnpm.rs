//! `pnpm-lock.yaml` — `lockfileVersion` 5.x, 6.0 and 9.0.
//!
//! # Three key notations for the same package
//!
//! | Declared version | pnpm | Package key |
//! |---|---|---|
//! | `5.x` | 7 | `/ms/2.1.2` |
//! | `'6.0'` | 8 | `/ms@2.1.2` |
//! | `'9.0'` | 9–10 | `ms@2.1.2` |
//!
//! All three verified against real output in `tests/fixtures/pnpm/`. There is no `7.0` or `8.0`
//! lockfile format: pnpm 8 writes `'6.0'` and pnpm 9 writes `'9.0'`, so the version numbering skips.
//! That gap is why the parser matches on the declared version rather than inferring the shape.
//!
//! # Peer suffixes are part of the key, not part of the version
//!
//! `debug@4.3.4(supports-color@9.4.0)` in 6.0/9.0, and `debug/4.3.4_supports-color@9.4.0` in 5.x, both
//! describe **debug at 4.3.4**. The suffix records which peer it was resolved against. Reading it as
//! part of the version would report a version that does not exist on the registry, and two PRs that
//! changed only a peer would look like they changed the package.
//!
//! # A git dependency's key can *be* a URL
//!
//! pnpm resolves `github:vercel/ms#2.1.3` to a codeload tarball, and 9.0 keys it
//! `ms@https://codeload.github.com/vercel/ms/tar.gz/<sha>`. The key therefore contains `@`, `/` and
//! `:`. Splitting on the last `@` — the obvious approach for `ms@2.1.2` — produces garbage here, so
//! the URL forms are detected first. 5.x/6.0 instead key it `github.com/vercel/ms/<sha>` and put the
//! name in a separate `name:` field.
//!
//! # `dev: false` does not mean "not a dev dependency"
//!
//! In 5.x/6.0 it means "reachable from a production dependency". A package reachable from both graphs
//! is written `dev: false`. Crucially, 9.0 has **no per-package `dev` key at all** — treating a
//! missing key as production would silently misreport every dev dependency in every modern pnpm
//! repository as production. So for 9.0 the groups are derived by walking the `importers` sections,
//! and `tests/fixtures/pnpm/v9-groups.yaml` sits next to `v6-groups.yaml` with identical inputs to
//! keep the two paths honest.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_yaml::Value;

use crate::error::{LockfileError, Result};
use crate::model::{Ecosystem, Groups, Lockfile, Package, Source};

/// Lockfile versions this parser reads.
const SUPPORTED: &str = "5.x, 6.0, 9.0";

/// Which notation a declared version uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// `5.x`: keys are `/name/version`, peer suffix after `_`.
    V5,
    /// `'6.0'`: keys are `/name@version`, peer suffix in parentheses.
    V6,
    /// `'9.0'`: keys are `name@version`, groups live in `importers`.
    V9,
}

/// The subset of the file this parser needs.
#[derive(Debug, Deserialize)]
struct Raw {
    /// A number in 5.x (`5.4`) and a string in 6.0/9.0 (`'6.0'`), so it is read untyped.
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<Value>,
    #[serde(default)]
    packages: BTreeMap<String, RawPackage>,
    /// 9.0 only. Carries the per-package `optional` flag that moved out of `packages`.
    #[serde(default)]
    snapshots: BTreeMap<String, RawSnapshot>,
    /// Present in 9.0 always, and in 5.x/6.0 only for a workspace.
    #[serde(default)]
    importers: BTreeMap<String, RawImporter>,
    /// Single-project 5.x/6.0 put the root importer's groups at the top level instead.
    #[serde(default)]
    dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, Value>,
}

/// An entry in `packages`.
#[derive(Debug, Deserialize)]
struct RawPackage {
    /// Present when the key does not carry it: a `file:` or git entry in 5.x/6.0.
    name: Option<String>,
    /// Present for a git or directory entry whose key has no version.
    version: Option<String>,
    #[serde(default)]
    resolution: Resolution,
    /// 5.x/6.0 only. See the module docs on what `false` means.
    dev: Option<bool>,
    #[serde(default)]
    optional: bool,
}

/// An entry in `snapshots` (9.0).
#[derive(Debug, Deserialize)]
struct RawSnapshot {
    #[serde(default)]
    optional: bool,
}

/// How a package's bytes are located.
#[derive(Debug, Default, Deserialize)]
struct Resolution {
    /// Registry packages carry only this.
    integrity: Option<String>,
    /// A direct tarball, including the codeload URL pnpm resolves `github:` to.
    tarball: Option<String>,
    /// A `file:` directory dependency.
    directory: Option<String>,
    /// `directory`, `git`, or absent for a registry package.
    #[serde(rename = "type")]
    kind: Option<String>,
    /// A git resolution that was not turned into a tarball.
    repo: Option<String>,
    /// The resolved commit, alongside `repo`.
    commit: Option<String>,
}

/// One workspace member, or the root project.
#[derive(Debug, Deserialize)]
struct RawImporter {
    #[serde(default)]
    dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, Value>,
}

/// Parses a `pnpm-lock.yaml`.
///
/// # Errors
/// [`LockfileError::Yaml`] when the text is not valid YAML, [`LockfileError::MissingVersion`] when it
/// declares no `lockfileVersion`, and [`LockfileError::UnsupportedVersion`] for a version outside
/// [`SUPPORTED`] — including the 7.x and 8.x numbers that no pnpm release ever wrote.
pub fn parse(text: &str) -> Result<Lockfile> {
    let raw: Raw = serde_yaml::from_str(text)?;

    let declared = raw.lockfile_version.as_ref().and_then(version_text).ok_or(
        LockfileError::MissingVersion {
            ecosystem: Ecosystem::Pnpm,
        },
    )?;
    let dialect = dialect_of(&declared).ok_or_else(|| LockfileError::UnsupportedVersion {
        ecosystem: Ecosystem::Pnpm,
        found: declared.clone(),
        supported: SUPPORTED,
    })?;

    // 9.0 dropped the per-package dev flag, so the graph roots are the only source of group
    // information. Built for every dialect because it is cheap and keeps the code path single.
    let graph = importer_graph(&raw);

    let mut packages = Vec::with_capacity(raw.packages.len());
    for (key, entry) in &raw.packages {
        let parsed = split_key(key, dialect).ok_or_else(|| LockfileError::Malformed {
            ecosystem: Ecosystem::Pnpm,
            version: declared.clone(),
            location: format!("packages[{key:?}]"),
            detail:
                "the key is not in any notation this lockfile version uses, so the package name \
                     cannot be determined"
                    .to_string(),
        })?;

        // The `name:`/`version:` fields win when present: they are what pnpm writes precisely for the
        // keys that do not carry the information.
        let name = entry.name.clone().unwrap_or(parsed.name);
        let version = entry.version.clone().or(parsed.version).unwrap_or_default();

        let source = source_of(entry, parsed.raw_source.as_deref());
        let groups = groups_of(entry, &raw, dialect, &name, &version, key, &graph);

        packages.push(Package {
            name,
            version,
            // pnpm records the alias in the importer's `specifier`, not on the package, so the
            // package entry itself cannot say. Left None rather than guessed: an alias attributed to
            // the wrong package would make a finding untraceable.
            alias: None,
            source,
            groups,
            // No pnpm version records this.
            has_install_script: None,
            key: key.clone(),
        });
    }

    packages.sort_by(|a, b| a.key.cmp(&b.key).then(a.name.cmp(&b.name)));
    Ok(Lockfile {
        ecosystem: Ecosystem::Pnpm,
        declared_version: declared,
        packages,
    })
}

/// Renders the `lockfileVersion` node as text, whether YAML typed it as a number or a string.
fn version_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Maps a declared version onto its notation.
///
/// Only the versions that exist are accepted. 7.x and 8.x are refused rather than guessed at: no pnpm
/// release writes them, so a file claiming one is either corrupt or from a future format, and both
/// deserve an error rather than a best-effort parse.
fn dialect_of(declared: &str) -> Option<Dialect> {
    let major = declared.split('.').next()?;
    match major {
        "5" => Some(Dialect::V5),
        "6" => Some(Dialect::V6),
        "9" => Some(Dialect::V9),
        _ => None,
    }
}

/// What a package key yielded.
struct ParsedKey {
    name: String,
    version: Option<String>,
    /// The URL or path portion, when the key encodes one.
    raw_source: Option<String>,
}

/// Splits a `packages` key into a name and version.
///
/// The URL and path forms are checked before the `name@version` split, because their text contains
/// both `@` and `/` and a naive split produces nonsense from them.
fn split_key(key: &str, dialect: Dialect) -> Option<ParsedKey> {
    // `file:local-dir` (5.x/6.0) and `local-dir@file:local-dir` (9.0).
    if let Some(path) = key.strip_prefix("file:") {
        return Some(ParsedKey {
            // 5.x/6.0 carry the name in a separate field; this is the fallback if it is absent.
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            version: None,
            raw_source: Some(path.to_string()),
        });
    }
    if let Some((name, rest)) = key.split_once("@file:") {
        return Some(ParsedKey {
            name: name.trim_start_matches('/').to_string(),
            version: None,
            raw_source: Some(rest.to_string()),
        });
    }

    // 9.0 git: `ms@https://codeload.github.com/...`.
    if let Some((name, url)) = key.split_once("@https://").or(key.split_once("@http://")) {
        let scheme = if key.contains("@https://") {
            "https://"
        } else {
            "http://"
        };
        return Some(ParsedKey {
            name: name.trim_start_matches('/').to_string(),
            version: None,
            raw_source: Some(format!("{scheme}{url}")),
        });
    }

    // 5.x/6.0 git: `github.com/vercel/ms/<sha>`. No leading slash, and it is a host rather than a
    // package name, so the `name:` field is the authority.
    if !key.starts_with('/') && key.contains('/') && !key.contains('@') {
        return Some(ParsedKey {
            name: key.to_string(),
            version: None,
            raw_source: Some(key.to_string()),
        });
    }

    let body = strip_peer_suffix(key.strip_prefix('/').unwrap_or(key), dialect);

    match dialect {
        // `/name/version` — the last `/` separates them, which also handles `@scope/name/version`.
        Dialect::V5 => {
            let (name, version) = body.rsplit_once('/')?;
            (!name.is_empty() && !version.is_empty()).then(|| ParsedKey {
                name: name.to_string(),
                version: Some(version.to_string()),
                raw_source: None,
            })
        }
        // `name@version`, with the scope's own `@` at index 0.
        Dialect::V6 | Dialect::V9 => {
            let at = body.rfind('@').filter(|index| *index > 0)?;
            let (name, version) = (&body[..at], &body[at + 1..]);
            (!name.is_empty() && !version.is_empty()).then(|| ParsedKey {
                name: name.to_string(),
                version: Some(version.to_string()),
                raw_source: None,
            })
        }
    }
}

/// Removes the peer-dependency suffix, which is not part of the version.
///
/// `_supports-color@9.4.0` in 5.x, `(supports-color@9.4.0)` in 6.0/9.0. The parenthesised form can
/// repeat, so everything from the first `(` is dropped.
fn strip_peer_suffix(body: &str, dialect: Dialect) -> &str {
    match dialect {
        Dialect::V5 => body.split_once('_').map_or(body, |(head, _)| head),
        Dialect::V6 | Dialect::V9 => body.split_once('(').map_or(body, |(head, _)| head),
    }
}

/// Builds the source from a resolution block and whatever the key encoded.
fn source_of(entry: &RawPackage, raw_source: Option<&str>) -> Source {
    let resolution = &entry.resolution;

    if let Some(directory) = &resolution.directory {
        return Source::Directory {
            path: directory.clone(),
        };
    }
    if resolution.kind.as_deref() == Some("directory") {
        return Source::Directory {
            path: raw_source.unwrap_or_default().to_string(),
        };
    }
    // A git resolution pnpm did not turn into a tarball.
    if let Some(repo) = &resolution.repo {
        let url = match &resolution.commit {
            Some(commit) => format!("{repo}#{commit}"),
            None => repo.clone(),
        };
        return Source::Git { url };
    }
    if let Some(tarball) = &resolution.tarball {
        return Source::Remote {
            url: Some(tarball.clone()),
            integrity: resolution.integrity.clone(),
        };
    }
    if resolution.integrity.is_some() {
        // A registry package. pnpm records no URL — the registry is a configuration value, not a
        // lockfile fact, so `url` stays None rather than being reconstructed from a guessed host.
        return Source::Remote {
            url: None,
            integrity: resolution.integrity.clone(),
        };
    }
    // Nothing in the resolution block was recognised. Preserved as Unknown rather than dropped: the
    // package will still be installed and will still run its scripts.
    Source::Unknown {
        raw: raw_source.unwrap_or_default().to_string(),
    }
}

/// How a package is reached from the graph roots.
///
/// Two independent booleans rather than a [`Groups`], because the derivation is not a fold: "dev" is
/// *not reachable from production*, so it cannot be accumulated one importer at a time without
/// remembering both sides. An earlier version of this function tried to and-fold `dev` into a
/// zero-initialised `Groups`, which made every package non-dev — caught by
/// `a_9x_dev_dependency_is_found_through_the_importers`.
#[derive(Debug, Default, Clone, Copy)]
struct Reachability {
    /// Named by a `dependencies` or `optionalDependencies` section somewhere.
    production: bool,
    /// Named by a `devDependencies` section somewhere.
    development: bool,
    /// Named by an `optionalDependencies` section somewhere.
    optional: bool,
}

impl Reachability {
    /// Collapses reachability into the reported groups.
    ///
    /// `dev` requires *no* production path. A package reachable from both graphs is production, which
    /// is the conservative direction: over-reporting a dev-only package as production makes a report
    /// stricter, whereas the reverse would let a real dependency be dismissed as dev-only.
    const fn groups(self) -> Groups {
        Groups {
            dev: self.development && !self.production,
            optional: self.optional,
        }
    }
}

/// Reachability for each package a graph root points at.
///
/// Keyed by `(name, resolved-version-text)`, because that is all an importer gives: `4.3.4`,
/// `4.3.4(supports-color@9.4.0)`, or `ms@2.1.3` for an alias.
type ImporterGraph = BTreeMap<(String, String), Reachability>;

/// Which dependency section an importer entry came from.
#[derive(Debug, Clone, Copy)]
enum Section {
    Production,
    Development,
    Optional,
}

/// Collects reachability from every importer, and from the top-level sections 5.x/6.0 use for a
/// single-project repository.
fn importer_graph(raw: &Raw) -> ImporterGraph {
    let mut out: ImporterGraph = BTreeMap::new();

    let mut absorb = |entries: &BTreeMap<String, Value>, section: Section| {
        for (name, node) in entries {
            // 5.x writes the resolved version directly; 6.0/9.0 write a map with `specifier` and
            // `version`.
            let resolved = match node {
                Value::String(text) => Some(text.clone()),
                Value::Mapping(map) => map
                    .get(Value::String("version".to_string()))
                    .and_then(version_text),
                _ => None,
            };
            let Some(resolved) = resolved else { continue };

            // An importer records the version as it appears in the package key, which may carry a peer
            // suffix or a `/` prefix. Both spellings are indexed so a lookup by parsed version finds
            // the entry either way.
            for spelling in version_spellings(&resolved) {
                let reach = out.entry((name.clone(), spelling)).or_default();
                match section {
                    Section::Production => reach.production = true,
                    Section::Development => reach.development = true,
                    Section::Optional => {
                        // An optional dependency is a production dependency that is allowed to fail.
                        reach.production = true;
                        reach.optional = true;
                    }
                }
            }
        }
    };

    for importer in raw.importers.values() {
        absorb(&importer.dependencies, Section::Production);
        absorb(&importer.dev_dependencies, Section::Development);
        absorb(&importer.optional_dependencies, Section::Optional);
    }
    absorb(&raw.dependencies, Section::Production);
    absorb(&raw.dev_dependencies, Section::Development);
    absorb(&raw.optional_dependencies, Section::Optional);

    out
}

/// Every way an importer might spell a resolved version, reduced toward the parsed form.
///
/// `4.3.4(supports-color@9.4.0)` and `/ms@2.1.3` both need to match a package parsed as `4.3.4` and
/// `2.1.3`. Returned as a small list rather than one canonical form because the alias spelling
/// (`ms@2.1.3`) carries a name that the version alone cannot recover.
fn version_spellings(resolved: &str) -> Vec<String> {
    let mut out = vec![resolved.to_string()];

    // Drop a peer suffix: `4.3.4(supports-color@9.4.0)` -> `4.3.4`.
    let without_peer = resolved.split_once('(').map_or(resolved, |(head, _)| head);
    // Drop an alias or leading-slash prefix: `/ms@2.1.3` and `ms@2.1.3` -> `2.1.3`.
    let bare = without_peer.trim_start_matches('/');
    let tail = bare
        .rfind('@')
        .filter(|index| *index > 0)
        .map_or(bare, |index| &bare[index + 1..]);

    for candidate in [without_peer, tail] {
        if !candidate.is_empty() && !out.iter().any(|existing| existing == candidate) {
            out.push(candidate.to_string());
        }
    }
    out
}

/// Determines a package's groups.
///
/// For 5.x/6.0 the per-package `dev` flag is authoritative — pnpm computed reachability itself, and
/// recomputing it here would be a worse answer from less information.
///
/// For 9.0 there is no such flag, so a direct graph root gets its groups from the importer that names
/// it. A transitive package cannot be attributed without walking `snapshots`, and the honest answer for
/// one is production, for the reason given on [`Reachability::groups`]. `optional` still comes from
/// `snapshots`, which does record it.
fn groups_of(
    entry: &RawPackage,
    raw: &Raw,
    dialect: Dialect,
    name: &str,
    version: &str,
    key: &str,
    graph: &ImporterGraph,
) -> Groups {
    match dialect {
        Dialect::V5 | Dialect::V6 => Groups {
            dev: entry.dev.unwrap_or(false),
            optional: entry.optional,
        },
        Dialect::V9 => {
            // Looked up by exact key. An earlier draft used `key.starts_with(name)`, which would have
            // let `ms-alias@1.0.0`'s optional flag leak onto `ms@2.1.3`.
            let optional_in_snapshot = raw
                .snapshots
                .get(key)
                .is_some_and(|snapshot| snapshot.optional);
            let from_graph = graph
                .get(&(name.to_string(), version.to_string()))
                .copied()
                .unwrap_or(Reachability {
                    // Not named by any importer: a transitive package. Production is the conservative
                    // reading.
                    production: true,
                    development: false,
                    optional: false,
                })
                .groups();
            Groups {
                dev: from_graph.dev,
                optional: from_graph.optional || entry.optional || optional_in_snapshot,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_version_is_refused_rather_than_assumed() {
        let err = parse("packages:\n  ms@2.1.3: {}\n").expect_err("must refuse");
        assert!(
            matches!(
                err,
                LockfileError::MissingVersion {
                    ecosystem: Ecosystem::Pnpm
                }
            ),
            "got {err}"
        );
    }

    #[test]
    fn the_version_is_read_whether_yaml_typed_it_as_a_number_or_a_string() {
        // 5.x writes `lockfileVersion: 5.4` (a number); 6.0 and 9.0 write `'6.0'` and `'9.0'`
        // (strings). Handling only one would reject half of all real lockfiles.
        assert_eq!(
            parse("lockfileVersion: 5.4\npackages: {}\n")
                .expect("parse")
                .declared_version,
            "5.4"
        );
        assert_eq!(
            parse("lockfileVersion: '9.0'\npackages: {}\n")
                .expect("parse")
                .declared_version,
            "9.0"
        );
    }

    #[test]
    fn versions_that_no_pnpm_release_writes_are_refused() {
        // There is no 7.0 or 8.0 lockfile format — pnpm 8 writes '6.0' and pnpm 9 writes '9.0'. A file
        // claiming one is corrupt or from the future, and both deserve an error.
        for declared in ["7.0", "8.0", "4.5", "10.0"] {
            let text = format!("lockfileVersion: '{declared}'\npackages: {{}}\n");
            match parse(&text).expect_err("must refuse") {
                LockfileError::UnsupportedVersion { found, .. } => assert_eq!(found, declared),
                other => panic!("{declared}: expected UnsupportedVersion, got {other}"),
            }
        }
        assert_eq!(dialect_of("5.4"), Some(Dialect::V5));
        assert_eq!(dialect_of("6.0"), Some(Dialect::V6));
        assert_eq!(dialect_of("9.0"), Some(Dialect::V9));
        assert_eq!(dialect_of("7.0"), None);
    }

    #[test]
    fn each_dialect_splits_its_own_key_notation() {
        let v5 = split_key("/ms/2.1.2", Dialect::V5).expect("v5 key");
        assert_eq!(
            (v5.name.as_str(), v5.version.as_deref()),
            ("ms", Some("2.1.2"))
        );

        let v6 = split_key("/ms@2.1.2", Dialect::V6).expect("v6 key");
        assert_eq!(
            (v6.name.as_str(), v6.version.as_deref()),
            ("ms", Some("2.1.2"))
        );

        let v9 = split_key("ms@2.1.2", Dialect::V9).expect("v9 key");
        assert_eq!(
            (v9.name.as_str(), v9.version.as_deref()),
            ("ms", Some("2.1.2"))
        );
    }

    #[test]
    fn scoped_names_survive_every_notation() {
        // The scope's own `@` and `/` are what make this worth a test in all three dialects.
        let v5 = split_key("/@babel/code-frame/7.24.7", Dialect::V5).expect("v5");
        assert_eq!(v5.name, "@babel/code-frame");
        assert_eq!(v5.version.as_deref(), Some("7.24.7"));

        let v6 = split_key("/@babel/code-frame@7.24.7", Dialect::V6).expect("v6");
        assert_eq!(v6.name, "@babel/code-frame");
        assert_eq!(v6.version.as_deref(), Some("7.24.7"));

        let v9 = split_key("@babel/code-frame@7.24.7", Dialect::V9).expect("v9");
        assert_eq!(v9.name, "@babel/code-frame");
        assert_eq!(v9.version.as_deref(), Some("7.24.7"));
    }

    #[test]
    fn a_peer_suffix_is_not_part_of_the_version() {
        // THE trap. Reading the suffix as part of the version reports a version that does not exist on
        // the registry, and makes a peer-only change look like a package change.
        let v9 = split_key("debug@4.3.4(supports-color@9.4.0)", Dialect::V9).expect("v9");
        assert_eq!(v9.name, "debug");
        assert_eq!(v9.version.as_deref(), Some("4.3.4"));

        let v6 = split_key("/debug@4.3.4(supports-color@9.4.0)", Dialect::V6).expect("v6");
        assert_eq!(v6.version.as_deref(), Some("4.3.4"));

        let v5 = split_key("/debug/4.3.4_supports-color@9.4.0", Dialect::V5).expect("v5");
        assert_eq!(v5.name, "debug");
        assert_eq!(v5.version.as_deref(), Some("4.3.4"));

        // Several peers at once, which pnpm also writes.
        let many = split_key("a@1.0.0(b@2.0.0)(c@3.0.0)", Dialect::V9).expect("v9");
        assert_eq!(many.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn a_git_key_that_is_a_url_is_not_split_on_its_at_signs() {
        // Verified against real pnpm 9 output. The obvious rsplit('@') would yield a version of
        // "https:" and a name containing the whole URL.
        let key = "ms@https://codeload.github.com/vercel/ms/tar.gz/1c6264b795492e8fdecbc82cb8802fcfbfc08d26";
        let parsed = split_key(key, Dialect::V9).expect("git key");
        assert_eq!(parsed.name, "ms");
        assert_eq!(parsed.version, None, "a URL is not a version");
        assert_eq!(
            parsed.raw_source.as_deref(),
            Some("https://codeload.github.com/vercel/ms/tar.gz/1c6264b795492e8fdecbc82cb8802fcfbfc08d26")
        );
    }

    #[test]
    fn a_5x_git_key_is_a_host_path_and_defers_to_the_name_field() {
        let parsed = split_key(
            "github.com/vercel/ms/1c6264b795492e8fdecbc82cb8802fcfbfc08d26",
            Dialect::V5,
        )
        .expect("git key");
        assert_eq!(parsed.version, None);
        assert!(parsed.raw_source.is_some());
    }

    #[test]
    fn file_keys_are_recognised_in_both_notations() {
        let v6 = split_key("file:local-dir", Dialect::V6).expect("v6 file key");
        assert_eq!(v6.raw_source.as_deref(), Some("local-dir"));
        assert_eq!(v6.version, None);

        let v9 = split_key("local-dir@file:local-dir", Dialect::V9).expect("v9 file key");
        assert_eq!(v9.name, "local-dir");
        assert_eq!(v9.raw_source.as_deref(), Some("local-dir"));
    }

    #[test]
    fn a_5x_dev_flag_is_taken_at_face_value() {
        // pnpm computed reachability itself; recomputing it here would be a worse answer from less
        // information.
        let text = "\
lockfileVersion: 5.4
dependencies:
  prod-pkg: 1.0.0
devDependencies:
  dev-pkg: 2.0.0
packages:
  /prod-pkg/1.0.0:
    resolution: {integrity: sha512-aaa}
    dev: false
  /dev-pkg/2.0.0:
    resolution: {integrity: sha512-bbb}
    dev: true
";
        let lockfile = parse(text).expect("parse");
        let dev = lockfile
            .packages
            .iter()
            .find(|p| p.name == "dev-pkg")
            .expect("dev-pkg");
        let prod = lockfile
            .packages
            .iter()
            .find(|p| p.name == "prod-pkg")
            .expect("prod-pkg");
        assert!(dev.groups.dev);
        assert!(!prod.groups.dev);
    }

    #[test]
    fn a_9x_dev_dependency_is_found_through_the_importers() {
        // 9.0 has no per-package dev key. Treating its absence as "production" would misreport every
        // dev dependency in every modern pnpm repository.
        let text = "\
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      prod-pkg:
        specifier: 1.0.0
        version: 1.0.0
    devDependencies:
      dev-pkg:
        specifier: 2.0.0
        version: 2.0.0
packages:
  prod-pkg@1.0.0:
    resolution: {integrity: sha512-aaa}
  dev-pkg@2.0.0:
    resolution: {integrity: sha512-bbb}
snapshots:
  prod-pkg@1.0.0: {}
  dev-pkg@2.0.0: {}
";
        let lockfile = parse(text).expect("parse");
        let dev = lockfile
            .packages
            .iter()
            .find(|p| p.name == "dev-pkg")
            .expect("dev-pkg");
        let prod = lockfile
            .packages
            .iter()
            .find(|p| p.name == "prod-pkg")
            .expect("prod-pkg");
        assert!(
            dev.groups.dev,
            "a 9.0 dev dependency must be found via importers"
        );
        assert!(!prod.groups.dev);
    }

    #[test]
    fn a_9x_optional_flag_is_read_from_snapshots() {
        // 9.0 moved `optional` out of `packages` and into `snapshots`.
        let text = "\
lockfileVersion: '9.0'
importers:
  .:
    optionalDependencies:
      picocolors:
        specifier: 1.1.1
        version: 1.1.1
packages:
  picocolors@1.1.1:
    resolution: {integrity: sha512-aaa}
snapshots:
  picocolors@1.1.1:
    optional: true
";
        let lockfile = parse(text).expect("parse");
        assert!(lockfile.packages[0].groups.optional);
    }

    #[test]
    fn a_package_in_both_graphs_is_reported_as_production() {
        // A dependency of one workspace member and a dev dependency of another is reachable from
        // production. Reporting it as dev-only would let a real dependency be dismissed.
        let text = "\
lockfileVersion: '9.0'
importers:
  packages/a:
    dependencies:
      shared:
        specifier: 1.0.0
        version: 1.0.0
  packages/b:
    devDependencies:
      shared:
        specifier: 1.0.0
        version: 1.0.0
packages:
  shared@1.0.0:
    resolution: {integrity: sha512-aaa}
";
        let lockfile = parse(text).expect("parse");
        assert!(
            !lockfile.packages[0].groups.dev,
            "reachable from production, so not dev-only"
        );
    }

    #[test]
    fn a_directory_resolution_is_repository_code() {
        let text = "\
lockfileVersion: '6.0'
dependencies:
  local-dir:
    specifier: file:./local-dir
    version: file:local-dir
packages:
  file:local-dir:
    resolution: {directory: local-dir, type: directory}
    name: local-dir
    dev: false
";
        let lockfile = parse(text).expect("parse");
        assert_eq!(lockfile.packages.len(), 1);
        assert_eq!(lockfile.packages[0].name, "local-dir");
        assert!(!lockfile.packages[0].source.is_external());
    }

    #[test]
    fn a_registry_package_reports_no_url_rather_than_a_guessed_one() {
        // pnpm records only the integrity hash; the registry is configuration, not a lockfile fact.
        // Reconstructing a URL would be inventing evidence.
        let text = "\
lockfileVersion: '9.0'
packages:
  ms@2.1.3:
    resolution: {integrity: sha512-aaa}
";
        let lockfile = parse(text).expect("parse");
        assert_eq!(
            lockfile.packages[0].source,
            Source::Remote {
                url: None,
                integrity: Some("sha512-aaa".to_string()),
            }
        );
    }

    #[test]
    fn a_repo_and_commit_resolution_becomes_a_git_source() {
        let text = "\
lockfileVersion: '9.0'
packages:
  thing@1.0.0:
    resolution: {repo: git+https://github.com/a/b.git, commit: abc123, type: git}
";
        let lockfile = parse(text).expect("parse");
        assert_eq!(
            lockfile.packages[0].source,
            Source::Git {
                url: "git+https://github.com/a/b.git#abc123".to_string()
            }
        );
    }

    #[test]
    fn no_pnpm_version_claims_install_script_knowledge() {
        let text = "\
lockfileVersion: '9.0'
packages:
  ms@2.1.3:
    resolution: {integrity: sha512-aaa}
";
        assert_eq!(
            parse(text).expect("parse").packages[0].has_install_script,
            None
        );
    }

    #[test]
    fn malformed_yaml_is_an_error_not_an_empty_lockfile() {
        assert!(matches!(
            parse("lockfileVersion: '9.0'\npackages:\n  - [unclosed").expect_err("must refuse"),
            LockfileError::Yaml(_)
        ));
    }

    #[test]
    fn output_order_is_deterministic() {
        let text = "\
lockfileVersion: '9.0'
packages:
  b@1.0.0:
    resolution: {integrity: sha512-bbb}
  a@1.0.0:
    resolution: {integrity: sha512-aaa}
";
        let first = parse(text).expect("parse");
        assert_eq!(first, parse(text).expect("parse"));
        let names: Vec<&str> = first.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
