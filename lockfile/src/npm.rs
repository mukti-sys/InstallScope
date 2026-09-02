//! `package-lock.json` — `lockfileVersion` 1, 2 and 3.
//!
//! # Three formats, two layouts
//!
//! | Version | Where the packages are | npm |
//! |---|---|---|
//! | 1 | `dependencies`, a recursive tree keyed by install name | ≤ 6 |
//! | 2 | **both** `packages` and `dependencies` | 7–8 |
//! | 3 | `packages`, a flat map keyed by install path | ≥ 9 |
//!
//! Version 2 is the trap: it carries the same tree twice, for forward and backward compatibility.
//! Reading both would report every package once per representation, doubling the dependency count on
//! any repository still on npm 7 or 8. So `packages` is preferred whenever present, and
//! `dependencies` is read only in its absence. `tests/fixtures/npm/v2-dual-representation.json` is a
//! real npm 11 `--lockfile-version 2` file and the test asserts the count, not just that parsing
//! succeeded.
//!
//! # The `link: true` pair
//!
//! A `file:` dependency and a workspace member are both recorded as *two* entries:
//!
//! ```json
//! "node_modules/thing": { "resolved": "vendor/thing", "link": true },
//! "vendor/thing":       { "version": "0.0.1" }
//! ```
//!
//! The first says where it appears in the tree, the second carries the version. Emitting both would
//! double-count; emitting only the first yields a package with no version; emitting only the second
//! loses the name it is installed under. So the pair is merged into one package, and the target key is
//! not emitted again on its own.
//!
//! # Aliases move between fields across versions
//!
//! In v2/v3 an alias is a `name` field that disagrees with the key: `node_modules/ms-alias` with
//! `"name": "ms"`. In v1 there is no `name` field and the alias lives in the *version*:
//! `"version": "npm:ms@2.1.3"`. Both are verified in fixtures because the v1 spelling is not something
//! a reader would predict.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::error::{LockfileError, Result};
use crate::model::{Ecosystem, Groups, Lockfile, Package, Source};

/// Lockfile versions this parser reads.
const SUPPORTED: &str = "1, 2, 3";

/// The top level of a `package-lock.json`.
#[derive(Debug, Deserialize)]
struct Raw {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u32>,
    /// v2 and v3. Keyed by install path; `""` is the project itself.
    #[serde(default)]
    packages: BTreeMap<String, RawPathEntry>,
    /// v1 and v2. Keyed by install name, recursive.
    #[serde(default)]
    dependencies: BTreeMap<String, RawTreeEntry>,
}

/// An entry in the v2/v3 `packages` map.
///
/// The five booleans are npm's, not a design choice here: `link`, `dev`, `optional`, `devOptional` and
/// `hasInstallScript` are all separate flags in the format, and collapsing them into an enum would mean
/// deciding which combinations are possible. npm does emit `dev` and `optional` together, so the
/// combinations are not exclusive and a state machine would be a lie about the input.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
struct RawPathEntry {
    /// Absent for a `link: true` entry and for the root project.
    version: Option<String>,
    /// The published name, when it differs from the key — i.e. an alias.
    name: Option<String>,
    /// Tarball URL, git URL, or a repo-relative path for a link.
    resolved: Option<String>,
    integrity: Option<String>,
    /// True when this entry is a symlink to another entry in this same map.
    #[serde(default)]
    link: bool,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
    /// npm's own union flag: reachable from both graphs, or from dev-optional.
    #[serde(default, rename = "devOptional")]
    dev_optional: bool,
    #[serde(default, rename = "hasInstallScript")]
    has_install_script: bool,
    /// Present on the root entry of a workspace root.
    #[serde(default)]
    workspaces: Vec<String>,
}

/// An entry in the v1/v2 `dependencies` tree.
#[derive(Debug, Deserialize)]
struct RawTreeEntry {
    /// A version, an `npm:name@version` alias, or a git URL.
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
    #[serde(default, rename = "devOptional")]
    dev_optional: bool,
    /// Privately nested dependencies, i.e. a deduplication conflict npm could not hoist.
    #[serde(default)]
    dependencies: BTreeMap<String, RawTreeEntry>,
}

/// Parses a `package-lock.json`.
///
/// # Errors
/// [`LockfileError::Json`] when the text is not valid JSON, [`LockfileError::MissingVersion`] when it
/// declares no `lockfileVersion`, and [`LockfileError::UnsupportedVersion`] for a version outside
/// [`SUPPORTED`].
pub fn parse(text: &str) -> Result<Lockfile> {
    let raw: Raw = serde_json::from_str(text)?;

    let version = raw.lockfile_version.ok_or(LockfileError::MissingVersion {
        ecosystem: Ecosystem::Npm,
    })?;
    if !(1..=3).contains(&version) {
        return Err(LockfileError::UnsupportedVersion {
            ecosystem: Ecosystem::Npm,
            found: version.to_string(),
            supported: SUPPORTED,
        });
    }

    // Preference, not a fallback chain: a v2 file has both, and reading both double-counts.
    let mut packages = if raw.packages.is_empty() {
        from_tree(&raw.dependencies, Groups::PROD)
    } else {
        from_paths(&raw.packages, &version.to_string())?
    };

    packages.sort_by(|a, b| a.key.cmp(&b.key).then(a.name.cmp(&b.name)));
    Ok(Lockfile {
        ecosystem: Ecosystem::Npm,
        declared_version: version.to_string(),
        packages,
    })
}

/// Reads the v2/v3 `packages` map.
fn from_paths(entries: &BTreeMap<String, RawPathEntry>, version: &str) -> Result<Vec<Package>> {
    // Link targets are merged into their link entry, so they must not also be emitted on their own.
    let link_targets: BTreeSet<&str> = entries
        .iter()
        .filter(|(_, entry)| entry.link)
        .filter_map(|(_, entry)| entry.resolved.as_deref())
        .collect();

    let workspace_globs: &[String] = entries
        .get("")
        .map_or(&[], |root| root.workspaces.as_slice());

    let mut packages = Vec::with_capacity(entries.len());
    for (key, entry) in entries {
        // The root entry describes the project under review, not a dependency of it.
        if key.is_empty() {
            continue;
        }
        if link_targets.contains(key.as_str()) {
            continue;
        }

        let (name, alias) =
            path_key_name(key, entry.name.as_deref()).ok_or_else(|| LockfileError::Malformed {
                ecosystem: Ecosystem::Npm,
                version: version.to_string(),
                location: format!("packages[{key:?}]"),
                detail:
                    "the key is neither a node_modules path nor a workspace path, and the entry \
                         carries no name field, so the package name cannot be determined"
                        .to_string(),
            })?;

        let (source, version_text) = if entry.link {
            // The link entry knows the path; its target entry knows the version.
            let path = entry.resolved.clone().unwrap_or_default();
            let target_version = entries
                .get(path.as_str())
                .and_then(|target| target.version.clone())
                .unwrap_or_default();
            (link_source(&path, workspace_globs), target_version)
        } else if !key.starts_with("node_modules/") {
            // A workspace member's own entry, present without a link when npm did not hoist it.
            (
                link_source(key, workspace_globs),
                entry.version.clone().unwrap_or_default(),
            )
        } else {
            (
                remote_source(entry.resolved.as_deref(), entry.integrity.as_deref()),
                entry.version.clone().unwrap_or_default(),
            )
        };

        packages.push(Package {
            name,
            version: version_text,
            alias,
            source,
            groups: Groups {
                dev: entry.dev || entry.dev_optional,
                optional: entry.optional || entry.dev_optional,
            },
            // v3 records this; v1 does not. `false` here means npm said there is no install script,
            // which is a real claim and distinct from "the format cannot tell us".
            has_install_script: Some(entry.has_install_script),
            key: key.clone(),
        });
    }
    Ok(packages)
}

/// Reads the v1 `dependencies` tree.
///
/// `inherited` carries the parent's groups: npm writes the flags on every entry, but a nested copy of
/// a dev-only dependency is dev-only regardless, and unioning cannot understate.
fn from_tree(entries: &BTreeMap<String, RawTreeEntry>, inherited: Groups) -> Vec<Package> {
    let mut packages = Vec::new();
    collect_tree(entries, inherited, "", &mut packages);
    packages
}

fn collect_tree(
    entries: &BTreeMap<String, RawTreeEntry>,
    inherited: Groups,
    prefix: &str,
    out: &mut Vec<Package>,
) {
    for (install_name, entry) in entries {
        let key = if prefix.is_empty() {
            format!("node_modules/{install_name}")
        } else {
            format!("{prefix}/node_modules/{install_name}")
        };

        let groups = Groups {
            dev: inherited.dev || entry.dev || entry.dev_optional,
            optional: inherited.optional || entry.optional || entry.dev_optional,
        };

        let raw_version = entry.version.as_deref().unwrap_or_default();
        // v1 puts an alias in the version field: "version": "npm:ms@2.1.3".
        let (name, alias, version) = match parse_v1_alias(raw_version) {
            Some((target, target_version)) => (
                target.to_string(),
                Some(install_name.clone()),
                target_version.to_string(),
            ),
            None => (install_name.clone(), None, raw_version.to_string()),
        };

        // v1 has no `resolved` for a git dependency; the version field holds the git URL instead.
        let (source, version) = if let Some(git) = git_url(&version) {
            (
                Source::Git {
                    url: git.to_string(),
                },
                version.clone(),
            )
        } else {
            (
                remote_source(entry.resolved.as_deref(), entry.integrity.as_deref()),
                version,
            )
        };

        out.push(Package {
            name,
            version,
            alias,
            source,
            groups,
            // v1 does not record it. `None` rather than `Some(false)`: the format cannot tell us, and
            // that is a different claim from "there is no install script".
            has_install_script: None,
            key: key.clone(),
        });

        if !entry.dependencies.is_empty() {
            collect_tree(&entry.dependencies, groups, &key, out);
        }
    }
}

/// Splits a v1 `npm:name@version` alias specifier.
///
/// Returns the published name and the version. Handles a scoped target (`npm:@scope/pkg@1.0.0`) by
/// looking for the last `@` rather than the first.
fn parse_v1_alias(version: &str) -> Option<(&str, &str)> {
    let rest = version.strip_prefix("npm:")?;
    let at = rest.rfind('@').filter(|index| *index > 0)?;
    Some((&rest[..at], &rest[at + 1..]))
}

/// Recognises the git URL forms npm writes.
fn git_url(text: &str) -> Option<&str> {
    const PREFIXES: &[&str] = &[
        "git+ssh://",
        "git+https://",
        "git+http://",
        "git+file://",
        "git://",
    ];
    PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
        .then_some(text)
}

/// Builds the source for a fetched package.
fn remote_source(resolved: Option<&str>, integrity: Option<&str>) -> Source {
    match resolved {
        Some(url) if git_url(url).is_some() => Source::Git {
            url: url.to_string(),
        },
        // Reported as what the file says — a URL and maybe a hash — rather than classified into
        // "registry" or "not". See the Source docs: deciding that from a URL's shape is a guess, and
        // the guess would be wrong in the reassuring direction.
        other => Source::Remote {
            url: other.map(ToString::to_string),
            integrity: integrity.map(ToString::to_string),
        },
    }
}

/// Classifies a local path as a workspace member or a plain directory dependency.
///
/// Both are repository code, so a misclassification costs a label rather than a decision — which is
/// why the glob support is deliberately limited to the `dir/*` form npm actually writes rather than
/// pulling in a glob dependency.
fn link_source(path: &str, workspace_globs: &[String]) -> Source {
    let is_workspace = workspace_globs
        .iter()
        .any(|glob| workspace_glob_matches(glob, path));
    if is_workspace {
        Source::Workspace {
            path: path.to_string(),
        }
    } else {
        Source::Directory {
            path: path.to_string(),
        }
    }
}

/// Matches the `packages/*` and `packages/name` forms.
fn workspace_glob_matches(glob: &str, path: &str) -> bool {
    let glob = glob.trim_end_matches('/');
    match glob.strip_suffix("/*") {
        Some(parent) => path
            .strip_prefix(parent)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|leaf| !leaf.is_empty() && !leaf.contains('/')),
        None => glob == path,
    }
}

/// Derives the published name and alias from a v2/v3 key.
///
/// The name is the segment after the final `node_modules/`, which handles both nesting
/// (`node_modules/debug/node_modules/ms`) and scopes (`node_modules/@babel/code-frame`). An explicit
/// `name` field overrides it and the key's segment becomes the alias.
fn path_key_name(key: &str, declared: Option<&str>) -> Option<(String, Option<String>)> {
    let install_name = key
        .rsplit_once("node_modules/")
        .map_or(key, |(_, leaf)| leaf);
    if install_name.is_empty() {
        return declared.map(|name| (name.to_string(), None));
    }
    match declared {
        Some(published) if published != install_name => {
            Some((published.to_string(), Some(install_name.to_string())))
        }
        Some(published) => Some((published.to_string(), None)),
        None => Some((install_name.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_version_is_refused_rather_than_assumed() {
        // The version determines how every key is interpreted, so guessing it means guessing the
        // dependency set.
        let err = parse(r#"{"name":"x","packages":{}}"#).expect_err("must refuse");
        assert!(
            matches!(
                err,
                LockfileError::MissingVersion {
                    ecosystem: Ecosystem::Npm
                }
            ),
            "got {err}"
        );
    }

    #[test]
    fn a_future_version_is_refused_rather_than_best_effort_parsed() {
        let err = parse(r#"{"lockfileVersion":4,"packages":{}}"#).expect_err("must refuse");
        match err {
            LockfileError::UnsupportedVersion { found, .. } => assert_eq!(found, "4"),
            other => panic!("expected UnsupportedVersion, got {other}"),
        }
    }

    #[test]
    fn malformed_json_is_an_error_not_an_empty_lockfile() {
        // An empty result would read as "this PR adds no dependencies", which is the wrong direction
        // to fail in.
        assert!(matches!(
            parse("{not json").expect_err("must refuse"),
            LockfileError::Json(_)
        ));
    }

    #[test]
    fn the_v1_alias_spelling_is_read_from_the_version_field() {
        // Verified against real npm output: v1 has no `name` field, and the alias target lives in the
        // version. Nobody would guess this.
        assert_eq!(parse_v1_alias("npm:ms@2.1.3"), Some(("ms", "2.1.3")));
        assert_eq!(
            parse_v1_alias("npm:@scope/pkg@1.0.0"),
            Some(("@scope/pkg", "1.0.0"))
        );
        assert_eq!(parse_v1_alias("2.1.3"), None);
        // A malformed alias must not produce an empty name.
        assert_eq!(parse_v1_alias("npm:@scope"), None);
    }

    #[test]
    fn git_urls_are_recognised_in_every_form_npm_writes() {
        for url in [
            "git+ssh://git@github.com/vercel/ms.git#1c6264b",
            "git+https://github.com/vercel/ms.git#1c6264b",
            "git://github.com/vercel/ms.git#1c6264b",
        ] {
            assert!(git_url(url).is_some(), "{url} must be recognised as git");
        }
        assert!(git_url("https://registry.npmjs.org/ms/-/ms-2.1.3.tgz").is_none());
    }

    #[test]
    fn a_tarball_url_is_not_claimed_to_be_a_registry() {
        // The distinction npm does not record, so the parser must not invent it. Saying "registry"
        // about https://evil.example/x.tgz would be the exact reassurance this product cannot give.
        let source = remote_source(Some("https://evil.example/x.tgz"), Some("sha512-abc"));
        assert_eq!(
            source,
            Source::Remote {
                url: Some("https://evil.example/x.tgz".to_string()),
                integrity: Some("sha512-abc".to_string()),
            }
        );
        assert_eq!(source.kind(), "remote");
    }

    #[test]
    fn a_nested_key_names_the_nested_package_not_its_parent() {
        assert_eq!(
            path_key_name("node_modules/debug/node_modules/ms", None),
            Some(("ms".to_string(), None))
        );
        assert_eq!(
            path_key_name("node_modules/@babel/code-frame", None),
            Some(("@babel/code-frame".to_string(), None))
        );
    }

    #[test]
    fn a_name_field_that_disagrees_with_the_key_is_an_alias() {
        assert_eq!(
            path_key_name("node_modules/ms-alias", Some("ms")),
            Some(("ms".to_string(), Some("ms-alias".to_string())))
        );
        // Agreeing is not an alias.
        assert_eq!(
            path_key_name("node_modules/ms", Some("ms")),
            Some(("ms".to_string(), None))
        );
    }

    #[test]
    fn workspace_globs_match_only_one_level() {
        assert!(workspace_glob_matches("packages/*", "packages/app"));
        assert!(!workspace_glob_matches("packages/*", "packages/app/nested"));
        assert!(!workspace_glob_matches("packages/*", "vendor/thing"));
        assert!(!workspace_glob_matches("packages/*", "packages"));
        // A literal entry, which npm also permits.
        assert!(workspace_glob_matches("packages/app", "packages/app"));
        assert!(!workspace_glob_matches("packages/app", "packages/other"));
        // A trailing slash must not defeat the match.
        assert!(workspace_glob_matches("packages/*/", "packages/app"));
    }

    #[test]
    fn a_path_outside_the_workspace_globs_is_a_directory_dependency() {
        let globs = vec!["packages/*".to_string()];
        assert_eq!(
            link_source("packages/app", &globs),
            Source::Workspace {
                path: "packages/app".to_string()
            }
        );
        assert_eq!(
            link_source("vendor/thing", &globs),
            Source::Directory {
                path: "vendor/thing".to_string()
            }
        );
        // With no workspaces declared at all, every link is a directory dependency.
        assert_eq!(
            link_source("vendor/thing", &[]),
            Source::Directory {
                path: "vendor/thing".to_string()
            }
        );
    }

    #[test]
    fn dev_optional_sets_both_flags() {
        // npm's `devOptional` means reachable from the dev graph *and* optional. Mapping it to only
        // one of the two would misreport the other.
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/x": { "version": "1.0.0", "devOptional": true }
            }
        }"#;
        let lockfile = parse(text).expect("parse");
        assert_eq!(lockfile.packages.len(), 1);
        assert!(lockfile.packages[0].groups.dev);
        assert!(lockfile.packages[0].groups.optional);
    }

    #[test]
    fn the_root_project_is_not_reported_as_its_own_dependency() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": { "": { "name": "root", "version": "1.0.0" } }
        }"#;
        assert!(parse(text).expect("parse").packages.is_empty());
    }

    #[test]
    fn v1_group_flags_are_inherited_by_nested_copies() {
        // A private copy nested under a dev-only dependency is dev-only, whatever its own entry says.
        let text = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "toolkit": {
                    "version": "1.0.0",
                    "dev": true,
                    "dependencies": {
                        "helper": { "version": "2.0.0" }
                    }
                }
            }
        }"#;
        let lockfile = parse(text).expect("parse");
        let helper = lockfile
            .packages
            .iter()
            .find(|package| package.name == "helper")
            .expect("nested package present");
        assert!(
            helper.groups.dev,
            "a nested copy of a dev-only dependency is dev-only"
        );
        assert_eq!(helper.key, "node_modules/toolkit/node_modules/helper");
    }

    #[test]
    fn v1_reports_no_install_script_knowledge_rather_than_claiming_there_is_none() {
        let text = r#"{
            "lockfileVersion": 1,
            "dependencies": { "x": { "version": "1.0.0" } }
        }"#;
        let lockfile = parse(text).expect("parse");
        assert_eq!(
            lockfile.packages[0].has_install_script, None,
            "v1 cannot tell us, which is not the same as telling us there is none"
        );
    }

    #[test]
    fn output_order_is_deterministic() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root" },
                "node_modules/b": { "version": "1.0.0" },
                "node_modules/a": { "version": "1.0.0" }
            }
        }"#;
        let first = parse(text).expect("parse");
        let second = parse(text).expect("parse");
        assert_eq!(first, second);
        let keys: Vec<&str> = first
            .packages
            .iter()
            .map(|package| package.key.as_str())
            .collect();
        assert_eq!(keys, vec!["node_modules/a", "node_modules/b"]);
    }
}
