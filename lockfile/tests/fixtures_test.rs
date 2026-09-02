//! Golden tests against real package-manager output.
//!
//! The unit tests in `src/npm.rs` and `src/pnpm.rs` check the parsing *logic* against inputs written
//! by hand. This suite checks it against files npm and pnpm actually produced — see
//! `tests/fixtures/README.md` for how each was generated.
//!
//! The distinction matters more than it looks. A hand-written fixture encodes the author's belief
//! about the format, which is the same belief the parser encodes, so the two agreeing proves nothing.
//! Three of the assertions below would have passed against a plausible hand-written fixture and failed
//! against reality:
//!
//! - npm `lockfileVersion: 1` puts an alias target in the *version* field, not a `name` field.
//! - npm records a `file:` dependency as two entries that must be merged into one package.
//! - pnpm resolves a `github:` specifier to a codeload tarball and then uses that URL as the package
//!   key, so the key contains `@`, `/` and `:`.
//!
//! `Rules.md` §5: verified claims over confident-looking ones.

use std::path::{Path, PathBuf};

use installscope_lockfile::{
    diff, npm, pnpm, Change, Ecosystem, Lockfile, LockfileError, Package, Source,
};

/// Loads a fixture by its path under `tests/fixtures/`.
fn fixture(relative: &str) -> String {
    let path = fixture_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(relative)
}

/// Parses an npm fixture.
fn npm_fixture(name: &str) -> Lockfile {
    npm::parse(&fixture(&format!("npm/{name}")))
        .unwrap_or_else(|error| panic!("npm/{name}: {error}"))
}

/// Parses a pnpm fixture.
fn pnpm_fixture(name: &str) -> Lockfile {
    pnpm::parse(&fixture(&format!("pnpm/{name}")))
        .unwrap_or_else(|error| panic!("pnpm/{name}: {error}"))
}

/// Finds the single entry for a name, failing loudly on zero or several.
///
/// Deliberately strict. Several of these fixtures resolve one name at two versions — that is what they
/// exist to prove — so a test that wants a specific entry must say which, and [`at_version`] is how.
fn one_named<'a>(lockfile: &'a Lockfile, name: &str) -> &'a Package {
    let matches = lockfile.entries_named(name);
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one {name}, found {}: {:?}",
        matches.len(),
        matches.iter().map(|p| &p.key).collect::<Vec<_>>()
    );
    matches[0]
}

/// Finds the entry for a name at a specific version.
fn at_version<'a>(lockfile: &'a Lockfile, name: &str, version: &str) -> &'a Package {
    lockfile
        .entries_named(name)
        .into_iter()
        .find(|package| package.version == version)
        .unwrap_or_else(|| {
            panic!(
                "no {name}@{version}; present: {:?}",
                lockfile
                    .entries_named(name)
                    .iter()
                    .map(|p| (&p.version, &p.key))
                    .collect::<Vec<_>>()
            )
        })
}

/// Finds the entry installed under a given local name (its lockfile key's leaf, or its alias).
fn under_key<'a>(lockfile: &'a Lockfile, key: &str) -> &'a Package {
    lockfile
        .packages
        .iter()
        .find(|package| package.key == key)
        .unwrap_or_else(|| {
            panic!(
                "no entry keyed {key}; present: {:?}",
                lockfile.packages.iter().map(|p| &p.key).collect::<Vec<_>>()
            )
        })
}

/// Every fixture in the directory, so a newly added one cannot sit unparsed.
fn all_fixtures(subdirectory: &str) -> Vec<(String, String)> {
    let dir = fixture_path(subdirectory);
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("listing {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("reading a dir entry: {error}"));
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        out.push((name, text));
    }
    out.sort();
    assert!(!out.is_empty(), "no fixtures found in {subdirectory}");
    out
}

// ---------------------------------------------------------------------------------------------
// Every fixture parses
// ---------------------------------------------------------------------------------------------

#[test]
fn every_npm_fixture_parses_and_finds_packages() {
    for (name, text) in all_fixtures("npm") {
        let lockfile = npm::parse(&text).unwrap_or_else(|error| panic!("npm/{name}: {error}"));
        assert_eq!(lockfile.ecosystem, Ecosystem::Npm, "npm/{name}");
        assert!(
            !lockfile.packages.is_empty(),
            "npm/{name} parsed to zero packages, which would read as 'this PR adds nothing'"
        );
        for package in &lockfile.packages {
            assert!(
                !package.name.is_empty(),
                "npm/{name}: a package has no name"
            );
            assert!(!package.key.is_empty(), "npm/{name}: a package has no key");
        }
    }
}

#[test]
fn every_pnpm_fixture_parses_and_finds_packages() {
    for (name, text) in all_fixtures("pnpm") {
        let lockfile = pnpm::parse(&text).unwrap_or_else(|error| panic!("pnpm/{name}: {error}"));
        assert_eq!(lockfile.ecosystem, Ecosystem::Pnpm, "pnpm/{name}");
        assert!(
            !lockfile.packages.is_empty(),
            "pnpm/{name} parsed to zero packages"
        );
        for package in &lockfile.packages {
            assert!(
                !package.name.is_empty(),
                "pnpm/{name}: a package has no name"
            );
            // A version can legitimately be empty (a `file:` entry in some versions), but a name
            // cannot, and a version must never contain a peer suffix.
            assert!(
                !package.version.contains('(') && !package.version.contains('_'),
                "pnpm/{name}: {} has a peer suffix in its version: {:?}",
                package.name,
                package.version
            );
        }
    }
}

#[test]
fn a_fixture_read_through_the_dispatcher_agrees_with_the_direct_parser() {
    // The dispatcher chooses by filename; a mismatch here would mean the Action and the CLI disagree
    // about the same file.
    let text = fixture("npm/v3-alias-scoped-nested.json");
    assert_eq!(
        installscope_lockfile::parse("package-lock.json", &text).expect("dispatch"),
        npm::parse(&text).expect("direct")
    );
}

// ---------------------------------------------------------------------------------------------
// npm: the three formats
// ---------------------------------------------------------------------------------------------

#[test]
fn npm_v2_is_not_double_counted() {
    // THE v2 trap: the file carries `packages` and `dependencies` describing the same tree. Reading
    // both doubles every dependency count on any repository still on npm 7 or 8.
    let v2 = npm_fixture("v2-dual-representation.json");
    let v3 = npm_fixture("v1-nested-duplicate.json");

    assert_eq!(v2.declared_version, "2");
    // The v2 and v1 fixtures were generated from the same package.json, so they resolve the same set.
    assert_eq!(
        v2.packages.len(),
        v3.packages.len(),
        "v2 must report the same package count as v1 for the same input, not double it.\n\
         v2: {:?}\nv1: {:?}",
        v2.packages.iter().map(|p| &p.key).collect::<Vec<_>>(),
        v3.packages.iter().map(|p| &p.key).collect::<Vec<_>>()
    );
    assert_eq!(
        v2.packages.len(),
        3,
        "debug, its nested ms, and the root ms"
    );
}

#[test]
fn npm_reports_the_same_package_at_two_versions() {
    // The reason identity is (name, version). Real npm output, not a constructed case: `ms` resolves
    // at 2.1.3 at the root and 2.1.2 nested under `debug`.
    for name in [
        "v1-nested-duplicate.json",
        "v2-dual-representation.json",
        "v3-alias-scoped-nested.json",
    ] {
        let lockfile = npm_fixture(name);
        let versions: Vec<&str> = lockfile
            .entries_named("ms")
            .iter()
            .map(|package| package.version.as_str())
            .collect();
        assert!(
            versions.len() >= 2,
            "{name}: expected ms at two versions, got {versions:?}"
        );
        assert!(versions.contains(&"2.1.2"), "{name}: {versions:?}");
    }
}

#[test]
fn npm_v1_reads_an_alias_out_of_the_version_field() {
    // Verified, not remembered: v1 writes `"version": "npm:ms@2.1.3"` with no name field. A parser
    // written from the v3 shape would report a package literally named `ms-alias` at version
    // `npm:ms@2.1.3`, and no such package exists.
    let lockfile = npm_fixture("v1-alias-git-groups.json");
    let aliased = under_key(&lockfile, "node_modules/ms-alias");
    assert_eq!(
        aliased.name, "ms",
        "the published name is what runs scripts"
    );
    assert_eq!(aliased.version, "2.1.3");
    assert_eq!(aliased.alias.as_deref(), Some("ms-alias"));

    // And the un-aliased `ms` that npm also resolved, at a different version, is a separate entry.
    let plain = under_key(&lockfile, "node_modules/ms");
    assert_eq!(plain.version, "2.1.2");
    assert_eq!(plain.alias, None);
}

#[test]
fn npm_v3_reads_an_alias_out_of_the_name_field() {
    let lockfile = npm_fixture("v3-alias-scoped-nested.json");
    let aliased = lockfile
        .packages
        .iter()
        .find(|package| package.alias.as_deref() == Some("ms-alias"))
        .expect("the aliased entry");
    assert_eq!(aliased.name, "ms");
    assert_eq!(aliased.version, "2.1.3");
}

#[test]
fn npm_v1_records_a_git_dependency_with_no_resolved_field() {
    // v1 puts the git URL in the version field and has no `resolved`. Treating the version as a semver
    // string would produce a package at version "git+ssh://...".
    let lockfile = npm_fixture("v1-alias-git-groups.json");
    let git = one_named(&lockfile, "git-dep");
    match &git.source {
        Source::Git { url } => {
            assert!(url.starts_with("git+ssh://"), "{url}");
            assert!(
                url.contains('#'),
                "the resolved commit must be present: {url}"
            );
        }
        other => panic!("expected a git source, got {other:?}"),
    }
    assert!(git.source.is_external());
    assert_eq!(
        git.source.integrity(),
        None,
        "git sources have no integrity"
    );
}

#[test]
fn npm_v3_records_a_git_dependency_as_a_git_url() {
    let lockfile = npm_fixture("v3-git-tarball.json");
    let git = under_key(&lockfile, "node_modules/ms");
    assert!(
        matches!(&git.source, Source::Git { url } if url.starts_with("git+ssh://")),
        "got {:?}",
        git.source
    );
    assert_eq!(git.version, "2.1.3");
}

#[test]
fn npm_does_not_claim_a_direct_tarball_is_a_registry_dependency() {
    // The distinction npm's format does not record. `"tarball"` in the fixture is `ms` fetched from a
    // registry URL under a different install name — the parser reports the URL and the hash it was
    // given, and leaves the "is this a registry?" question to the rule catalog, which owns it.
    let lockfile = npm_fixture("v3-git-tarball.json");
    let direct = lockfile
        .packages
        .iter()
        .find(|package| package.alias.as_deref() == Some("tarball"))
        .expect("the direct-tarball entry");
    match &direct.source {
        Source::Remote { url, integrity } => {
            assert!(
                url.as_deref().is_some_and(|u| u.ends_with(".tgz")),
                "{url:?}"
            );
            assert!(
                integrity.is_some(),
                "npm recorded a hash, so it must survive"
            );
        }
        other => panic!("expected a remote source, got {other:?}"),
    }
    assert_eq!(direct.source.kind(), "remote");
}

#[test]
fn npm_merges_the_two_entry_file_dependency_into_one_package() {
    // Real npm output records `node_modules/thing` with `"link": true` and `vendor/thing` with the
    // version. Emitting both double-counts; emitting only one loses either the name or the version.
    let lockfile = npm_fixture("v3-file-link.json");
    assert_eq!(
        lockfile.packages.len(),
        1,
        "the link and its target are one package, got {:?}",
        lockfile.packages.iter().map(|p| &p.key).collect::<Vec<_>>()
    );
    let thing = &lockfile.packages[0];
    assert_eq!(thing.name, "thing");
    assert_eq!(
        thing.version, "0.0.1",
        "the version lives on the target entry and must be carried across"
    );
    assert_eq!(
        thing.source,
        Source::Directory {
            path: "vendor/thing".to_string()
        }
    );
    assert!(
        !thing.source.is_external(),
        "a file: dependency is repository code"
    );
}

#[test]
fn npm_distinguishes_a_workspace_member_from_a_directory_dependency() {
    let lockfile = npm_fixture("v3-workspace-groups.json");
    let member = one_named(&lockfile, "local-a");
    assert_eq!(
        member.source,
        Source::Workspace {
            path: "packages/local-a".to_string()
        },
        "declared under workspaces: [packages/*], so it is a workspace member"
    );
    assert!(!member.source.is_external());
    // And it must not appear twice, once for the link and once for its own entry.
    assert_eq!(lockfile.entries_named("local-a").len(), 1);
}

#[test]
fn npm_reads_dependency_groups() {
    let lockfile = npm_fixture("v3-workspace-groups.json");
    assert!(one_named(&lockfile, "has-flag").groups.dev, "devDependency");
    assert!(
        one_named(&lockfile, "picocolors").groups.optional,
        "optionalDependency"
    );
    assert!(
        !one_named(&lockfile, "ms").groups.dev && !one_named(&lockfile, "ms").groups.optional,
        "a plain dependency is production"
    );
}

#[test]
fn npm_v3_reports_install_script_knowledge_and_v1_does_not() {
    // esbuild declares an install script; npm v3 records that as `hasInstallScript: true`.
    let v3 = npm_fixture("v3-install-script.json");
    let esbuild = one_named(&v3, "esbuild");
    assert_eq!(
        esbuild.has_install_script,
        Some(true),
        "npm recorded hasInstallScript: true, so it must reach the model"
    );
    let ms = at_version(&v3, "ms", "2.1.3");
    assert_eq!(
        ms.has_install_script,
        Some(false),
        "npm said nothing, which for v3 means there is none"
    );

    // v1 cannot tell us at all, which is a different claim.
    let v1 = npm_fixture("v1-nested-duplicate.json");
    for package in &v1.packages {
        assert_eq!(
            package.has_install_script, None,
            "{} in a v1 lockfile: the format carries no such field",
            package.name
        );
    }
}

#[test]
fn npm_reads_scoped_names_intact() {
    let lockfile = npm_fixture("v3-alias-scoped-nested.json");
    let scoped = one_named(&lockfile, "@babel/code-frame");
    assert_eq!(scoped.version, "7.24.7");
    assert_eq!(scoped.key, "node_modules/@babel/code-frame");
}

// ---------------------------------------------------------------------------------------------
// pnpm: three notations for the same facts
// ---------------------------------------------------------------------------------------------

#[test]
fn all_three_pnpm_notations_yield_the_same_dependency_set() {
    // The strongest statement this suite can make: three real files, three different key notations,
    // one answer. If a notation were mis-split, its set would differ.
    let expected: Vec<(&str, &str)> = vec![("debug", "4.3.4"), ("ms", "2.1.2"), ("ms", "2.1.3")];

    for name in ["v5-basic.yaml", "v6-basic.yaml", "v9-basic.yaml"] {
        let lockfile = pnpm_fixture(name);
        let mut got: Vec<(String, String)> = lockfile
            .packages
            .iter()
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect();
        got.sort();
        let got_refs: Vec<(&str, &str)> = got
            .iter()
            .map(|(name, version)| (name.as_str(), version.as_str()))
            .collect();
        assert_eq!(
            got_refs, expected,
            "{name} disagrees with the other notations"
        );
    }
}

#[test]
fn a_pnpm_peer_suffix_never_reaches_the_version() {
    // `debug@4.3.4(supports-color@9.4.0)` is debug at 4.3.4. Reading the suffix as part of the version
    // reports a version that does not exist on the registry, and makes a peer-only change look like a
    // package change.
    //
    // The `-basic` fixtures have no peer suffix and the `-alias-peer` ones do, which is why both sets
    // are checked: the suffix must be stripped where present and not invented where absent.
    for name in [
        "v5-alias-peer.yaml",
        "v6-alias-peer.yaml",
        "v9-alias-peer.yaml",
    ] {
        let lockfile = pnpm_fixture(name);
        let debug = one_named(&lockfile, "debug");
        assert_eq!(
            debug.version, "4.3.4",
            "{name}: the peer suffix leaked into the version"
        );
        assert!(
            debug.key.contains("4.3.4"),
            "{name}: the raw key is kept verbatim for greppability: {}",
            debug.key
        );
    }

    // pnpm 6.0 and 9.0 spell the suffix in parentheses; 5.4 uses an underscore. At least one fixture
    // must actually contain each spelling, or this test would pass against files that never exercise
    // the stripping.
    let v6 = pnpm_fixture("v6-alias-peer.yaml");
    assert!(
        one_named(&v6, "debug").key.contains("(supports-color@"),
        "the v6 fixture must contain a parenthesised peer suffix, or the test proves nothing"
    );
    let v5 = pnpm_fixture("v5-alias-peer.yaml");
    assert!(
        one_named(&v5, "debug").key.contains("_supports-color@"),
        "the v5 fixture must contain an underscore peer suffix"
    );
}

#[test]
fn a_pnpm_git_key_that_is_a_url_is_parsed_correctly() {
    // pnpm 9 keys a github: dependency as `ms@https://codeload.github.com/...`. A naive rsplit('@')
    // yields a version of "https:" and a name containing the URL.
    let lockfile = pnpm_fixture("v9-git-only.yaml");
    let ms = one_named(&lockfile, "ms");
    assert_eq!(
        ms.version, "2.1.3",
        "the version comes from the entry's version field, not from the key"
    );
    match &ms.source {
        Source::Remote { url, .. } => assert!(
            url.as_deref()
                .is_some_and(|u| u.starts_with("https://codeload.github.com/")),
            "{url:?}"
        ),
        other => panic!("expected a remote tarball source, got {other:?}"),
    }
    assert!(ms.source.is_external());
}

#[test]
fn pnpm_5x_and_6x_git_keys_defer_to_the_name_field() {
    // 5.x/6.0 key it `github.com/vercel/ms/<sha>` — a host path, not a package name — and put the real
    // name in a `name:` field. Using the key as the name would report a package called
    // "github.com/vercel/ms/1c6264b...".
    for name in ["v5-git-file.yaml", "v6-git-file.yaml"] {
        let lockfile = pnpm_fixture(name);
        let git = lockfile
            .packages
            .iter()
            .find(|package| package.key.starts_with("github.com/"))
            .unwrap_or_else(|| panic!("{name}: no github.com/ keyed entry"));
        assert_eq!(
            git.name, "ms",
            "{name}: the name must come from the name field, not the key"
        );
        assert_eq!(git.version, "2.1.3", "{name}");
        assert!(git.source.is_external());

        // The registry `ms@2.1.2` in the same file is a separate entry and must not be confused with it.
        let registry = at_version(&lockfile, "ms", "2.1.2");
        assert!(registry.key.contains("/ms"), "{name}: {}", registry.key);
    }
}

#[test]
fn pnpm_reads_a_file_dependency_as_repository_code() {
    for name in ["v5-git-file.yaml", "v6-git-file.yaml", "v9-git-file.yaml"] {
        let lockfile = pnpm_fixture(name);
        let local = one_named(&lockfile, "local-dir");
        assert!(
            matches!(&local.source, Source::Directory { .. }),
            "{name}: expected a directory source, got {:?}",
            local.source
        );
        assert!(
            !local.source.is_external(),
            "{name}: a file: dependency is not third-party code"
        );
    }
}

#[test]
fn pnpm_reads_dependency_groups_in_every_notation() {
    // The `dev` trap. 5.x/6.0 carry a per-package flag; 9.0 dropped it entirely and the groups have to
    // come from the importer sections. A parser that read a missing flag as "production" would
    // misreport every dev dependency in every modern pnpm repository.
    for name in ["v5-groups.yaml", "v6-groups.yaml", "v9-groups.yaml"] {
        let lockfile = pnpm_fixture(name);

        let chalk = one_named(&lockfile, "chalk");
        assert!(
            chalk.groups.dev,
            "{name}: chalk is a devDependency and must be reported as one"
        );

        let debug = one_named(&lockfile, "debug");
        assert!(
            !debug.groups.dev,
            "{name}: debug is a production dependency"
        );

        let picocolors = one_named(&lockfile, "picocolors");
        assert!(
            picocolors.groups.optional,
            "{name}: picocolors is an optionalDependency"
        );
        assert!(
            !picocolors.groups.dev,
            "{name}: an optional dependency is not a dev dependency"
        );
    }
}

#[test]
fn pnpm_reads_workspace_importers_in_every_notation() {
    for name in [
        "v5-workspace.yaml",
        "v6-workspace.yaml",
        "v9-workspace.yaml",
    ] {
        let lockfile = pnpm_fixture(name);
        assert!(
            one_named(&lockfile, "has-flag").groups.dev,
            "{name}: a root devDependency in a workspace must still be dev"
        );
        assert!(
            !one_named(&lockfile, "ms").groups.dev,
            "{name}: a workspace member's dependency is production"
        );
    }
}

#[test]
fn pnpm_reads_scoped_names_in_every_notation() {
    for name in [
        "v5-alias-peer.yaml",
        "v6-alias-peer.yaml",
        "v9-alias-peer.yaml",
    ] {
        let lockfile = pnpm_fixture(name);
        let scoped = one_named(&lockfile, "@babel/code-frame");
        assert_eq!(scoped.version, "7.24.7", "{name}");
    }
}

#[test]
fn pnpm_records_no_url_for_a_registry_package() {
    // pnpm stores only the integrity hash; the registry host is configuration, not a lockfile fact.
    // Reconstructing a URL would be inventing evidence.
    let lockfile = pnpm_fixture("v9-basic.yaml");
    let ms = lockfile
        .entries_named("ms")
        .into_iter()
        .find(|package| package.version == "2.1.3")
        .expect("ms@2.1.3");
    match &ms.source {
        Source::Remote { url, integrity } => {
            assert_eq!(*url, None, "pnpm records no URL, so none may be invented");
            assert!(integrity.is_some());
        }
        other => panic!("expected a remote source, got {other:?}"),
    }
}

#[test]
fn the_declared_version_is_reported_verbatim() {
    // npm writes a number, pnpm writes a string. A report claiming "lockfileVersion 9" when the file
    // says '9.0' is a small lie that costs trust for nothing.
    assert_eq!(
        npm_fixture("v1-nested-duplicate.json").declared_version,
        "1"
    );
    assert_eq!(
        npm_fixture("v2-dual-representation.json").declared_version,
        "2"
    );
    assert_eq!(
        npm_fixture("v3-alias-scoped-nested.json").declared_version,
        "3"
    );
    assert_eq!(pnpm_fixture("v5-basic.yaml").declared_version, "5.4");
    assert_eq!(pnpm_fixture("v6-basic.yaml").declared_version, "6.0");
    assert_eq!(pnpm_fixture("v9-basic.yaml").declared_version, "9.0");
}

#[test]
fn parsing_is_deterministic_across_every_fixture() {
    // Two reads of one file must be byte-identical, or the Action would post a different comment on a
    // re-run and a reviewer would see a phantom change.
    for (name, text) in all_fixtures("npm") {
        assert_eq!(
            npm::parse(&text).expect("first"),
            npm::parse(&text).expect("second"),
            "npm/{name} parsed differently on a second pass"
        );
    }
    for (name, text) in all_fixtures("pnpm") {
        assert_eq!(
            pnpm::parse(&text).expect("first"),
            pnpm::parse(&text).expect("second"),
            "pnpm/{name} parsed differently on a second pass"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Diffing real files
// ---------------------------------------------------------------------------------------------

#[test]
fn a_lockfile_diffed_against_itself_is_empty_for_every_fixture() {
    // The most common real case: a PR touches a lockfile without changing the resolved set. Any noise
    // here becomes noise on every such PR, which is how a tool gets muted.
    for (name, text) in all_fixtures("npm") {
        let lockfile = npm::parse(&text).expect("parse");
        let result = diff(&lockfile, &lockfile);
        assert!(
            result.is_empty(),
            "npm/{name}: self-diff produced {:?}",
            result.changes
        );
        assert!(!result.should_record(), "npm/{name}");
    }
    for (name, text) in all_fixtures("pnpm") {
        let lockfile = pnpm::parse(&text).expect("parse");
        let result = diff(&lockfile, &lockfile);
        assert!(
            result.is_empty(),
            "pnpm/{name}: self-diff produced {:?}",
            result.changes
        );
    }
}

#[test]
fn adding_dependencies_is_detected_across_real_files() {
    // The smaller fixture grew into the larger one: same package.json plus @babel/code-frame, an alias
    // and supports-color.
    let before = npm_fixture("v1-nested-duplicate.json");
    let after = npm_fixture("v3-alias-scoped-nested.json");

    let result = diff(&before, &after);
    assert!(
        result.should_record(),
        "new packages must trigger a recording"
    );

    let added: Vec<&str> = result
        .changes
        .iter()
        .filter(|change| matches!(change, Change::Added { .. }))
        .map(Change::name)
        .collect();
    assert!(
        added.contains(&"@babel/code-frame"),
        "the scoped addition must be found: {added:?}"
    );
    assert!(
        added.contains(&"supports-color"),
        "supports-color was added: {added:?}"
    );
    assert!(
        !result.ecosystem_changed,
        "both files are npm, however different their formats"
    );
}

#[test]
fn the_same_tree_read_through_two_npm_formats_produces_no_spurious_changes() {
    // v1 and v2 of the same resolved tree. The formats differ enormously — v1 has no `packages` map at
    // all — but the dependency set is identical, so the only differences a diff may report are ones
    // caused by information v1 does not carry.
    let v1 = npm_fixture("v1-nested-duplicate.json");
    let v2 = npm_fixture("v2-dual-representation.json");

    let result = diff(&v1, &v2);
    assert!(
        !result.should_record(),
        "reading the same tree through two formats must not look like new code: {:?}",
        result.changes
    );
    assert!(
        result.is_empty(),
        "a format difference is not a dependency change: {:?}",
        result.changes
    );
}

#[test]
fn the_same_tree_read_through_three_pnpm_notations_produces_no_changes() {
    let v5 = pnpm_fixture("v5-basic.yaml");
    let v6 = pnpm_fixture("v6-basic.yaml");
    let v9 = pnpm_fixture("v9-basic.yaml");

    for (left_name, left) in [("v5", &v5), ("v6", &v6)] {
        for (right_name, right) in [("v6", &v6), ("v9", &v9)] {
            let result = diff(left, right);
            assert!(
                result.is_empty(),
                "{left_name} vs {right_name}: notation differences are not dependency changes: {:?}",
                result.changes
            );
        }
    }
}

#[test]
fn an_npm_to_pnpm_migration_is_flagged_as_an_ecosystem_change() {
    // A real migration PR. Every package is being reinstalled by a different tool, and a report that
    // presented that as a hundred ordinary additions would be useless.
    let npm = npm_fixture("v1-nested-duplicate.json");
    let pnpm = pnpm_fixture("v9-basic.yaml");

    let result = diff(&npm, &pnpm);
    assert!(result.ecosystem_changed);
    // The two files describe the same three packages, so the *set* has not changed even though the
    // tool has. That the diff is quiet here is the point: the ecosystem flag carries the news.
    assert!(
        result.is_empty(),
        "the same dependency set through two package managers: {:?}",
        result.changes
    );
}

#[test]
fn a_workspace_addition_does_not_report_third_party_changes() {
    let before = npm_fixture("v1-nested-duplicate.json");
    let after = npm_fixture("v3-workspace-groups.json");

    let result = diff(&before, &after);
    for change in &result.changes {
        assert_ne!(
            change.name(),
            "local-a",
            "a workspace member must never be reported as a dependency change"
        );
    }
}

#[test]
fn diffing_is_deterministic() {
    let before = npm_fixture("v1-nested-duplicate.json");
    let after = npm_fixture("v3-alias-scoped-nested.json");
    assert_eq!(diff(&before, &after), diff(&before, &after));
}

// ---------------------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------------------

#[test]
fn a_pnpm_lockfile_is_not_accepted_by_the_npm_parser() {
    // A crossed wire must fail loudly. Parsing YAML as JSON happens to fail anyway, but the assertion
    // pins the behaviour rather than relying on the coincidence.
    assert!(matches!(
        npm::parse(&fixture("pnpm/v9-basic.yaml")).expect_err("must refuse"),
        LockfileError::Json(_)
    ));
}

#[test]
fn an_npm_lockfile_read_as_pnpm_is_refused() {
    // The dangerous direction: JSON *is* valid YAML, so this parses structurally and must be caught by
    // the version check rather than by luck.
    let err = pnpm::parse(&fixture("npm/v3-alias-scoped-nested.json")).expect_err("must refuse");
    assert!(
        matches!(
            err,
            LockfileError::UnsupportedVersion { .. } | LockfileError::MissingVersion { .. }
        ),
        "an npm lockfile must not be silently read as pnpm: got {err}"
    );
}

#[test]
fn an_empty_file_is_an_error_not_an_empty_dependency_set() {
    // Reporting "no dependencies" for an unreadable file is the failure direction that matters: it
    // looks like a clean result.
    assert!(npm::parse("").is_err());
    assert!(pnpm::parse("").is_err());
}
