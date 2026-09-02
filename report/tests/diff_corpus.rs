//! Golden tests for the version-diff engine and its renderers.
//!
//! The claim under test is the one Architecture.md:90 calls the moat: *"this package's behavior changed
//! between 1.2.3 and 1.2.4."* It rests entirely on a property that is easy to assert and easy to get
//! wrong — that two recordings of the same behavior, made on different machines at different times,
//! reduce to the same thing.
//!
//! `corpus/demo/diff-before.jsonl` and `diff-after.jsonl` differ in every incidental respect: project
//! directory, cache directory, home, pids, timestamps, resolver, registry IP, kernel, even the byte count
//! of a written file. If any of that leaked into the comparison, every pair of recordings would differ
//! and the diff would be noise. These tests are where that is checked.
//!
//! Both fixtures are labelled synthetic (`Rules.md` §5) and describe a package that does not exist.

use installscope_core::Event;
use installscope_registry::{compare, profile_of, Behavior, BehaviorClass, Comparison, Recording};
use installscope_report::{render_diff_html, render_diff_markdown};

/// Loads a demo fixture and reduces it to a comparable recording.
fn recording(name: &str, version: &str) -> Recording {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("corpus")
        .join("demo")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));

    let events: Vec<Event> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            Event::from_jsonl(line, index + 1)
                .unwrap_or_else(|error| panic!("{name} line {}: {error}", index + 1))
        })
        .collect();

    let agent_version = events
        .iter()
        .find_map(|event| match &event.payload {
            installscope_core::Payload::SessionStart(start) => Some(start.agent_version.clone()),
            _ => None,
        })
        .unwrap_or_default();

    Recording {
        version: version.to_string(),
        agent_version,
        profile: profile_of(&events),
    }
}

/// The comparison under test.
fn drifting_pkg() -> Comparison {
    compare(
        "SYNTHETIC-drifting-pkg",
        &recording("diff-before.jsonl", "1.4.2"),
        &recording("diff-after.jsonl", "1.4.3"),
    )
}

/// Every summary line on one side of the comparison.
fn summaries(behaviors: &[Behavior]) -> Vec<String> {
    behaviors.iter().map(Behavior::summary).collect()
}

#[test]
fn both_fixtures_are_complete_recordings() {
    // A PARTIAL fixture would block the comparison, and every assertion below would pass for the wrong
    // reason.
    let before = recording("diff-before.jsonl", "1.4.2");
    let after = recording("diff-after.jsonl", "1.4.3");
    assert!(
        before.profile.complete,
        "the before fixture must be complete"
    );
    assert!(after.profile.complete, "the after fixture must be complete");
    assert_eq!(before.profile.backend, after.profile.backend);
}

#[test]
fn the_comparison_is_sound() {
    let comparison = drifting_pkg();
    assert!(
        comparison.comparable(),
        "two complete strace recordings must be comparable: {:?}",
        comparison.blockers
    );
    assert!(!comparison.is_identical());
    assert!(
        comparison.headline().contains("behavior changed"),
        "{}",
        comparison.headline()
    );
}

#[test]
fn no_incidental_difference_is_reported_as_a_behavioral_change() {
    // THE test. Every path in the two fixtures lives under a different root, the pids and timestamps
    // differ, and the byte counts differ. None of it may appear in the diff.
    let comparison = drifting_pkg();
    let all: Vec<String> = summaries(&comparison.added)
        .into_iter()
        .chain(summaries(&comparison.removed))
        .collect();

    for leak in [
        "repo-4f2a1c",
        "backfill-8b3d",
        "/home/runner/.npm",
        "npm-cache",
        "104.16.2.34",
        "104.16.9.12",
        "127.0.0.53",
        "8.8.8.8",
        "7100",
        "9200",
        "4096",
        "5120",
    ] {
        assert!(
            !all.iter().any(|line| line.contains(leak)),
            "{leak:?} is incidental to the recording and must not appear in a behavioral diff: {all:?}"
        );
    }
}

#[test]
fn the_shared_behaviors_report_as_unchanged() {
    // The complement: the writes, the registry lookup, the cache write, the .npmrc read, the /dev/null
    // write and the postinstall spawn are common to both versions and must not appear as changes.
    let comparison = drifting_pkg();
    assert!(
        comparison.unchanged >= 8,
        "expected the shared behaviors to be recognised, got {} unchanged",
        comparison.unchanged
    );

    let changed: Vec<String> = summaries(&comparison.added)
        .into_iter()
        .chain(summaries(&comparison.removed))
        .collect();
    for shared in [
        "registry.npmjs.org",
        "SYNTHETIC-drifting-pkg/index.js",
        "SYNTHETIC-drifting-pkg/package.json",
        "_cacache",
        ".npmrc",
        "/dev/null",
    ] {
        assert!(
            !changed.iter().any(|line| line.contains(shared)),
            "{shared:?} appears in both recordings and must not be reported as changed: {changed:?}"
        );
    }
}

#[test]
fn nothing_is_reported_as_removed() {
    // 1.4.3 does everything 1.4.2 did and more. A spurious removal would mean a shared behavior failed
    // to match across the two directory layouts, which is the failure this fixture pair exists to catch.
    let comparison = drifting_pkg();
    assert!(
        comparison.removed.is_empty(),
        "1.4.3 removed nothing; a reported removal means a shared behavior failed to match: {:?}",
        summaries(&comparison.removed)
    );
}

#[test]
fn every_genuinely_new_behavior_is_reported() {
    let comparison = drifting_pkg();
    let added = summaries(&comparison.added);

    for expected in [
        // The new hostname.
        "metrics.synthetic-vendor.example",
        // The unusual port.
        "port 8443",
        // The credential read attempt — failed, and still evidence of intent.
        ".ssh/id_rsa",
        // The write outside every declared zone.
        "/etc/cron.d/SYNTHETIC-vendor-sync",
        // The download piped into a shell.
        "piped curl",
        // The permission change inside node_modules.
        "changed permissions on",
    ] {
        assert!(
            added.iter().any(|line| line.contains(expected)),
            "the diff must report {expected:?}: {added:?}"
        );
    }
}

#[test]
fn the_new_hostname_is_lowercased_consistently() {
    // DNS is case-insensitive, and the fixture spells the host with mixed case on purpose. A diff that
    // preserved the case would report a changed host whenever a resolver echoed it differently.
    let comparison = drifting_pkg();
    let added = summaries(&comparison.added);
    assert!(
        added
            .iter()
            .any(|line| line.contains("metrics.synthetic-vendor.example")),
        "the qname must be lowercased: {added:?}"
    );
}

#[test]
fn the_escape_and_the_pipeline_are_classified_correctly() {
    // Classification drives the ordering in every renderer, so it is asserted directly rather than only
    // through the rendered text.
    let comparison = drifting_pkg();
    assert_eq!(
        comparison.added_in(BehaviorClass::FilesystemEscape).len(),
        1,
        "exactly one write outside the declared zones: {:?}",
        summaries(&comparison.added)
    );
    assert_eq!(
        comparison.added_in(BehaviorClass::CredentialRead).len(),
        1,
        "the ssh key read attempt"
    );
    assert!(
        comparison.added_in(BehaviorClass::Network).len() >= 2,
        "a new hostname and a new port"
    );
    assert!(
        comparison.added_in(BehaviorClass::Process).len() >= 2,
        "sh, curl, and the pipeline"
    );
}

#[test]
fn the_port_zero_probe_is_not_a_behavior() {
    // Both fixtures contain a port-0 connect, which is glibc probing candidate addresses (Memory.md,
    // Phase 1 limitations). It must not be a behavior on either side, or every recording that resolved a
    // name would carry it.
    let comparison = drifting_pkg();
    let all: Vec<String> = summaries(&comparison.added)
        .into_iter()
        .chain(summaries(&comparison.removed))
        .collect();
    assert!(
        !all.iter().any(|line| line.contains("port 0")),
        "port 0 is a resolver probe, not a destination: {all:?}"
    );
}

#[test]
fn the_highlights_lead_with_the_escape() {
    // A three-bullet summary has to spend its bullets on what matters most. The write outside the
    // project is the critical class (Architecture.md §4).
    let comparison = drifting_pkg();
    let highlights = comparison.highlights(3);
    assert_eq!(highlights.len(), 3);
    assert_eq!(
        highlights[0].class(),
        BehaviorClass::FilesystemEscape,
        "the escape must lead: {:?}",
        highlights.iter().map(|b| b.summary()).collect::<Vec<_>>()
    );
}

#[test]
fn the_markdown_surface_reports_the_change() {
    let comparison = drifting_pkg();
    let rendered = render_diff_markdown(&comparison);

    assert!(rendered.contains("behavior changed"), "{rendered}");
    assert!(rendered.contains("1.4.2"), "{rendered}");
    assert!(rendered.contains("1.4.3"), "{rendered}");
    assert!(
        rendered.contains("/etc/cron.d/SYNTHETIC-vendor-sync"),
        "{rendered}"
    );
    assert!(
        rendered.contains("metrics.synthetic-vendor.example"),
        "{rendered}"
    );
    assert!(rendered.contains("piped curl"), "{rendered}");
    // Advisory, not a verdict (PRD.md:43).
    assert!(!rendered.contains("FAIL"), "{rendered}");
}

#[test]
fn the_html_surface_is_self_contained_and_two_column() {
    let comparison = drifting_pkg();
    let rendered = render_diff_html(&comparison);

    assert!(rendered.starts_with("<!DOCTYPE html>"));
    assert!(rendered.contains("</html>"));
    assert!(rendered.contains("class=\"columns\""));
    assert!(rendered.contains("1.4.2"));
    assert!(rendered.contains("1.4.3"));
    // Rules.md §1: the artifact must render without a network.
    assert!(!rendered.contains("@import"), "{rendered}");
    assert!(!rendered.contains("<script"), "{rendered}");
    assert!(!rendered.contains("fonts.googleapis"), "{rendered}");
    assert!(rendered.contains("Advisory"));
}

#[test]
fn a_recording_compared_against_itself_reports_no_change() {
    // The case that would embarrass the product most: a re-record of an unchanged version must be quiet.
    for (name, version) in [
        ("diff-before.jsonl", "1.4.2"),
        ("diff-after.jsonl", "1.4.3"),
    ] {
        let comparison = compare(
            "SYNTHETIC-drifting-pkg",
            &recording(name, version),
            &recording(name, version),
        );
        assert!(comparison.comparable());
        assert!(
            comparison.is_identical(),
            "{name} compared against itself reported changes: added {:?} removed {:?}",
            summaries(&comparison.added),
            summaries(&comparison.removed)
        );
        assert!(comparison.headline().contains("behaved identically"));
    }
}

#[test]
fn reversing_the_comparison_swaps_added_and_removed() {
    // Direction is meaningful and must be symmetric. An asymmetry would mean one of the two set
    // differences is computed against the wrong side.
    let forward = drifting_pkg();
    let backward = compare(
        "SYNTHETIC-drifting-pkg",
        &recording("diff-after.jsonl", "1.4.3"),
        &recording("diff-before.jsonl", "1.4.2"),
    );

    assert_eq!(summaries(&forward.added), summaries(&backward.removed));
    assert_eq!(summaries(&forward.removed), summaries(&backward.added));
    assert_eq!(forward.unchanged, backward.unchanged);
}

#[test]
fn both_surfaces_are_deterministic() {
    // A digest over an artifact means nothing if two renders differ, and a bot re-posting a comment would
    // show a phantom change.
    let comparison = drifting_pkg();
    assert_eq!(
        render_diff_markdown(&comparison),
        render_diff_markdown(&comparison)
    );
    assert_eq!(render_diff_html(&comparison), render_diff_html(&comparison));
    // And the comparison itself, since the renderers only reflect it.
    assert_eq!(drifting_pkg(), drifting_pkg());
}

#[test]
fn the_fixtures_are_labelled_synthetic() {
    // Rules.md §5: a fabricated recording presented as real would be the exact failure this product
    // exists to detect in other tools. The label is in the data, not only in the README, because a
    // fixture travels further than its directory.
    for name in ["diff-before.jsonl", "diff-after.jsonl"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("corpus")
            .join("demo")
            .join(name);
        let text = std::fs::read_to_string(&path).expect("read fixture");
        assert!(
            text.contains("SYNTHETIC"),
            "{name} must carry the SYNTHETIC label in its own contents"
        );
    }
}
