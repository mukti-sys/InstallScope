//! Golden tests over the demo corpus.
//!
//! Fixtures in `corpus/demo/` are **synthetic and labelled as such** (`Rules.md` §5); see that
//! directory's README. They exist to pin the engine's behaviour at each level of the score range, so a
//! change in scoring shows up as a failing assertion rather than as a surprise in a report.
//!
//! Expectations live here rather than in files next to the fixtures. A stored expectation drifts
//! silently; a test fails loudly.

use std::path::{Path, PathBuf};

use installscope_core::{evaluate, Analysis, Backend, Catalog, Event, Severity};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("corpus")
        .join("demo")
        .join(name)
}

/// Parses a fixture, failing loudly on a malformed line.
///
/// Deliberately strict: a fixture with a bad line would otherwise quietly analyse fewer events and the
/// expectations below would pass for the wrong reason.
fn load(name: &str) -> Vec<Event> {
    let path = fixture_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            Event::from_jsonl(line, index + 1)
                .unwrap_or_else(|error| panic!("{} line {}: {error}", path.display(), index + 1))
        })
        .collect()
}

fn analyse(name: &str) -> Analysis {
    let catalog = Catalog::embedded().expect("the shipped catalog must validate");
    evaluate(&catalog, &load(name))
}

fn rule_ids(analysis: &Analysis) -> Vec<&str> {
    analysis
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect()
}

// =============================================================================================
// clean
// =============================================================================================

#[test]
fn a_clean_install_scores_zero() {
    // The most important assertion in the suite. If an ordinary install scores above zero, the product
    // is unusable regardless of how good its critical detection is (PRD.md:43).
    let analysis = analyse("clean.jsonl");
    assert_eq!(
        analysis.score.value,
        0,
        "an ordinary install must score zero; findings were {:?}",
        rule_ids(&analysis)
    );
    assert_eq!(analysis.score.raw, 0);
    assert!(analysis.score.is_clean());
    assert!(!analysis.is_partial());
}

#[test]
fn a_clean_install_still_shows_informational_evidence() {
    // Design.md:43 makes silence a designed state that renders as evidence. An empty report would be
    // less useful than one saying what was seen and found ordinary.
    let analysis = analyse("clean.jsonl");
    assert!(
        !analysis.findings.is_empty(),
        "a clean install should still report what it saw"
    );
    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.severity == Severity::Low),
        "everything in a clean install must be informational: {:?}",
        analysis
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity))
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_things_that_look_suspicious_in_a_clean_install_are_not_scored() {
    // Each of these is present in the fixture precisely because a naive rule set fires on it.
    let analysis = analyse("clean.jsonl");
    let ids = rule_ids(&analysis);

    // Three port-0 resolver probes.
    assert!(
        !ids.contains(&"network_connect_unusual_port"),
        "port 0 is a resolver probe, not an unusual port"
    );
    // An .npmrc read, which matches the credential path list.
    assert!(
        !ids.contains(&"credential_path_read"),
        "npm reading its own config is not a credential finding"
    );
    assert!(
        ids.contains(&"npmrc_read"),
        "but it is reported informationally"
    );
    // Writes to /proc and /dev.
    assert!(
        !ids.contains(&"write_outside_expected_dirs"),
        "kernel pseudo-paths are not filesystem escapes"
    );
    // A registry lookup.
    assert!(!ids.contains(&"dns_non_registry_host"));
}

#[test]
fn a_clean_strace_result_is_trustworthy() {
    // Complete recording, no blind spots, no unresolved paths — the three conditions under which a zero
    // score is a statement about the install rather than about the recording.
    let analysis = analyse("clean.jsonl");
    assert!(analysis.clean_result_is_trustworthy());
    assert_eq!(analysis.unresolved_paths, 0);
    assert!(analysis.coverage.is_complete());
    assert!(analysis.skipped_rules.is_empty());
    assert_eq!(analysis.coverage.caveat_line(), None);
}

// =============================================================================================
// high
// =============================================================================================

#[test]
fn a_native_build_scores_in_the_middle_of_the_range() {
    // A package that fetches headers and compiles them is worth a look and is not alarming. This is the
    // level most real findings will land at, so the exact arithmetic is pinned.
    //
    // 15 (curl spawn) + 5 (nodejs.org as a binary distribution host) + 5 (the vendor postinstall helper,
    // which is not on the expected-toolchain list) = 25. `tar` and `make` are on that list and correctly
    // do not score, which is the point of having it.
    let analysis = analyse("high.jsonl");

    assert_eq!(
        analysis.score.value,
        25,
        "findings were {:?}",
        analysis
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity, f.subject.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(!analysis.score.was_capped());
    assert_eq!(analysis.score.counts.critical, 0, "nothing alarming here");
    assert_eq!(analysis.score.counts.high, 1, "only the curl spawn");
    assert_eq!(analysis.score.counts.medium, 2);
}

#[test]
fn a_binary_download_is_reported_but_not_alarming() {
    let analysis = analyse("high.jsonl");
    let ids = rule_ids(&analysis);

    assert!(
        ids.contains(&"spawned_network_tool"),
        "curl during an install is worth reporting: {ids:?}"
    );
    assert!(
        ids.contains(&"dns_binary_distribution_host"),
        "nodejs.org is a known distribution host, reported at medium: {ids:?}"
    );
    assert!(
        !ids.contains(&"download_piped_to_shell"),
        "curl -o writes a file; it does not execute what it downloaded"
    );
    assert!(
        !ids.contains(&"write_outside_expected_dirs"),
        "the build writes into the project and tmp, both declared"
    );
}

#[test]
fn the_worst_finding_leads_the_bullets() {
    let analysis = analyse("high.jsonl");
    let bullets = installscope_core::select_bullets(&analysis.findings);
    assert!(!bullets.is_empty());
    assert_eq!(
        bullets[0].severity,
        Severity::High,
        "the highest severity present must lead"
    );
    assert!(bullets.len() <= 3, "PRD.md:57 caps the comment at three");
}

// =============================================================================================
// critical
// =============================================================================================

#[test]
fn a_hostile_package_reaches_the_cap() {
    let analysis = analyse("critical.jsonl");

    assert_eq!(analysis.score.value, 100);
    assert!(
        analysis.score.was_capped(),
        "the raw sum should exceed the cap, and the excess must stay visible"
    );
    assert!(
        analysis.score.raw > 100,
        "raw was {}, which would mean the cap never fired",
        analysis.score.raw
    );
    assert!(analysis.score.counts.critical >= 2);
}

#[test]
fn every_critical_behaviour_in_the_fixture_is_found() {
    // The fixture contains each shape the catalog calls critical or high. A missing one means a rule
    // silently stopped matching.
    let analysis = analyse("critical.jsonl");
    let ids = rule_ids(&analysis);

    for expected in [
        "download_piped_to_shell",
        "write_outside_expected_dirs",
        "chmod_exec_outside_project",
        "credential_path_read",
        "credential_path_read_attempted",
        "dns_non_registry_host",
        "network_connect_unusual_port",
        "spawned_network_tool",
        "spawned_unexpected_binary",
    ] {
        assert!(ids.contains(&expected), "{expected} did not fire: {ids:?}");
    }
}

#[test]
fn the_critical_findings_come_first() {
    let analysis = analyse("critical.jsonl");
    let severities: Vec<Severity> = analysis
        .findings
        .iter()
        .map(|finding| finding.severity)
        .collect();
    let mut sorted = severities.clone();
    sorted.sort_unstable();
    assert_eq!(
        severities, sorted,
        "findings must be ordered most severe first"
    );
    assert_eq!(severities.first(), Some(&Severity::Critical));

    // And the three bullets are all criticals, because two exist and nothing should displace them.
    let bullets = installscope_core::select_bullets(&analysis.findings);
    assert_eq!(bullets.len(), 3);
    assert_eq!(bullets[0].severity, Severity::Critical);
    assert_eq!(bullets[1].severity, Severity::Critical);
}

#[test]
fn the_credential_read_names_the_file_it_read() {
    // Evidence, not assertion. A finding a reader cannot trace to a specific path is an opinion.
    let analysis = analyse("critical.jsonl");
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.rule_id == "credential_path_read")
        .expect("the SSH key read must be found");
    assert!(
        finding.subject.contains(".ssh/id_rsa") || finding.subject.contains(".env"),
        "subject was {:?}",
        finding.subject
    );
    assert!(!finding.evidence.is_empty());
    assert!(finding.evidence[0].ts_ns > 0);
}

// =============================================================================================
// partial
// =============================================================================================

#[test]
fn a_partial_recording_reports_its_findings_and_its_incompleteness() {
    // PRD.md:58. The score is real — a write to /etc/ld.so.preload happened — but the recording stopped
    // early, so the report must not imply that is all that happened.
    let analysis = analyse("partial.jsonl");

    assert_eq!(analysis.score.value, 40, "the finding it did see is real");
    assert!(analysis.is_partial());
    assert!(
        !analysis.clean_result_is_trustworthy(),
        "a PARTIAL recording cannot support a trustworthy verdict"
    );
    assert_eq!(analysis.partial_reasons.len(), 1);
    assert!(
        analysis.partial_reasons[0].contains("120s"),
        "the reason must be specific: {:?}",
        analysis.partial_reasons
    );
}

// =============================================================================================
// aya coverage
// =============================================================================================

#[test]
fn an_aya_clean_result_carries_its_caveat() {
    // The Phase 2 Option A decision made visible. A zero from aya is weaker than a zero from strace, and
    // the report must say so rather than presenting them as equivalent.
    let analysis = analyse("aya-clean.jsonl");

    assert_eq!(analysis.score.value, 0);
    assert_eq!(analysis.coverage.backend, Backend::Aya);
    assert!(
        !analysis.clean_result_is_trustworthy(),
        "aya has blind spots and unresolved paths; a clean score is not the whole story"
    );

    let caveat = analysis
        .coverage
        .caveat_line()
        .expect("aya must produce a caveat");
    assert!(caveat.contains("credential reads"));
    assert!(caveat.contains("DNS queries"));
    assert!(caveat.contains("not evidence"));
}

#[test]
fn aya_unresolved_paths_are_counted_not_scored() {
    // Three of the fixture's writes carry unresolved paths, including one to "<unknown descriptor>".
    // None may become a filesystem escape.
    let analysis = analyse("aya-clean.jsonl");
    assert!(
        analysis.unresolved_paths >= 3,
        "expected the unresolved writes to be counted, got {}",
        analysis.unresolved_paths
    );
    assert!(
        !rule_ids(&analysis).contains(&"write_outside_expected_dirs"),
        "an unresolved path must never raise the critical rule"
    );
}

#[test]
fn aya_names_the_rules_it_could_not_run() {
    let analysis = analyse("aya-clean.jsonl");
    let skipped: Vec<&str> = analysis
        .skipped_rules
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();

    assert!(skipped.contains(&"credential_path_read"), "{skipped:?}");
    assert!(skipped.contains(&"dns_non_registry_host"), "{skipped:?}");
    for (id, reason) in &analysis.skipped_rules {
        assert!(
            reason.len() > 30,
            "`{id}` needs a substantive reason, got {reason:?}"
        );
    }
}

// =============================================================================================
// cross-fixture properties
// =============================================================================================

#[test]
fn every_fixture_parses_and_is_analysable() {
    for name in [
        "clean.jsonl",
        "high.jsonl",
        "critical.jsonl",
        "partial.jsonl",
        "aya-clean.jsonl",
    ] {
        let events = load(name);
        assert!(!events.is_empty(), "{name} is empty");
        let analysis = analyse(name);
        assert!(
            analysis.score.value <= 100,
            "{name} produced an out-of-range score"
        );
    }
}

#[test]
fn the_fixtures_span_the_score_range() {
    // A corpus where everything scores the same would not exercise the renderers. Phases.md:29 asks for
    // reports at clean, high, and critical levels.
    let clean = analyse("clean.jsonl").score.value;
    let high = analyse("high.jsonl").score.value;
    let critical = analyse("critical.jsonl").score.value;

    assert_eq!(clean, 0);
    assert!(
        high > clean && high < critical,
        "clean {clean}, high {high}, critical {critical}"
    );
    assert_eq!(critical, 100);
}

#[test]
fn analysis_is_deterministic_across_repeated_runs() {
    // PRD.md:60. Two people analysing the same recording must get the same report.
    for name in ["clean.jsonl", "high.jsonl", "critical.jsonl"] {
        let first = analyse(name);
        let second = analyse(name);
        assert_eq!(first.score, second.score, "{name} score varied");
        assert_eq!(
            rule_ids(&first),
            rule_ids(&second),
            "{name} findings varied"
        );
        assert_eq!(
            first
                .findings
                .iter()
                .map(|f| f.subject.clone())
                .collect::<Vec<_>>(),
            second
                .findings
                .iter()
                .map(|f| f.subject.clone())
                .collect::<Vec<_>>(),
            "{name} subjects varied"
        );
    }
}

#[test]
fn every_finding_in_every_fixture_carries_evidence_and_reasoning() {
    // A report that asserts behaviour it cannot point at is an opinion, and the catalog's note is what
    // lets a reader judge whether a finding is a false positive.
    for name in [
        "clean.jsonl",
        "high.jsonl",
        "critical.jsonl",
        "partial.jsonl",
    ] {
        let analysis = analyse(name);
        for finding in &analysis.findings {
            assert!(
                !finding.evidence.is_empty(),
                "{name}: `{}` has no evidence",
                finding.rule_id
            );
            assert!(
                finding.note.is_some(),
                "{name}: `{}` has no reasoning",
                finding.rule_id
            );
            assert!(
                !finding.title.is_empty(),
                "{name}: `{}` has no title",
                finding.rule_id
            );
            assert!(
                finding.occurrences >= 1,
                "{name}: `{}` has a zero occurrence count",
                finding.rule_id
            );
        }
    }
}

#[test]
fn fixtures_are_labelled_synthetic() {
    // Rules.md §5. A fabricated recording presented as real would be the exact failure this product
    // exists to detect in other tools, so the labelling is asserted rather than trusted to convention.
    let readme = std::fs::read_to_string(fixture_path("README.md")).expect("the README must exist");
    assert!(
        readme.contains("synthetic"),
        "the corpus README must label these as synthetic"
    );
    assert!(
        readme.contains("None is a recording of a real package"),
        "the README must state that no fixture is a real recording"
    );

    // The hostile fixtures name themselves synthetic in their command lines, so a leaked artifact is
    // self-identifying rather than looking like a real package.
    for name in ["critical.jsonl", "partial.jsonl", "high.jsonl"] {
        let text = std::fs::read_to_string(fixture_path(name)).expect("fixture readable");
        assert!(
            text.contains("SYNTHETIC"),
            "{name} should name itself synthetic in its recorded command"
        );
    }
}
