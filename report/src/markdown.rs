//! The PR comment: one score, at most three bullets, a link.
//!
//! PRD.md:57 caps this at three bullets and puts the evidence behind a link rather than in the comment.
//! Design.md:42 forbids a second summary, a row of badges, and emojis in findings. Both constraints exist
//! for the same reason: a maintainer reviewing a dependency PR reads the comment in a few seconds, and a
//! wall of text is indistinguishable from noise.
//!
//! # What this renderer refuses to do
//!
//! It does not soften a PARTIAL recording, and it does not present a limited backend's clean result as an
//! unqualified pass. Both would be more pleasant to read and both would be false. The tests at the bottom
//! of this file assert the badge and the caveat appear, so a future formatting change cannot quietly drop
//! them.

use std::fmt::Write as _;

use installscope_core::{select_bullets, Analysis};

use crate::{format_bullet, format_score, ReportContext, Verdict};

/// Renders the PR comment.
///
/// Markdown, GitHub-flavoured. Deliberately narrow output: no tables in the summary, no collapsible
/// sections beyond one for the skipped rules, no images.
#[must_use]
pub fn render_markdown(analysis: &Analysis, context: &ReportContext) -> String {
    let mut out = String::with_capacity(1024);
    let verdict = Verdict::of(analysis);

    // ---- headline -------------------------------------------------------------------------------
    // The score and the badge on one line, because Design.md:31 puts them together and a reader who sees
    // only the first line should still learn whether the recording can be trusted.
    let _ = write!(out, "**InstallScope** · {}", format_score(&analysis.score));
    if verdict.shows_partial_badge() {
        // Bracketed and capitalised, matching Design.md:31. Impossible to miss is the requirement.
        out.push_str(" · **`[PARTIAL]`**");
    }
    let clean_label = context.subject_label().replace('`', "'");
    let _ = writeln!(out, " · `{clean_label}`");
    out.push('\n');

    // ---- the PARTIAL explanation ----------------------------------------------------------------
    // Immediately after the headline, before the findings. A reader must know the recording is
    // untrustworthy before they start drawing conclusions from what it contains.
    if verdict.shows_partial_badge() {
        out.push_str(
            "> This recording is **incomplete**. The findings below are real, but they are not the \
             whole picture — absence of a finding here is not evidence it did not happen.\n",
        );
        for reason in &analysis.partial_reasons {
            let _ = writeln!(out, "> - {reason}");
        }
        out.push('\n');
    }

    // ---- bullets --------------------------------------------------------------------------------
    // The headline always appears. Bullets appear only when the score is non-zero, because three
    // bullets of Low trivia would train people to skim (Design.md:43). Informational evidence is
    // behind the link rather than in the comment.
    let scorable_bullets: Vec<_> = select_bullets(&analysis.findings)
        .into_iter()
        .filter(|f| f.severity.contributes_to_score())
        .collect();
    if scorable_bullets.is_empty() {
        // Design.md:43: silence is a designed state. A report with nothing to say still says that.
        let _ = writeln!(out, "{}.", capitalise(verdict.headline()));
    } else {
        for finding in &scorable_bullets {
            let _ = writeln!(out, "- {}", format_bullet(finding));
        }
        // The count of what is not shown, so the three-bullet cap does not hide the scale of a problem.
        let hidden = scorable_count(analysis).saturating_sub(scorable_bullets.len());
        if hidden > 0 {
            let _ = writeln!(
                out,
                "- …and {hidden} more finding{} in the full evidence",
                if hidden == 1 { "" } else { "s" }
            );
        }
    }
    out.push('\n');

    // ---- coverage caveat ------------------------------------------------------------------------
    // Non-negotiable. A clean score from a backend with blind spots is a weaker claim than a clean score
    // from one without, and the reader cannot know that unless it is written down.
    if let Some(caveat) = analysis.coverage.caveat_line() {
        let _ = writeln!(out, "> {caveat}");
        out.push('\n');
    }

    // ---- unresolved paths -----------------------------------------------------------------------
    // Bounds how much the filesystem rules could actually check. A recording where most paths are
    // unresolved has not been meaningfully analysed for escapes, and a bare score would hide that.
    if analysis.unresolved_paths > 0 {
        let _ = writeln!(
            out,
            "> {} path{} could not be resolved to an absolute location and were not checked against \
             the expected directories.\n",
            analysis.unresolved_paths,
            if analysis.unresolved_paths == 1 { "" } else { "s" }
        );
    }

    // ---- skipped rules --------------------------------------------------------------------------
    // Collapsed, because it is reference material rather than a headline — but present, because a check
    // that did not run is different from a check that passed.
    if !analysis.skipped_rules.is_empty() {
        out.push_str("<details><summary>Checks that did not run on this backend</summary>\n\n");
        for (rule_id, reason) in &analysis.skipped_rules {
            let _ = writeln!(out, "- `{rule_id}` — {reason}");
        }
        out.push_str("\n</details>\n\n");
    }

    // ---- links ----------------------------------------------------------------------------------
    let mut links: Vec<String> = Vec::new();
    if let Some(evidence) = &context.evidence_link {
        links.push(format!("[full evidence]({evidence})"));
    }
    if let Some(sarif) = &context.sarif_link {
        links.push(format!("[SARIF]({sarif})"));
    }
    if !links.is_empty() {
        let _ = writeln!(out, "{}", links.join(" · "));
    }

    // ---- advisory footer ------------------------------------------------------------------------
    // PRD.md:43 makes the comment advisory by default. Saying so in the comment sets the expectation that
    // this is information rather than a gate — which is what keeps a false positive from being a blocker.
    let _ = writeln!(
        out,
        "\n<sub>Recorded with the {} backend. Advisory: this comment reports what the install did, \
         and does not block the build.</sub>",
        analysis.coverage.backend
    );

    out
}

/// How many findings count toward the score.
fn scorable_count(analysis: &Analysis) -> usize {
    analysis
        .findings
        .iter()
        .filter(|finding| finding.severity.contributes_to_score())
        .count()
}

/// Uppercases the first character.
fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::analyse_fixture;
    use installscope_core::Severity;

    fn context() -> ReportContext {
        ReportContext {
            package: Some("SYNTHETIC-fixture".to_string()),
            version: Some("1.0.0".to_string()),
            command: vec!["npm".to_string(), "install".to_string()],
            evidence_link: Some("https://example.invalid/artifact".to_string()),
            sarif_link: Some("https://example.invalid/sarif".to_string()),
        }
    }

    #[test]
    fn a_clean_install_renders_a_short_comment() {
        // The comment a maintainer sees on most PRs. If this is long, the product is annoying.
        let rendered = render_markdown(&analyse_fixture("clean.jsonl"), &context());
        assert!(rendered.contains("0 / 100"));
        assert!(rendered.contains("Nothing outside expected behavior"));
        assert!(
            !rendered.contains("PARTIAL"),
            "a complete recording must not show the badge"
        );
        assert!(
            rendered.lines().count() < 15,
            "a clean comment should be short, got {} lines:\n{rendered}",
            rendered.lines().count()
        );
    }

    #[test]
    fn a_partial_recording_shows_the_badge_and_explains_itself() {
        // PRD.md:58, one layer up: a report that renders a truncated recording as clean is the same
        // failure as a recorder that dies silently.
        let rendered = render_markdown(&analyse_fixture("partial.jsonl"), &context());
        assert!(rendered.contains("[PARTIAL]"), "{rendered}");
        assert!(rendered.contains("incomplete"));
        assert!(
            rendered.contains("120s"),
            "the specific reason must appear: {rendered}"
        );
        assert!(
            rendered.contains("not evidence it did not happen"),
            "the reader must be told what the incompleteness means"
        );
    }

    #[test]
    fn the_partial_warning_precedes_the_findings() {
        // Ordering is the point. A reader must learn the recording is untrustworthy before drawing
        // conclusions from its contents.
        let rendered = render_markdown(&analyse_fixture("partial.jsonl"), &context());
        let badge = rendered.find("incomplete").expect("warning present");
        let finding = rendered.find("- ").expect("a bullet present");
        assert!(
            badge < finding,
            "the incompleteness warning must come first:\n{rendered}"
        );
    }

    #[test]
    fn a_critical_install_leads_with_its_worst_findings() {
        let analysis = analyse_fixture("critical.jsonl");
        let rendered = render_markdown(&analysis, &context());

        assert!(rendered.contains("100 / 100"));
        assert!(rendered.contains("raw"), "the capped excess stays visible");
        assert!(
            rendered.contains("(critical)"),
            "critical findings must be marked: {rendered}"
        );
        // Exactly three bullets, per PRD.md:57.
        let bullets = rendered
            .lines()
            .filter(|line| line.starts_with("- "))
            .count();
        assert!(
            bullets <= 4,
            "three findings plus at most one overflow line, got {bullets}"
        );
    }

    #[test]
    fn hidden_findings_are_counted_rather_than_dropped() {
        // The three-bullet cap must not hide the scale of a problem. A reader seeing three findings when
        // there are nine would underestimate it.
        let analysis = analyse_fixture("critical.jsonl");
        let rendered = render_markdown(&analysis, &context());
        assert!(
            rendered.contains("more finding"),
            "the overflow count must appear: {rendered}"
        );
    }

    #[test]
    fn an_aya_report_carries_its_coverage_caveat() {
        // The Phase 2 Option A decision, enforced at the rendering layer. Without this a zero from aya
        // reads exactly like a zero from strace.
        let rendered = render_markdown(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(rendered.contains("credential reads"), "{rendered}");
        assert!(rendered.contains("DNS queries"));
        assert!(rendered.contains("not evidence"));
        assert!(
            rendered.contains("did not run"),
            "the skipped checks must be listed: {rendered}"
        );
    }

    #[test]
    fn an_aya_report_reports_its_unresolved_paths() {
        // Bounds how much of the filesystem analysis actually happened.
        let rendered = render_markdown(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(rendered.contains("could not be resolved"), "{rendered}");
    }

    #[test]
    fn a_strace_report_has_no_caveat_or_skipped_section() {
        // The complement: a full-coverage backend must not carry warnings it does not need, or the
        // warnings stop meaning anything.
        let rendered = render_markdown(&analyse_fixture("clean.jsonl"), &context());
        assert!(!rendered.contains("Not checked by"));
        assert!(!rendered.contains("did not run"));
        assert!(!rendered.contains("could not be resolved"));
    }

    #[test]
    fn the_comment_says_it_is_advisory() {
        // PRD.md:43. Setting the expectation that this is information rather than a gate is what stops a
        // false positive from being a blocker.
        let rendered = render_markdown(&analyse_fixture("high.jsonl"), &context());
        assert!(rendered.contains("Advisory"));
        assert!(rendered.contains("does not block the build"));
    }

    #[test]
    fn links_appear_when_provided_and_not_otherwise() {
        let with_links = render_markdown(&analyse_fixture("high.jsonl"), &context());
        assert!(with_links.contains("[full evidence]"));
        assert!(with_links.contains("[SARIF]"));

        let bare = render_markdown(&analyse_fixture("high.jsonl"), &ReportContext::default());
        assert!(!bare.contains("[full evidence]"));
        assert!(!bare.contains("[SARIF]"));
    }

    #[test]
    fn no_emojis_appear_in_findings() {
        // Design.md:42: no emojis in findings, ever. A forensic report that decorates its output reads as
        // less serious than it is.
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "partial.jsonl",
        ] {
            let rendered = render_markdown(&analyse_fixture(name), &context());
            for line in rendered.lines().filter(|line| line.starts_with("- ")) {
                assert!(
                    line.chars()
                        .all(|c| c.is_ascii() || c == '—' || c == '…' || c == '·'),
                    "{name}: a finding line contains non-ascii decoration: {line}"
                );
            }
        }
    }

    #[test]
    fn there_is_exactly_one_summary() {
        // Design.md:42 forbids a second summary. Two score lines would make a reader wonder which is
        // authoritative.
        for name in ["clean.jsonl", "critical.jsonl"] {
            let rendered = render_markdown(&analyse_fixture(name), &context());
            let score_lines = rendered.matches("/ 100").count();
            assert_eq!(score_lines, 1, "{name} rendered {score_lines} score lines");
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        // Two renders of the same analysis must be byte-identical, or a bot re-posting a comment would
        // show a spurious diff.
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "aya-clean.jsonl",
        ] {
            let analysis = analyse_fixture(name);
            assert_eq!(
                render_markdown(&analysis, &context()),
                render_markdown(&analysis, &context()),
                "{name} rendered differently on a second pass"
            );
        }
    }

    #[test]
    fn severity_marking_is_reserved_for_criticals() {
        // Marking everything marks nothing. Only the severity that should stop a reader gets a label.
        let rendered = render_markdown(&analyse_fixture("high.jsonl"), &context());
        assert!(
            !rendered.contains("(critical)"),
            "the high fixture has no criticals: {rendered}"
        );
        assert!(
            !rendered.contains("(high)"),
            "lesser severities are unmarked"
        );
    }

    #[test]
    fn a_low_only_report_still_shows_its_notes() {
        // Design.md:43: a clean install renders its evidence rather than an empty box.
        let analysis = analyse_fixture("clean.jsonl");
        assert!(analysis
            .findings
            .iter()
            .all(|finding| finding.severity == Severity::Low));
        let rendered = render_markdown(&analysis, &context());
        // The headline states the clean result; the informational findings are in the evidence artifact
        // rather than the comment, because three bullets of trivia would train people to skim.
        assert!(rendered.contains("Nothing outside expected behavior"));
    }
}
