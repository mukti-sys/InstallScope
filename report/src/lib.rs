//! Rendering an analysis for humans and for tools.
//!
//! Three surfaces, one hierarchy. Design.md:28 requires the PR comment and the HTML report to present the
//! same information in the same order, so a reader who sees the comment and then opens the artifact is
//! not re-orienting.
//!
//! - [`markdown`] — the PR comment. One score, at most three bullets, a link. PRD.md:57.
//! - [`sarif`] — SARIF 2.1.0 for GitHub code scanning.
//! - [`html`] — a self-contained artifact, no external assets (Rules.md §1).
//! - [`diff`] — the version-to-version behavioral diff (Design.md:51), in Markdown and HTML.
//!
//! # What every renderer must show
//!
//! Two things are not optional, and both are enforced by tests in each module:
//!
//! 1. **`PARTIAL` when the recording is incomplete.** PRD.md:58 calls a silently-dead recorder the worst
//!    failure this product can produce. A report that renders a truncated recording as clean *is* that
//!    failure, one layer up.
//! 2. **The coverage caveat when the backend had blind spots.** A zero score from the aya backend means
//!    something weaker than a zero from strace, and a reader cannot know that unless the report says it.
//!
//! Neither is a formatting preference. A renderer that omits either is making a false claim about
//! evidence, which is the one thing this product cannot do.
//!
//! The diff renderers carry the same obligation in a different shape: a comparison that cannot support a
//! behavioral claim must not be rendered as one. See [`diff`].

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

pub mod diff;
pub mod html;
pub mod markdown;
pub mod sarif;

use installscope_core::{Analysis, Score, Severity};

pub use diff::{render_diff_html, render_diff_markdown};
pub use html::render_html;
pub use markdown::render_markdown;
pub use sarif::render_sarif;

/// Context a report needs that the analysis itself does not carry.
///
/// The analysis knows what happened; this knows what it happened *to*. Kept separate so the engine has no
/// opinion about presentation, and so a stored recording can be re-rendered later with a link that still
/// works.
#[derive(Debug, Clone, Default)]
pub struct ReportContext {
    /// The package under analysis, when a single one is identifiable.
    pub package: Option<String>,
    /// Version, when known.
    pub version: Option<String>,
    /// The command that was recorded.
    pub command: Vec<String>,
    /// Where the full evidence lives — an artifact URL or a path.
    ///
    /// Design.md:37 puts evidence behind a link rather than in the comment. Without this the comment has
    /// to either omit the evidence or inline it, and inlining is the wall of text PRD.md:57 forbids.
    pub evidence_link: Option<String>,
    /// Where the SARIF file lives, when it was uploaded separately.
    pub sarif_link: Option<String>,
}

impl ReportContext {
    /// A label for the thing analysed: `package@version`, or the command, or a fallback.
    #[must_use]
    pub fn subject_label(&self) -> String {
        match (&self.package, &self.version) {
            (Some(package), Some(version)) => format!("{package}@{version}"),
            (Some(package), None) => package.clone(),
            (None, _) if !self.command.is_empty() => self.command.join(" "),
            (None, _) => "this install".to_string(),
        }
    }
}

/// The verdict line every renderer leads with.
///
/// Centralised because all three surfaces must agree. If the comment said "clean" while the HTML said
/// "partial", a reader would have to guess which to believe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Complete recording, full coverage, nothing found.
    Clean,
    /// Findings were reported.
    Findings,
    /// The recording is incomplete. Takes precedence over everything else.
    ///
    /// Even with a zero score: a truncated recording found nothing *so far*, and presenting that as clean
    /// is the failure PRD.md:58 names.
    Partial,
    /// Complete and scored zero, but the backend could not see everything.
    ///
    /// Distinct from [`Self::Clean`] because the claims differ: "nothing happened" versus "nothing that
    /// this recorder watches happened".
    CleanWithCaveat,
}

impl Verdict {
    /// Determines the verdict for an analysis.
    ///
    /// Order matters. PARTIAL is checked first because incompleteness invalidates any reading of the
    /// score, and a caveat is checked before Clean because an unqualified "clean" from a partial-coverage
    /// backend overstates what was checked.
    #[must_use]
    pub fn of(analysis: &Analysis) -> Self {
        if analysis.is_partial() {
            return Self::Partial;
        }
        if !analysis.score.is_clean() {
            return Self::Findings;
        }
        if analysis.clean_result_is_trustworthy() {
            Self::Clean
        } else {
            Self::CleanWithCaveat
        }
    }

    /// True when the report must carry a visible PARTIAL badge.
    #[must_use]
    pub const fn shows_partial_badge(self) -> bool {
        matches!(self, Self::Partial)
    }

    /// The headline, without the score.
    ///
    /// Phrased as what is known rather than as reassurance. "Nothing outside expected behavior" is a
    /// claim about observation; "safe" would be a claim about the future, and Rules.md §4 bans that
    /// framing outright.
    #[must_use]
    pub const fn headline(self) -> &'static str {
        match self {
            Self::Clean => "nothing outside expected behavior",
            Self::Findings => "surprise index",
            Self::Partial => "recording incomplete",
            Self::CleanWithCaveat => "nothing outside expected behavior, with gaps",
        }
    }
}

/// Renders `score` as `value / 100`, noting the raw sum when the cap fired.
///
/// The raw sum is shown because three criticals and thirty both report 100, and a reader comparing two
/// versions of a package needs to see they are not the same install.
#[must_use]
pub fn format_score(score: &Score) -> String {
    if score.was_capped() {
        format!("{} / 100 (raw {})", score.value, score.raw)
    } else {
        format!("{} / 100", score.value)
    }
}

/// A short, verb-first bullet for one finding.
///
/// Design.md:33 wants bullets that read as verbs. The occurrence count is appended only when it is above
/// one, because "wrote to /etc/cron.d/evil (×1)" is noise.
#[must_use]
pub fn format_bullet(finding: &installscope_core::Finding) -> String {
    let severity_marker = match finding.severity {
        Severity::Critical => " (critical)",
        Severity::High | Severity::Medium | Severity::Low => "",
    };
    if finding.occurrences > 1 {
        format!(
            "{}{severity_marker} — {} times",
            finding.title, finding.occurrences
        )
    } else {
        format!("{}{severity_marker}", finding.title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_core::{Catalog, Event};

    /// Loads and analyses a demo fixture.
    ///
    /// Shared by every renderer's tests so all three are exercised against the same evidence — which is
    /// what makes "the three surfaces agree" a checkable claim rather than an intention.
    pub(crate) fn analyse_fixture(name: &str) -> Analysis {
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
                    .unwrap_or_else(|error| panic!("line {}: {error}", index + 1))
            })
            .collect();
        let catalog = Catalog::embedded().expect("catalog");
        installscope_core::evaluate(&catalog, &events)
    }

    #[test]
    fn a_partial_recording_outranks_a_clean_score() {
        // The precedence that matters. A truncated recording with no findings must not read as clean.
        let partial = analyse_fixture("partial.jsonl");
        assert_eq!(Verdict::of(&partial), Verdict::Partial);
        assert!(Verdict::of(&partial).shows_partial_badge());
    }

    #[test]
    fn a_clean_strace_recording_is_unqualified() {
        let clean = analyse_fixture("clean.jsonl");
        assert_eq!(Verdict::of(&clean), Verdict::Clean);
        assert!(!Verdict::of(&clean).shows_partial_badge());
    }

    #[test]
    fn a_clean_aya_recording_is_qualified() {
        // "Nothing happened" and "nothing that this recorder watches happened" are different claims, and
        // the verdict distinguishes them so no renderer has to decide.
        let aya = analyse_fixture("aya-clean.jsonl");
        assert_eq!(Verdict::of(&aya), Verdict::CleanWithCaveat);
        assert!(Verdict::of(&aya).headline().contains("gaps"));
    }

    #[test]
    fn findings_produce_a_findings_verdict() {
        assert_eq!(
            Verdict::of(&analyse_fixture("critical.jsonl")),
            Verdict::Findings
        );
        assert_eq!(
            Verdict::of(&analyse_fixture("high.jsonl")),
            Verdict::Findings
        );
    }

    #[test]
    fn no_headline_uses_banned_framing() {
        // Rules.md §4 bans "safe", "protection", "guaranteed". A headline is the single most quoted line
        // in a report, so it is the worst place for a claim the product cannot support.
        for verdict in [
            Verdict::Clean,
            Verdict::Findings,
            Verdict::Partial,
            Verdict::CleanWithCaveat,
        ] {
            let headline = verdict.headline().to_ascii_lowercase();
            for banned in ["safe", "protect", "guarantee", "secure"] {
                assert!(
                    !headline.contains(banned),
                    "{verdict:?} headline contains banned framing {banned:?}: {headline}"
                );
            }
        }
    }

    #[test]
    fn a_capped_score_shows_its_raw_sum() {
        let critical = analyse_fixture("critical.jsonl");
        let rendered = format_score(&critical.score);
        assert!(rendered.starts_with("100 / 100"));
        assert!(
            rendered.contains("raw"),
            "the excess above the cap must stay visible: {rendered}"
        );
    }

    #[test]
    fn an_uncapped_score_is_rendered_plainly() {
        let high = analyse_fixture("high.jsonl");
        assert_eq!(format_score(&high.score), "25 / 100");
    }

    #[test]
    fn a_repeated_finding_shows_its_count() {
        let mut finding = installscope_core::Finding::new(
            "escape",
            Severity::Critical,
            "/etc/x",
            "wrote outside the project: /etc/x",
            installscope_core::Evidence {
                ts_ns: 1,
                pid: Some(1),
                syscall: Some("openat".to_string()),
                op: "fs_write".to_string(),
                detail: "d".to_string(),
            },
        );
        assert_eq!(
            format_bullet(&finding),
            "wrote outside the project: /etc/x (critical)"
        );

        finding.occurrences = 12;
        let rendered = format_bullet(&finding);
        assert!(rendered.contains("12 times"), "{rendered}");
    }

    #[test]
    fn the_subject_label_falls_back_sensibly() {
        let named = ReportContext {
            package: Some("lodash".to_string()),
            version: Some("4.17.21".to_string()),
            ..ReportContext::default()
        };
        assert_eq!(named.subject_label(), "lodash@4.17.21");

        let unversioned = ReportContext {
            package: Some("lodash".to_string()),
            ..ReportContext::default()
        };
        assert_eq!(unversioned.subject_label(), "lodash");

        let command_only = ReportContext {
            command: vec!["npm".to_string(), "install".to_string()],
            ..ReportContext::default()
        };
        assert_eq!(command_only.subject_label(), "npm install");

        assert_eq!(ReportContext::default().subject_label(), "this install");
    }
}
