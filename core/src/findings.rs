//! Findings, severity weights, and the Surprise Index.
//!
//! PRD.md:56 fixes the arithmetic: weighted sum, capped at 100, with `critical ×40`, `high ×15`,
//! `medium ×5`, `low ×1`. PRD.md:57 caps the PR comment at three bullets. Both are encoded here rather
//! than in a renderer, so every output surface computes the same number from the same evidence.
//!
//! # The cap is a ceiling, not a saturation
//!
//! Two criticals reach 80; three reach 100 and so does thirty. That is deliberate — the score is a
//! triage signal, not a measurement, and a reader who sees 100 needs to open the evidence either way.
//! [`Score::raw`] is retained so the flattening is visible rather than hidden: a report can say
//! "100/100 (raw 340)" and a diff between two versions of a package can still show the difference.
//!
//! # Low severity does not raise a score on its own
//!
//! A `low` finding weighs 1, so a hundred of them would reach 100 — turning informational noise into a
//! critical-looking score. `low` is therefore *informational only* and excluded from the total. It still
//! appears in the report, because Design.md:43 makes silence a designed state and a reader may want the
//! detail; it simply cannot manufacture alarm. See [`Severity::contributes_to_score`].

use serde::{Deserialize, Serialize};

/// How much a finding matters.
///
/// Ordered most severe first, so `sort` puts the worst finding at the top of a report without a custom
/// comparator — which is what the three-bullet cap selects from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Behavior that would be alarming in any install: escaping the project, piping a download into a
    /// shell.
    Critical,
    /// Behavior that is often legitimate but always worth a human look.
    High,
    /// Weak signal. Meaningful in aggregate or alongside something else.
    Medium,
    /// Informational. Recorded for context; **never contributes to the score**.
    Low,
}

impl Severity {
    /// Every severity, most severe first.
    pub const ALL: &'static [Self] = &[Self::Critical, Self::High, Self::Medium, Self::Low];

    /// Score weight, from PRD.md:56.
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::Critical => 40,
            Self::High => 15,
            Self::Medium => 5,
            Self::Low => 1,
        }
    }

    /// Whether findings of this severity are summed into the Surprise Index.
    ///
    /// `low` is excluded. At weight 1 a hundred informational findings would reach 100, and an install
    /// that merely does a lot of ordinary things would score as critical — the false-positive failure
    /// PRD.md:43 calls the religion to avoid.
    #[must_use]
    pub const fn contributes_to_score(self) -> bool {
        !matches!(self, Self::Low)
    }

    /// Name for reports and SARIF.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A piece of evidence pointing at the event that produced a finding.
///
/// Every finding must be traceable back to a specific observation. A report that asserts behavior it
/// cannot point at is an opinion, and PRD.md's whole claim is evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Session-relative timestamp of the event.
    pub ts_ns: u64,
    /// Observing process id, when the event had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The syscall the observation came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<String>,
    /// The `op` of the source event, so a reader can find it in the stream.
    pub op: String,
    /// Short rendering of what was observed: a path, an address, a command line.
    pub detail: String,
}

/// One rule firing on one subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, matching the YAML catalog.
    pub rule_id: String,
    /// Severity as resolved for this instance. A rule may escalate — Architecture.md:59 makes a spawn
    /// `high` but a download piped into a shell `critical`.
    pub severity: Severity,
    /// What the finding is about: a path, a host, a command. Deduplication key together with `rule_id`.
    pub subject: String,
    /// One-line, verb-first summary. Design.md:33 requires bullets read as verbs.
    pub title: String,
    /// Why this is worth a reader's attention, when the title is not self-explanatory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// How many times the rule fired on this subject.
    ///
    /// Collapsed rather than repeated: a thousand writes to one file is one finding with a count, not a
    /// thousand findings. Without this the three-bullet cap would show the same file three times.
    pub occurrences: u32,
    /// Up to a few supporting events. Bounded because a report is not the event stream.
    pub evidence: Vec<Evidence>,
}

/// Evidence entries retained per finding.
///
/// Enough to establish a pattern; the full stream is linked from the report rather than inlined
/// (Design.md:38).
pub const MAX_EVIDENCE_PER_FINDING: usize = 5;

impl Finding {
    /// A finding with one piece of evidence.
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        subject: impl Into<String>,
        title: impl Into<String>,
        evidence: Evidence,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            subject: subject.into(),
            title: title.into(),
            note: None,
            occurrences: 1,
            evidence: vec![evidence],
        }
    }

    /// Attaches an explanatory note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Records another occurrence of the same rule on the same subject.
    pub fn merge_occurrence(&mut self, evidence: Evidence) {
        self.occurrences = self.occurrences.saturating_add(1);
        if self.evidence.len() < MAX_EVIDENCE_PER_FINDING {
            self.evidence.push(evidence);
        }
    }

    /// Deduplication key.
    #[must_use]
    pub fn key(&self) -> (&str, &str) {
        (&self.rule_id, &self.subject)
    }
}

/// The Surprise Index and its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    /// The reported value, 0–100.
    pub value: u32,
    /// The uncapped weighted sum.
    ///
    /// Kept so the cap is visible. Three criticals and thirty both report 100, and a reader comparing
    /// two versions of a package needs to see that they are not the same.
    pub raw: u32,
    /// Findings counted, by severity.
    pub counts: SeverityCounts,
}

/// Finding counts per severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    /// Critical findings.
    pub critical: u32,
    /// High findings.
    pub high: u32,
    /// Medium findings.
    pub medium: u32,
    /// Low, informational findings. Not summed into the score.
    pub low: u32,
}

impl SeverityCounts {
    /// Total findings, including informational ones.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.critical + self.high + self.medium + self.low
    }

    /// Count for one severity.
    #[must_use]
    pub const fn of(self, severity: Severity) -> u32 {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
        }
    }
}

/// Upper bound on the reported score.
pub const SCORE_CAP: u32 = 100;

/// Bullets shown in a PR comment (PRD.md:57).
pub const MAX_BULLETS: usize = 3;

impl Score {
    /// Computes the Surprise Index for a set of findings.
    ///
    /// One finding counts once regardless of its occurrence count. A postinstall script that writes a
    /// thousand files outside the project is one escape, not a thousand — counting occurrences would let
    /// a single behavior saturate the score and make every install with a busy loop look identical.
    #[must_use]
    pub fn compute(findings: &[Finding]) -> Self {
        let mut counts = SeverityCounts::default();
        let mut raw: u32 = 0;

        for finding in findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
            }
            if finding.severity.contributes_to_score() {
                raw = raw.saturating_add(finding.severity.weight());
            }
        }

        Self {
            value: raw.min(SCORE_CAP),
            raw,
            counts,
        }
    }

    /// True when the raw sum exceeded the cap.
    #[must_use]
    pub const fn was_capped(&self) -> bool {
        self.raw > SCORE_CAP
    }

    /// True when nothing scorable was found.
    ///
    /// Distinct from `value == 0` only in intent, but the intent matters: Design.md:43 makes a clean
    /// install a designed state that renders as evidence, not as an empty result.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.value == 0
    }
}

/// Selects the findings a PR comment should show.
///
/// Sorted most severe first, then by occurrence count, then by rule id for stability — two runs over the
/// same recording must produce the same bullets, or a reader comparing them sees phantom changes.
///
/// Informational findings are eligible only if nothing scorable exists. A clean install with a few `low`
/// notes should show them rather than an empty box; an install with a critical should not spend one of
/// its three bullets on trivia.
#[must_use]
pub fn select_bullets(findings: &[Finding]) -> Vec<&Finding> {
    let mut scorable: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.severity.contributes_to_score())
        .collect();

    let pool = if scorable.is_empty() {
        let mut informational: Vec<&Finding> = findings.iter().collect();
        sort_for_display(&mut informational);
        informational
    } else {
        sort_for_display(&mut scorable);
        scorable
    };

    pool.into_iter().take(MAX_BULLETS).collect()
}

/// Orders findings for display: severity, then frequency, then id.
fn sort_for_display(findings: &mut [&Finding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.subject.cmp(&b.subject))
    });
}

/// Collapses findings that share a rule and subject.
///
/// The engine may fire the same rule repeatedly as it walks the stream; this is where that becomes one
/// finding with an occurrence count. Order of first appearance is preserved so the result is
/// deterministic.
#[must_use]
pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for finding in findings {
        if let Some(existing) = out
            .iter_mut()
            .find(|candidate| candidate.key() == finding.key())
        {
            // Escalation wins: if the same subject triggers a worse variant of the rule later, the
            // finding takes the higher severity rather than the first one seen.
            if finding.severity < existing.severity {
                existing.severity = finding.severity;
                existing.title.clone_from(&finding.title);
            }
            existing.occurrences = existing.occurrences.saturating_add(finding.occurrences);
            for evidence in finding.evidence {
                if existing.evidence.len() < MAX_EVIDENCE_PER_FINDING {
                    existing.evidence.push(evidence);
                }
            }
        } else {
            out.push(finding);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(ts_ns: u64) -> Evidence {
        Evidence {
            ts_ns,
            pid: Some(42),
            syscall: Some("openat".to_string()),
            op: "fs_write".to_string(),
            detail: "/etc/cron.d/evil".to_string(),
        }
    }

    fn finding(rule: &str, severity: Severity, subject: &str) -> Finding {
        Finding::new(
            rule,
            severity,
            subject,
            format!("{rule} on {subject}"),
            evidence(1),
        )
    }

    #[test]
    fn weights_match_the_prd() {
        // PRD.md:56 is the contract. A silent change here would move every score in the corpus.
        assert_eq!(Severity::Critical.weight(), 40);
        assert_eq!(Severity::High.weight(), 15);
        assert_eq!(Severity::Medium.weight(), 5);
        assert_eq!(Severity::Low.weight(), 1);
    }

    #[test]
    fn severity_orders_most_severe_first() {
        // Report ordering depends on this, and so does the three-bullet selection.
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);

        let mut all = vec![
            Severity::Low,
            Severity::Critical,
            Severity::Medium,
            Severity::High,
        ];
        all.sort_unstable();
        assert_eq!(all, Severity::ALL.to_vec());
    }

    #[test]
    fn low_findings_never_raise_the_score() {
        // At weight 1, a hundred informational findings would reach 100 and an install that merely does
        // many ordinary things would look critical. That is the false-positive failure PRD.md:43 names.
        let many_low: Vec<Finding> = (0..200)
            .map(|i| finding("noisy", Severity::Low, &format!("/tmp/file-{i}")))
            .collect();
        let score = Score::compute(&many_low);
        assert_eq!(score.value, 0, "informational findings must not score");
        assert_eq!(score.raw, 0);
        assert_eq!(score.counts.low, 200, "but they are still counted");
        assert!(score.is_clean());
    }

    #[test]
    fn score_is_a_weighted_sum() {
        let findings = vec![
            finding("a", Severity::Critical, "x"),
            finding("b", Severity::High, "y"),
            finding("c", Severity::Medium, "z"),
        ];
        let score = Score::compute(&findings);
        assert_eq!(score.raw, 40 + 15 + 5);
        assert_eq!(score.value, 60);
        assert!(!score.was_capped());
    }

    #[test]
    fn the_cap_is_visible_rather_than_silent() {
        // Three criticals and thirty both report 100. A reader comparing two versions of a package needs
        // to see they are not the same install, so the raw sum is retained.
        let three: Vec<Finding> = (0..3)
            .map(|i| finding("escape", Severity::Critical, &format!("/etc/{i}")))
            .collect();
        let thirty: Vec<Finding> = (0..30)
            .map(|i| finding("escape", Severity::Critical, &format!("/etc/{i}")))
            .collect();

        let low = Score::compute(&three);
        let high = Score::compute(&thirty);
        assert_eq!(low.value, 100);
        assert_eq!(high.value, 100);
        assert_eq!(low.raw, 120);
        assert_eq!(high.raw, 1200);
        assert!(low.was_capped() && high.was_capped());
        assert_ne!(low.raw, high.raw, "the cap must not erase the difference");
    }

    #[test]
    fn boundary_scores_land_exactly() {
        // Two criticals is 80; a third takes it to the cap. Worth pinning because these are the values a
        // "fail the build above N" threshold would be set against.
        let two = vec![
            finding("a", Severity::Critical, "x"),
            finding("b", Severity::Critical, "y"),
        ];
        assert_eq!(Score::compute(&two).value, 80);

        let six_high: Vec<Finding> = (0..6)
            .map(|i| finding("h", Severity::High, &format!("s{i}")))
            .collect();
        assert_eq!(Score::compute(&six_high).value, 90);

        let seven_high: Vec<Finding> = (0..7)
            .map(|i| finding("h", Severity::High, &format!("s{i}")))
            .collect();
        assert_eq!(Score::compute(&seven_high).value, 100);
        assert_eq!(Score::compute(&seven_high).raw, 105);
    }

    #[test]
    fn an_empty_recording_scores_zero_and_is_clean() {
        let score = Score::compute(&[]);
        assert_eq!(score.value, 0);
        assert_eq!(score.counts.total(), 0);
        assert!(score.is_clean());
        assert!(!score.was_capped());
    }

    #[test]
    fn occurrences_do_not_inflate_the_score() {
        // A postinstall script writing a thousand files outside the project is one escape, not a thousand.
        // Counting occurrences would let one behavior saturate the score.
        let mut once = finding("escape", Severity::Critical, "/etc/cron.d/evil");
        let mut many = finding("escape", Severity::Critical, "/etc/cron.d/evil");
        for ts in 0..1_000 {
            many.merge_occurrence(evidence(ts));
        }
        once.merge_occurrence(evidence(2));

        assert_eq!(Score::compute(&[once]).value, Score::compute(&[many]).value);
    }

    #[test]
    fn evidence_is_bounded_per_finding() {
        // A report is not the event stream (Design.md:38). Unbounded evidence would make one noisy
        // finding dominate the artifact.
        let mut subject = finding("escape", Severity::Critical, "/etc/x");
        for ts in 0..50 {
            subject.merge_occurrence(evidence(ts));
        }
        assert_eq!(subject.evidence.len(), MAX_EVIDENCE_PER_FINDING);
        assert_eq!(subject.occurrences, 51, "the count is not truncated");
    }

    #[test]
    fn bullets_are_capped_at_three() {
        let findings: Vec<Finding> = (0..10)
            .map(|i| finding("r", Severity::High, &format!("s{i}")))
            .collect();
        assert_eq!(select_bullets(&findings).len(), MAX_BULLETS);
    }

    #[test]
    fn bullets_lead_with_the_worst_finding() {
        let findings = vec![
            finding("medium-rule", Severity::Medium, "m"),
            finding("critical-rule", Severity::Critical, "c"),
            finding("high-rule", Severity::High, "h"),
        ];
        let bullets = select_bullets(&findings);
        assert_eq!(
            bullets.iter().map(|f| f.severity).collect::<Vec<_>>(),
            vec![Severity::Critical, Severity::High, Severity::Medium]
        );
    }

    #[test]
    fn a_critical_finding_does_not_lose_a_bullet_to_trivia() {
        // Three bullets is a tight budget. Spending one on an informational note while a critical exists
        // would bury the thing that matters.
        let mut findings = vec![finding("escape", Severity::Critical, "/etc/x")];
        for i in 0..10 {
            findings.push(finding("noise", Severity::Low, &format!("/tmp/{i}")));
        }
        let bullets = select_bullets(&findings);
        assert!(
            bullets.iter().all(|f| f.severity != Severity::Low),
            "informational findings must not displace scorable ones"
        );
        assert_eq!(bullets.len(), 1, "only one scorable finding exists");
    }

    #[test]
    fn a_clean_install_still_shows_its_informational_notes() {
        // Design.md:43: silence is a designed state that renders as evidence. An empty box would be
        // worse than a note saying what was seen.
        let findings = vec![
            finding("npmrc", Severity::Low, "/home/u/.npmrc"),
            finding("cdn", Severity::Low, "github.com"),
        ];
        let bullets = select_bullets(&findings);
        assert_eq!(bullets.len(), 2);
        assert!(bullets.iter().all(|f| f.severity == Severity::Low));
    }

    #[test]
    fn bullet_order_is_deterministic() {
        // Two runs over one recording must produce the same bullets, or a reader comparing them sees
        // phantom changes. Ties break on occurrence count, then rule id, then subject.
        let build = || {
            vec![
                finding("z-rule", Severity::High, "a"),
                finding("a-rule", Severity::High, "b"),
                finding("m-rule", Severity::High, "c"),
            ]
        };
        let first: Vec<String> = select_bullets(&build())
            .iter()
            .map(|f| f.rule_id.clone())
            .collect();
        let second: Vec<String> = select_bullets(&build())
            .iter()
            .map(|f| f.rule_id.clone())
            .collect();
        assert_eq!(first, second);
        assert_eq!(first, vec!["a-rule", "m-rule", "z-rule"]);
    }

    #[test]
    fn frequent_findings_sort_ahead_of_rare_ones_at_equal_severity() {
        let mut frequent = finding("r", Severity::High, "often");
        for ts in 0..20 {
            frequent.merge_occurrence(evidence(ts));
        }
        let rare = finding("r", Severity::High, "once");

        let findings = vec![rare, frequent];
        let bullets = select_bullets(&findings);
        assert_eq!(bullets.first().map(|f| f.subject.as_str()), Some("often"));
    }

    #[test]
    fn deduplication_collapses_a_rule_on_one_subject() {
        let findings = vec![
            finding("escape", Severity::Critical, "/etc/x"),
            finding("escape", Severity::Critical, "/etc/x"),
            finding("escape", Severity::Critical, "/etc/y"),
        ];
        let deduped = deduplicate(findings);
        assert_eq!(deduped.len(), 2, "two subjects, not three firings");
        let first = deduped
            .iter()
            .find(|f| f.subject == "/etc/x")
            .expect("subject x");
        assert_eq!(first.occurrences, 2);
    }

    #[test]
    fn deduplication_escalates_rather_than_keeping_the_first_severity() {
        // Architecture.md:59: a spawn is high, but a spawn that pipes a download into a shell is
        // critical. If the escalating variant fires second, the finding must take the worse severity —
        // reporting it as high would understate the one finding that matters most.
        let findings = vec![
            finding("spawn", Severity::High, "sh -c"),
            finding("spawn", Severity::Critical, "sh -c"),
        ];
        let deduped = deduplicate(findings);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].severity, Severity::Critical);
        assert_eq!(deduped[0].occurrences, 2);
    }

    #[test]
    fn deduplication_preserves_first_appearance_order() {
        let findings = vec![
            finding("b", Severity::High, "second"),
            finding("a", Severity::High, "first"),
            finding("b", Severity::High, "second"),
        ];
        let deduped = deduplicate(findings);
        assert_eq!(
            deduped
                .iter()
                .map(|f| f.subject.as_str())
                .collect::<Vec<_>>(),
            vec!["second", "first"]
        );
    }

    #[test]
    fn severity_counts_are_addressable_by_severity() {
        let findings = vec![
            finding("a", Severity::Critical, "1"),
            finding("b", Severity::High, "2"),
            finding("c", Severity::High, "3"),
            finding("d", Severity::Low, "4"),
        ];
        let counts = Score::compute(&findings).counts;
        assert_eq!(counts.of(Severity::Critical), 1);
        assert_eq!(counts.of(Severity::High), 2);
        assert_eq!(counts.of(Severity::Medium), 0);
        assert_eq!(counts.of(Severity::Low), 1);
        assert_eq!(counts.total(), 4);
    }

    #[test]
    fn severity_round_trips_through_serde() {
        // Severities appear in the YAML catalog and in SARIF output; a rename would silently break both.
        for severity in Severity::ALL {
            let json = serde_json::to_string(severity).unwrap_or_default();
            let back: Severity = serde_json::from_str(&json).unwrap_or(Severity::Low);
            assert_eq!(*severity, back);
            assert_eq!(json, format!("\"{}\"", severity.as_str()));
        }
    }
}
