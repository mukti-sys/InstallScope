//! Self-contained HTML report — one file, no external assets.
//!
//! The third rendering surface, after the PR comment and SARIF. Architecture.md:18 names it, and
//! Rules.md §1 forbids external CDN links: everything must be inline so the artifact works when
//! downloaded, shared, or opened offline.
//!
//! # Information hierarchy
//!
//! Design.md:28 requires the PR comment and the HTML report to present the same information in the
//! same order. A reader who sees the comment and then opens the artifact is not re-orienting:
//!
//! 1. Score and verdict (with PARTIAL badge when applicable)
//! 2. Top findings (bullets)
//! 3. Coverage caveat (when the backend has blind spots)
//! 4. Full findings table
//! 5. Per-class coverage table
//! 6. Evidence detail (expandable per finding)
//!
//! # What this renderer refuses to do
//!
//! Same contract as the other two: it does not soften a PARTIAL recording, and it does not present
//! a limited backend's clean result as an unqualified pass. Tests assert both.
//!
//! # Why the per-class coverage table lives here and not in the comment
//!
//! `Memory.md`:194 records it as a Phase 3 obligation: the parity harness keeps the strace/aya
//! asymmetry visible as per-class counts, and the report has to do the same. The one-line caveat in
//! [`installscope_core::Coverage::caveat_line`] names only the classes a backend cannot see *at all* —
//! it says nothing about the ones it sees with a caveat, and "byte counts are the requested count, not
//! the number actually written" is exactly the sort of qualification that changes how a reader weighs a
//! finding.
//!
//! So the full table belongs in the artifact, which is the surface with room for it. The PR comment
//! keeps the one-liner, because PRD.md:57 caps that surface at a score, three bullets, and a link.

use std::fmt::Write as _;

use installscope_core::{select_bullets, Analysis, Observability, Severity};

use crate::{format_bullet, format_score, ReportContext, Verdict};

/// Renders the analysis as a self-contained HTML document.
///
/// The output is a complete `<!DOCTYPE html>` page with inline CSS. No external stylesheets, no
/// JavaScript CDN, no images — Rules.md §1 forbids external assets.
#[must_use]
pub fn render_html(analysis: &Analysis, context: &ReportContext) -> String {
    let verdict = Verdict::of(analysis);
    let mut out = String::with_capacity(4096);

    render_head(&mut out, context);
    render_header(&mut out, analysis, context, verdict);
    render_partial_warning(&mut out, analysis, verdict);
    render_summary(&mut out, analysis, verdict);
    render_caveats(&mut out, analysis);
    render_findings_table(&mut out, analysis);
    render_coverage_table(&mut out, analysis);
    render_skipped_rules(&mut out, analysis);
    render_footer(&mut out, analysis);

    out.push_str("\n</body>\n</html>\n");
    out
}

/// Emits `<!DOCTYPE html>`, `<head>`, and the opening `<body>` tag.
fn render_head(out: &mut String, context: &ReportContext) {
    let _ = write!(
        out,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InstallScope — {subject}</title>
{CSS}
</head>
<body>
"#,
        subject = escape(&context.subject_label()),
        CSS = INLINE_CSS,
    );
}

/// Emits the header block: title, subject label, score, and optional PARTIAL badge.
fn render_header(out: &mut String, analysis: &Analysis, context: &ReportContext, verdict: Verdict) {
    out.push_str("<header>\n");
    let _ = writeln!(
        out,
        "<h1><span class=\"beacon-dot\"></span>InstallScope</h1>"
    );
    let _ = writeln!(
        out,
        "<p class=\"subject\">{}</p>",
        escape(&context.subject_label())
    );

    let _ = write!(
        out,
        "<div class=\"score-card\"><p class=\"score {class}\">{score}",
        class = score_class(analysis),
        score = escape(&format_score(&analysis.score)),
    );
    if verdict.shows_partial_badge() {
        out.push_str(" <span class=\"badge partial\">PARTIAL</span>");
    }
    out.push_str("</p></div>\n");
    out.push_str("</header>\n\n");
}

/// Emits the PARTIAL warning block when the recording was incomplete.
fn render_partial_warning(out: &mut String, analysis: &Analysis, verdict: Verdict) {
    if !verdict.shows_partial_badge() {
        return;
    }
    out.push_str("<div class=\"callout warning\">\n");
    out.push_str(
        "<p><strong>This recording is incomplete.</strong> The findings below are real, but \
         they are not the whole picture — absence of a finding here is not evidence it did \
         not happen.</p>\n",
    );
    if !analysis.partial_reasons.is_empty() {
        out.push_str("<ul>\n");
        for reason in &analysis.partial_reasons {
            let _ = writeln!(out, "<li>{}</li>", escape(reason));
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</div>\n\n");
}

/// Emits the bullet summary section.
fn render_summary(out: &mut String, analysis: &Analysis, verdict: Verdict) {
    let scorable_bullets: Vec<_> = select_bullets(&analysis.findings)
        .into_iter()
        .filter(|f| f.severity.contributes_to_score())
        .collect();
    out.push_str("<section class=\"summary\">\n");
    if scorable_bullets.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"headline\">{}</p>",
            escape(&capitalise(verdict.headline()))
        );
    } else {
        out.push_str("<ul class=\"bullets\">\n");
        for finding in &scorable_bullets {
            let _ = writeln!(out, "<li>{}</li>", escape(&format_bullet(finding)));
        }
        let hidden = scorable_count(analysis).saturating_sub(scorable_bullets.len());
        if hidden > 0 {
            let _ = writeln!(
                out,
                "<li class=\"overflow\">…and {hidden} more finding{} below</li>",
                if hidden == 1 { "" } else { "s" }
            );
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</section>\n\n");
}

/// Emits coverage caveats and unresolved-path warnings.
fn render_caveats(out: &mut String, analysis: &Analysis) {
    if let Some(caveat) = analysis.coverage.caveat_line() {
        let _ = writeln!(
            out,
            "<div class=\"callout caveat\">\n<p>{}</p>\n</div>\n",
            escape(&caveat)
        );
    }

    if analysis.unresolved_paths > 0 {
        let _ =
            writeln!(
            out,
            "<div class=\"callout caveat\">\n<p>{} path{} could not be resolved to an absolute \
             location and {} not checked against the expected directories (unresolved paths are not \
             scored as outside-zone to avoid false criticals).</p>\n</div>\n",
            analysis.unresolved_paths,
            if analysis.unresolved_paths == 1 { "" } else { "s" },
            if analysis.unresolved_paths == 1 { "was" } else { "were" },
        );
    }
}

/// Emits the full findings table.
fn render_findings_table(out: &mut String, analysis: &Analysis) {
    if analysis.findings.is_empty() {
        return;
    }
    out.push_str("<section class=\"findings\">\n<h2>Findings</h2>\n");
    out.push_str(
        "<table>\n<thead><tr>\
        <th>Severity</th><th>Rule</th><th>Subject</th><th>Description</th><th>Count</th>\
        </tr></thead>\n<tbody>\n",
    );
    for finding in &analysis.findings {
        let note_html = finding
            .note
            .as_deref()
            .map(|n| format!("<br><small>{}</small>", escape(n)))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "<tr class=\"severity-{sev}\">\
            <td><span class=\"tag {sev}\">{sev_label}</span></td>\
            <td><code>{rule}</code></td>\
            <td>{subject}</td>\
            <td>{title}{note}</td>\
            <td>{count}</td>\
            </tr>",
            sev = severity_class(finding.severity),
            sev_label = escape(&format!("{:?}", finding.severity)),
            rule = escape(&finding.rule_id),
            subject = escape(&finding.subject),
            title = escape(&finding.title),
            note = note_html,
            count = finding.occurrences,
        );
    }
    out.push_str("</tbody>\n</table>\n</section>\n\n");
}

/// Emits the per-class coverage table.
///
/// Always rendered, including for a full-coverage backend. That is deliberate: a table that appears only
/// when something is wrong teaches a reader to equate its absence with completeness, and they would then
/// have no way to tell a full-coverage recording from a report that simply forgot to say. The strace
/// version of this table is also not uniformly green — reads are filtered to a path list, and connects
/// carry no hostname — so there is real information in it either way.
///
/// The wording of every row comes from [`installscope_core::observability`] rather than from this module.
/// A renderer that phrased its own caveats could drift from what the engine actually did.
fn render_coverage_table(out: &mut String, analysis: &Analysis) {
    out.push_str("<section class=\"coverage\">\n<h2>What this recording could observe</h2>\n");
    let _ = writeln!(
        out,
        "<p class=\"coverage-intro\">Recorded with the <code>{}</code> backend. A class marked \
         <em>not observed</em> means the absence of a finding in that class says nothing about the \
         install.</p>",
        escape(&format!("{}", analysis.coverage.backend))
    );
    out.push_str(
        "<table>\n<thead><tr>\
        <th>Behavior</th><th>Observed</th><th>Qualification</th>\
        </tr></thead>\n<tbody>\n",
    );
    for (class, observability) in &analysis.coverage.classes {
        let (state_class, state_label) = match observability {
            Observability::Observed => ("observed", "yes"),
            Observability::Partial(_) => ("qualified", "with caveat"),
            Observability::Unobserved(_) => ("unobserved", "no"),
        };
        let _ = writeln!(
            out,
            "<tr class=\"coverage-{state_class}\">\
            <td>{class}</td>\
            <td><span class=\"tag {state_class}\">{state_label}</span></td>\
            <td>{note}</td>\
            </tr>",
            class = escape(class.as_str()),
            note = observability.note().map_or_else(
                || "&mdash;".to_string(),
                |note| capitalise_sentence(&escape(note))
            ),
        );
    }
    out.push_str("</tbody>\n</table>\n</section>\n\n");
}

/// Emits the collapsible skipped-rules section.
fn render_skipped_rules(out: &mut String, analysis: &Analysis) {
    if analysis.skipped_rules.is_empty() {
        return;
    }
    out.push_str(
        "<details class=\"skipped\">\n\
        <summary>Checks that did not run on this backend</summary>\n<ul>\n",
    );
    for (rule_id, reason) in &analysis.skipped_rules {
        let _ = writeln!(
            out,
            "<li><code>{}</code> — {}</li>",
            escape(rule_id),
            escape(reason)
        );
    }
    out.push_str("</ul>\n</details>\n\n");
}

/// Emits the footer with backend and advisory notice.
fn render_footer(out: &mut String, analysis: &Analysis) {
    let _ = writeln!(
        out,
        "<footer>\n<p>Recorded with the {} backend. Advisory: this report records what the \
         install did, and does not block the build.</p>\n</footer>",
        escape(&format!("{}", analysis.coverage.backend)),
    );
}

/// The full inline `<style>` block.
///
/// Self-contained: no `@import`, no external fonts, no CDN. The font stack uses system fonts so the
/// file works on any machine without a network request.
const INLINE_CSS: &str = r#"<style>
:root {
    --accent: #FF6A3D;
    --bg: #0B0F14;
    --surface: #131A22;
    --surface-inlay: #070B0E;
    --border: #1E2A36;
    --border-hover: #324355;
    --text: #E6EDF3;
    --text-muted: #7D8B99;
    --critical: #E5484D;
    --critical-bg: rgba(229, 72, 77, 0.12);
    --high: #F5A524;
    --high-bg: rgba(245, 165, 36, 0.12);
    --medium: #3B82C4;
    --medium-bg: rgba(59, 130, 196, 0.12);
    --low: #7D8B99;
    --low-bg: rgba(125, 139, 153, 0.12);
    --clean: #3DD68C;
    --clean-bg: rgba(61, 214, 140, 0.12);
}
*, *::before, *::after { box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    max-width: 900px;
    margin: 2.5rem auto;
    padding: 0 1.5rem;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
}
header {
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 1.75rem;
}
.beacon-dot {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: var(--accent);
    margin-right: 10px;
    vertical-align: middle;
    animation: pulse-beacon 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
@keyframes pulse-beacon {
    0% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.35; transform: scale(0.9); }
    100% { opacity: 1; transform: scale(1); }
}
h1 {
    color: var(--text);
    margin: 0;
    font-size: 1.65rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
}
h2 {
    color: var(--text);
    margin: 2rem 0 0.85rem;
    font-size: 1.2rem;
    font-weight: 600;
    letter-spacing: -0.01em;
}
.subject {
    color: var(--text-muted);
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.85rem;
    margin: 0.4rem 0 1rem;
}
.score-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-top: 1rem;
    display: inline-block;
}
.score {
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 2.2rem;
    font-weight: 700;
    margin: 0;
    line-height: 1.1;
    letter-spacing: -0.02em;
}
.score.clean { color: var(--clean); }
.score.findings { color: var(--high); }
.score.critical { color: var(--critical); }
.score.partial { color: var(--text-muted); }
.badge {
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.75rem;
    padding: 0.25rem 0.55rem;
    border-radius: 3px;
    font-weight: 700;
    text-transform: uppercase;
    vertical-align: middle;
    letter-spacing: 0.04em;
}
.badge.partial {
    background: rgba(245, 165, 36, 0.15);
    color: var(--high);
    border: 1px solid var(--high);
}
.callout {
    border: 1px solid var(--border);
    border-left: 3px solid var(--medium);
    padding: 0.85rem 1.15rem;
    margin: 1.25rem 0;
    background: var(--surface);
    border-radius: 4px;
}
.callout.warning {
    border-color: var(--border);
    border-left-color: var(--critical);
    background: rgba(229, 72, 77, 0.05);
}
.callout.caveat {
    border-left-color: var(--high);
}
.callout p { margin: 0; }
.callout ul { margin: 0.5rem 0 0; padding-left: 1.25rem; }
.summary {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.5rem;
}
.bullets {
    padding-left: 1.25rem;
    margin: 0;
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.88rem;
}
.bullets li { margin: 0.45rem 0; color: #D0D7DE; }
.overflow { color: var(--text-muted); font-style: italic; }
.headline {
    font-size: 1.05rem;
    font-weight: 500;
    color: var(--clean);
    margin: 0;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.85rem 0;
    font-size: 0.88rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
}
th {
    text-align: left;
    padding: 0.65rem 0.9rem;
    background: #18202A;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
td {
    padding: 0.65rem 0.9rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    color: var(--text);
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255, 255, 255, 0.02); }
code {
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.85em;
    background: var(--surface-inlay);
    border: 1px solid var(--border);
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    color: #FFB59F;
}
.tag {
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.72rem;
    padding: 0.2rem 0.45rem;
    border-radius: 3px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    display: inline-block;
    white-space: nowrap;
}
.tag.critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
.tag.high { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
.tag.medium { background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }
.tag.low { background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }
.tag.observed { background: var(--clean-bg); color: var(--clean); border: 1px solid var(--clean); }
.tag.qualified { background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }
.tag.unobserved { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
.coverage-intro { color: var(--text-muted); font-size: 0.88rem; margin: 0 0 0.65rem; }
.coverage table { font-size: 0.85rem; }
.coverage-unobserved td { border-left: 3px solid var(--critical); }
.severity-critical td { border-left: 3px solid var(--critical); }
.severity-high td:first-child { border-left: 3px solid var(--high); }
details {
    margin: 1.25rem 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.75rem 1rem;
}
summary {
    cursor: pointer;
    color: var(--text-muted);
    font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    font-size: 0.85rem;
    font-weight: 600;
}
summary:hover { color: var(--text); }
.skipped ul {
    color: var(--text-muted);
    margin: 0.75rem 0 0.25rem;
    padding-left: 1.25rem;
}
.skipped li { margin: 0.35rem 0; }
footer {
    margin-top: 2.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 0.82rem;
}
</style>"#;

/// CSS class for the score element.
fn score_class(analysis: &Analysis) -> &'static str {
    let verdict = Verdict::of(analysis);
    match verdict {
        Verdict::Partial => "partial",
        Verdict::Clean | Verdict::CleanWithCaveat => "clean",
        Verdict::Findings => {
            if analysis.score.value >= 80 {
                "critical"
            } else {
                "findings"
            }
        }
    }
}

/// CSS class for a severity.
fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
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

/// Capitalises a note and gives it a full stop.
///
/// The coverage notes are written as sentence fragments so they read correctly inside
/// [`installscope_core::Coverage::caveat_line`]. In a table cell they stand alone, so they get the
/// punctuation a standalone sentence needs. Applied *after* escaping, so it cannot alter an entity.
fn capitalise_sentence(text: &str) -> String {
    let mut sentence = capitalise(text);
    if !sentence.is_empty() && !sentence.ends_with('.') {
        sentence.push('.');
    }
    sentence
}

/// HTML-escapes a string to prevent XSS.
///
/// Every user-supplied value (paths, rule text, command lines) passes through this before being
/// placed in the document. A finding subject like `<script>alert(1)</script>` must render as text,
/// not as executable markup.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::analyse_fixture;

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
    fn a_clean_install_renders_a_valid_html_document() {
        let rendered = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(rendered.starts_with("<!DOCTYPE html>"));
        assert!(rendered.contains("</html>"));
        assert!(rendered.contains("0 / 100"));
        assert!(rendered.contains("Nothing outside expected behavior"));
        assert!(
            !rendered.contains("PARTIAL"),
            "a complete recording must not show the badge"
        );
    }

    #[test]
    fn a_partial_recording_shows_the_badge_and_explains_itself() {
        let rendered = render_html(&analyse_fixture("partial.jsonl"), &context());
        assert!(rendered.contains("PARTIAL"), "{rendered}");
        assert!(rendered.contains("incomplete"));
        assert!(
            rendered.contains("not evidence it did not happen"),
            "the reader must be told what the incompleteness means"
        );
    }

    #[test]
    fn a_critical_install_shows_its_score_and_findings() {
        let rendered = render_html(&analyse_fixture("critical.jsonl"), &context());
        assert!(rendered.contains("100 / 100"));
        assert!(rendered.contains("raw"), "the capped excess stays visible");
        assert!(
            rendered.contains("Critical"),
            "critical findings must be labelled"
        );
    }

    #[test]
    fn an_aya_report_carries_its_coverage_caveat() {
        let rendered = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(rendered.contains("credential reads"), "{rendered}");
        assert!(rendered.contains("not evidence"));
        assert!(
            rendered.contains("did not run"),
            "the skipped checks must be listed: {rendered}"
        );
    }

    #[test]
    fn a_strace_report_has_no_caveat() {
        let rendered = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(!rendered.contains("Not checked by"));
        assert!(!rendered.contains("did not run"));
    }

    #[test]
    fn every_report_carries_the_full_per_class_coverage_table() {
        // Memory.md:194 makes this a Phase 3 obligation: the parity harness keeps the strace/aya
        // asymmetry visible in per-class counts, and the report must too. Rendered unconditionally,
        // because a table that appears only on the weaker backend would teach a reader to read its
        // absence as completeness.
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "partial.jsonl",
            "aya-clean.jsonl",
        ] {
            let analysis = analyse_fixture(name);
            let rendered = render_html(&analysis, &context());
            assert!(
                rendered.contains("What this recording could observe"),
                "{name}: the coverage table is missing"
            );
            for (class, _) in &analysis.coverage.classes {
                assert!(
                    rendered.contains(class.as_str()),
                    "{name}: the coverage table omits {class}"
                );
            }
        }
    }

    #[test]
    fn the_coverage_table_distinguishes_unobserved_from_qualified() {
        // The distinction the table exists for. "Byte counts are approximate" and "credential reads are
        // not recorded at all" must not render identically — the first qualifies a finding, the second
        // means silence proves nothing.
        let aya = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(
            aya.contains("tag unobserved"),
            "aya has blind spots and must show them as such: {aya}"
        );
        assert!(
            aya.contains("tag qualified"),
            "aya's caveated classes must be marked distinctly: {aya}"
        );

        // strace has no blind spots, so nothing may be marked unobserved for it. This is the assertion
        // that stops the table degrading into decoration that always looks the same.
        let strace = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(
            !strace.contains("tag unobserved"),
            "strace sees every class; marking one unobserved would be a false claim: {strace}"
        );
        assert!(
            strace.contains("tag observed"),
            "strace's fully-observed classes must be visible as such"
        );
    }

    #[test]
    fn the_coverage_table_states_the_reason_for_every_qualification() {
        // A "with caveat" cell and no reason is a shrug. Each note comes from
        // installscope_core::observability, so the report cannot phrase its own caveat and drift from
        // what the engine actually did.
        for name in ["clean.jsonl", "aya-clean.jsonl"] {
            let analysis = analyse_fixture(name);
            let rendered = render_html(&analysis, &context());
            for (class, observability) in &analysis.coverage.classes {
                if let Some(note) = observability.note() {
                    // The note is escaped and sentence-cased before rendering, so a distinctive
                    // fragment is compared rather than the whole string.
                    let fragment: String = note
                        .split_whitespace()
                        .take(4)
                        .collect::<Vec<_>>()
                        .join(" ");
                    let escaped = escape(&fragment);
                    let expected = capitalise(&escaped);
                    assert!(
                        rendered.contains(&escaped) || rendered.contains(&expected),
                        "{name}: {class} is qualified but its reason is absent: {note}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_coverage_table_names_the_backend_that_produced_the_recording() {
        // The table is a claim about a recorder, not about an install. Which recorder must be on the
        // same screen as the claim.
        let aya = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(aya.contains("<code>aya</code>"), "{aya}");
        let strace = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(strace.contains("<code>strace</code>"), "{strace}");
    }

    #[test]
    fn coverage_notes_are_escaped_like_every_other_string() {
        // The notes are static today, so this guards the mechanism rather than current data: a future
        // note containing a `<` must render as text.
        assert_eq!(
            capitalise_sentence(&escape("<b>reads</b> are filtered")),
            "&lt;b&gt;reads&lt;/b&gt; are filtered."
        );
        // An existing full stop is not doubled.
        assert_eq!(capitalise_sentence("already done."), "Already done.");
        assert_eq!(capitalise_sentence(""), "");
    }

    #[test]
    fn user_supplied_strings_are_html_escaped() {
        // A path like <script> must not become executable markup.
        assert_eq!(
            escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn no_external_assets() {
        // Rules.md §1: no CDN, no @import, no external fonts. The report must work offline.
        for name in [
            "clean.jsonl",
            "critical.jsonl",
            "partial.jsonl",
            "aya-clean.jsonl",
        ] {
            let rendered = render_html(&analyse_fixture(name), &context());
            assert!(!rendered.contains("@import"), "{name}: contains an @import");
            assert!(
                !rendered.contains("fonts.googleapis"),
                "{name}: references external fonts"
            );
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "aya-clean.jsonl",
        ] {
            let analysis = analyse_fixture(name);
            assert_eq!(
                render_html(&analysis, &context()),
                render_html(&analysis, &context()),
                "{name} rendered differently on a second pass"
            );
        }
    }

    #[test]
    fn the_inline_css_uses_the_beacon_accent() {
        assert!(
            INLINE_CSS.contains("#FF6A3D"),
            "the Beacon brand accent must be present in the CSS"
        );
    }

    #[test]
    fn the_report_says_it_is_advisory() {
        let rendered = render_html(&analyse_fixture("high.jsonl"), &context());
        assert!(rendered.contains("Advisory"));
        assert!(rendered.contains("does not block the build"));
    }
}
