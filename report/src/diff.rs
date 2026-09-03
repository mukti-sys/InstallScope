//! Rendering a behavioral version-diff: the moat, made readable.
//!
//! Design.md:51 specifies the shape — two columns, added behaviors highlighted, removed struck through,
//! header "This package's behavior changed between installs" — and calls the screenshot launch content.
//! Two surfaces are produced here for the same reason the finding report has three: Markdown for a PR
//! comment or a terminal, and a self-contained HTML file for the artifact.
//!
//! # The renderer's job is to refuse to overclaim
//!
//! [`installscope_registry::Comparison`] already knows whether it can support a behavioral claim, and
//! this module's most important behavior is honoring that. When a comparison is blocked — different
//! backends, or a PARTIAL recording on either side — the renderers lead with *why no comparison is
//! possible* and do not present the difference as a change in the package. The differences are still
//! shown, because someone debugging their own pipeline needs them, but under a heading that says what
//! they are.
//!
//! This is the same discipline as the PARTIAL badge one level up: the failure mode to avoid is a
//! confident-looking answer built on evidence that cannot support it.

use std::fmt::Write as _;

use installscope_registry::{Behavior, Comparison};

/// Cap on the behaviors listed per class in the Markdown surface.
///
/// A version bump that touches four hundred files in `node_modules` is one behavioral fact about
/// vendoring, not four hundred facts, and a PR comment that lists them all is indistinguishable from
/// noise (PRD.md:57). The HTML artifact is uncapped: it is the place the full evidence lives.
pub const MARKDOWN_PER_CLASS_CAP: usize = 8;

/// Renders a comparison as Markdown.
///
/// Suitable for a PR comment and for a terminal. Deliberately narrow: no tables in the summary, one
/// collapsible section per changed class.
#[must_use]
pub fn render_diff_markdown(comparison: &Comparison) -> String {
    let mut out = String::with_capacity(1024);

    let _ = writeln!(out, "**InstallScope** · {}", comparison.headline());
    out.push('\n');

    // Blockers first and unmissably. A reader must know the comparison is invalid before they read
    // anything that looks like a result.
    if !comparison.comparable() {
        out.push_str(
            "> **No behavioral comparison is possible between these two recordings.** The differences \
             below are differences between *recordings*, not between package versions:\n",
        );
        for blocker in &comparison.blockers {
            let _ = writeln!(out, "> - {}", blocker.explanation());
        }
        out.push('\n');
    } else if comparison.is_identical() {
        let _ = writeln!(
            out,
            "Both recordings observed the same {} behavior{}.",
            comparison.unchanged,
            if comparison.unchanged == 1 { "" } else { "s" }
        );
        out.push('\n');
    }

    if !comparison.is_identical() {
        let _ = writeln!(
            out,
            "{} added · {} removed · {} unchanged",
            comparison.added.len(),
            comparison.removed.len(),
            comparison.unchanged
        );
        out.push('\n');

        for class in comparison.changed_classes() {
            let added = comparison.added_in(class);
            let removed = comparison.removed_in(class);
            let _ = writeln!(
                out,
                "<details><summary><strong>{class}</strong> — {} added, {} removed</summary>\n",
                added.len(),
                removed.len()
            );
            write_capped(&mut out, "+", &added);
            write_capped(&mut out, "−", &removed);
            out.push_str("\n</details>\n\n");
        }
    }

    // Caveats after the result, because they qualify it rather than invalidate it — the reverse order
    // from blockers, and the difference is deliberate.
    if !comparison.caveats.is_empty() {
        for caveat in &comparison.caveats {
            let _ = writeln!(out, "> {}", caveat.explanation());
        }
        out.push('\n');
    }

    out
}

/// Writes a capped list of behaviors with a marker, noting what was withheld.
fn write_capped(out: &mut String, marker: &str, behaviors: &[&Behavior]) {
    for behavior in behaviors.iter().take(MARKDOWN_PER_CLASS_CAP) {
        let clean_summary = behavior.summary().replace('<', "&lt;").replace('>', "&gt;");
        let _ = writeln!(out, "- `{marker}` {clean_summary}");
    }
    let hidden = behaviors.len().saturating_sub(MARKDOWN_PER_CLASS_CAP);
    if hidden > 0 {
        // The count, not silence. A cap that hides the scale of a change is worse than no cap.
        let _ = writeln!(
            out,
            "- `{marker}` …and {hidden} more, in the full evidence artifact"
        );
    }
}

/// Renders a comparison as a self-contained HTML document.
///
/// Design.md:51's two-column layout: the earlier version on the left, the later on the right, additions
/// tinted and removals struck through. No external assets (Rules.md §1), so the artifact works offline
/// and in an email.
#[must_use]
pub fn render_diff_html(comparison: &Comparison) -> String {
    let mut out = String::with_capacity(4096);

    let _ = write!(
        out,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InstallScope diff — {subject}</title>
{CSS}
</head>
<body>
<header>
<h1>InstallScope</h1>
<p class="subject">{subject}</p>
<p class="headline">{headline}</p>
</header>
"#,
        subject = escape(&format!(
            "{} {} → {}",
            comparison.package, comparison.before_version, comparison.after_version
        )),
        headline = escape(&comparison.headline()),
        CSS = DIFF_CSS,
    );

    if !comparison.comparable() {
        out.push_str("<div class=\"callout warning\">\n");
        out.push_str(
            "<p><strong>No behavioral comparison is possible between these two recordings.</strong> \
             The differences below are differences between recordings, not between package \
             versions.</p>\n<ul>\n",
        );
        for blocker in &comparison.blockers {
            let _ = writeln!(out, "<li>{}</li>", escape(&blocker.explanation()));
        }
        out.push_str("</ul>\n</div>\n\n");
    }

    let _ = writeln!(
        out,
        "<p class=\"counts\">{} added · {} removed · {} unchanged</p>",
        comparison.added.len(),
        comparison.removed.len(),
        comparison.unchanged
    );

    if comparison.is_identical() {
        out.push_str("<p class=\"identical\">Both recordings observed identical behavior.</p>\n");
    } else {
        for class in comparison.changed_classes() {
            let added = comparison.added_in(class);
            let removed = comparison.removed_in(class);
            let _ = writeln!(
                out,
                "<section class=\"class-block\">\n<h2>{}</h2>",
                escape(class.as_str())
            );
            out.push_str("<div class=\"columns\">\n");

            let _ = writeln!(
                out,
                "<div class=\"column before\">\n<h3>{} <span class=\"version\">{}</span></h3>",
                escape(&comparison.package),
                escape(&comparison.before_version)
            );
            render_column(&mut out, &removed, "removed");
            out.push_str("</div>\n");

            let _ = writeln!(
                out,
                "<div class=\"column after\">\n<h3>{} <span class=\"version\">{}</span></h3>",
                escape(&comparison.package),
                escape(&comparison.after_version)
            );
            render_column(&mut out, &added, "added");
            out.push_str("</div>\n");

            out.push_str("</div>\n</section>\n\n");
        }
    }

    if !comparison.caveats.is_empty() {
        out.push_str("<div class=\"callout caveat\">\n<ul>\n");
        for caveat in &comparison.caveats {
            let _ = writeln!(out, "<li>{}</li>", escape(&caveat.explanation()));
        }
        out.push_str("</ul>\n</div>\n\n");
    }

    out.push_str(
        "<footer>\n<p>Advisory: this report records what each install did, and does not block the \
         build.</p>\n</footer>\n</body>\n</html>\n",
    );
    out
}

/// Renders one column's behaviors, or an explicit empty state.
///
/// An empty column says so rather than rendering nothing: a blank half of a two-column layout reads as a
/// rendering bug, and "nothing here" is a real result.
fn render_column(out: &mut String, behaviors: &[&Behavior], state: &str) {
    if behaviors.is_empty() {
        out.push_str("<p class=\"none\">nothing in this class</p>\n");
        return;
    }
    let _ = writeln!(out, "<ul class=\"{state}\">");
    for behavior in behaviors {
        let _ = writeln!(out, "<li>{}</li>", escape(&behavior.summary()));
    }
    out.push_str("</ul>\n");
}

/// Inline stylesheet. Design.md's palette, including `diff-add` for the added-behavior tint.
const DIFF_CSS: &str = r#"<style>
:root {
    --accent: #FF6A3D;
    --bg: #0B0F14;
    --panel: #131A22;
    --line: #1E2A36;
    --text: #E6EDF3;
    --dim: #7D8B99;
    --critical: #E5484D;
    --diff-add: #1E3A2A;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    max-width: 1040px;
    margin: 2rem auto;
    padding: 0 1.5rem;
    line-height: 1.6;
}
header { border-bottom: 2px solid var(--accent); padding-bottom: 1rem; margin-bottom: 1.5rem; }
h1 { color: var(--accent); margin: 0; font-size: 1.75rem; }
h2 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
h3 { font-size: 0.9rem; color: var(--dim); margin: 0 0 0.5rem; font-weight: 600; }
.version { color: var(--accent); }
.subject { color: var(--dim); margin: 0.25rem 0; font-family: ui-monospace, monospace; }
.headline { font-size: 1.15rem; margin: 0.5rem 0 0; }
.counts { color: var(--dim); font-family: ui-monospace, monospace; font-size: 0.9rem; }
.identical { color: var(--dim); }
.callout { border-left: 3px solid var(--line); padding: 0.75rem 1rem; margin: 1rem 0;
           background: var(--panel); border-radius: 0 4px 4px 0; }
.callout.warning { border-color: var(--critical); }
.callout.caveat { border-color: var(--dim); }
.callout p, .callout li { margin: 0.2rem 0; }
.class-block { border: 1px solid var(--line); border-radius: 6px; padding: 0.75rem 1rem;
               margin: 1rem 0; background: var(--panel); }
.columns { display: flex; gap: 1.25rem; flex-wrap: wrap; }
.column { flex: 1 1 320px; min-width: 280px; }
ul { padding-left: 1.1rem; margin: 0.25rem 0; }
li { font-family: ui-monospace, monospace; font-size: 0.85rem; margin: 0.2rem 0;
     word-break: break-all; }
ul.added li { background: var(--diff-add); padding: 0.1rem 0.3rem; border-radius: 3px; }
ul.removed li { color: var(--dim); text-decoration: line-through; }
.none { color: var(--dim); font-size: 0.85rem; font-style: italic; margin: 0.25rem 0; }
footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--dim); font-size: 0.85rem; }
</style>"#;

/// HTML-escapes a string.
///
/// Every value here is derived from an observed path or command line, so it is attacker-influenced by
/// construction: a package that writes to a file called `<script>` must render as text.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_core::{Backend, WriteKind, Zone};
    use installscope_registry::{
        compare, BehaviorClass, Blocker, Caveat, Profile, Recording, Side,
    };

    fn wrote(relative: &str) -> Behavior {
        Behavior::Wrote {
            zone: Zone::Project,
            relative: relative.to_string(),
            kind: WriteKind::Open,
        }
    }

    fn profile(backend: Backend, complete: bool, behaviors: Vec<Behavior>) -> Profile {
        Profile {
            backend,
            complete,
            behaviors: behaviors.into_iter().collect(),
            unresolved_paths: 0,
        }
    }

    fn recording(version: &str, profile: Profile) -> Recording {
        Recording {
            version: version.to_string(),
            agent_version: "0.1.0".to_string(),
            profile,
        }
    }

    /// A comparison with one added network behavior and one removed write.
    fn changed() -> Comparison {
        compare(
            "lodash",
            &recording(
                "4.17.20",
                profile(
                    Backend::Strace,
                    true,
                    vec![wrote("index.js"), wrote("old.js")],
                ),
            ),
            &recording(
                "4.17.21",
                profile(
                    Backend::Strace,
                    true,
                    vec![
                        wrote("index.js"),
                        Behavior::Resolved {
                            qname: "telemetry.example".to_string(),
                        },
                    ],
                ),
            ),
        )
    }

    fn identical() -> Comparison {
        compare(
            "lodash",
            &recording(
                "4.17.20",
                profile(Backend::Strace, true, vec![wrote("a.js")]),
            ),
            &recording(
                "4.17.21",
                profile(Backend::Strace, true, vec![wrote("a.js")]),
            ),
        )
    }

    fn blocked() -> Comparison {
        compare(
            "lodash",
            &recording(
                "4.17.20",
                profile(Backend::Strace, true, vec![wrote("a.js")]),
            ),
            &recording("4.17.21", profile(Backend::Aya, true, vec![])),
        )
    }

    fn partial() -> Comparison {
        compare(
            "lodash",
            &recording(
                "4.17.20",
                profile(Backend::Strace, true, vec![wrote("a.js")]),
            ),
            &recording("4.17.21", profile(Backend::Strace, false, vec![])),
        )
    }

    #[test]
    fn markdown_leads_with_the_headline_from_the_comparison() {
        // Centralised in the comparison so both surfaces agree; a renderer phrasing its own would let
        // the comment and the artifact disagree about what happened.
        let rendered = render_diff_markdown(&changed());
        let first = rendered.lines().next().expect("a first line");
        assert!(first.contains("behavior changed"), "{first}");
        assert!(first.contains("4.17.20"), "{first}");
        assert!(first.contains("4.17.21"), "{first}");
    }

    #[test]
    fn markdown_reports_the_counts_and_the_changed_classes() {
        let rendered = render_diff_markdown(&changed());
        assert!(rendered.contains("1 added"), "{rendered}");
        assert!(rendered.contains("1 removed"), "{rendered}");
        assert!(rendered.contains("1 unchanged"), "{rendered}");
        assert!(rendered.contains("network"), "{rendered}");
        assert!(rendered.contains("telemetry.example"), "{rendered}");
    }

    #[test]
    fn markdown_marks_additions_and_removals_distinctly() {
        let rendered = render_diff_markdown(&changed());
        assert!(rendered.contains("`+`"), "{rendered}");
        assert!(rendered.contains("`−`"), "{rendered}");
    }

    #[test]
    fn an_identical_comparison_says_so_without_an_empty_diff_block() {
        // The common case for a patch release. A rendered-but-empty diff would read as a rendering bug.
        let rendered = render_diff_markdown(&identical());
        assert!(rendered.contains("behaved identically"), "{rendered}");
        assert!(rendered.contains("same 1 behavior"), "{rendered}");
        assert!(!rendered.contains("<details>"), "{rendered}");
    }

    #[test]
    fn a_blocked_comparison_refuses_to_call_the_difference_a_change() {
        // THE property of this module. Diffing strace against aya must not be presented as the package
        // having stopped reading credentials.
        let rendered = render_diff_markdown(&blocked());
        assert!(rendered.contains("cannot be compared"), "{rendered}");
        assert!(
            rendered.contains("No behavioral comparison is possible"),
            "{rendered}"
        );
        assert!(
            rendered.contains("not between package versions"),
            "the reader must be told what the differences actually are: {rendered}"
        );
        assert!(
            !rendered.contains("behavior changed"),
            "a blocked comparison must not claim a change: {rendered}"
        );
    }

    #[test]
    fn the_blocker_warning_precedes_the_differences() {
        // Ordering is the point: a reader must know the comparison is invalid before they read anything
        // that looks like a result.
        let rendered = render_diff_markdown(&blocked());
        let warning = rendered
            .find("No behavioral comparison")
            .expect("warning present");
        let difference = rendered.find("`−`").expect("a difference line present");
        assert!(warning < difference, "{rendered}");
    }

    #[test]
    fn a_partial_recording_blocks_the_comparison_in_both_surfaces() {
        // PRD.md:58 one level up: an incomplete recording must never look like a package that stopped
        // doing something.
        let comparison = partial();
        assert!(matches!(
            comparison.blockers.first(),
            Some(Blocker::PartialRecording { side: Side::After })
        ));
        for rendered in [
            render_diff_markdown(&comparison),
            render_diff_html(&comparison),
        ] {
            assert!(rendered.contains("incomplete"), "{rendered}");
            assert!(
                rendered.contains("No behavioral comparison is possible"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn caveats_appear_after_the_result_rather_than_before_it() {
        // A caveat qualifies a result; a blocker invalidates it. The order encodes the difference.
        let comparison = compare(
            "x",
            &recording("1.0.0", profile(Backend::Aya, true, vec![])),
            &recording("1.0.1", profile(Backend::Aya, true, vec![wrote("a.js")])),
        );
        assert!(comparison.comparable());
        let rendered = render_diff_markdown(&comparison);
        let counts = rendered.find("1 added").expect("counts present");
        let caveat = rendered
            .find("does not observe")
            .expect("blind-spot caveat present");
        assert!(counts < caveat, "{rendered}");
        assert!(rendered.contains("credential reads"), "{rendered}");
    }

    #[test]
    fn a_long_class_is_capped_but_its_scale_stays_visible() {
        // A vendoring change that touches 400 files is one fact, but a cap that hides the number would
        // understate it.
        let many: Vec<Behavior> = (0..40)
            .map(|index| wrote(&format!("node_modules/file-{index}.js")))
            .collect();
        let comparison = compare(
            "x",
            &recording("1.0.0", profile(Backend::Strace, true, vec![])),
            &recording("1.0.1", profile(Backend::Strace, true, many)),
        );
        let rendered = render_diff_markdown(&comparison);
        let listed = rendered.matches("`+` wrote").count();
        assert_eq!(listed, MARKDOWN_PER_CLASS_CAP, "{rendered}");
        assert!(rendered.contains("and 32 more"), "{rendered}");
        assert!(rendered.contains("40 added"), "the true total must appear");
    }

    #[test]
    fn html_is_a_complete_self_contained_document() {
        for comparison in [changed(), identical(), blocked()] {
            let rendered = render_diff_html(&comparison);
            assert!(rendered.starts_with("<!DOCTYPE html>"));
            assert!(rendered.contains("</html>"));
            // Rules.md §1: no external assets, so the artifact works offline.
            assert!(!rendered.contains("@import"), "{rendered}");
            assert!(!rendered.contains("http://"), "{rendered}");
            assert!(
                !rendered.contains("fonts.googleapis"),
                "no external fonts: {rendered}"
            );
            assert!(!rendered.contains("<script"), "no scripts");
        }
    }

    #[test]
    fn html_uses_the_two_column_layout_with_both_versions_labelled() {
        // Design.md:51: two columns, v1 | v2. The screenshot is launch content, so the layout is pinned.
        let rendered = render_diff_html(&changed());
        assert!(rendered.contains("class=\"columns\""), "{rendered}");
        assert!(rendered.contains("column before"), "{rendered}");
        assert!(rendered.contains("column after"), "{rendered}");
        assert!(rendered.contains("4.17.20"), "{rendered}");
        assert!(rendered.contains("4.17.21"), "{rendered}");
    }

    #[test]
    fn html_tints_additions_and_strikes_removals() {
        let rendered = render_diff_html(&changed());
        assert!(rendered.contains("ul class=\"added\""), "{rendered}");
        assert!(rendered.contains("ul class=\"removed\""), "{rendered}");
        assert!(
            DIFF_CSS.contains("--diff-add"),
            "Design.md:17 names the added-behavior tint"
        );
        assert!(
            DIFF_CSS.contains("line-through"),
            "Design.md:52 strikes removed behaviors"
        );
        assert!(
            DIFF_CSS.contains("#FF6A3D"),
            "the Beacon accent must be present"
        );
    }

    #[test]
    fn an_empty_column_says_so_rather_than_rendering_blank() {
        // A blank half of a two-column layout reads as a rendering bug; "nothing here" is a real result.
        let comparison = compare(
            "x",
            &recording("1.0.0", profile(Backend::Strace, true, vec![])),
            &recording("1.0.1", profile(Backend::Strace, true, vec![wrote("a.js")])),
        );
        let rendered = render_diff_html(&comparison);
        assert!(rendered.contains("nothing in this class"), "{rendered}");
    }

    #[test]
    fn html_lists_every_behavior_without_a_cap() {
        // The artifact is where the full evidence lives; only the comment is capped.
        let many: Vec<Behavior> = (0..40)
            .map(|index| wrote(&format!("node_modules/file-{index}.js")))
            .collect();
        let comparison = compare(
            "x",
            &recording("1.0.0", profile(Backend::Strace, true, vec![])),
            &recording("1.0.1", profile(Backend::Strace, true, many)),
        );
        let rendered = render_diff_html(&comparison);
        assert_eq!(rendered.matches("<li>wrote project/").count(), 40);
        assert!(!rendered.contains("and 32 more"));
    }

    #[test]
    fn user_supplied_strings_are_escaped_in_the_html() {
        // Every value here comes from an observed path, so it is attacker-influenced by construction.
        let hostile = Behavior::WroteOutside {
            path: "/tmp/<script>alert(1)</script>".to_string(),
            kind: WriteKind::Open,
        };
        let comparison = compare(
            "x",
            &recording("1.0.0", profile(Backend::Strace, true, vec![])),
            &recording("1.0.1", profile(Backend::Strace, true, vec![hostile])),
        );
        let rendered = render_diff_html(&comparison);
        assert!(rendered.contains("&lt;script&gt;"), "{rendered}");
        assert!(
            !rendered.contains("<script>alert"),
            "a path must never become executable markup"
        );
    }

    #[test]
    fn a_hostile_package_name_is_escaped_in_the_title() {
        let comparison = compare(
            "</title><script>alert(1)</script>",
            &recording("1.0.0", profile(Backend::Strace, true, vec![])),
            &recording("1.0.1", profile(Backend::Strace, true, vec![])),
        );
        let rendered = render_diff_html(&comparison);
        assert!(!rendered.contains("<script>alert"), "{rendered}");
    }

    #[test]
    fn both_surfaces_are_deterministic() {
        // A bot re-posting a comment must not show a spurious diff, and two renders of an artifact must
        // be byte-identical for a digest to mean anything.
        for comparison in [changed(), identical(), blocked(), partial()] {
            assert_eq!(
                render_diff_markdown(&comparison),
                render_diff_markdown(&comparison)
            );
            assert_eq!(render_diff_html(&comparison), render_diff_html(&comparison));
        }
    }

    #[test]
    fn neither_surface_uses_banned_framing() {
        // Rules.md §4. Design.md:53 calls the diff screenshot launch content, which makes this the most
        // quoted text in the project.
        for comparison in [changed(), identical(), blocked(), partial()] {
            for rendered in [
                render_diff_markdown(&comparison),
                render_diff_html(&comparison),
            ] {
                let lower = rendered.to_ascii_lowercase();
                for banned in ["protection", "sandbox", "guaranteed", "safe"] {
                    assert!(
                        !lower.contains(banned),
                        "rendered output contains banned framing {banned:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_diff_report_states_that_it_is_advisory() {
        // PRD.md:43. Same footer discipline as the finding report.
        let rendered = render_diff_html(&changed());
        assert!(rendered.contains("Advisory"), "{rendered}");
        assert!(rendered.contains("does not block the build"), "{rendered}");
    }

    #[test]
    fn every_behavior_class_renders_a_name() {
        // The class heading comes from the registry crate; this asserts the renderer surfaces it for all
        // of them rather than silently skipping one.
        for class in BehaviorClass::ALL {
            let behavior = match class {
                BehaviorClass::Filesystem => wrote("a.js"),
                BehaviorClass::FilesystemEscape => Behavior::WroteOutside {
                    path: "/etc/x".to_string(),
                    kind: WriteKind::Open,
                },
                BehaviorClass::CredentialRead => Behavior::ReadCredential {
                    path: "home/.ssh/id_rsa".to_string(),
                },
                BehaviorClass::Network => Behavior::Resolved {
                    qname: "x.invalid".to_string(),
                },
                BehaviorClass::Process => Behavior::Spawned {
                    program: "node".to_string(),
                },
            };
            let comparison = compare(
                "x",
                &recording("1.0.0", profile(Backend::Strace, true, vec![])),
                &recording("1.0.1", profile(Backend::Strace, true, vec![behavior])),
            );
            let markdown = render_diff_markdown(&comparison);
            assert!(
                markdown.contains(class.as_str()),
                "{class} is missing from the markdown surface: {markdown}"
            );
            let html = render_diff_html(&comparison);
            assert!(
                html.contains(class.as_str()),
                "{class} is missing from the html surface"
            );
        }
    }

    #[test]
    fn a_caveat_only_comparison_still_renders_its_result() {
        // Regression guard: an early draft rendered caveats in place of the diff rather than after it.
        let mut weak = profile(Backend::Strace, true, vec![]);
        weak.unresolved_paths = 12;
        let comparison = compare(
            "x",
            &recording("1.0.0", weak),
            &recording("1.0.1", profile(Backend::Strace, true, vec![wrote("a.js")])),
        );
        assert!(comparison.comparable());
        let rendered = render_diff_markdown(&comparison);
        assert!(rendered.contains("1 added"), "{rendered}");
        assert!(rendered.contains("12 paths"), "{rendered}");
        assert!(matches!(
            comparison.caveats.first(),
            Some(Caveat::UnresolvedPaths { .. })
        ));
    }
}
