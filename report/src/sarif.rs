//! SARIF 2.1.0 output, for GitHub code scanning.
//!
//! Architecture.md:18 lists SARIF as one of the three report surfaces, and Rules.md §6 requires schema
//! validation in CI. The schema is checked there rather than here: this module's job is to emit a document
//! that validates, and the workflow's job is to prove it does against the published schema rather than
//! against my reading of it.
//!
//! # Why the document is built by hand rather than with a SARIF crate
//!
//! SARIF is large and this uses a small, fixed subset. A crate modelling the whole specification would be
//! a substantial dependency for the sake of about eighty lines of JSON, and Rules.md §1 asks for a
//! deliberately small tree. The tradeoff is that correctness rests on the CI schema check, which is why
//! that check is not optional.
//!
//! # What SARIF cannot express, and how that is handled
//!
//! SARIF has no concept of "the analysis was incomplete" or "this rule could not run". Both are central to
//! this product: PRD.md:58 makes PARTIAL mandatory, and a rule that never ran is different from one that
//! passed. Rather than drop them, they are emitted as `notification` entries on the tool invocation and as
//! an explicit `invocation.executionSuccessful: false` — the closest the format comes to saying "do not
//! read this as a complete result".

use serde_json::{json, Map, Value};

use installscope_core::{Analysis, Severity};

use crate::ReportContext;

/// SARIF version this emitter targets.
pub const SARIF_VERSION: &str = "2.1.0";

/// The published schema, referenced so a consumer can validate without guessing.
pub const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// Maps a severity onto a SARIF result level.
///
/// SARIF has four levels and they do not line up with four severities: it has no "medium". `warning`
/// carries both `high` and `medium`, and the finding's own `rank` preserves the distinction so a consumer
/// that cares can still order them.
const fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// SARIF `rank`, 0.0–100.0, preserving the severity ordering `level` flattens.
const fn sarif_rank(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 100.0,
        Severity::High => 70.0,
        Severity::Medium => 40.0,
        Severity::Low => 10.0,
    }
}

/// Renders the analysis as a SARIF 2.1.0 document.
///
/// # Errors
/// [`serde_json::Error`] only if serialization fails, which for a document built from owned values means an
/// out-of-memory condition rather than a data problem.
pub fn render_sarif(
    analysis: &Analysis,
    context: &ReportContext,
) -> Result<String, serde_json::Error> {
    let document = build_document(analysis, context);
    serde_json::to_string_pretty(&document)
}

/// Builds the document as a value, so tests can inspect structure without reparsing.
#[must_use]
pub fn build_document(analysis: &Analysis, context: &ReportContext) -> Value {
    let rules = build_rules(analysis);
    let results = build_results(analysis);
    let notifications = build_notifications(analysis);

    // `executionSuccessful: false` on a PARTIAL recording. The analysis itself did not fail, but the
    // closest thing SARIF has to "treat this as provisional" is this flag, and leaving it true would let a
    // truncated recording present as a completed scan.
    let invocation = json!({
        "executionSuccessful": !analysis.is_partial(),
        "toolExecutionNotifications": notifications,
        "commandLine": context.command.join(" "),
        "properties": {
            "backend": analysis.coverage.backend.to_string(),
            "surpriseIndex": analysis.score.value,
            "surpriseIndexRaw": analysis.score.raw,
            "recordingComplete": !analysis.is_partial(),
        }
    });

    json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "InstallScope",
                    "informationUri": "https://github.com/mukti-sys/InstallScope",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "invocations": [invocation],
            "results": results,
            "properties": {
                "subject": context.subject_label(),
                "score": analysis.score.value,
                "scoreRaw": analysis.score.raw,
                "findingCounts": {
                    "critical": analysis.score.counts.critical,
                    "high": analysis.score.counts.high,
                    "medium": analysis.score.counts.medium,
                    "low": analysis.score.counts.low,
                },
            }
        }]
    })
}

/// Builds the SARIF `rules` array — one entry per distinct rule that fired.
fn build_rules(analysis: &Analysis) -> Vec<Value> {
    analysis
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|rule_id| {
            // The first finding for this rule carries the wording; SARIF wants the rule described once
            // and referenced by results.
            let finding = analysis
                .findings
                .iter()
                .find(|candidate| candidate.rule_id == rule_id);
            let help = finding
                .and_then(|finding| finding.note.clone())
                .unwrap_or_else(|| "See the InstallScope rule catalog.".to_string());
            json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": { "text": finding.map_or("", |f| f.title.as_str()) },
                "fullDescription": { "text": help.clone() },
                "help": { "text": help },
                "properties": {
                    "severity": finding.map_or("low", |f| f.severity.as_str()),
                }
            })
        })
        .collect()
}

/// Builds the SARIF `results` array — one entry per finding.
fn build_results(analysis: &Analysis) -> Vec<Value> {
    analysis
        .findings
        .iter()
        .map(|finding| {
            let mut properties = Map::new();
            properties.insert("occurrences".to_string(), json!(finding.occurrences));
            properties.insert("severity".to_string(), json!(finding.severity.as_str()));
            properties.insert("subject".to_string(), json!(finding.subject));

            json!({
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity),
                "rank": sarif_rank(finding.severity),
                "message": { "text": finding.title },
                // A location is required for a result to be actionable in a code-scanning UI. An install's
                // behaviour has no source line, so the observed path is used as the artifact — which is
                // honest: the "location" of this finding really is that path.
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": artifact_uri(&finding.subject) },
                    },
                    "message": { "text": finding.subject.clone() }
                }],
                "properties": properties,
            })
        })
        .collect()
}

/// Builds notifications for conditions SARIF results cannot express: incomplete recordings,
/// backend blind spots, skipped rules, and unresolved paths.
fn build_notifications(analysis: &Analysis) -> Vec<Value> {
    let mut notifications: Vec<Value> = Vec::new();
    if analysis.is_partial() {
        let reasons = if analysis.partial_reasons.is_empty() {
            "no reason recorded".to_string()
        } else {
            analysis.partial_reasons.join("; ")
        };
        notifications.push(json!({
            "level": "warning",
            "message": {
                "text": format!(
                    "The recording is incomplete, so these results are not the whole picture: {reasons}"
                )
            },
            "descriptor": { "id": "installscope/partial_recording" }
        }));
    }
    if let Some(caveat) = analysis.coverage.caveat_line() {
        notifications.push(json!({
            "level": "warning",
            "message": { "text": caveat },
            "descriptor": { "id": "installscope/backend_coverage" }
        }));
    }
    for (rule_id, reason) in &analysis.skipped_rules {
        notifications.push(json!({
            "level": "note",
            "message": {
                "text": format!("Rule `{rule_id}` did not run on this backend: {reason}")
            },
            "descriptor": { "id": "installscope/rule_not_run" }
        }));
    }
    if analysis.unresolved_paths > 0 {
        notifications.push(json!({
            "level": "note",
            "message": {
                "text": format!(
                    "{} path(s) could not be resolved to an absolute location and were not checked \
                     against the expected directories",
                    analysis.unresolved_paths
                )
            },
            "descriptor": { "id": "installscope/unresolved_paths" }
        }));
    }
    notifications
}

/// Renders a finding's subject as a SARIF artifact URI.
///
/// An absolute path becomes a `file:` URI. Anything else — a hostname, a command line, an unresolved
/// relative path — is passed through as an opaque string rather than being coerced into a fake path,
/// because a consumer resolving `curl https://x` as a filename would be worse than one seeing it verbatim.
fn artifact_uri(subject: &str) -> String {
    if subject.starts_with('/') {
        format!("file://{subject}")
    } else {
        subject.to_string()
    }
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
            evidence_link: None,
            sarif_link: None,
        }
    }

    fn document(name: &str) -> Value {
        build_document(&analyse_fixture(name), &context())
    }

    fn run(document: &Value) -> &Value {
        document
            .get("runs")
            .and_then(|runs| runs.get(0))
            .expect("a run")
    }

    #[test]
    fn the_document_declares_the_version_and_schema() {
        let doc = document("critical.jsonl");
        assert_eq!(doc["version"], SARIF_VERSION);
        assert!(
            doc["$schema"].as_str().is_some_and(|s| s.contains("2.1.0")),
            "the schema URL must be present so a consumer can validate"
        );
    }

    #[test]
    fn every_result_references_a_declared_rule() {
        // SARIF requires it, and a result pointing at an undeclared rule renders with no description in a
        // code-scanning UI — the finding appears without its reasoning.
        let doc = document("critical.jsonl");
        let run = run(&doc);
        let declared: Vec<&str> = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array")
            .iter()
            .filter_map(|rule| rule["id"].as_str())
            .collect();
        let results = run["results"].as_array().expect("results array");
        assert!(!results.is_empty());
        for result in results {
            let rule_id = result["ruleId"].as_str().expect("a ruleId");
            assert!(
                declared.contains(&rule_id),
                "result references undeclared rule {rule_id}"
            );
        }
    }

    #[test]
    fn severity_maps_onto_a_sarif_level_and_keeps_its_rank() {
        // SARIF has no "medium", so level flattens high and medium onto `warning`/`error`. Rank preserves
        // the ordering a consumer needs to triage.
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");

        assert!(sarif_rank(Severity::Critical) > sarif_rank(Severity::High));
        assert!(sarif_rank(Severity::High) > sarif_rank(Severity::Medium));
        assert!(sarif_rank(Severity::Medium) > sarif_rank(Severity::Low));
    }

    #[test]
    fn a_partial_recording_marks_the_invocation_unsuccessful() {
        // SARIF cannot say "provisional". This flag is the closest equivalent, and leaving it true would
        // let a truncated recording present as a completed scan.
        let doc = document("partial.jsonl");
        let invocation = &run(&doc)["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], json!(false));
        assert_eq!(invocation["properties"]["recordingComplete"], json!(false));
    }

    #[test]
    fn a_partial_recording_carries_a_notification_naming_the_reason() {
        let doc = document("partial.jsonl");
        let notifications = run(&doc)["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .expect("notifications");
        let text = notifications
            .iter()
            .filter_map(|n| n["message"]["text"].as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("incomplete"), "{text}");
        assert!(
            text.contains("120s"),
            "the specific reason must appear: {text}"
        );
    }

    #[test]
    fn a_complete_recording_is_successful_and_uncaveated() {
        let doc = document("clean.jsonl");
        let invocation = &run(&doc)["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], json!(true));
        assert!(
            invocation["toolExecutionNotifications"]
                .as_array()
                .is_some_and(std::vec::Vec::is_empty),
            "a full-coverage complete recording needs no notifications"
        );
    }

    #[test]
    fn an_aya_recording_carries_its_coverage_and_skipped_rules() {
        // The Option A decision, third surface. A SARIF consumer must be able to tell that credential
        // reads were never checked.
        let doc = document("aya-clean.jsonl");
        let notifications = run(&doc)["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .expect("notifications");
        let text = notifications
            .iter()
            .filter_map(|n| n["message"]["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("credential reads"), "{text}");
        assert!(text.contains("did not run"), "{text}");
        assert!(text.contains("could not be resolved"), "{text}");

        let ids: Vec<&str> = notifications
            .iter()
            .filter_map(|n| n["descriptor"]["id"].as_str())
            .collect();
        assert!(ids.contains(&"installscope/backend_coverage"));
        assert!(ids.contains(&"installscope/rule_not_run"));
        assert!(ids.contains(&"installscope/unresolved_paths"));
    }

    #[test]
    fn the_score_appears_in_run_properties() {
        // A consumer gating on the score should not have to re-derive it from the results.
        let doc = document("critical.jsonl");
        let properties = &run(&doc)["properties"];
        assert_eq!(properties["score"], json!(100));
        assert!(
            properties["scoreRaw"].as_u64().unwrap_or(0) > 100,
            "the raw sum must survive the cap"
        );
        assert!(
            properties["findingCounts"]["critical"]
                .as_u64()
                .unwrap_or(0)
                >= 2
        );
    }

    #[test]
    fn an_absolute_path_becomes_a_file_uri_and_nothing_else_is_coerced() {
        // A consumer resolving `curl https://x` as a filename would be worse than one seeing it verbatim.
        assert_eq!(artifact_uri("/etc/cron.d/evil"), "file:///etc/cron.d/evil");
        assert_eq!(
            artifact_uri("telemetry.example.com"),
            "telemetry.example.com"
        );
        assert_eq!(artifact_uri("curl"), "curl");
        assert_eq!(artifact_uri("<unknown descriptor>"), "<unknown descriptor>");
    }

    #[test]
    fn every_result_has_a_location_and_a_message() {
        // Both are required for a result to be actionable in a code-scanning UI.
        for name in ["high.jsonl", "critical.jsonl"] {
            let doc = document(name);
            for result in run(&doc)["results"].as_array().expect("results") {
                assert!(
                    result["message"]["text"]
                        .as_str()
                        .is_some_and(|t| !t.is_empty()),
                    "{name}: a result has no message"
                );
                assert!(
                    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                        .as_str()
                        .is_some_and(|uri| !uri.is_empty()),
                    "{name}: a result has no location"
                );
            }
        }
    }

    #[test]
    fn a_clean_recording_produces_a_valid_document_with_low_results_only() {
        // A zero-finding scan still has to be a well-formed SARIF document, or uploading it fails and the
        // PR shows nothing at all.
        let doc = document("clean.jsonl");
        let results = run(&doc)["results"].as_array().expect("results");
        for result in results {
            assert_eq!(result["level"], json!("note"));
        }
        assert_eq!(run(&doc)["properties"]["score"], json!(0));
    }

    #[test]
    fn the_output_is_valid_json_and_deterministic() {
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "partial.jsonl",
        ] {
            let analysis = analyse_fixture(name);
            let first = render_sarif(&analysis, &context()).expect("render");
            let second = render_sarif(&analysis, &context()).expect("render");
            assert_eq!(first, second, "{name} rendered differently");
            let _: Value = serde_json::from_str(&first)
                .unwrap_or_else(|error| panic!("{name} produced invalid JSON: {error}"));
        }
    }

    #[test]
    fn rules_are_declared_once_each() {
        // Duplicated rule declarations are a schema violation and would double every rule in a UI.
        let doc = document("critical.jsonl");
        let ids: Vec<&str> = run(&doc)["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter_map(|rule| rule["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            ids.len(),
            unique.len(),
            "duplicate rule declarations: {ids:?}"
        );
    }

    #[test]
    fn each_declared_rule_carries_its_reasoning() {
        // The catalog's note is what lets a reader judge a false positive. Dropping it in SARIF would make
        // the code-scanning view strictly less useful than the PR comment.
        let doc = document("critical.jsonl");
        for rule in run(&doc)["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules")
        {
            let help = rule["help"]["text"].as_str().unwrap_or_default();
            assert!(
                help.len() > 40,
                "rule {} has no substantive help text: {help:?}",
                rule["id"]
            );
        }
    }
}
