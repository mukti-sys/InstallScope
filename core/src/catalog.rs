//! The rule catalog: schema, loading, and validation.
//!
//! Architecture.md:63 makes the catalog a versioned YAML file that the community can send PRs against.
//! That shapes the design more than it might appear: the file is *input from outside this codebase*, so
//! everything the parser hands back is validated rather than trusted, and a malformed catalog fails
//! loudly before any recording begins rather than silently disabling a rule.
//!
//! # Why rule kinds are an enum rather than an expression language
//!
//! A rule's `kind` selects a hardcoded predicate in [`crate::rules`]. The catalog controls *whether* a
//! rule runs, its severity, and its wording — not its logic.
//!
//! The alternative, a match language in YAML, would let a contributor add rules without touching Rust,
//! which sounds like the point of a community catalog. It is rejected because a mis-specified pattern
//! would produce a confident wrong finding, and PRD.md:60 makes determinism a feature. A new predicate
//! is a code review with tests; a new severity or wording is a text review. Both are PR-able, and the
//! one that can fabricate evidence gets the stricter path.
//!
//! # Unknown fields are an error
//!
//! `deny_unknown_fields` throughout. A typo in a catalog key would otherwise parse cleanly and silently
//! drop whatever the contributor meant — the rule would appear to be configured and would not run.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::findings::Severity;

/// Catalog schema version this build understands.
pub const CATALOG_VERSION: u32 = 1;

/// What a rule actually checks.
///
/// Each variant maps to one predicate in [`crate::rules`]. Adding a variant is a code change with
/// tests; that is deliberate — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// A write to a path placed outside every declared zone.
    WriteOutsideZones,
    /// An execute bit set on a path outside every declared zone.
    ChmodExecutableOutsideZones,
    /// A successful read of a credential- or environment-bearing path.
    CredentialRead,
    /// A failed read of the same. Intent without effect.
    CredentialReadFailed,
    /// A read of npm configuration.
    NpmrcRead,
    /// A DNS question for a host that is not registry infrastructure.
    DnsOutsideRegistry,
    /// A DNS question for a known binary distribution host.
    DnsBinaryDistribution,
    /// An external connection on a port other than 80 or 443.
    ConnectUnusualPort,
    /// Any external connection.
    ConnectExternal,
    /// A shell invocation whose script downloads and pipes into an interpreter.
    DownloadPipedToShell,
    /// A spawn of curl, wget, or similar.
    SpawnNetworkTool,
    /// A spawn of a binary outside the expected toolchain list.
    SpawnUnexpected,
}

impl RuleKind {
    /// Which observation class this rule depends on.
    ///
    /// Lets a report say "this rule could not run on this backend" rather than reporting no findings and
    /// letting a reader assume the behavior did not occur — the [`crate::coverage`] contract.
    #[must_use]
    pub const fn observation_class(self) -> crate::coverage::ObservationClass {
        use crate::coverage::ObservationClass as Class;
        match self {
            Self::WriteOutsideZones | Self::ChmodExecutableOutsideZones => Class::FilesystemWrites,
            Self::CredentialRead | Self::CredentialReadFailed | Self::NpmrcRead => {
                Class::CredentialReads
            }
            Self::DnsOutsideRegistry | Self::DnsBinaryDistribution => Class::DnsQueries,
            Self::ConnectUnusualPort | Self::ConnectExternal => Class::NetworkConnections,
            Self::DownloadPipedToShell | Self::SpawnNetworkTool | Self::SpawnUnexpected => {
                Class::ProcessSpawns
            }
        }
    }
}

/// One entry in the catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, used in findings and SARIF output. Renaming one breaks anything that
    /// suppressed it, so it is treated as public API.
    pub id: String,
    /// Severity for findings this rule produces.
    pub severity: Severity,
    /// Which predicate to run.
    pub kind: RuleKind,
    /// Verb-first summary, per Design.md:33.
    pub title: String,
    /// Reasoning, and what a false positive looks like. Required by convention in the catalog file; the
    /// schema allows its absence so a rule can be added in one commit and explained in the next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Set false to keep a rule in the catalog without running it.
    ///
    /// Better than deleting: the entry and its reasoning stay reviewable, and re-enabling is a one-line
    /// diff rather than an archaeology exercise.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

/// The full catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Schema version. Refused if it does not match [`CATALOG_VERSION`].
    pub version: u32,
    /// Hostnames that are package registries.
    #[serde(default)]
    pub registry_hosts: Vec<String>,
    /// Suffixes treated as registry infrastructure.
    #[serde(default)]
    pub registry_suffixes: Vec<String>,
    /// Suffixes of hosts that distribute prebuilt binaries.
    #[serde(default)]
    pub binary_distribution_suffixes: Vec<String>,
    /// Path fragments whose contents are credentials.
    #[serde(default)]
    pub credential_paths: Vec<String>,
    /// Credential-bearing filenames, matched in any directory.
    #[serde(default)]
    pub credential_filenames: Vec<String>,
    /// Binaries whose spawn is worth reporting.
    #[serde(default)]
    pub network_tools: Vec<String>,
    /// Binaries an ordinary install legitimately spawns.
    #[serde(default)]
    pub expected_spawns: Vec<String>,
    /// The rules themselves.
    pub rules: Vec<Rule>,
}

/// Why a catalog was rejected.
///
/// Every variant names the offending entry. A validation error a maintainer cannot act on is barely
/// better than silent acceptance.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// The YAML did not parse.
    #[error("catalog is not valid YAML: {0}")]
    Parse(#[from] serde_yaml::Error),

    /// Schema version mismatch.
    ///
    /// Refused rather than best-effort parsed: a future catalog may give an existing key new meaning,
    /// and misreading a severity would silently change every score.
    #[error("catalog declares version {found}; this build understands {supported}")]
    UnsupportedVersion {
        /// Version in the file.
        found: u32,
        /// Version this build supports.
        supported: u32,
    },

    /// Two rules share an id.
    ///
    /// Ids appear in findings and in SARIF, and a suppression keyed on one would silently apply to both.
    #[error("duplicate rule id `{id}`")]
    DuplicateId {
        /// The repeated id.
        id: String,
    },

    /// A rule id is empty or malformed.
    #[error("rule id {position} is invalid: {reason}")]
    InvalidId {
        /// Zero-based position in the rules list.
        position: usize,
        /// What is wrong with it.
        reason: String,
    },

    /// A rule has no title.
    #[error("rule `{id}` has an empty title; a finding with no wording cannot be read")]
    EmptyTitle {
        /// The offending rule.
        id: String,
    },

    /// The catalog has no enabled rules.
    ///
    /// An empty catalog would produce a clean report for every install, which is the most dangerous
    /// possible output: it looks like a pass.
    #[error("catalog has no enabled rules; every recording would report clean")]
    NoEnabledRules,

    /// I/O reading the catalog file.
    #[error("cannot read catalog at {path}: {source}")]
    Io {
        /// The path attempted.
        path: std::path::PathBuf,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
}

impl Catalog {
    /// The catalog compiled into the binary.
    ///
    /// Shipped as a default so `installscope` works on a fresh clone with no configuration, which
    /// PRD.md:46 asks for. A `--rules` path overrides it.
    ///
    /// # Errors
    /// [`CatalogError`] if the embedded file fails validation — which would be a build-time bug, caught
    /// by the test at the bottom of this module rather than by a user.
    pub fn embedded() -> std::result::Result<Self, CatalogError> {
        Self::from_yaml(include_str!("../../rules/catalog.yaml"))
    }

    /// Parses and validates a catalog from YAML text.
    ///
    /// # Errors
    /// [`CatalogError`] on a parse failure or any validation failure.
    pub fn from_yaml(text: &str) -> std::result::Result<Self, CatalogError> {
        let catalog: Self = serde_yaml::from_str(text)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Loads a catalog from disk.
    ///
    /// # Errors
    /// [`CatalogError::Io`] if the file cannot be read, then as [`Self::from_yaml`].
    pub fn load(path: &std::path::Path) -> std::result::Result<Self, CatalogError> {
        let text = std::fs::read_to_string(path).map_err(|source| CatalogError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_yaml(&text)
    }

    /// Checks every invariant a rule evaluation depends on.
    ///
    /// Runs before any recording is analysed, so a broken catalog costs a clear error rather than a
    /// misleading report.
    fn validate(&self) -> std::result::Result<(), CatalogError> {
        if self.version != CATALOG_VERSION {
            return Err(CatalogError::UnsupportedVersion {
                found: self.version,
                supported: CATALOG_VERSION,
            });
        }

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for (position, rule) in self.rules.iter().enumerate() {
            if rule.id.trim().is_empty() {
                return Err(CatalogError::InvalidId {
                    position,
                    reason: "empty".to_string(),
                });
            }
            // Ids reach SARIF and command lines, so the character set is restricted rather than
            // left to whatever YAML permits.
            if !rule
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(CatalogError::InvalidId {
                    position,
                    reason: format!(
                        "`{}` must be lowercase ascii, digits, and underscores only",
                        rule.id
                    ),
                });
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(CatalogError::DuplicateId {
                    id: rule.id.clone(),
                });
            }
            if rule.title.trim().is_empty() {
                return Err(CatalogError::EmptyTitle {
                    id: rule.id.clone(),
                });
            }
        }

        if !self.rules.iter().any(|rule| rule.enabled) {
            return Err(CatalogError::NoEnabledRules);
        }

        Ok(())
    }

    /// The enabled rule for a kind, if any.
    ///
    /// Returns the first match, and `validate` guarantees ids are unique — but not that kinds are,
    /// deliberately: two rules may share a kind with different severities once the engine supports
    /// per-rule parameters. Until then the first wins, which is stable because catalog order is stable.
    #[must_use]
    pub fn rule_for(&self, kind: RuleKind) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| rule.enabled && rule.kind == kind)
    }

    /// True when `host` is registry infrastructure.
    #[must_use]
    pub fn is_registry_host(&self, host: &str) -> bool {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        if self
            .registry_hosts
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&normalized))
        {
            return true;
        }
        self.registry_suffixes
            .iter()
            .any(|suffix| suffix_matches(&normalized, suffix))
    }

    /// True when `host` is a known binary distribution point.
    #[must_use]
    pub fn is_binary_distribution_host(&self, host: &str) -> bool {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        self.binary_distribution_suffixes
            .iter()
            .any(|suffix| suffix_matches(&normalized, suffix))
    }

    /// True when `path` holds credentials or environment secrets.
    #[must_use]
    pub fn is_credential_path(&self, path: &str) -> bool {
        if self
            .credential_paths
            .iter()
            .any(|fragment| path.contains(fragment.as_str()))
        {
            return true;
        }
        let base = path.rsplit('/').next().unwrap_or(path);
        self.credential_filenames.iter().any(|name| {
            base == name.as_str()
                // .env.production and friends.
                || (name == ".env" && base.starts_with(".env"))
        })
    }

    /// True when `binary` is a network tool.
    #[must_use]
    pub fn is_network_tool(&self, binary: &str) -> bool {
        self.network_tools
            .iter()
            .any(|tool| tool.as_str() == binary)
    }

    /// True when spawning `binary` is ordinary for an install.
    #[must_use]
    pub fn is_expected_spawn(&self, binary: &str) -> bool {
        self.expected_spawns
            .iter()
            .any(|expected| expected.as_str() == binary)
    }
}

/// Suffix match that respects a label boundary.
///
/// `evil-npmjs.org` must not match the suffix `.npmjs.org`, and `npmjs.org` itself must. Without the
/// boundary check a lookalike domain would be classified as registry infrastructure and its traffic
/// would silently stop being a finding — the exact case Architecture.md:61 wants reported.
fn suffix_matches(host: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.');
    if host == suffix {
        return true;
    }
    host.strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r"
version: 1
rules:
  - id: only_rule
    severity: high
    kind: write_outside_zones
    title: wrote somewhere unexpected
";

    #[test]
    fn the_embedded_catalog_is_valid() {
        // A malformed shipped catalog is a build-time bug, and this is where it is caught rather than by
        // a user on first run.
        let catalog = Catalog::embedded().expect("the shipped catalog must validate");
        assert_eq!(catalog.version, CATALOG_VERSION);
        assert!(
            catalog.rules.len() >= 12,
            "the catalog should cover every rule kind, got {}",
            catalog.rules.len()
        );
    }

    #[test]
    fn every_rule_kind_has_an_entry_in_the_shipped_catalog() {
        // A kind with no catalog entry is dead code: the predicate exists and can never fire, so the
        // product silently does not check something it appears to.
        let catalog = Catalog::embedded().expect("valid");
        for kind in [
            RuleKind::WriteOutsideZones,
            RuleKind::ChmodExecutableOutsideZones,
            RuleKind::CredentialRead,
            RuleKind::CredentialReadFailed,
            RuleKind::NpmrcRead,
            RuleKind::DnsOutsideRegistry,
            RuleKind::DnsBinaryDistribution,
            RuleKind::ConnectUnusualPort,
            RuleKind::ConnectExternal,
            RuleKind::DownloadPipedToShell,
            RuleKind::SpawnNetworkTool,
            RuleKind::SpawnUnexpected,
        ] {
            assert!(
                catalog.rule_for(kind).is_some(),
                "{kind:?} has no enabled rule in the shipped catalog"
            );
        }
    }

    #[test]
    fn the_shipped_severities_match_architecture_md() {
        // Architecture.md §4 is the contract. A silent severity change moves every score in the corpus,
        // so the load-bearing ones are pinned here.
        let catalog = Catalog::embedded().expect("valid");
        let severity_of = |kind| catalog.rule_for(kind).map(|rule| rule.severity);

        assert_eq!(
            severity_of(RuleKind::WriteOutsideZones),
            Some(Severity::Critical)
        );
        assert_eq!(
            severity_of(RuleKind::DownloadPipedToShell),
            Some(Severity::Critical)
        );
        assert_eq!(severity_of(RuleKind::CredentialRead), Some(Severity::High));
        assert_eq!(
            severity_of(RuleKind::DnsOutsideRegistry),
            Some(Severity::High)
        );
        assert_eq!(
            severity_of(RuleKind::SpawnNetworkTool),
            Some(Severity::High)
        );
        assert_eq!(
            severity_of(RuleKind::DnsBinaryDistribution),
            Some(Severity::Medium)
        );
        // Informational rules must stay informational: at weight 1 they would otherwise accumulate.
        assert_eq!(severity_of(RuleKind::NpmrcRead), Some(Severity::Low));
        assert_eq!(severity_of(RuleKind::ConnectExternal), Some(Severity::Low));
    }

    #[test]
    fn every_shipped_rule_explains_itself() {
        // The catalog is a public artifact people send PRs against. A rule with no stated reasoning
        // cannot be argued with, and PRD.md:43 asks contributors to describe a false positive.
        let catalog = Catalog::embedded().expect("valid");
        for rule in &catalog.rules {
            let note = rule
                .note
                .as_deref()
                .unwrap_or_else(|| panic!("rule `{}` has no note", rule.id));
            assert!(
                note.len() > 60,
                "rule `{}` needs substantive reasoning, got {} chars",
                rule.id,
                note.len()
            );
        }
    }

    #[test]
    fn a_minimal_catalog_parses() {
        let catalog = Catalog::from_yaml(MINIMAL).expect("valid");
        assert_eq!(catalog.rules.len(), 1);
        assert!(catalog.rules[0].enabled, "enabled defaults to true");
        assert!(catalog.registry_hosts.is_empty());
    }

    #[test]
    fn a_future_version_is_refused_rather_than_best_effort_parsed() {
        // A later catalog may give an existing key new meaning. Misreading a severity would silently
        // change every score, so an unknown version is a hard stop.
        let text = MINIMAL.replace("version: 1", "version: 2");
        match Catalog::from_yaml(&text) {
            Err(CatalogError::UnsupportedVersion { found: 2, .. }) => {}
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_field_is_an_error_not_a_silent_drop() {
        // THE reason for deny_unknown_fields. A typo would otherwise parse cleanly and the rule would
        // appear configured while doing nothing.
        let text = r"
version: 1
rules:
  - id: typo_rule
    saverity: high
    kind: write_outside_zones
    title: oops
";
        assert!(
            matches!(Catalog::from_yaml(text), Err(CatalogError::Parse(_))),
            "a misspelled key must fail loudly"
        );
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        // Ids reach SARIF and any suppression mechanism; two rules sharing one would make a suppression
        // silently apply to both.
        let text = r"
version: 1
rules:
  - id: same
    severity: high
    kind: write_outside_zones
    title: first
  - id: same
    severity: low
    kind: connect_external
    title: second
";
        match Catalog::from_yaml(text) {
            Err(CatalogError::DuplicateId { id }) => assert_eq!(id, "same"),
            other => panic!("expected DuplicateId, got {other:?}"),
        }
    }

    #[test]
    fn ids_are_restricted_to_a_safe_character_set() {
        for bad in ["Write-Outside", "rule id", "rule.id", "RULE"] {
            let text = format!(
                "version: 1\nrules:\n  - id: \"{bad}\"\n    severity: high\n    kind: write_outside_zones\n    title: t\n"
            );
            assert!(
                matches!(
                    Catalog::from_yaml(&text),
                    Err(CatalogError::InvalidId { .. })
                ),
                "`{bad}` should be rejected"
            );
        }
    }

    #[test]
    fn an_empty_title_is_rejected() {
        let text = r"
version: 1
rules:
  - id: untitled
    severity: high
    kind: write_outside_zones
    title: '   '
";
        match Catalog::from_yaml(text) {
            Err(CatalogError::EmptyTitle { id }) => assert_eq!(id, "untitled"),
            other => panic!("expected EmptyTitle, got {other:?}"),
        }
    }

    #[test]
    fn a_catalog_with_nothing_enabled_is_refused() {
        // The most dangerous possible output is a clean report that looks like a pass. A catalog that can
        // never fire would produce one for every install.
        let text = r"
version: 1
rules:
  - id: disabled_rule
    severity: critical
    kind: write_outside_zones
    title: t
    enabled: false
";
        assert!(matches!(
            Catalog::from_yaml(text),
            Err(CatalogError::NoEnabledRules)
        ));
    }

    #[test]
    fn a_disabled_rule_is_kept_but_not_returned() {
        // Disabling beats deleting: the reasoning stays reviewable and re-enabling is a one-line diff.
        let text = r"
version: 1
rules:
  - id: live
    severity: high
    kind: connect_external
    title: t
  - id: dormant
    severity: critical
    kind: write_outside_zones
    title: t
    enabled: false
";
        let catalog = Catalog::from_yaml(text).expect("valid");
        assert_eq!(catalog.rules.len(), 2, "the entry is retained");
        assert!(catalog.rule_for(RuleKind::WriteOutsideZones).is_none());
        assert!(catalog.rule_for(RuleKind::ConnectExternal).is_some());
    }

    #[test]
    fn registry_matching_respects_label_boundaries() {
        // A lookalike domain must not be classified as registry infrastructure, or its traffic silently
        // stops being a finding — the case Architecture.md:61 exists to catch.
        let catalog = Catalog::embedded().expect("valid");
        assert!(catalog.is_registry_host("registry.npmjs.org"));
        assert!(catalog.is_registry_host("cdn.npmjs.org"));
        assert!(catalog.is_registry_host("npmjs.org"));

        assert!(!catalog.is_registry_host("evil-npmjs.org"));
        assert!(!catalog.is_registry_host("npmjs.org.attacker.com"));
        assert!(!catalog.is_registry_host("telemetry.example.com"));
    }

    #[test]
    fn host_matching_is_case_and_dot_insensitive() {
        let catalog = Catalog::embedded().expect("valid");
        assert!(catalog.is_registry_host("REGISTRY.NPMJS.ORG"));
        // A fully-qualified name with a trailing dot is the same host.
        assert!(catalog.is_registry_host("registry.npmjs.org."));
    }

    #[test]
    fn binary_distribution_hosts_are_recognized_separately_from_registries() {
        let catalog = Catalog::embedded().expect("valid");
        assert!(catalog.is_binary_distribution_host("objects.githubusercontent.com"));
        assert!(catalog.is_binary_distribution_host("github.com"));
        assert!(!catalog.is_binary_distribution_host("telemetry.example.com"));
        // And a registry host is not a binary distribution host.
        assert!(!catalog.is_binary_distribution_host("registry.npmjs.org"));
    }

    #[test]
    fn credential_paths_match_by_fragment_and_by_filename() {
        let catalog = Catalog::embedded().expect("valid");
        assert!(catalog.is_credential_path("/home/runner/.ssh/id_rsa"));
        assert!(catalog.is_credential_path("/root/.aws/credentials"));
        assert!(catalog.is_credential_path("/work/project/.env"));
        assert!(catalog.is_credential_path("/work/project/.env.production"));
        assert!(catalog.is_credential_path("/etc/shadow"));

        assert!(!catalog.is_credential_path("/work/project/index.js"));
        assert!(!catalog.is_credential_path("/work/project/environment.md"));
    }

    #[test]
    fn expected_and_network_spawns_are_distinguished() {
        let catalog = Catalog::embedded().expect("valid");
        assert!(catalog.is_expected_spawn("node"));
        assert!(catalog.is_expected_spawn("gcc"));
        assert!(catalog.is_network_tool("curl"));
        assert!(catalog.is_network_tool("wget"));
        // curl is a network tool and deliberately NOT on the expected list, or the rule could never fire.
        assert!(!catalog.is_expected_spawn("curl"));
        assert!(!catalog.is_network_tool("node"));
    }

    #[test]
    fn every_kind_maps_to_an_observation_class() {
        // The coverage contract: a report must be able to say "this rule could not run here" rather than
        // reporting nothing and letting a reader infer the behavior did not happen.
        use crate::coverage::ObservationClass;
        assert_eq!(
            RuleKind::CredentialRead.observation_class(),
            ObservationClass::CredentialReads
        );
        assert_eq!(
            RuleKind::DnsOutsideRegistry.observation_class(),
            ObservationClass::DnsQueries
        );
        assert_eq!(
            RuleKind::WriteOutsideZones.observation_class(),
            ObservationClass::FilesystemWrites
        );
        assert_eq!(
            RuleKind::DownloadPipedToShell.observation_class(),
            ObservationClass::ProcessSpawns
        );
        assert_eq!(
            RuleKind::ConnectUnusualPort.observation_class(),
            ObservationClass::NetworkConnections
        );
    }

    #[test]
    fn a_catalog_round_trips_through_yaml() {
        // The catalog is serialized back out in reports, so a field that cannot round trip would appear
        // in the artifact differently from the file it came from.
        let catalog = Catalog::embedded().expect("valid");
        let text = serde_yaml::to_string(&catalog).expect("serialize");
        let back = Catalog::from_yaml(&text).expect("reparse");
        assert_eq!(catalog, back);
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let path = std::path::Path::new("/definitely/not/here/catalog.yaml");
        match Catalog::load(path) {
            Err(CatalogError::Io { path: reported, .. }) => assert_eq!(reported, path),
            other => panic!("expected Io, got {other:?}"),
        }
    }
}
