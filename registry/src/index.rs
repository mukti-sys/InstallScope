//! The snapshot index: which recordings exist, and where.
//!
//! Architecture.md:89 specifies a JSONL index of `{pkg, version, digest, recorded_at, agent_v}`. One
//! line per recording, appended, never rewritten — the same format as the event stream itself, for the
//! same reason: a process killed mid-write leaves a file whose surviving lines are all still readable.
//!
//! # Why several entries per version are allowed
//!
//! The same `package@version` can be recorded more than once: by a different backend, on a different
//! kernel, or after a fix to the recorder. Collapsing those into one entry would throw away the ability
//! to say *why* two recordings of the same version disagree, which is precisely the question a
//! behavioral diff raises. So the index is a log, and lookups return the most recent match while
//! keeping the rest reachable.
//!
//! # Why a malformed line is fatal
//!
//! Skipping it would report a smaller corpus than exists. A diff against a version whose index line was
//! quietly dropped looks like a first recording — "no previous behavior to compare" — which is the same
//! silent-absence failure PRD.md:58 names. So [`Index::load`] refuses, naming the line.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, Result};
use crate::store::Digest;

/// The index filename inside a registry root.
pub const INDEX_FILENAME: &str = "index.jsonl";

/// One recording, as the index records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Package name, as published.
    #[serde(rename = "pkg")]
    pub package: String,
    /// Package version.
    pub version: String,
    /// Content address of the snapshot blob.
    pub digest: String,
    /// RFC3339 UTC instant the recording was made.
    ///
    /// Copied from the recording's own `session_start.wall_clock_utc` rather than taken from the clock
    /// at push time. The index describes when the behavior was observed, not when someone got around to
    /// storing it, and those can be days apart when a corpus is backfilled.
    pub recorded_at: String,
    /// Recorder version that produced the stream.
    ///
    /// Load-bearing for the diff engine: a behavioral difference between two versions means nothing if
    /// the two recordings came from recorders that saw different things.
    #[serde(rename = "agent_v")]
    pub agent_version: String,
    /// Which backend recorded it.
    pub backend: String,
    /// Observations in the stream, excluding framing events.
    pub events: u64,
    /// Uncompressed size of the stream in bytes.
    pub uncompressed_bytes: u64,
}

impl Entry {
    /// The digest as a validated address.
    ///
    /// # Errors
    /// [`RegistryError::InvalidDigest`] when the recorded digest is malformed — which matters because
    /// the digest becomes a path, and an index file is editable.
    pub fn digest(&self) -> Result<Digest> {
        Digest::parse(&self.digest)
    }

    /// `package@version`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}@{}", self.package, self.version)
    }
}

/// The append-only snapshot index.
#[derive(Debug, Clone, Default)]
pub struct Index {
    entries: Vec<Entry>,
    path: PathBuf,
}

impl Index {
    /// Loads the index at a registry root, treating an absent file as empty.
    ///
    /// An absent index is the normal first-run state, so it is not an error. A *malformed* one is.
    ///
    /// # Errors
    /// [`RegistryError::Io`] when the file exists but cannot be read, and
    /// [`RegistryError::MalformedIndexEntry`] when any line is not a valid entry.
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(INDEX_FILENAME);
        if !path.exists() {
            return Ok(Self {
                entries: Vec::new(),
                path,
            });
        }
        let text =
            std::fs::read_to_string(&path).map_err(|source| RegistryError::io(&path, source))?;

        let mut entries = Vec::new();
        for (offset, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: Entry = serde_json::from_str(line).map_err(|source| {
                RegistryError::MalformedIndexEntry {
                    line: offset + 1,
                    path: path.clone(),
                    source,
                }
            })?;
            entries.push(entry);
        }
        Ok(Self { entries, path })
    }

    /// Every entry, in the order they were appended.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of recordings indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends an entry and flushes it.
    ///
    /// Appended rather than rewritten so an interrupted push cannot corrupt entries that were already
    /// durable. Flushed immediately for the same reason the recorder flushes per event: a record that
    /// exists only in memory is not a record.
    ///
    /// # Errors
    /// [`RegistryError::Io`] on a write failure, or a serialization failure surfaced as I/O.
    pub fn append(&mut self, entry: Entry) -> Result<()> {
        use std::io::Write as _;

        let line = serde_json::to_string(&entry).map_err(|source| {
            RegistryError::io(
                &self.path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            )
        })?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| RegistryError::io(parent, source))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| RegistryError::io(&self.path, source))?;
        writeln!(file, "{line}").map_err(|source| RegistryError::io(&self.path, source))?;
        file.flush()
            .map_err(|source| RegistryError::io(&self.path, source))?;

        self.entries.push(entry);
        Ok(())
    }

    /// The most recent entry for a package version.
    ///
    /// "Most recent" means last appended, not the largest `recorded_at`. A backfill records old
    /// versions after new ones, so append order is the honest reading of "the recording we would use
    /// now", and it does not depend on a timestamp a caller could get wrong.
    #[must_use]
    pub fn latest(&self, package: &str, version: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.package == package && entry.version == version)
    }

    /// Every entry for a package version, oldest first.
    #[must_use]
    pub fn all_for(&self, package: &str, version: &str) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|entry| entry.package == package && entry.version == version)
            .collect()
    }

    /// Every version recorded for a package, in the order first seen.
    ///
    /// Deliberately *not* sorted: semver ordering is not this crate's job, and a naive string sort
    /// would put `1.10.0` before `1.9.0` and make a diff report the wrong direction.
    #[must_use]
    pub fn versions_of(&self, package: &str) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for entry in &self.entries {
            if entry.package == package && !seen.contains(&entry.version.as_str()) {
                seen.push(&entry.version);
            }
        }
        seen
    }

    /// Every package with at least one recording, sorted.
    #[must_use]
    pub fn packages(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .entries
            .iter()
            .map(|entry| entry.package.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Looks up an entry, or reports what is available instead.
    ///
    /// # Errors
    /// [`RegistryError::NoSuchVersion`] naming the package and version, so a caller can tell "we have
    /// never recorded this" from "the store is broken".
    pub fn require(&self, package: &str, version: &str) -> Result<&Entry> {
        self.latest(package, version)
            .ok_or_else(|| RegistryError::NoSuchVersion {
                package: package.to_string(),
                version: version.to_string(),
                index: self.path.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let unique = format!(
                "installscope-index-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let path = std::env::temp_dir().join(unique.replace(['(', ')', ' '], ""));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create scratch");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entry(package: &str, version: &str, digest_seed: u8) -> Entry {
        Entry {
            package: package.to_string(),
            version: version.to_string(),
            digest: format!("{digest_seed:02x}").repeat(32),
            recorded_at: "2026-09-01T12:00:00Z".to_string(),
            agent_version: "0.1.0".to_string(),
            backend: "strace".to_string(),
            events: 42,
            uncompressed_bytes: 4096,
        }
    }

    #[test]
    fn an_absent_index_is_empty_rather_than_an_error() {
        // The normal first-run state. Erroring would make every fresh checkout look broken.
        let scratch = Scratch::new("absent");
        let index = Index::load(scratch.path()).expect("load");
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn an_appended_entry_survives_a_reload() {
        let scratch = Scratch::new("append");
        let mut index = Index::load(scratch.path()).expect("load");
        index
            .append(entry("lodash", "4.17.21", 0xaa))
            .expect("append");

        let reloaded = Index::load(scratch.path()).expect("reload");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.entries()[0].package, "lodash");
        assert_eq!(reloaded.entries()[0].version, "4.17.21");
    }

    #[test]
    fn appending_does_not_rewrite_earlier_entries() {
        // The property that makes an interrupted push survivable.
        let scratch = Scratch::new("append-only");
        let mut index = Index::load(scratch.path()).expect("load");
        index.append(entry("a", "1.0.0", 0x11)).expect("append");
        let after_first =
            std::fs::read_to_string(scratch.path().join(INDEX_FILENAME)).expect("read");
        index.append(entry("b", "2.0.0", 0x22)).expect("append");
        let after_second =
            std::fs::read_to_string(scratch.path().join(INDEX_FILENAME)).expect("read");

        assert!(
            after_second.starts_with(&after_first),
            "the second append must extend the file, not rewrite it"
        );
        assert_eq!(after_second.lines().count(), 2);
    }

    #[test]
    fn a_malformed_line_is_refused_and_named() {
        // Skipping it would report a smaller corpus than exists, and a diff against the dropped version
        // would look like a first recording.
        let scratch = Scratch::new("malformed");
        let path = scratch.path().join(INDEX_FILENAME);
        std::fs::write(
            &path,
            "{\"pkg\":\"a\",\"version\":\"1\",\"digest\":\"aa\",\"recorded_at\":\"x\",\"agent_v\":\"1\",\"backend\":\"strace\",\"events\":1,\"uncompressed_bytes\":1}\nnot json at all\n",
        )
        .expect("write");

        let err = Index::load(scratch.path()).expect_err("must refuse");
        match err {
            RegistryError::MalformedIndexEntry { line, .. } => {
                assert_eq!(line, 2, "the error must name the offending line");
            }
            other => panic!("expected MalformedIndexEntry, got {other}"),
        }
    }

    #[test]
    fn blank_lines_are_tolerated() {
        // A trailing newline is normal; an editor may leave a blank line. Neither is corruption.
        let scratch = Scratch::new("blank");
        let path = scratch.path().join(INDEX_FILENAME);
        let line = serde_json::to_string(&entry("a", "1.0.0", 0x11)).expect("serialize");
        std::fs::write(&path, format!("{line}\n\n{line}\n")).expect("write");
        assert_eq!(Index::load(scratch.path()).expect("load").len(), 2);
    }

    #[test]
    fn several_recordings_of_one_version_are_all_kept() {
        // A second recording by another backend is a different observation of the same version, and the
        // disagreement between them is information a diff might need to explain.
        let scratch = Scratch::new("multi");
        let mut index = Index::load(scratch.path()).expect("load");
        index.append(entry("ms", "2.1.3", 0x11)).expect("append");
        let mut second = entry("ms", "2.1.3", 0x22);
        second.backend = "aya".to_string();
        index.append(second).expect("append");

        assert_eq!(index.all_for("ms", "2.1.3").len(), 2);
        assert_eq!(
            index.latest("ms", "2.1.3").map(|e| e.backend.as_str()),
            Some("aya"),
            "the most recent append wins for a plain lookup"
        );
        assert_eq!(index.versions_of("ms"), vec!["2.1.3"], "one version, twice");
    }

    #[test]
    fn latest_means_last_appended_not_largest_timestamp() {
        // A backfill records old versions after new ones. Using the timestamp would make the lookup
        // depend on the order a corpus happened to be built in.
        let scratch = Scratch::new("latest");
        let mut index = Index::load(scratch.path()).expect("load");
        let mut newer_timestamp = entry("ms", "2.1.3", 0x11);
        newer_timestamp.recorded_at = "2027-01-01T00:00:00Z".to_string();
        newer_timestamp.agent_version = "old-run".to_string();
        index.append(newer_timestamp).expect("append");

        let mut older_timestamp = entry("ms", "2.1.3", 0x22);
        older_timestamp.recorded_at = "2020-01-01T00:00:00Z".to_string();
        older_timestamp.agent_version = "new-run".to_string();
        index.append(older_timestamp).expect("append");

        assert_eq!(
            index
                .latest("ms", "2.1.3")
                .map(|e| e.agent_version.as_str()),
            Some("new-run")
        );
    }

    #[test]
    fn versions_are_reported_in_first_seen_order_not_sorted() {
        // A string sort would put 1.10.0 before 1.9.0 and make a diff report the wrong direction.
        // Semver ordering is not this crate's job, so it does not pretend to do it.
        let scratch = Scratch::new("order");
        let mut index = Index::load(scratch.path()).expect("load");
        index.append(entry("x", "1.9.0", 0x11)).expect("append");
        index.append(entry("x", "1.10.0", 0x22)).expect("append");
        assert_eq!(index.versions_of("x"), vec!["1.9.0", "1.10.0"]);
    }

    #[test]
    fn packages_are_deduplicated_and_sorted() {
        let scratch = Scratch::new("packages");
        let mut index = Index::load(scratch.path()).expect("load");
        index.append(entry("zebra", "1.0.0", 0x11)).expect("append");
        index.append(entry("alpha", "1.0.0", 0x22)).expect("append");
        index.append(entry("alpha", "2.0.0", 0x33)).expect("append");
        assert_eq!(index.packages(), vec!["alpha", "zebra"]);
    }

    #[test]
    fn a_missing_version_is_reported_specifically() {
        // "We have never recorded this" and "the store is broken" need different responses.
        let scratch = Scratch::new("require");
        let index = Index::load(scratch.path()).expect("load");
        let err = index.require("lodash", "4.17.21").expect_err("must fail");
        let text = err.to_string();
        assert!(text.contains("lodash"), "{text}");
        assert!(text.contains("4.17.21"), "{text}");
        assert!(matches!(err, RegistryError::NoSuchVersion { .. }));
    }

    #[test]
    fn a_malformed_digest_in_the_index_is_refused_when_used() {
        // An index file is editable text. A digest becomes a path, so it is validated at the point of
        // use rather than trusted because it came from our own file.
        let mut hostile = entry("x", "1.0.0", 0x11);
        hostile.digest = "../../etc/passwd".to_string();
        assert!(matches!(
            hostile.digest().expect_err("must refuse"),
            RegistryError::InvalidDigest { .. }
        ));
    }

    #[test]
    fn an_entry_round_trips_through_the_documented_field_names() {
        // Architecture.md:89 names the fields {pkg, version, digest, recorded_at, agent_v}. The struct
        // uses clearer Rust names, so the rename attributes are what keep the file format as specified.
        let line = serde_json::to_string(&entry("ms", "2.1.3", 0xab)).expect("serialize");
        let json: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        for field in [
            "pkg",
            "version",
            "digest",
            "recorded_at",
            "agent_v",
            "backend",
            "events",
        ] {
            assert!(
                json.get(field).is_some(),
                "the index format requires a {field} field: {line}"
            );
        }
        let back: Entry = serde_json::from_str(&line).expect("deserialize");
        assert_eq!(back, entry("ms", "2.1.3", 0xab));
    }
}
