//! Snapshot registry v0 and the behavioral version-diff engine.
//!
//! Architecture.md §6 calls this deliberately boring, and Architecture.md:90 calls the diff the moat:
//! *"this package's behavior changed between 1.2.3 and 1.2.4."* Two things have to be true for that
//! sentence to be worth saying, and this crate is where both are enforced.
//!
//! ```text
//! events.jsonl ──▶ push ──┬──▶ blobs/ab/cdef…   sha256(zstd(events))
//!                         └──▶ index.jsonl      {pkg, version, digest, recorded_at, agent_v}
//!
//! index.jsonl ──▶ diff_versions("lodash", "4.17.20", "4.17.21") ──▶ Comparison
//! ```
//!
//! # The store must be able to prove what it holds
//!
//! Content addressing is not a filename scheme here. [`store::Store::read`] hashes every blob it reads
//! and refuses a mismatch, so a corpus is tamper-evident to its own users — the same property
//! Architecture.md:101 asks of a single recording, one level up. There is no unverified read path.
//!
//! # The store must refuse evidence it cannot stand behind
//!
//! [`push`] rejects a PARTIAL recording. This is the one refusal in the crate that costs a user
//! something, so the reasoning is worth stating plainly: a version-to-version diff drawn against an
//! incomplete recording reports "this behavior disappeared in 1.2.4" when the recorder actually stopped
//! early. That is PRD.md:58's worst failure mode made permanent and then published as a receipt.
//!
//! A caller who wants to keep an incomplete recording still can — the artifact is on disk either way.
//! What they cannot do is put it in the durable record that the diff engine reads.
//!
//! # No network authority
//!
//! Architecture.md:103: the product never uploads anything the user did not see in their report first.
//! This crate has no network dependency and no way to acquire one — the store is a directory. A remote
//! backend, if it ever exists, is an adapter over this layout, and the decision to upload belongs to the
//! CLI where a human can see it.

#![forbid(unsafe_code)]
// Rules.md §2 bans unwrap/expect in non-test code.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

pub mod behavior;
pub mod diff;
pub mod error;
pub mod index;
pub mod store;

pub use behavior::{profile_of, Behavior, BehaviorClass, Profile};
pub use diff::{compare, Blocker, Caveat, Comparison, Recording, Side};
pub use error::{RegistryError, Result};
pub use index::{Entry, Index, INDEX_FILENAME};
pub use store::{Digest, Store, COMPRESSION_LEVEL, MAX_DECOMPRESSED_BYTES};

use installscope_core::{Event, Payload};

/// A registry: a blob store plus its index.
#[derive(Debug)]
pub struct Registry {
    store: Store,
    index: Index,
}

impl Registry {
    /// Opens a registry at `root`, creating it if absent.
    ///
    /// # Errors
    /// [`RegistryError::Io`] if the root cannot be created, or
    /// [`RegistryError::MalformedIndexEntry`] if an existing index has an unreadable line.
    pub fn open(root: impl Into<std::path::PathBuf>) -> Result<Self> {
        let root = root.into();
        let store = Store::open(&root)?;
        let index = Index::load(&root)?;
        Ok(Self { store, index })
    }

    /// The blob store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// The index.
    #[must_use]
    pub const fn index(&self) -> &Index {
        &self.index
    }

    /// Stores a recording and indexes it.
    ///
    /// The stream is parsed before anything is written, so a malformed or incomplete recording is
    /// refused without leaving a blob behind. See the crate docs for why PARTIAL is refused.
    ///
    /// # Errors
    /// [`RegistryError::PartialRecording`] when the recording is incomplete,
    /// [`RegistryError::UnreadableStream`] when the stream does not parse, and otherwise as
    /// [`Store::write`] and [`Index::append`].
    pub fn push(&mut self, package: &str, version: &str, events_jsonl: &str) -> Result<Entry> {
        let events = parse_stream(events_jsonl, package, version)?;
        let facts = StreamFacts::of(&events);

        if !facts.complete {
            return Err(RegistryError::PartialRecording {
                package: package.to_string(),
                version: version.to_string(),
                reasons: if facts.incomplete_reasons.is_empty() {
                    "the recording has no session_end event".to_string()
                } else {
                    facts.incomplete_reasons.join("; ")
                },
            });
        }

        let digest = self.store.write(events_jsonl.as_bytes())?;
        let entry = Entry {
            package: package.to_string(),
            version: version.to_string(),
            digest: digest.to_string(),
            recorded_at: facts.recorded_at,
            agent_version: facts.agent_version,
            backend: facts.backend,
            events: facts.events,
            uncompressed_bytes: events_jsonl.len() as u64,
        };
        self.index.append(entry.clone())?;
        Ok(entry)
    }

    /// Reads a stored recording back as parsed events.
    ///
    /// # Errors
    /// As [`Store::read`], plus [`RegistryError::UnreadableStream`] if the stored bytes are not a valid
    /// event stream — which would mean a valid blob holding invalid content, so it names the digest.
    pub fn events_of(&self, entry: &Entry) -> Result<Vec<Event>> {
        let digest = entry.digest()?;
        let bytes = self.store.read(&digest)?;
        let text = String::from_utf8_lossy(&bytes);
        parse_stream_for_digest(&text, digest.as_str())
    }

    /// Reduces a stored recording to a comparable profile.
    ///
    /// # Errors
    /// As [`Self::events_of`].
    pub fn recording_of(&self, entry: &Entry) -> Result<Recording> {
        let events = self.events_of(entry)?;
        Ok(Recording {
            version: entry.version.clone(),
            agent_version: entry.agent_version.clone(),
            profile: profile_of(&events),
        })
    }

    /// Compares two recorded versions of a package.
    ///
    /// # Errors
    /// [`RegistryError::NoSuchVersion`] when either version is not indexed, and otherwise as
    /// [`Self::recording_of`].
    pub fn diff_versions(
        &self,
        package: &str,
        before_version: &str,
        after_version: &str,
    ) -> Result<Comparison> {
        let before_entry = self.index.require(package, before_version)?;
        let after_entry = self.index.require(package, after_version)?;
        let before = self.recording_of(before_entry)?;
        let after = self.recording_of(after_entry)?;
        Ok(compare(package, &before, &after))
    }

    /// Verifies every indexed snapshot against its content address.
    ///
    /// Exists because content addressing only pays off if someone checks. A corpus is the durable record
    /// behind every published receipt, and "the digests were right when we wrote them" is a weaker claim
    /// than "they are right now" — the file may have been edited, restored from a bad backup, or lost a
    /// bit on disk since.
    ///
    /// Returns one report per entry rather than the first failure, so a single corrupted blob does not
    /// hide the state of the rest.
    ///
    /// # Errors
    /// Never fails as a whole: a per-entry failure is a [`Verification`] result, because the point is to
    /// survey the store rather than to stop at the first problem.
    #[must_use]
    pub fn verify_all(&self) -> Vec<Verification> {
        self.index
            .entries()
            .iter()
            .map(|entry| {
                let outcome = match entry.digest() {
                    Err(error) => Err(error),
                    Ok(digest) => self.store.read(&digest).and_then(|bytes| {
                        // A blob that hashes correctly can still hold something that is not an event
                        // stream, which would be a valid address over invalid content.
                        let text = String::from_utf8_lossy(&bytes);
                        parse_stream_for_digest(&text, digest.as_str()).map(|events| {
                            // Observations only, so the number is comparable with the index entry's own
                            // `events` field. Counting framing events here would make a survey disagree
                            // with the index for every snapshot.
                            events
                                .iter()
                                .filter(|event| !event.payload.is_framing())
                                .count()
                        })
                    }),
                };
                Verification {
                    package: entry.package.clone(),
                    version: entry.version.clone(),
                    digest: entry.digest.clone(),
                    outcome: match outcome {
                        Ok(events) => Ok(events),
                        Err(error) => Err(error.to_string()),
                    },
                }
            })
            .collect()
    }
}

/// The result of verifying one stored snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Package the entry claims to be of.
    pub package: String,
    /// Version.
    pub version: String,
    /// The address it is stored under.
    pub digest: String,
    /// `Ok(event count)` when the blob verified and parsed; `Err(reason)` otherwise.
    ///
    /// The count excludes framing events, so it is directly comparable with the index entry's own
    /// `events` field — a survey that disagreed with the index on every intact snapshot would be useless.
    ///
    /// The reason is a rendered string rather than a typed error because a survey is presentation, and a
    /// caller that needs to act on a specific failure should read the blob itself.
    pub outcome: std::result::Result<usize, String>,
}

impl Verification {
    /// True when this snapshot is intact and readable.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.outcome.is_ok()
    }

    /// `package@version`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}@{}", self.package, self.version)
    }
}

/// Facts a stream carries about itself, needed for the index.
struct StreamFacts {
    complete: bool,
    incomplete_reasons: Vec<String>,
    recorded_at: String,
    agent_version: String,
    backend: String,
    events: u64,
}

impl StreamFacts {
    /// Reads the framing events.
    ///
    /// Everything here comes from the recording rather than from the caller or the clock. An index entry
    /// that said "recorded at" the push time would be wrong by days for a backfilled corpus, and one
    /// that took the agent version from the running binary would attribute an old recording to a new
    /// recorder — which is exactly the thing the diff engine's caveat depends on being accurate.
    fn of(events: &[Event]) -> Self {
        let mut facts = Self {
            complete: false,
            incomplete_reasons: Vec::new(),
            recorded_at: String::new(),
            agent_version: String::new(),
            backend: events.first().map_or_else(
                || "unknown".to_string(),
                |event| event.meta.backend.to_string(),
            ),
            events: 0,
        };

        for event in events {
            match &event.payload {
                Payload::SessionStart(start) => {
                    facts.recorded_at.clone_from(&start.wall_clock_utc);
                    facts.agent_version.clone_from(&start.agent_version);
                }
                Payload::SessionEnd(end) => {
                    facts.complete = end.complete;
                    facts.incomplete_reasons = end
                        .incomplete_reasons
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                }
                Payload::Heartbeat(_) => {}
                _ => facts.events += 1,
            }
        }
        facts
    }
}

/// Parses a JSONL stream, attributing a failure to the package being pushed.
fn parse_stream(text: &str, package: &str, version: &str) -> Result<Vec<Event>> {
    parse_lines(text).map_err(|source| RegistryError::UnreadableStream {
        digest: format!("{package}@{version} (not yet stored)"),
        source,
    })
}

/// Parses a JSONL stream, attributing a failure to a stored digest.
fn parse_stream_for_digest(text: &str, digest: &str) -> Result<Vec<Event>> {
    parse_lines(text).map_err(|source| RegistryError::UnreadableStream {
        digest: digest.to_string(),
        source,
    })
}

/// Strict line-by-line parse.
///
/// A line that does not parse is an error rather than a skip, for the reason the event schema already
/// gives (`core/src/events.rs`): a reader that ignores what it does not understand reports a cleaner
/// install than actually occurred.
fn parse_lines(text: &str) -> std::result::Result<Vec<Event>, installscope_core::CoreError> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(offset, line)| Event::from_jsonl(line, offset + 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let unique = format!(
                "installscope-registry-{label}-{}-{:?}",
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

    /// A minimal complete recording, parameterised so two "versions" can differ by one behavior.
    ///
    /// `session_end.events_emitted` is computed rather than hardcoded: a fixture whose framing
    /// contradicts its own body would let a bug in the counting logic pass unnoticed.
    fn recording_jsonl(root: &str, extra_write: Option<&str>, complete: bool) -> String {
        let mut lines = vec![format!(
            r#"{{"schema_version":1,"ts_ns":0,"backend":"strace","op":"session_start","wall_clock_utc":"2026-09-01T12:00:00Z","agent_version":"0.1.0","command":["npm","install"],"zones":{{"project":"{root}/project","cache":"{root}/cache"}}}}"#
        )];
        lines.push(format!(
            r#"{{"schema_version":1,"ts_ns":1,"pid":10,"syscall":"openat","backend":"strace","op":"fs_write","target":{{"path":"{root}/project/node_modules/base.js","origin":"kernel"}},"kind":"open","ok":true}}"#
        ));
        let mut observations = 1;
        if let Some(path) = extra_write {
            observations += 1;
            lines.push(format!(
                r#"{{"schema_version":1,"ts_ns":2,"pid":10,"syscall":"openat","backend":"strace","op":"fs_write","target":{{"path":"{path}","origin":"kernel"}},"kind":"open","ok":true}}"#
            ));
        }
        lines.push(format!(
            r#"{{"schema_version":1,"ts_ns":3,"backend":"strace","op":"heartbeat","seq":1,"events_so_far":{observations}}}"#
        ));
        if complete {
            lines.push(format!(
                r#"{{"schema_version":1,"ts_ns":4,"backend":"strace","op":"session_end","complete":true,"command_exit_code":0,"duration_ns":4,"events_emitted":{observations},"heartbeats":1}}"#
            ));
        } else {
            lines.push(format!(
                r#"{{"schema_version":1,"ts_ns":4,"backend":"strace","op":"session_end","complete":false,"incomplete_reasons":[{{"timeout":{{"limit_secs":120}}}}],"duration_ns":4,"events_emitted":{observations},"heartbeats":1}}"#
            ));
        }
        format!("{}\n", lines.join("\n"))
    }

    #[test]
    fn a_pushed_recording_is_retrievable_and_indexed() {
        let scratch = Scratch::new("push");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let jsonl = recording_jsonl("/work", None, true);

        let entry = registry.push("lodash", "4.17.21", &jsonl).expect("push");
        assert_eq!(entry.package, "lodash");
        assert_eq!(entry.version, "4.17.21");
        assert_eq!(entry.backend, "strace");
        assert_eq!(entry.events, 1, "one observation, framing excluded");
        assert_eq!(entry.uncompressed_bytes, jsonl.len() as u64);

        // The blob reads back byte-identical, through the verifying path.
        let digest = entry.digest().expect("digest");
        assert_eq!(
            registry.store().read(&digest).expect("read"),
            jsonl.as_bytes()
        );
        // And the index survives a reopen.
        let reopened = Registry::open(scratch.path()).expect("reopen");
        assert_eq!(reopened.index().len(), 1);
        assert_eq!(
            reopened
                .index()
                .latest("lodash", "4.17.21")
                .map(|e| e.digest.clone()),
            Some(entry.digest)
        );
    }

    #[test]
    fn the_index_records_the_recordings_own_metadata_not_the_pushers() {
        // A backfilled corpus records old versions months later. An index that stamped push time would
        // be wrong by months, and one that stamped the running binary's version would break the diff
        // engine's agent-version caveat.
        let scratch = Scratch::new("metadata");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let entry = registry
            .push("x", "1.0.0", &recording_jsonl("/work", None, true))
            .expect("push");
        assert_eq!(entry.recorded_at, "2026-09-01T12:00:00Z");
        assert_eq!(entry.agent_version, "0.1.0");
    }

    #[test]
    fn a_partial_recording_is_refused_and_leaves_no_blob() {
        // The refusal that costs a user something, so it must not half-happen: no blob, no index line.
        let scratch = Scratch::new("partial");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let jsonl = recording_jsonl("/work", None, false);

        let err = registry
            .push("x", "1.0.0", &jsonl)
            .expect_err("must refuse");
        match &err {
            RegistryError::PartialRecording {
                package, reasons, ..
            } => {
                assert_eq!(package, "x");
                assert!(
                    reasons.contains("120s"),
                    "the reason must be specific: {reasons}"
                );
            }
            other => panic!("expected PartialRecording, got {other}"),
        }
        assert!(
            err.to_string()
                .contains("attribute the recorder's failure to the package"),
            "the error must say why: {err}"
        );

        assert!(registry.index().is_empty(), "nothing may be indexed");
        // Checked by inspecting the store rather than by recomputing the digest, so the assertion does
        // not depend on the compression settings it is trying to prove were never applied.
        let blobs = scratch.path().join("blobs");
        assert!(
            !blobs.exists() || std::fs::read_dir(&blobs).into_iter().flatten().count() == 0,
            "no blob may be written for a refused push: {}",
            blobs.display()
        );
    }

    #[test]
    fn a_recording_with_no_session_end_is_refused() {
        // Structurally the same failure as an explicit PARTIAL, and the more dangerous one because it
        // looks like a clean short stream.
        let scratch = Scratch::new("no-end");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let jsonl = recording_jsonl("/work", None, true);
        let mut truncated = String::new();
        for line in jsonl.lines().filter(|line| !line.contains("session_end")) {
            truncated.push_str(line);
            truncated.push('\n');
        }

        let err = registry
            .push("x", "1.0.0", &truncated)
            .expect_err("must refuse");
        assert!(
            matches!(err, RegistryError::PartialRecording { .. }),
            "got {err}"
        );
        assert!(err.to_string().contains("no session_end"), "{err}");
    }

    #[test]
    fn a_malformed_stream_is_refused_before_anything_is_written() {
        let scratch = Scratch::new("malformed");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let err = registry
            .push("x", "1.0.0", "{not an event}\n")
            .expect_err("must refuse");
        assert!(
            matches!(err, RegistryError::UnreadableStream { .. }),
            "got {err}"
        );
        assert!(registry.index().is_empty());
    }

    #[test]
    fn pushing_the_same_recording_twice_stores_one_blob_and_two_index_lines() {
        // Deduplicated storage, but the index is a log: two pushes are two events, and collapsing them
        // would lose the fact that the same version was recorded twice.
        let scratch = Scratch::new("twice");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let jsonl = recording_jsonl("/work", None, true);
        let first = registry.push("x", "1.0.0", &jsonl).expect("push");
        let second = registry.push("x", "1.0.0", &jsonl).expect("push again");

        assert_eq!(first.digest, second.digest, "identical evidence, one blob");
        assert_eq!(registry.index().len(), 2);
        assert_eq!(registry.index().all_for("x", "1.0.0").len(), 2);
    }

    #[test]
    fn two_versions_recorded_in_different_directories_diff_cleanly() {
        // The end-to-end property the moat depends on: two recordings made on different machines, one
        // behavioral difference, and the diff must report exactly that difference and nothing else.
        let scratch = Scratch::new("diff");
        let mut registry = Registry::open(scratch.path()).expect("open");

        registry
            .push(
                "lodash",
                "4.17.20",
                &recording_jsonl("/home/runner/work/abc", None, true),
            )
            .expect("push before");
        registry
            .push(
                "lodash",
                "4.17.21",
                &recording_jsonl("/tmp/scratch", Some("/etc/cron.d/evil"), true),
            )
            .expect("push after");

        let comparison = registry
            .diff_versions("lodash", "4.17.20", "4.17.21")
            .expect("diff");

        assert!(comparison.comparable(), "{:?}", comparison.blockers);
        assert!(!comparison.is_identical());
        assert_eq!(
            comparison.added.len(),
            1,
            "only the /etc write differs; the directory change must not: {:?}",
            comparison
                .added
                .iter()
                .map(Behavior::summary)
                .collect::<Vec<_>>()
        );
        assert!(comparison.removed.is_empty(), "{:?}", comparison.removed);
        assert_eq!(comparison.unchanged, 1, "the shared project write");
        assert_eq!(
            comparison.added_in(BehaviorClass::FilesystemEscape).len(),
            1
        );
        assert!(comparison.headline().contains("behavior changed"));
    }

    #[test]
    fn identical_versions_recorded_in_different_directories_report_no_change() {
        // The complement, and the one a false positive would ruin: same behavior, different machines.
        let scratch = Scratch::new("same");
        let mut registry = Registry::open(scratch.path()).expect("open");
        registry
            .push(
                "x",
                "1.0.0",
                &recording_jsonl("/home/runner/work/abc", None, true),
            )
            .expect("push");
        registry
            .push("x", "1.0.1", &recording_jsonl("/tmp/elsewhere", None, true))
            .expect("push");

        let comparison = registry.diff_versions("x", "1.0.0", "1.0.1").expect("diff");
        assert!(comparison.comparable());
        assert!(
            comparison.is_identical(),
            "added {:?} removed {:?}",
            comparison
                .added
                .iter()
                .map(Behavior::summary)
                .collect::<Vec<_>>(),
            comparison
                .removed
                .iter()
                .map(Behavior::summary)
                .collect::<Vec<_>>()
        );
        assert!(comparison.headline().contains("behaved identically"));
    }

    #[test]
    fn diffing_an_unrecorded_version_names_it() {
        let scratch = Scratch::new("missing-version");
        let mut registry = Registry::open(scratch.path()).expect("open");
        registry
            .push("x", "1.0.0", &recording_jsonl("/work", None, true))
            .expect("push");

        let err = registry
            .diff_versions("x", "1.0.0", "9.9.9")
            .expect_err("must fail");
        assert!(err.to_string().contains("9.9.9"), "{err}");
        assert!(matches!(err, RegistryError::NoSuchVersion { .. }));
    }

    #[test]
    fn a_tampered_blob_breaks_the_diff_rather_than_producing_a_quiet_answer() {
        // The property that makes the corpus trustworthy: editing a stored recording to change history
        // fails loudly instead of silently rewriting every later comparison.
        let scratch = Scratch::new("tamper-diff");
        let mut registry = Registry::open(scratch.path()).expect("open");
        registry
            .push("x", "1.0.0", &recording_jsonl("/work", None, true))
            .expect("push");
        let entry = registry
            .push("x", "1.0.1", &recording_jsonl("/work", None, true))
            .expect("push");

        let digest = entry.digest().expect("digest");
        let path = registry.store().path_of(&digest);
        let mut bytes = std::fs::read(&path).expect("read blob");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xFF;
        std::fs::write(&path, &bytes).expect("tamper");

        let err = registry
            .diff_versions("x", "1.0.0", "1.0.1")
            .expect_err("must refuse");
        assert!(
            matches!(err, RegistryError::DigestMismatch { .. }),
            "got {err}"
        );
    }

    #[test]
    fn verify_all_surveys_the_whole_store_rather_than_stopping_at_the_first_problem() {
        // A corpus is the durable record behind every published receipt. One corrupted blob must not hide
        // the state of the rest, or an operator cannot tell a single bad file from a broken store.
        let scratch = Scratch::new("verify-all");
        let mut registry = Registry::open(scratch.path()).expect("open");
        registry
            .push("a", "1.0.0", &recording_jsonl("/work-a", None, true))
            .expect("push");
        let corrupt_me = registry
            .push("b", "1.0.0", &recording_jsonl("/work-b", None, true))
            .expect("push");
        registry
            .push("c", "1.0.0", &recording_jsonl("/work-c", None, true))
            .expect("push");

        // All three intact first.
        let clean = registry.verify_all();
        assert_eq!(clean.len(), 3);
        assert!(
            clean.iter().all(Verification::is_ok),
            "a freshly written store must verify: {clean:?}"
        );
        assert_eq!(clean[0].outcome, Ok(1), "one observation per fixture");
        assert_eq!(
            clean[0].outcome.clone().expect("intact"),
            usize::try_from(registry.index().entries()[0].events).expect("fits"),
            "the survey's count must agree with the index entry it verified"
        );

        // Corrupt the middle one.
        let digest = corrupt_me.digest().expect("digest");
        let path = registry.store().path_of(&digest);
        let mut bytes = std::fs::read(&path).expect("read blob");
        bytes[0] ^= 0xFF;
        std::fs::write(&path, &bytes).expect("tamper");

        let surveyed = registry.verify_all();
        assert_eq!(surveyed.len(), 3, "every entry is still reported");
        assert!(surveyed[0].is_ok(), "the first is untouched");
        assert!(!surveyed[1].is_ok(), "the corrupted one is reported");
        assert!(
            surveyed[2].is_ok(),
            "a corrupted entry must not hide the entries after it"
        );
        assert_eq!(surveyed[1].label(), "b@1.0.0");
        let reason = surveyed[1]
            .outcome
            .clone()
            .expect_err("the corrupted entry reports why");
        assert!(
            reason.contains("does not match its contents"),
            "the reason must name the failure: {reason}"
        );
    }

    #[test]
    fn verify_all_reports_a_valid_address_holding_invalid_content() {
        // A blob can hash correctly and still not be an event stream — a store that only checked digests
        // would call that intact.
        let scratch = Scratch::new("verify-content");
        let mut registry = Registry::open(scratch.path()).expect("open");
        let entry = registry
            .push("x", "1.0.0", &recording_jsonl("/work", None, true))
            .expect("push");

        // Replace the blob with a correctly-addressed compression of garbage.
        let junk = b"{\"not\":\"an event\"}\n";
        let digest = registry.store().write(junk).expect("write junk");
        let mut index_path = scratch.path().join(INDEX_FILENAME);
        let text = std::fs::read_to_string(&index_path).expect("read index");
        let rewritten = text.replace(&entry.digest, digest.as_str());
        std::fs::write(&mut index_path, rewritten).expect("rewrite index");

        let reopened = Registry::open(scratch.path()).expect("reopen");
        let surveyed = reopened.verify_all();
        assert_eq!(surveyed.len(), 1);
        assert!(
            !surveyed[0].is_ok(),
            "a valid address over invalid content is not an intact snapshot"
        );
    }

    #[test]
    fn verify_all_on_an_empty_store_reports_nothing_rather_than_failing() {
        let scratch = Scratch::new("verify-empty");
        let registry = Registry::open(scratch.path()).expect("open");
        assert!(registry.verify_all().is_empty());
    }

    #[test]
    fn the_crate_has_no_network_dependency() {
        // Architecture.md:103 and Rules.md §1. Asserted structurally in CI via `cargo tree`; asserted
        // here as a reminder at the point where someone would be tempted to add one, because "push"
        // sounds like it should upload something and it must not.
        //
        // The store is a directory. If this test ever needs changing, the change is a Scope.md decision.
        let scratch = Scratch::new("local-only");
        let registry = Registry::open(scratch.path()).expect("open");
        assert!(
            registry.store().root().is_dir(),
            "the registry is a local directory, not a client"
        );
    }
}
