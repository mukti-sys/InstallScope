//! Session writing — turns parsed events into a JSONL stream with trustworthy framing.
//!
//! Rules.md §2 is the whole design here: **a dead recording must surface as PARTIAL, never as
//! silence.** A green build with a silently-dead recorder is the worst outcome this project can
//! produce, worse than crashing. So:
//!
//! - every session opens with `session_start` and closes with `session_end`;
//! - heartbeats are emitted throughout, so a truncated stream shows where it stopped;
//! - events are flushed to disk as they are produced, not buffered until the end, because a
//!   recorder killed by the OOM killer must still leave the evidence it had;
//! - [`SessionWriter::finish_partial`] exists so every failure path has a way to say so.
//!
//! The type system carries the invariant: [`SessionWriter`] is consumed by both `finish_complete`
//! and `finish_partial`, so a session cannot be left unterminated without the compiler noticing an
//! unused value.

use std::io::Write;
use std::time::Instant;

use installscope_core::{
    Backend, CoreError, Event, Heartbeat, HostInfo, IncompleteReason, Payload, Result, SessionEnd,
    SessionStart, Zones,
};

/// Emit a heartbeat at least this often, measured in events.
const HEARTBEAT_EVENT_INTERVAL: u64 = 2_000;

/// Emit a heartbeat at least this often, measured in milliseconds. Time-based too, because a quiet
/// install that hangs for a minute must still prove the recorder was alive.
const HEARTBEAT_MS_INTERVAL: u128 = 2_000;

/// Writes a schema v1 JSONL stream, maintaining the framing invariants.
pub struct SessionWriter<W: Write> {
    sink: W,
    backend: Backend,
    started: Instant,
    events_emitted: u64,
    heartbeats: u64,
    last_heartbeat_events: u64,
    last_heartbeat_ms: u128,
    phase: Option<String>,
    finished: bool,
}

impl<W: Write> SessionWriter<W> {
    /// Opens a session, writing `session_start` immediately.
    ///
    /// Written before the traced command starts, so a recorder that dies during startup still leaves
    /// a stream that says what it was trying to do.
    ///
    /// # Errors
    /// [`CoreError::Io`] if the opening event cannot be written, or [`CoreError::Serialize`] if it
    /// cannot be encoded. Both are fatal: a session that cannot record its own start cannot be
    /// trusted to record anything else.
    pub fn start(
        mut sink: W,
        wall_clock_utc: String,
        agent_version: &str,
        backend: Backend,
        command: Vec<String>,
        zones: Zones,
        host: Option<HostInfo>,
    ) -> Result<Self> {
        let event = Event::framing(
            0,
            backend,
            Payload::SessionStart(SessionStart {
                wall_clock_utc,
                agent_version: agent_version.to_string(),
                command,
                zones,
                host,
            }),
        );
        let line = event.to_jsonl()?;
        writeln!(sink, "{line}").map_err(|source| CoreError::io("<session stream>", source))?;
        sink.flush()
            .map_err(|source| CoreError::io("<session stream>", source))?;

        Ok(Self {
            sink,
            backend,
            started: Instant::now(),
            events_emitted: 0,
            heartbeats: 0,
            last_heartbeat_events: 0,
            last_heartbeat_ms: 0,
            phase: None,
            finished: false,
        })
    }

    /// Sets the coarse phase label attached to subsequent heartbeats.
    pub fn set_phase(&mut self, phase: impl Into<String>) {
        self.phase = Some(phase.into());
    }

    /// Writes one observation, flushing immediately.
    ///
    /// Flushing per event costs throughput and buys the property that matters: evidence already
    /// observed survives an abrupt death.
    ///
    /// # Errors
    /// [`CoreError::Io`] on a write or flush failure, [`CoreError::Serialize`] on an encoding
    /// failure.
    pub fn write_event(&mut self, event: &Event) -> Result<()> {
        let line = event.to_jsonl()?;
        writeln!(self.sink, "{line}")
            .map_err(|source| CoreError::io("<session stream>", source))?;
        self.events_emitted += 1;
        self.maybe_heartbeat()?;
        self.sink
            .flush()
            .map_err(|source| CoreError::io("<session stream>", source))
    }

    /// Writes several observations.
    ///
    /// # Errors
    /// As [`Self::write_event`]; stops at the first failure so the stream is never left with a
    /// half-written line.
    pub fn write_events(&mut self, events: &[Event]) -> Result<()> {
        for event in events {
            self.write_event(event)?;
        }
        Ok(())
    }

    /// Emits a heartbeat if either the event-count or time threshold has been crossed.
    fn maybe_heartbeat(&mut self) -> Result<()> {
        let elapsed_ms = self.started.elapsed().as_millis();
        let by_events =
            self.events_emitted - self.last_heartbeat_events >= HEARTBEAT_EVENT_INTERVAL;
        let by_time = elapsed_ms.saturating_sub(self.last_heartbeat_ms) >= HEARTBEAT_MS_INTERVAL;
        if by_events || by_time {
            self.heartbeat()?;
        }
        Ok(())
    }

    /// Forces a heartbeat.
    ///
    /// # Errors
    /// [`CoreError::Io`] on a write or flush failure.
    pub fn heartbeat(&mut self) -> Result<()> {
        self.heartbeats += 1;
        self.last_heartbeat_events = self.events_emitted;
        self.last_heartbeat_ms = self.started.elapsed().as_millis();
        let event = Event::framing(
            self.elapsed_ns(),
            self.backend,
            Payload::Heartbeat(Heartbeat {
                seq: self.heartbeats,
                events_so_far: self.events_emitted,
                phase: self.phase.clone(),
            }),
        );
        let line = event.to_jsonl()?;
        writeln!(self.sink, "{line}")
            .map_err(|source| CoreError::io("<session stream>", source))?;
        self.sink
            .flush()
            .map_err(|source| CoreError::io("<session stream>", source))
    }

    /// Events written so far, excluding framing.
    #[must_use]
    pub const fn events_emitted(&self) -> u64 {
        self.events_emitted
    }

    /// Closes the session as complete. Only correct when the recording is genuinely whole.
    ///
    /// # Errors
    /// [`CoreError::Io`] if the closing event cannot be written. That is the one failure that leaves
    /// a stream without `session_end`, which downstream readers reject outright rather than treating
    /// as clean.
    pub fn finish_complete(mut self, command_exit_code: Option<i32>) -> Result<SessionEnd> {
        let end = SessionEnd::complete(
            command_exit_code,
            self.elapsed_ns(),
            self.events_emitted,
            self.heartbeats,
        );
        self.write_end(&end)?;
        Ok(end)
    }

    /// Closes the session as PARTIAL, recording why.
    ///
    /// Takes the first reason separately so "partial with no reason" is unrepresentable: telling a
    /// user their evidence is untrustworthy without saying why is barely better than silence.
    ///
    /// # Errors
    /// [`CoreError::Io`] if the closing event cannot be written.
    pub fn finish_partial(
        mut self,
        first_reason: IncompleteReason,
        rest: Vec<IncompleteReason>,
        command_exit_code: Option<i32>,
    ) -> Result<SessionEnd> {
        let end = SessionEnd::partial(
            first_reason,
            rest,
            command_exit_code,
            self.elapsed_ns(),
            self.events_emitted,
            self.heartbeats,
        );
        self.write_end(&end)?;
        Ok(end)
    }

    fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn write_end(&mut self, end: &SessionEnd) -> Result<()> {
        let event = Event::framing(
            self.elapsed_ns(),
            self.backend,
            Payload::SessionEnd(end.clone()),
        );
        let line = event.to_jsonl()?;
        writeln!(self.sink, "{line}")
            .map_err(|source| CoreError::io("<session stream>", source))?;
        self.sink
            .flush()
            .map_err(|source| CoreError::io("<session stream>", source))?;
        self.finished = true;
        Ok(())
    }
}

impl<W: Write> Drop for SessionWriter<W> {
    /// Last-resort guard. Reaching this means a code path forgot to terminate the session, which
    /// would leave a stream that reads as "still recording" forever. A best-effort `session_end`
    /// with an explicit reason is written, and the bug is announced on the tracing channel.
    ///
    /// Errors here are unreportable by construction, hence the `let _`: Drop cannot fail, and
    /// panicking in a destructor would abort a recording that still has usable evidence on disk.
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        tracing::error!(
            "session dropped without an explicit end; writing PARTIAL. This is a recorder bug."
        );
        let end = SessionEnd::partial(
            IncompleteReason::Other {
                detail: "recorder dropped the session without terminating it (internal bug)"
                    .to_string(),
            },
            Vec::new(),
            None,
            self.elapsed_ns(),
            self.events_emitted,
            self.heartbeats,
        );
        let elapsed = self.elapsed_ns();
        if let Ok(line) = Event::framing(elapsed, self.backend, Payload::SessionEnd(end)).to_jsonl()
        {
            let _ = writeln!(self.sink, "{line}");
            let _ = self.sink.flush();
        }
    }
}

/// Reads a JSONL stream back and reports whether it is trustworthy.
///
/// Used by the CLI to verify what it just wrote, and by tests. Deliberately strict: a stream missing
/// its `session_end` is [`CoreError::MissingSessionEnd`], not an empty success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSummary {
    /// Observations, excluding framing events.
    pub events: u64,
    /// Heartbeats seen.
    pub heartbeats: u64,
    /// Whether `session_end` declared the recording whole.
    pub complete: bool,
    /// Why it was not, when it was not.
    pub incomplete_reasons: Vec<IncompleteReason>,
    /// Exit code of the recorded command.
    pub command_exit_code: Option<i32>,
    /// Whether the stream opened with `session_start`.
    pub has_session_start: bool,
}

impl StreamSummary {
    /// True when the report must show a PARTIAL badge (PRD.md:58).
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.complete
    }
}

/// Parses a full JSONL stream and summarizes it.
///
/// # Errors
/// [`CoreError::MalformedEvent`] or [`CoreError::UnsupportedSchemaVersion`] on any unreadable line,
/// and [`CoreError::MissingSessionEnd`] when the stream never terminated. The last one is the
/// important case: a truncated recording must be a hard error, never a clean summary with zero
/// findings (`Rules.md` §2).
pub fn summarize_stream(contents: &str) -> Result<StreamSummary> {
    let mut summary = StreamSummary {
        events: 0,
        heartbeats: 0,
        complete: false,
        incomplete_reasons: Vec::new(),
        command_exit_code: None,
        has_session_start: false,
    };
    let mut saw_end = false;

    for (idx, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = Event::from_jsonl(line, idx + 1)?;
        match event.payload {
            Payload::SessionStart(_) => summary.has_session_start = true,
            Payload::Heartbeat(_) => summary.heartbeats += 1,
            Payload::SessionEnd(end) => {
                saw_end = true;
                summary.complete = end.complete;
                summary.incomplete_reasons = end.incomplete_reasons;
                summary.command_exit_code = end.command_exit_code;
            }
            _ => summary.events += 1,
        }
    }

    if !saw_end {
        return Err(CoreError::MissingSessionEnd);
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_core::{EventMeta, FsWrite, Outcome, PathOrigin, TracedPath, WriteKind};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A sink that shares its buffer with the test, so the stream can be read after the writer is
    /// consumed by `finish_complete`/`finish_partial`. Those methods take `self` by value on
    /// purpose — that is what makes "a session must be terminated" a compile-time property — so the
    /// test cannot simply borrow the buffer back out of the writer.
    #[derive(Clone)]
    struct SharedSink(Rc<RefCell<Vec<u8>>>);

    impl SharedSink {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(Vec::new())))
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap_or_default()
        }
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn writer(sink: SharedSink) -> SessionWriter<SharedSink> {
        SessionWriter::start(
            sink,
            "2026-08-29T12:00:00Z".to_string(),
            "test-0.1.0",
            Backend::Strace,
            vec!["npm".to_string(), "install".to_string()],
            Zones::default(),
            None,
        )
        .expect("start session")
    }

    fn sample_event(ts_ns: u64) -> Event {
        Event::observed(
            EventMeta::observed(ts_ns, 1, "openat", Backend::Strace),
            Payload::FsWrite(FsWrite {
                target: TracedPath::new("/tmp/x", PathOrigin::Absolute),
                kind: WriteKind::Open,
                bytes: None,
                flags: None,
                mode: None,
                source: None,
                outcome: Outcome::success(),
            }),
        )
    }

    #[test]
    fn session_start_is_written_before_any_event() {
        let sink = SharedSink::new();
        let w = writer(sink.clone());
        w.finish_complete(Some(0)).expect("finish");

        let text = sink.text();
        let first = text.lines().next().expect("a first line");
        assert!(
            first.contains(r#""op":"session_start""#),
            "first line must be session_start: {first}"
        );
    }

    #[test]
    fn complete_session_summarizes_as_clean() {
        let sink = SharedSink::new();
        let mut w = writer(sink.clone());
        w.write_event(&sample_event(1)).expect("write");
        w.write_event(&sample_event(2)).expect("write");
        let end = w.finish_complete(Some(0)).expect("finish");

        assert!(end.complete);
        let summary = summarize_stream(&sink.text()).expect("summary");
        assert_eq!(summary.events, 2);
        assert!(summary.has_session_start);
        assert!(!summary.is_partial(), "a complete recording is not PARTIAL");
        assert_eq!(summary.command_exit_code, Some(0));
    }

    #[test]
    fn partial_session_summarizes_as_partial_with_a_reason() {
        let sink = SharedSink::new();
        let mut w = writer(sink.clone());
        w.write_event(&sample_event(1)).expect("write");
        let end = w
            .finish_partial(IncompleteReason::Interrupted, Vec::new(), None)
            .expect("finish");

        assert!(!end.complete);
        let summary = summarize_stream(&sink.text()).expect("summary");
        assert!(summary.is_partial());
        assert_eq!(summary.incomplete_reasons.len(), 1);
        assert_eq!(summary.incomplete_reasons[0], IncompleteReason::Interrupted);
    }

    #[test]
    fn a_stream_without_session_end_is_an_error_not_a_clean_result() {
        // The core failure mode from Rules.md §2: a recorder that dies must not read as clean. A
        // truncated stream is rejected outright rather than summarized as zero findings. Built by
        // hand here because the writer itself refuses to produce one.
        let sink = SharedSink::new();
        {
            let mut w = writer(sink.clone());
            w.write_event(&sample_event(1)).expect("write");
            // Capture the text while the session is still open, before Drop appends its PARTIAL end.
            let truncated = sink.text();
            let err = summarize_stream(&truncated).expect_err("must reject");
            assert!(matches!(err, CoreError::MissingSessionEnd), "got {err}");
            w.finish_partial(IncompleteReason::Interrupted, Vec::new(), None)
                .expect("finish");
        }
    }

    #[test]
    fn dropping_without_finishing_still_writes_partial() {
        // Defense in depth: if a future code path forgets to terminate a session, Drop writes a
        // PARTIAL end rather than leaving a stream that reads as still-recording.
        let sink = SharedSink::new();
        {
            let mut w = writer(sink.clone());
            w.write_event(&sample_event(1)).expect("write");
        }
        let summary = summarize_stream(&sink.text()).expect("summary");
        assert!(
            summary.is_partial(),
            "an abandoned session must render as PARTIAL"
        );
        assert!(!summary.incomplete_reasons.is_empty());
    }

    #[test]
    fn heartbeats_are_emitted_and_counted() {
        let sink = SharedSink::new();
        let mut w = writer(sink.clone());
        w.set_phase("postinstall");
        w.heartbeat().expect("heartbeat");
        w.heartbeat().expect("heartbeat");
        let end = w.finish_complete(Some(0)).expect("finish");

        assert_eq!(end.heartbeats, 2);
        let text = sink.text();
        let summary = summarize_stream(&text).expect("summary");
        assert_eq!(summary.heartbeats, 2);
        assert!(
            text.contains(r#""phase":"postinstall""#),
            "phase label must reach the stream"
        );
    }

    #[test]
    fn every_line_is_independently_parseable() {
        // A truncated artifact is exactly when interpretation must not go wrong, so each line
        // carries its own schema_version rather than relying on a header.
        let sink = SharedSink::new();
        let mut w = writer(sink.clone());
        w.write_event(&sample_event(1)).expect("write");
        w.heartbeat().expect("heartbeat");
        w.finish_complete(Some(0)).expect("finish");

        for (idx, line) in sink.text().lines().enumerate() {
            let event = Event::from_jsonl(line, idx + 1).expect("each line parses alone");
            assert_eq!(event.schema_version, installscope_core::SCHEMA_VERSION);
        }
    }
}
