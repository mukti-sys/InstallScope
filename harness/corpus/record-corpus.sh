#!/usr/bin/env bash
# record-corpus.sh — record ONE package@version with the product recorder, for the corpus backfill.
#
# Phase 5, not Phase 0. The difference from harness/g2/record-package.sh matters:
#
#   | | g2/record-package.sh | this |
#   |---|---|---|
#   | recorder | strace + a throwaway Node parser | `installscope record` (product code) |
#   | version | whatever npm resolves | pinned exact, and verified after install |
#   | output | session.json + events.jsonl | schema v1 stream, pushed to the registry |
#   | purpose | answer the G2 gate cheaply | build the dataset the diff moat needs |
#
# The G2 harness was deliberately disposable (harness/README.md). This is not: what it produces gets
# published, so it uses the recorder whose failure modes are tested and whose PARTIAL handling is
# enforced structurally.
#
# CACHE ISOLATION, AND WHY IT IS PER RECORDING RATHER THAN PER PACKAGE
#
# Phases.md:38 says "clean-VM-per-package harness (no cache contamination)". The cache half is the
# subtle one. Recording lodash@4.18.1 and then lodash@4.18.0 against a shared cache means the second
# install finds its tarball already present, makes no network requests, and produces a recording with
# no DNS and no connects. The two recordings would then differ enormously — for a reason that has
# nothing to do with the package.
#
# That difference is invisible to the diff engine, because the events genuinely are not there to
# compare. Zone-relative paths cannot fix an absent event. So every recording gets a cold cache, and
# the cost is that every install re-downloads. That cost is the price of two recordings of the same
# package being comparable at all.
#
# The *VM* can be shared across versions of one package, which is what keeps the backfill at ~200 jobs
# rather than ~1000: the recorder's zones (project, cache, home, tmp) are all fresh per recording, so
# what a shared VM leaks is only state outside those zones. A postinstall that writes to /usr/local
# would be visible to a later recording in the same job, which is exactly why versions of *different*
# packages never share a job.
#
# FAILURE PHILOSOPHY (Rules.md rule 2)
#
# Fail loud, and never silently. A recording that died must be visibly incomplete. This script always
# writes recording.json, and marks it incomplete when the recorder said PARTIAL, when the install
# exceeded its timeout, or when the installed version is not the one requested. It exits non-zero only
# when it could not record at all — a package whose install *fails* is still a valid recording.
#
# The registry refuses PARTIAL recordings by design, so a PARTIAL here is counted and reported rather
# than pushed. Hiding it would make the corpus look cleaner than it is.
set -uo pipefail

HARNESS_VERSION="corpus-0.1.0"

die() { printf 'record-corpus: FATAL: %s\n' "$*" >&2; exit 2; }
log() { printf 'record-corpus: %s\n' "$*" >&2; }

PACKAGE=""
VERSION=""
OUTDIR=""
REGISTRY_DIR=""
TIMEOUT=600
INSTALLSCOPE="installscope"

while [ $# -gt 0 ]; do
  case "$1" in
    --package)     PACKAGE="${2:-}";      shift 2 ;;
    --version)     VERSION="${2:-}";      shift 2 ;;
    --outdir)      OUTDIR="${2:-}";       shift 2 ;;
    --registry)    REGISTRY_DIR="${2:-}"; shift 2 ;;
    --timeout)     TIMEOUT="${2:-}";      shift 2 ;;
    --installscope) INSTALLSCOPE="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
Usage: record-corpus.sh --package <name> --version <exact> --outdir <dir>
                        [--registry <dir>] [--timeout SECONDS] [--installscope PATH]

Records one npm install of an exactly-pinned package version with `installscope record`, verifies the
installed version matches, and pushes the recording to the snapshot registry when it is complete.

Writes <outdir>/{recording.json, recording/events.jsonl, install.log}.
Exit 0 = recorded (complete or PARTIAL).  3 = could not record at all.
USAGE
      exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$PACKAGE" ] || die "--package is required"
[ -n "$VERSION" ] || die "--version is required"
[ -n "$OUTDIR" ]  || die "--outdir is required"
case "$TIMEOUT" in ''|*[!0-9]*) die "--timeout must be a positive integer, got: $TIMEOUT" ;; esac
[ "$TIMEOUT" -gt 0 ] || die "--timeout must be > 0"

# Same character policy as the G2 harness and the workflow planner. A name and a version both reach a
# shell and a filesystem path; anything outside npm's conservative set is a harness bug or an attack.
case "$PACKAGE" in
  *[!A-Za-z0-9@/._-]*) die "package name contains unexpected characters: $PACKAGE" ;;
  ''|-*|*..*)          die "refusing suspicious package name: $PACKAGE" ;;
esac
# Deliberately stricter than semver permits: the corpus records released versions, and a version with
# a shell metacharacter in it is not one.
case "$VERSION" in
  *[!A-Za-z0-9.+-]*) die "version contains unexpected characters: $VERSION" ;;
  ''|-*|*..*)        die "refusing suspicious version: $VERSION" ;;
esac

command -v strace >/dev/null 2>&1 || die "strace not found; the recorder's v1.0 backend needs it"
command -v node   >/dev/null 2>&1 || die "node not found"
command -v npm    >/dev/null 2>&1 || die "npm not found"
command -v timeout >/dev/null 2>&1 || die "timeout (coreutils) not found"

# Resolved to an absolute path HERE, before `env -i` below wipes PATH.
#
# This is the bug that made the first real backfill fail 30 recordings out of 30 with
# `env: 'installscope': No such file or directory`, and it is worth stating plainly because
# `command -v` passing above is exactly what makes it invisible: this check runs with the caller's PATH,
# and the recorder runs without it. A workflow that puts the binary on PATH via GITHUB_PATH satisfies
# the check and then fails the invocation.
#
# `bash -n` cannot catch it either — the script parses fine. Only running it does.
INSTALLSCOPE_BIN="$(command -v "$INSTALLSCOPE" 2>/dev/null)" \
  || die "installscope not found at: $INSTALLSCOPE"
case "$INSTALLSCOPE_BIN" in
  /*) ;;
  # command -v returns a bare name for a shell builtin or a relative path for `./installscope`. Neither
  # survives `env -i`, so both are resolved rather than accepted.
  *) INSTALLSCOPE_BIN="$(cd "$(dirname "$INSTALLSCOPE_BIN")" && pwd)/$(basename "$INSTALLSCOPE_BIN")" ;;
esac
[ -x "$INSTALLSCOPE_BIN" ] || die "installscope is not executable: $INSTALLSCOPE_BIN"

mkdir -p "$OUTDIR" || die "cannot create outdir: $OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)" || die "cannot resolve outdir"

# The registry path is made absolute for the same reason the recorder's own `--out` is (Memory.md,
# Phase 1: a relative `-o` produced a silently empty recording because strace resolved it against the
# *install's* directory). A relative --registry here would be resolved against whatever directory the
# push happens to run in, and in the first backfill it meant the workflow uploaded the repository's own
# `registry/` crate as the artifact instead of a store.
if [ -n "$REGISTRY_DIR" ]; then
  mkdir -p "$REGISTRY_DIR" || die "cannot create registry dir: $REGISTRY_DIR"
  REGISTRY_DIR="$(cd "$REGISTRY_DIR" && pwd)" || die "cannot resolve registry dir"
fi

WORK="$OUTDIR/work"
FAKE_HOME="$WORK/home"
CACHE_DIR="$WORK/cache"
PROJECT_DIR="$WORK/project"
TMP_DIR="$WORK/tmp"
RECORDING_DIR="$OUTDIR/recording"

# Removed rather than reused. A leftover cache from a previous version of this same package is the
# exact contamination this script exists to avoid.
rm -rf "$WORK" "$RECORDING_DIR"
mkdir -p "$FAKE_HOME" "$CACHE_DIR" "$PROJECT_DIR" "$TMP_DIR" || die "cannot create work dirs"

printf '%s\n' '{"name":"installscope-corpus-scratch","version":"0.0.0","private":true}' \
  > "$PROJECT_DIR/package.json" || die "cannot seed package.json"

# ---- environment recorded BEFORE tracing, so it is never attributed to the recording -------------
node_version="$(node --version 2>/dev/null || echo unknown)"
npm_version="$(npm --version 2>/dev/null || echo unknown)"
strace_version="$(strace -V 2>/dev/null | head -n 1 || echo unknown)"
recorder_version="$("$INSTALLSCOPE_BIN" --version 2>/dev/null || echo unknown)"
kernel_release="$(uname -r 2>/dev/null || echo unknown)"

SPEC="${PACKAGE}@${VERSION}"
log "recording ${SPEC} (timeout ${TIMEOUT}s, cold cache)"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
start_epoch="$(date +%s)"

# `env -i` so the recording sees a known environment rather than whatever the runner exported. The
# npm_config_* vars point every cache npm has at the private directory: npm_config_cache alone leaves
# _cacache elsewhere on some versions.
#
# The recorder is invoked by absolute path ($INSTALLSCOPE_BIN, resolved above) because `env -i` wipes
# PATH and the fixed PATH below deliberately does not include wherever the binary was built. The PATH
# that *is* set is for the traced command — npm needs node, and node needs the system directories.
#
# --project/--cache/--expect declare the recorder's zones. Without them every write looks like it
# landed somewhere unexpected and an ordinary install scores as critical (core/src/zones.rs).
env -i \
  HOME="$FAKE_HOME" \
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  TMPDIR="$TMP_DIR" \
  npm_config_cache="$CACHE_DIR" \
  npm_config_update_notifier=false \
  npm_config_fund=false \
  npm_config_audit=false \
  CI=true \
  INSTALLSCOPE_CORPUS=1 \
  "$INSTALLSCOPE_BIN" record \
    --out "$RECORDING_DIR" \
    --cwd "$PROJECT_DIR" \
    --project "$PROJECT_DIR" \
    --cache "$CACHE_DIR" \
    --expect "$FAKE_HOME" \
    --expect "$TMP_DIR" \
    --timeout "$TIMEOUT" \
    -- npm install "$SPEC" --no-audit --no-fund --foreground-scripts --loglevel=error \
  > "$OUTDIR/install.log" 2>&1
record_status=$?

end_epoch="$(date +%s)"
ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
duration=$((end_epoch - start_epoch))

# Exit 3 from the recorder is PARTIAL: it recorded, but the stream is incomplete. Exit 1 is a hard
# failure. Distinguishing them is the whole reason the recorder has a third exit code.
recorded=true
complete=true
incomplete_reason=""
case "$record_status" in
  0) ;;
  3) complete=false; incomplete_reason="recorder reported PARTIAL" ;;
  *) recorded=false; complete=false; incomplete_reason="recorder exited ${record_status}" ;;
esac

EVENTS="$RECORDING_DIR/events.jsonl"
if [ ! -s "$EVENTS" ]; then
  recorded=false
  complete=false
  incomplete_reason="no events.jsonl was written"
fi

if [ "$recorded" = false ]; then
  log "COULD NOT RECORD: $incomplete_reason"
  log "--- install.log (tail) ---"
  tail -n 30 "$OUTDIR/install.log" >&2 2>/dev/null || true
fi

# ---- independent verification, rather than trusting the recorder's exit code (Rules.md rule 2) ----
verify_status="skipped"
events_count=0
if [ -s "$EVENTS" ]; then
  "$INSTALLSCOPE_BIN" verify "$EVENTS" > "$OUTDIR/verify.log" 2>&1
  case "$?" in
    0) verify_status="complete" ;;
    3) verify_status="partial"; complete=false
       [ -n "$incomplete_reason" ] || incomplete_reason="verify reported PARTIAL" ;;
    *) verify_status="unreadable"; complete=false; recorded=false
       incomplete_reason="verify could not read the stream" ;;
  esac
  events_count="$(grep -c '"op":' "$EVENTS" 2>/dev/null || echo 0)"
fi

# ---- the installed version must be the one requested --------------------------------------------
#
# An exact pin should make this redundant, and it is checked anyway: a mislabeled recording in a
# corpus that backs public receipts is worse than a missing one. `npm install pkg@1.2.3` can still
# land something else if the pin is satisfiable by an alias or if npm resolves a dist-tag that looks
# like a version.
installed_version="unknown"
version_matches=false
INSTALLED_MANIFEST="$PROJECT_DIR/node_modules/$PACKAGE/package.json"
if [ -f "$INSTALLED_MANIFEST" ]; then
  installed_version="$(node -e '
    try {
      const fs = require("node:fs");
      const m = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String(m.version ?? "unknown"));
    } catch { process.stdout.write("unreadable"); }
  ' "$INSTALLED_MANIFEST" 2>/dev/null || echo unreadable)"
  [ "$installed_version" = "$VERSION" ] && version_matches=true
fi
if [ "$version_matches" = false ] && [ "$recorded" = true ]; then
  complete=false
  if [ -n "$incomplete_reason" ]; then
    incomplete_reason="${incomplete_reason}; installed version ${installed_version} != requested ${VERSION}"
  else
    incomplete_reason="installed version ${installed_version} != requested ${VERSION}"
  fi
  log "VERSION MISMATCH: requested ${VERSION}, installed ${installed_version}"
fi

installed_bytes=0
if [ -d "$PROJECT_DIR/node_modules" ]; then
  installed_bytes="$(du -sb "$PROJECT_DIR/node_modules" 2>/dev/null | awk '{printf "%d", $1+0}')"
fi

# ---- push to the registry, but only a recording worth keeping ------------------------------------
#
# The registry refuses PARTIAL recordings itself (registry/src/lib.rs), so this could simply attempt
# the push and let it fail. It checks first so the reason recorded here is the harness's own reading
# rather than a parsed error message, and so the push is not attempted ~N times across a backfill for
# recordings already known to be unusable.
pushed=false
push_error=""
digest=""
if [ -n "$REGISTRY_DIR" ]; then
  if [ "$complete" = true ]; then
    if "$INSTALLSCOPE_BIN" snapshot push "$EVENTS" \
         --registry "$REGISTRY_DIR" \
         --package "$PACKAGE" \
         --version "$VERSION" > "$OUTDIR/push.log" 2>&1; then
      pushed=true
      digest="$(sed -n 's/^digest: *//p' "$OUTDIR/push.log" | head -n 1)"
      log "pushed ${SPEC} as ${digest}"
    else
      push_error="$(tail -n 3 "$OUTDIR/push.log" 2>/dev/null | tr '\n' ' ')"
      log "PUSH FAILED: $push_error"
    fi
  else
    push_error="recording is incomplete; the registry refuses PARTIAL recordings by design"
    log "not pushed: $push_error"
  fi
fi

# ---- recording.json, written via node so every string is escaped by a real serializer ------------
CORPUS_HARNESS_VERSION="$HARNESS_VERSION" \
CORPUS_PACKAGE="$PACKAGE" \
CORPUS_VERSION="$VERSION" \
CORPUS_SPEC="$SPEC" \
CORPUS_STARTED_AT="$started_at" \
CORPUS_ENDED_AT="$ended_at" \
CORPUS_DURATION="$duration" \
CORPUS_TIMEOUT="$TIMEOUT" \
CORPUS_RECORD_STATUS="$record_status" \
CORPUS_RECORDED="$recorded" \
CORPUS_COMPLETE="$complete" \
CORPUS_REASON="$incomplete_reason" \
CORPUS_VERIFY="$verify_status" \
CORPUS_EVENTS="$events_count" \
CORPUS_INSTALLED_VERSION="$installed_version" \
CORPUS_VERSION_MATCHES="$version_matches" \
CORPUS_INSTALLED_BYTES="$installed_bytes" \
CORPUS_PUSHED="$pushed" \
CORPUS_PUSH_ERROR="$push_error" \
CORPUS_DIGEST="$digest" \
CORPUS_NODE="$node_version" \
CORPUS_NPM="$npm_version" \
CORPUS_STRACE="$strace_version" \
CORPUS_RECORDER="$recorder_version" \
CORPUS_KERNEL="$kernel_release" \
CORPUS_RUNNER="${RUNNER_OS:-local}" \
CORPUS_PROJECT="$PROJECT_DIR" \
CORPUS_CACHE="$CACHE_DIR" \
CORPUS_HOME="$FAKE_HOME" \
CORPUS_TMP="$TMP_DIR" \
node -e '
  const e = process.env;
  const num = (k) => Number(e[k] ?? 0);
  const out = {
    schema: "installscope-corpus-recording/1",
    harness_version: e.CORPUS_HARNESS_VERSION,
    phase: "5",
    package: e.CORPUS_PACKAGE,
    version: e.CORPUS_VERSION,
    spec: e.CORPUS_SPEC,
    started_at: e.CORPUS_STARTED_AT,
    ended_at: e.CORPUS_ENDED_AT,
    duration_s: num("CORPUS_DURATION"),
    timeout_s: num("CORPUS_TIMEOUT"),
    recorder_exit_code: num("CORPUS_RECORD_STATUS"),
    recorded: e.CORPUS_RECORDED === "true",
    complete: e.CORPUS_COMPLETE === "true",
    incomplete_reason: e.CORPUS_REASON || null,
    verify: e.CORPUS_VERIFY,
    events: num("CORPUS_EVENTS"),
    installed: {
      version: e.CORPUS_INSTALLED_VERSION,
      matches_requested: e.CORPUS_VERSION_MATCHES === "true",
      node_modules_bytes: num("CORPUS_INSTALLED_BYTES")
    },
    snapshot: {
      pushed: e.CORPUS_PUSHED === "true",
      digest: e.CORPUS_DIGEST || null,
      error: e.CORPUS_PUSH_ERROR || null
    },
    // Recorded so a later reproducibility check can tell a genuine behavioral difference from a
    // difference in the machine that observed it. Two recordings from different recorder versions are
    // comparable only with a caveat (registry/src/diff.rs).
    env: {
      node: e.CORPUS_NODE,
      npm: e.CORPUS_NPM,
      strace: e.CORPUS_STRACE,
      recorder: e.CORPUS_RECORDER,
      kernel: e.CORPUS_KERNEL,
      runner_os: e.CORPUS_RUNNER
    },
    zones: {
      project: e.CORPUS_PROJECT,
      cache: e.CORPUS_CACHE,
      home: e.CORPUS_HOME,
      tmp: e.CORPUS_TMP
    }
  };
  require("fs").writeFileSync(process.argv[1], JSON.stringify(out, null, 2) + "\n");
' "$OUTDIR/recording.json" || die "could not write recording.json"

log "recording.json: complete=$complete events=$events_count pushed=$pushed"

# The work tree is large and is not evidence: the recording is. Removed so an artifact upload does not
# carry a copy of node_modules per recording.
rm -rf "$WORK"

# A failed install is evidence. Only an absent recording is a harness failure.
if [ "$recorded" = false ]; then
  exit 3
fi
exit 0
