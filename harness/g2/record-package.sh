#!/usr/bin/env bash
# record-package.sh — G2 harness: record ONE npm install under strace.
#
# Gate tooling, not product code (see ../README.md). Phase 1 rewrites this in Rust.
#
# Isolation: private HOME, private npm cache, scratch project dir. Combined with one ephemeral
# ubuntu-latest job per package, this gives the "clean VM per package" property Phases.md:7 asks
# for. Nothing from the runner image's npm state leaks in.
#
# Failure philosophy (Rules.md §2): fail LOUD. A recording that died must be visibly incomplete,
# never silently clean. This script therefore ALWAYS writes session.json, and sets
# complete:false whenever strace did not start cleanly, the install timed out, or no trace files
# were produced. It exits non-zero only when it could not record at all — a package whose install
# *fails* is still a valid recording and exits 0.
set -uo pipefail

HARNESS_VERSION="g2-0.1.0"

die() { printf 'record-package: FATAL: %s\n' "$*" >&2; exit 2; }
log() { printf 'record-package: %s\n' "$*" >&2; }

PACKAGE=""
OUTDIR=""
TIMEOUT=300
PKG_MANAGER="npm"

while [ $# -gt 0 ]; do
  case "$1" in
    --package) PACKAGE="${2:-}"; shift 2 ;;
    --outdir)  OUTDIR="${2:-}";  shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    --manager) PKG_MANAGER="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
Usage: record-package.sh --package <spec> --outdir <dir> [--timeout SECONDS] [--manager npm|pnpm]
Records one install under strace. Writes <outdir>/{session.json,trace/,npm-stdout.log,npm-stderr.log}.
USAGE
      exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$PACKAGE" ] || die "--package is required"
[ -n "$OUTDIR" ]  || die "--outdir is required"
case "$TIMEOUT" in ''|*[!0-9]*) die "--timeout must be a positive integer, got: $TIMEOUT" ;; esac
[ "$TIMEOUT" -gt 0 ] || die "--timeout must be > 0"

# Reject specs that could escape into shell or path context. Package names are restricted by npm
# to a conservative character set; anything else here is a harness bug or an attack.
case "$PACKAGE" in
  *[!A-Za-z0-9@/._-]*) die "package spec contains unexpected characters: $PACKAGE" ;;
  ''|-*|*..*)          die "refusing suspicious package spec: $PACKAGE" ;;
esac

command -v strace >/dev/null 2>&1 || die "strace not found; install it before running the harness"
command -v node   >/dev/null 2>&1 || die "node not found"
command -v timeout >/dev/null 2>&1 || die "timeout (coreutils) not found"
command -v "$PKG_MANAGER" >/dev/null 2>&1 || die "package manager not found: $PKG_MANAGER"

mkdir -p "$OUTDIR" || die "cannot create outdir: $OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)" || die "cannot resolve outdir"

TRACE_DIR="$OUTDIR/trace"
WORK="$OUTDIR/work"
FAKE_HOME="$WORK/home"
CACHE_DIR="$WORK/cache"
PROJECT_DIR="$WORK/project"
TMP_DIR="$WORK/tmp"
rm -rf "$TRACE_DIR" "$WORK"
mkdir -p "$TRACE_DIR" "$FAKE_HOME" "$CACHE_DIR" "$PROJECT_DIR" "$TMP_DIR" \
  || die "cannot create work dirs"

# Minimal project so the manager has somewhere to install into. private:true keeps npm quiet.
printf '%s\n' '{"name":"g2-harness-scratch","version":"0.0.0","private":true}' \
  > "$PROJECT_DIR/package.json" || die "cannot seed package.json"

# ---- versions recorded BEFORE tracing, so they are never attributed to the recording ----------
node_version="$(node --version 2>/dev/null || echo unknown)"
mgr_version="$("$PKG_MANAGER" --version 2>/dev/null || echo unknown)"
strace_version="$(strace -V 2>/dev/null | head -n 1 || echo unknown)"
kernel_release="$(uname -r 2>/dev/null || echo unknown)"
ptrace_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unavailable)"

# Syscalls traced. Rationale in README.md: an openat carrying a write flag already proves write
# intent, so write()/pwrite() are omitted to keep traces small — at the documented cost of having
# no byte counts.
TRACE_SET='openat,open,creat,truncate,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,rmdir,chmod,fchmodat,chown,fchownat,link,linkat,symlink,symlinkat,connect,sendto,sendmsg,execve,execveat'

case "$PKG_MANAGER" in
  npm)  install_args="install $PACKAGE --no-audit --no-fund --foreground-scripts --loglevel=error" ;;
  pnpm) install_args="add $PACKAGE --reporter=append-only" ;;
  *)    die "unsupported manager: $PKG_MANAGER" ;;
esac

log "recording: $PKG_MANAGER $install_args (timeout ${TIMEOUT}s)"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
start_epoch="$(date +%s.%N)"

# -f follow children · -ff one file per pid · -ttt absolute epoch timestamps (parser converts to
# session-relative) · -s 512 keep enough of sendto payloads to read DNS qnames · -yy annotate fds
# with socket/file details.
env -i \
  HOME="$FAKE_HOME" \
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  TMPDIR="$TMP_DIR" \
  npm_config_cache="$CACHE_DIR" \
  npm_config_update_notifier=false \
  npm_config_fund=false \
  npm_config_audit=false \
  PNPM_HOME="$FAKE_HOME/.pnpm" \
  CI=true \
  G2_HARNESS=1 \
  timeout --signal=TERM --kill-after=30 "$TIMEOUT" \
    strace -f -ff -ttt -s 512 -yy \
      -e "trace=$TRACE_SET" \
      -o "$TRACE_DIR/trace" \
      -- "$(command -v "$PKG_MANAGER")" $install_args \
  > "$OUTDIR/npm-stdout.log" 2> "$OUTDIR/npm-stderr.log"
outer_status=$?

end_epoch="$(date +%s.%N)"
ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

timed_out=false
if [ "$outer_status" -eq 124 ] || [ "$outer_status" -eq 137 ]; then
  timed_out=true
  log "TIMED OUT after ${TIMEOUT}s — recording will be marked incomplete"
fi

trace_file_count=$(find "$TRACE_DIR" -maxdepth 1 -type f -name 'trace.*' 2>/dev/null | wc -l | tr -d ' ')
trace_bytes=$(find "$TRACE_DIR" -maxdepth 1 -type f -name 'trace.*' -printf '%s\n' 2>/dev/null \
  | awk '{s+=$1} END {printf "%d", s+0}')

# strace itself failing to start is the one condition that makes the whole record worthless.
strace_started=true
if [ "$trace_file_count" -eq 0 ]; then
  strace_started=false
  log "no trace files produced — strace did not run"
  log "--- npm-stderr.log (tail) ---"
  tail -n 20 "$OUTDIR/npm-stderr.log" >&2 2>/dev/null || true
fi

# complete == the recording can be trusted to be whole. Anything else renders as PARTIAL.
complete=true
incomplete_reason=""
if [ "$strace_started" = false ]; then
  complete=false; incomplete_reason="strace produced no trace files"
elif [ "$timed_out" = true ]; then
  complete=false; incomplete_reason="install exceeded ${TIMEOUT}s timeout"
fi

# The installed tree is evidence too: record what actually landed on disk.
installed_json="null"
if [ -d "$PROJECT_DIR/node_modules" ]; then
  installed_count=$(find "$PROJECT_DIR/node_modules" -maxdepth 2 -name package.json -type f 2>/dev/null | wc -l | tr -d ' ')
  installed_bytes=$(du -sb "$PROJECT_DIR/node_modules" 2>/dev/null | awk '{printf "%d", $1+0}')
  installed_json="{\"package_json_count\":${installed_count:-0},\"bytes\":${installed_bytes:-0}}"
fi

# Written via node -e so every string is JSON-escaped by a real serializer rather than by hand.
INSTALL_CMD="$PKG_MANAGER $install_args" \
G2_HARNESS_VERSION="$HARNESS_VERSION" \
G2_PACKAGE="$PACKAGE" \
G2_MANAGER="$PKG_MANAGER" \
G2_STARTED_AT="$started_at" \
G2_ENDED_AT="$ended_at" \
G2_START_EPOCH="$start_epoch" \
G2_END_EPOCH="$end_epoch" \
G2_EXIT="$outer_status" \
G2_TIMED_OUT="$timed_out" \
G2_TIMEOUT="$TIMEOUT" \
G2_COMPLETE="$complete" \
G2_REASON="$incomplete_reason" \
G2_STRACE_STARTED="$strace_started" \
G2_TRACE_FILES="$trace_file_count" \
G2_TRACE_BYTES="$trace_bytes" \
G2_NODE="$node_version" \
G2_MGR_VERSION="$mgr_version" \
G2_STRACE_VERSION="$strace_version" \
G2_KERNEL="$kernel_release" \
G2_PTRACE_SCOPE="$ptrace_scope" \
G2_PROJECT_DIR="$PROJECT_DIR" \
G2_CACHE_DIR="$CACHE_DIR" \
G2_HOME_DIR="$FAKE_HOME" \
G2_TMP_DIR="$TMP_DIR" \
G2_RUNNER="${RUNNER_OS:-local}" \
G2_INSTALLED="$installed_json" \
node -e '
  const e = process.env;
  const num = (k) => Number(e[k] ?? 0);
  const out = {
    harness_version: e.G2_HARNESS_VERSION,
    gate: "G2",
    package: e.G2_PACKAGE,
    manager: e.G2_MANAGER,
    manager_version: e.G2_MGR_VERSION,
    install_command: e.INSTALL_CMD,
    started_at: e.G2_STARTED_AT,
    ended_at: e.G2_ENDED_AT,
    start_epoch: e.G2_START_EPOCH,
    duration_s: Number((num("G2_END_EPOCH") - num("G2_START_EPOCH")).toFixed(3)),
    timeout_s: num("G2_TIMEOUT"),
    exit_code: num("G2_EXIT"),
    timed_out: e.G2_TIMED_OUT === "true",
    strace_started: e.G2_STRACE_STARTED === "true",
    complete: e.G2_COMPLETE === "true",
    incomplete_reason: e.G2_REASON || null,
    trace_files: num("G2_TRACE_FILES"),
    trace_bytes: num("G2_TRACE_BYTES"),
    installed: JSON.parse(e.G2_INSTALLED),
    paths: {
      project: e.G2_PROJECT_DIR,
      cache: e.G2_CACHE_DIR,
      home: e.G2_HOME_DIR,
      tmp: e.G2_TMP_DIR
    },
    env: {
      node: e.G2_NODE,
      strace: e.G2_STRACE_VERSION,
      kernel: e.G2_KERNEL,
      ptrace_scope: e.G2_PTRACE_SCOPE,
      runner_os: e.G2_RUNNER
    }
  };
  require("fs").writeFileSync(process.argv[1], JSON.stringify(out, null, 2) + "\n");
' "$OUTDIR/session.json" || die "could not write session.json"

log "session.json written: complete=$complete exit=$outer_status trace_files=$trace_file_count"

# A failed install is still evidence. Only an absent recording is a harness failure.
if [ "$strace_started" = false ]; then
  exit 3
fi
exit 0
