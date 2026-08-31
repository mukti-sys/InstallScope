#!/usr/bin/env bash
# parity-workload.sh — the synthetic workload both backends record for a parity comparison.
#
# Phase 2's Done condition is "parity on synthetic workload" (Phases.md:24). This is that workload.
#
# WHY SYNTHETIC RATHER THAN A REAL INSTALL
#
# A real `npm install` is not reproducible enough to compare two recordings of. It resolves versions,
# hits a CDN whose IPs rotate, and spawns a different number of processes depending on cache state — so
# two runs differ for reasons that have nothing to do with backend fidelity, and every difference would
# have to be hand-triaged. This script does exactly the same thing twice, so any difference between the
# two recordings is attributable to how they were observed.
#
# Phase 1's E2E workflow already records a real install; that covers realism. This covers comparability.
#
# WHAT IT EXERCISES, AND WHY EACH ONE IS HERE
#
#   fs_write   creates, appends, truncates, mkdir, rename, symlink, unlink, chmod
#              — every WriteKind the ABI defines, so a mis-mapped kind shows up as a diff
#   write vol  a known byte count via dd, so the aggregation paths can be compared
#   relative   a write via a relative path after cd, which is the documented fidelity gap:
#              strace resolves it, aya does not. Present deliberately so the harness proves it
#              classifies that difference rather than tripping over it
#   net        a TCP connect to a fixed loopback listener, and a DNS query
#              — loopback because a public IP would differ between runs
#   proc       several execve calls, including a shell pipeline, since a command line piped into an
#              interpreter is the highest-value finding shape in the corpus
#   nested     a subshell that forks and writes, to exercise process-tree tracking on the aya side
#              (its in-kernel pid filter is what keeps a recording scoped to the install)
#
# WHAT IT DELIBERATELY AVOIDS
#
#   - anything reaching the public internet: unreproducible between runs
#   - background processes outliving the script: they would be recorded by one backend and not the other
#     purely on timing
#   - /etc or other system paths: this must be safe to run on a developer's machine, not just a runner
#
# Everything happens inside the directory given as $1.

set -euo pipefail

WORK="${1:?usage: parity-workload.sh <work-dir>}"
mkdir -p "$WORK"
cd "$WORK"

log() { printf 'workload: %s\n' "$*" >&2; }

# ---- fs_write: every mutation kind the ABI can express ----------------------------------------
log "filesystem mutations"
mkdir -p project/nested
mkdir -p cache

# create + append + truncate, so open flags vary
printf 'first line\n' > project/created.txt
printf 'appended\n' >> project/created.txt
: > project/truncated.txt

# a known byte volume. 256 KiB in 4 KiB blocks: large enough that a backend dropping writes shows up
# in the total, small enough not to slow the run.
dd if=/dev/zero of=project/volume.bin bs=4096 count=64 status=none

# rename, symlink, hard link, unlink, chmod
printf 'staged\n' > project/staged.tmp
mv project/staged.tmp project/renamed.txt
ln -s renamed.txt project/link-to-renamed
ln project/renamed.txt project/hardlink.txt
printf 'doomed\n' > project/doomed.txt
rm project/doomed.txt
chmod 0755 project/created.txt

# ---- a relative-path write: the documented fidelity gap ----------------------------------------
# strace's -yy reports the kernel's resolved absolute path; the aya probes read the syscall argument,
# which stays relative. The parity harness must classify that as expected rather than failing — and it
# must still fail if the write is missing entirely, which is why the pair matters.
log "relative-path write (expected divergence)"
(
  cd project/nested
  printf 'relative\n' > relative-only.txt
)

# ---- network: loopback only, so addresses are identical across runs ---------------------------
# A public host would resolve to a rotating CDN IP and produce a spurious difference. A local listener
# gives a real TCP connect with a fixed address.
log "network"
PORT=39917
if command -v python3 >/dev/null 2>&1; then
  python3 - "$PORT" <<'PY' &
import socket, sys, time
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4)
srv.settimeout(5)
try:
    conn, _ = srv.accept()
    conn.recv(64)
    conn.close()
except Exception:
    pass
srv.close()
PY
  LISTENER=$!
  # Give the listener a moment to bind. A connect to a closed port is still a recordable event, so a
  # slow start degrades the workload rather than breaking it.
  sleep 0.5

  if command -v curl >/dev/null 2>&1; then
    curl -s --max-time 3 "http://127.0.0.1:$PORT/" > /dev/null 2>&1 || true
  else
    # Bash's /dev/tcp needs no external binary.
    (printf 'GET / HTTP/1.0\r\n\r\n' > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null || true
  fi
  wait "$LISTENER" 2>/dev/null || true
else
  log "python3 unavailable; skipping the TCP listener"
fi

# A DNS lookup. The aya backend decodes no DNS payloads by design, so this exists precisely to confirm
# the harness reports that as an expected difference rather than a defect.
if command -v getent >/dev/null 2>&1; then
  getent hosts localhost > /dev/null 2>&1 || true
fi

# ---- proc_spawn ---------------------------------------------------------------------------------
log "process spawns"
/bin/true
/usr/bin/env true 2>/dev/null || true

# A shell pipeline. Not a download-piped-to-shell — this workload must be safe to run anywhere — but
# structurally the same shape, so argv capture and truncation handling are exercised on the pattern that
# matters most in real findings.
sh -c 'printf "one\ntwo\n" | sort > project/piped.txt'

# ---- a forked subshell that writes ------------------------------------------------------------
# The aya backend's pid filter is maintained in-kernel through sched_process_fork. If that propagation is
# broken, this child's writes are missing from the aya stream and present in strace's — which the parity
# harness reports as an unexplained difference rather than silently tolerating.
log "forked child writes"
(
  printf 'from a child\n' > project/child-wrote.txt
  mkdir -p project/child-made
) &
wait

log "done"
