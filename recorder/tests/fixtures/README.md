# SYNTHETIC strace fixture — NOT a recording of any real package.
#
# Rules.md §5 requires golden fixtures to be labeled synthetic. Every line here was hand-written to
# exercise a specific parser path. Citing any of it as a receipt, or presenting it as observed
# behavior of a real npm package, is fabrication.
#
# Format matches what recorder/src/strace.rs actually invokes:
#   strace -f -ff -ttt -yy -s 512 -e trace=<set> -o <dir>/trace -- <cmd>
# so lines are `<epoch.micros> syscall(args) = ret`, one file per pid, named trace.<pid>.
#
# Session start epoch for these fixtures is 1719245678.000000 — see parse.rs.

## What trace.4100 (root process) covers
#  - execve of the install command
#  - chdir, so later relative paths RESOLVE instead of being discarded
#  - openat with write intent -> fs_write(Open)
#  - write()/pwrite64 accumulation across multiple calls to ONE descriptor -> a single fs_write(Write)
#    carrying summed bytes. This is the Phase 0 gap: the harness could not produce byte volumes.
#  - close() flushing the byte total at the right moment
#  - a descriptor REOPENED to a different path, which must not merge totals
#  - write() to a socket fd, which must NOT be reported as a file write
#  - credential reads (~/.ssh/id_rsa succeeds, ~/.aws/credentials fails with ENOENT)
#  - an uninteresting read (/usr/lib/...) that must produce NO event
#  - connect to a public address, a loopback resolver, and a private metadata IP
#  - DNS via sendto (decodable) and via sendmsg with a truncated payload (must yield nothing)
#  - connect split across <unfinished ...> / <... resumed> with EINPROGRESS
#  - clone, so the child inherits the fd table
#  - chmod +x, rename, symlink, unlink, mkdir
#  - exit notice
#
## What trace.4101 (forked child) covers
#  - a write() through an INHERITED descriptor, proving fork propagation
#  - a relative openat with no known cwd for that pid -> PathOrigin::Unresolved
#  - execve of a shell pipeline (curl | sh), argv preserved intact
#  - dup2, so the duplicate resolves to the same path
#  - a signal notice, which carries no syscall
#
## What trace.4102 covers
#  - a truncated final line: the process died mid-syscall, leaving `<unfinished ...>` unmatched.
#    This must increment unmatched_unfinished and therefore force PARTIAL.
