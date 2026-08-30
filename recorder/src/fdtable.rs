//! Per-process file descriptor table and path resolution.
//!
//! strace tells you `write(7, …)`, not `write("/etc/cron.d/evil", …)`. Byte volumes — the thing the
//! Phase 0 harness could not produce, making Design.md:35's "wrote ~13 MB outside project dir"
//! impossible — require joining a `write` back to the `openat` that created its descriptor. That is
//! what this module does.
//!
//! The `-yy` flag annotates descriptors inline, and where it does, that annotation is preferred: it
//! is the kernel's own answer. This table exists for the cases `-yy` cannot cover, notably a `write`
//! whose descriptor was inherited across a fork.

use std::collections::HashMap;

use installscope_core::{PathOrigin, TracedPath};

/// What a descriptor refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdTarget {
    /// A file, with the path known at open time.
    File {
        /// Path the descriptor refers to.
        path: String,
        /// How that path was resolved.
        origin: PathOrigin,
    },
    /// A socket. Kept distinct so a `write` to a socket is never reported as a file write.
    Socket {
        /// strace's rendering of the socket arguments, for evidence display.
        description: String,
    },
}

/// Tracks open descriptors per pid, plus each process's working directory.
///
/// Descriptors are per-process, and a child inherits its parent's table at fork. [`Self::fork`]
/// copies rather than shares, because a child closing a descriptor must not affect the parent's view.
#[derive(Debug, Default)]
pub struct FdTable {
    per_pid: HashMap<u32, HashMap<i32, FdTarget>>,
    cwd: HashMap<u32, String>,
}

impl FdTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `pid` opened `fd` pointing at `path`.
    pub fn open_file(&mut self, pid: u32, fd: i32, path: impl Into<String>, origin: PathOrigin) {
        if fd < 0 {
            return;
        }
        self.per_pid.entry(pid).or_default().insert(
            fd,
            FdTarget::File {
                path: path.into(),
                origin,
            },
        );
    }

    /// Records that `pid` opened `fd` as a socket.
    pub fn open_socket(&mut self, pid: u32, fd: i32, description: impl Into<String>) {
        if fd < 0 {
            return;
        }
        self.per_pid.entry(pid).or_default().insert(
            fd,
            FdTarget::Socket {
                description: description.into(),
            },
        );
    }

    /// Forgets `fd` for `pid`.
    pub fn close(&mut self, pid: u32, fd: i32) {
        if let Some(table) = self.per_pid.get_mut(&pid) {
            table.remove(&fd);
        }
    }

    /// Looks up what `fd` refers to for `pid`.
    #[must_use]
    pub fn get(&self, pid: u32, fd: i32) -> Option<&FdTarget> {
        self.per_pid.get(&pid)?.get(&fd)
    }

    /// Copies `parent`'s descriptor table and cwd to `child`, as `fork`/`clone` does.
    pub fn fork(&mut self, parent: u32, child: u32) {
        if let Some(table) = self.per_pid.get(&parent).cloned() {
            self.per_pid.insert(child, table);
        }
        if let Some(dir) = self.cwd.get(&parent).cloned() {
            self.cwd.insert(child, dir);
        }
    }

    /// Drops all state for an exited process, so a recycled pid cannot inherit stale descriptors.
    pub fn process_exited(&mut self, pid: u32) {
        self.per_pid.remove(&pid);
        self.cwd.remove(&pid);
    }

    /// Records a successful `chdir`.
    pub fn set_cwd(&mut self, pid: u32, dir: impl Into<String>) {
        self.cwd.insert(pid, dir.into());
    }

    /// The known working directory for `pid`.
    #[must_use]
    pub fn cwd(&self, pid: u32) -> Option<&str> {
        self.cwd.get(&pid).map(String::as_str)
    }

    /// Seeds the working directory for the root traced process.
    pub fn seed_cwd(&mut self, pid: u32, dir: impl Into<String>) {
        self.cwd.entry(pid).or_insert_with(|| dir.into());
    }

    /// Number of processes with tracked state. Used by tests and diagnostics.
    #[must_use]
    pub fn tracked_processes(&self) -> usize {
        self.per_pid.len()
    }
}

/// Normalizes `.` and `..` components without touching the filesystem.
///
/// Purely lexical, which is the only option when replaying a trace after the fact. Symlinks are not
/// resolved, so the result is what the process asked for rather than where it landed. Callers get
/// [`PathOrigin`] alongside so they know how much to trust it.
#[must_use]
pub fn normalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(stack.last(), Some(&"..")) || (!absolute && stack.is_empty()) {
                    stack.push("..");
                } else {
                    stack.pop();
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Joins a relative path onto a base directory.
#[must_use]
pub fn join(base: &str, relative: &str) -> String {
    if relative.starts_with('/') {
        return normalize(relative);
    }
    let trimmed = base.trim_end_matches('/');
    normalize(&format!("{trimmed}/{relative}"))
}

/// Resolves a path argument into a [`TracedPath`], recording how it was resolved.
///
/// Preference order, strongest first:
/// 1. the kernel's own `-yy` annotation on the return value;
/// 2. an absolute path in the arguments;
/// 3. a relative path joined onto a known `dirfd` or the process's known cwd;
/// 4. otherwise [`PathOrigin::Unresolved`] — deliberately *not* a guess, because a fabricated
///    absolute path would manufacture a critical "write outside expected dirs" finding.
#[must_use]
pub fn resolve(
    table: &FdTable,
    pid: u32,
    dirfd_arg: Option<&str>,
    raw_path: Option<&str>,
    ret_annotation: Option<&str>,
) -> Option<TracedPath> {
    if let Some(annotation) = ret_annotation {
        if annotation.starts_with('/') {
            return Some(TracedPath::new(normalize(annotation), PathOrigin::Kernel));
        }
    }

    let raw = raw_path?;
    if raw.starts_with('/') {
        return Some(TracedPath::new(normalize(raw), PathOrigin::Absolute));
    }

    // A dirfd annotated by -yy gives the base directly.
    if let Some(arg) = dirfd_arg {
        if arg != "AT_FDCWD" {
            if let Some(annotation) = crate::decode::fd_annotation(arg) {
                if annotation.starts_with('/') {
                    return Some(TracedPath::new(
                        join(annotation, raw),
                        PathOrigin::ResolvedFromDirfd,
                    ));
                }
            }
            // Otherwise consult the table for that descriptor.
            if let Some(fd) = crate::decode::fd_number(arg) {
                if let Some(FdTarget::File { path, .. }) = table.get(pid, fd) {
                    return Some(TracedPath::new(
                        join(path, raw),
                        PathOrigin::ResolvedFromDirfd,
                    ));
                }
            }
            // dirfd is neither AT_FDCWD nor known: refuse to assume it meant cwd.
            return Some(TracedPath::new(raw, PathOrigin::Unresolved));
        }
    }

    // AT_FDCWD, or no dirfd argument at all (open, mkdir, …): use the tracked cwd if we have one.
    if let Some(dir) = table.cwd(pid) {
        return Some(TracedPath::new(
            join(dir, raw),
            PathOrigin::ResolvedFromDirfd,
        ));
    }

    Some(TracedPath::new(raw, PathOrigin::Unresolved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dot_and_dotdot() {
        assert_eq!(normalize("/a/b/../c"), "/a/c");
        assert_eq!(normalize("/a/./b"), "/a/b");
        assert_eq!(normalize("/a//b"), "/a/b");
        assert_eq!(normalize("/a/b/"), "/a/b");
        assert_eq!(normalize("/.."), "/");
        assert_eq!(normalize("a/b/../c"), "a/c");
        // A relative path that escapes its base keeps the .. rather than silently anchoring at /.
        assert_eq!(normalize("../x"), "../x");
        assert_eq!(normalize("."), ".");
    }

    #[test]
    fn joins_relative_onto_base() {
        assert_eq!(
            join("/work/project", "node_modules/x"),
            "/work/project/node_modules/x"
        );
        assert_eq!(join("/work/project/", "x"), "/work/project/x");
        assert_eq!(join("/work/project", "../sibling"), "/work/sibling");
        // An absolute "relative" path wins outright.
        assert_eq!(join("/work", "/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn tracks_descriptors_per_process() {
        let mut table = FdTable::new();
        table.open_file(100, 3, "/work/a.txt", PathOrigin::Absolute);
        table.open_socket(100, 4, "TCP:[1.2.3.4:443]");

        assert!(matches!(
            table.get(100, 3),
            Some(FdTarget::File { path, .. }) if path == "/work/a.txt"
        ));
        assert!(matches!(table.get(100, 4), Some(FdTarget::Socket { .. })));
        // Another process's descriptor 3 is unrelated.
        assert_eq!(table.get(200, 3), None);

        table.close(100, 3);
        assert_eq!(table.get(100, 3), None);
    }

    #[test]
    fn child_inherits_a_copy_not_a_reference() {
        let mut table = FdTable::new();
        table.open_file(100, 3, "/work/a.txt", PathOrigin::Absolute);
        table.set_cwd(100, "/work");
        table.fork(100, 101);

        assert!(table.get(101, 3).is_some(), "child inherits descriptors");
        assert_eq!(table.cwd(101), Some("/work"));

        table.close(101, 3);
        assert!(
            table.get(100, 3).is_some(),
            "child closing a descriptor must not affect the parent"
        );
    }

    #[test]
    fn exited_process_state_is_dropped() {
        let mut table = FdTable::new();
        table.open_file(100, 3, "/work/a.txt", PathOrigin::Absolute);
        table.set_cwd(100, "/work");
        assert_eq!(table.tracked_processes(), 1);

        table.process_exited(100);
        assert_eq!(table.tracked_processes(), 0);
        assert_eq!(
            table.get(100, 3),
            None,
            "a recycled pid must not inherit stale descriptors"
        );
        assert_eq!(table.cwd(100), None);
    }

    #[test]
    fn prefers_the_kernel_annotation() {
        let table = FdTable::new();
        let resolved = resolve(
            &table,
            1,
            Some("AT_FDCWD"),
            Some("relative/thing"),
            Some("/absolute/truth"),
        )
        .expect("resolved");
        assert_eq!(resolved.path, "/absolute/truth");
        assert_eq!(resolved.origin, PathOrigin::Kernel);
    }

    #[test]
    fn resolves_relative_against_dirfd_annotation() {
        let table = FdTable::new();
        let resolved = resolve(
            &table,
            1,
            Some("7</work/project>"),
            Some("pkg/file.js"),
            None,
        )
        .expect("resolved");
        assert_eq!(resolved.path, "/work/project/pkg/file.js");
        assert_eq!(resolved.origin, PathOrigin::ResolvedFromDirfd);
    }

    #[test]
    fn resolves_relative_against_tracked_cwd() {
        let mut table = FdTable::new();
        table.set_cwd(42, "/work/project");
        let resolved =
            resolve(&table, 42, Some("AT_FDCWD"), Some("node_modules/x"), None).expect("resolved");
        assert_eq!(resolved.path, "/work/project/node_modules/x");
        assert_eq!(resolved.origin, PathOrigin::ResolvedFromDirfd);
    }

    #[test]
    fn refuses_to_guess_when_the_base_is_unknown() {
        // The critical negative case. Without a known cwd, a relative path stays unresolved, and
        // TracedPath::is_resolved() is false — so the rules engine cannot place it inside or outside
        // any zone, and cannot manufacture a critical finding from it.
        let table = FdTable::new();
        let resolved = resolve(&table, 1, Some("AT_FDCWD"), Some("relative-file.txt"), None)
            .expect("resolved");
        assert_eq!(resolved.path, "relative-file.txt");
        assert_eq!(resolved.origin, PathOrigin::Unresolved);
        assert!(!resolved.is_resolved());

        // An unknown, non-AT_FDCWD dirfd must not be assumed to be cwd either.
        let mut with_cwd = FdTable::new();
        with_cwd.set_cwd(1, "/work");
        let unknown_dirfd =
            resolve(&with_cwd, 1, Some("9"), Some("x.txt"), None).expect("resolved");
        assert_eq!(unknown_dirfd.origin, PathOrigin::Unresolved);
    }

    #[test]
    fn resolves_dirfd_through_the_table_when_annotation_is_absent() {
        let mut table = FdTable::new();
        table.open_file(5, 9, "/work/project", PathOrigin::Absolute);
        let resolved = resolve(&table, 5, Some("9"), Some("sub/file"), None).expect("resolved");
        assert_eq!(resolved.path, "/work/project/sub/file");
        assert_eq!(resolved.origin, PathOrigin::ResolvedFromDirfd);
    }
}
