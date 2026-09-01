//! Placing an observed path inside or outside the directories that give it meaning.
//!
//! This is the module the most severe rule depends on. "Wrote outside the project, cache, and package
//! manager directories" is `critical` at weight 40 (Architecture.md §4), which means a mistake here is
//! not a cosmetic error — it manufactures the worst finding the product can report.
//!
//! # Unresolvable is a third answer, not a synonym for outside
//!
//! Both recorder backends can produce a path they could not resolve. strace hits this when a process
//! passes a relative path and no `dirfd` or cwd is known; the aya probes hit it constantly, because they
//! read the syscall's raw path argument and have no dentry walk. Phase 2's parity run showed most aya
//! write paths arriving as [`PathOrigin::Unresolved`].
//!
//! Treating those as "outside" would score an ordinary `npm install` as critical. Treating them as
//! "inside" would hide a real escape. Both are wrong, so [`Placement::Unresolvable`] exists and no rule
//! may score it. The consequence is a missed finding rather than a fabricated one, which is the correct
//! direction to fail — `Rules.md` §5, and PRD.md:43 on false-positive discipline.

use crate::events::{TracedPath, Zones};

/// Where an observed path sits relative to the recording's declared zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Placement {
    /// Inside a declared zone. Expected behavior for an install.
    Inside(Zone),
    /// Provably outside every declared zone. The only placement that can raise the critical rule.
    Outside,
    /// Not placeable, because the path was never resolved to an absolute form.
    ///
    /// **No rule may score this.** See the module docs: guessing in either direction is worse than
    /// declining to answer.
    Unresolvable,
    /// A kernel pseudo-path rather than a location on disk.
    ///
    /// `/proc`, `/sys`, `/dev`, and the runtime directories are where processes talk to the kernel, not
    /// where they persist anything. Writing to `/dev/null` is a no-op, and a recording of any real
    /// install is full of these. Scoring them would bury genuine findings in noise.
    Runtime,
}

impl Placement {
    /// True when this placement can support an "outside expected directories" finding.
    ///
    /// The single question the critical rule asks. Written as a method so the guard cannot be
    /// accidentally re-derived, incorrectly, at a call site.
    #[must_use]
    pub const fn is_scorable_as_outside(self) -> bool {
        matches!(self, Self::Outside)
    }

    /// True when the path could not be placed at all.
    #[must_use]
    pub const fn is_unresolvable(self) -> bool {
        matches!(self, Self::Unresolvable)
    }
}

/// Which declared zone a path fell into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Zone {
    /// The project being installed into.
    Project,
    /// Package manager cache.
    Cache,
    /// `HOME` of the recorded process.
    Home,
    /// `TMPDIR`.
    Tmp,
    /// An additional prefix the caller declared, including the recorder's own output directory.
    Declared,
}

impl Zone {
    /// Name for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Cache => "cache",
            Self::Home => "home",
            Self::Tmp => "tmp",
            Self::Declared => "declared",
        }
    }
}

impl std::fmt::Display for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Path prefixes that are kernel interfaces rather than storage.
///
/// Deliberately narrow. Each entry is a directory whose contents are not persistent files, so a write
/// there is not a filesystem mutation in the sense the rules care about. Adding to this list weakens the
/// critical rule, so anything new needs the same justification.
const RUNTIME_PREFIXES: &[&str] = &["/proc/", "/sys/", "/dev/", "/run/", "/var/run/"];

/// Exact runtime paths, for the cases with no trailing component.
const RUNTIME_EXACT: &[&str] = &["/proc", "/sys", "/dev", "/run", "/var/run"];

/// Places a traced path against a recording's zones.
///
/// Zone prefixes are compared with a component boundary, so `/work/project-evil` is not inside
/// `/work/project`. Getting that wrong would silently exempt a sibling directory from the critical rule.
#[must_use]
pub fn placement_of(path: &TracedPath, zones: &Zones) -> Placement {
    // Ordering matters: resolvability is checked first, because an unresolved path must never reach the
    // zone comparison at all. A relative path can lexically "not start with" every zone prefix and would
    // otherwise fall through to Outside.
    if !path.is_resolved() {
        return Placement::Unresolvable;
    }
    // Defence in depth. `is_resolved` already requires an absolute path, but the critical rule keys off
    // this function and a future change to either side should not be able to produce a placement for a
    // relative string.
    if !path.path.starts_with('/') {
        return Placement::Unresolvable;
    }

    if is_runtime(&path.path) {
        return Placement::Runtime;
    }

    for (candidate, zone) in [
        (zones.project.as_deref(), Zone::Project),
        (zones.cache.as_deref(), Zone::Cache),
        (zones.home.as_deref(), Zone::Home),
        (zones.tmp.as_deref(), Zone::Tmp),
    ] {
        if let Some(prefix) = candidate {
            if within(&path.path, prefix) {
                return Placement::Inside(zone);
            }
        }
    }
    for prefix in &zones.extra {
        if within(&path.path, prefix) {
            return Placement::Inside(Zone::Declared);
        }
    }

    Placement::Outside
}

/// True when `path` is inside `prefix`, respecting component boundaries.
fn within(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let trimmed = prefix.trim_end_matches('/');
    // An empty trimmed prefix means the zone was "/" — everything is inside it, which is almost certainly
    // a configuration mistake rather than an intent, so it is rejected rather than matching everything.
    if trimmed.is_empty() {
        return false;
    }
    if path == trimmed {
        return true;
    }
    path.strip_prefix(trimmed)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// True for kernel pseudo-filesystems and runtime directories.
fn is_runtime(path: &str) -> bool {
    RUNTIME_EXACT.contains(&path) || RUNTIME_PREFIXES.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::PathOrigin;

    fn zones() -> Zones {
        Zones {
            project: Some("/work/project".to_string()),
            cache: Some("/work/cache".to_string()),
            home: Some("/home/runner".to_string()),
            tmp: Some("/tmp".to_string()),
            extra: vec!["/work/out".to_string()],
        }
    }

    fn resolved(path: &str) -> TracedPath {
        TracedPath::new(path, PathOrigin::Kernel)
    }

    #[test]
    fn places_paths_in_their_declared_zones() {
        assert_eq!(
            placement_of(&resolved("/work/project/index.js"), &zones()),
            Placement::Inside(Zone::Project)
        );
        assert_eq!(
            placement_of(&resolved("/work/cache/_cacache/x"), &zones()),
            Placement::Inside(Zone::Cache)
        );
        assert_eq!(
            placement_of(&resolved("/home/runner/.npmrc"), &zones()),
            Placement::Inside(Zone::Home)
        );
        assert_eq!(
            placement_of(&resolved("/tmp/staging"), &zones()),
            Placement::Inside(Zone::Tmp)
        );
        assert_eq!(
            placement_of(&resolved("/work/out/events.jsonl"), &zones()),
            Placement::Inside(Zone::Declared)
        );
        // The zone directory itself, not just its contents.
        assert_eq!(
            placement_of(&resolved("/work/project"), &zones()),
            Placement::Inside(Zone::Project)
        );
    }

    #[test]
    fn a_write_outside_every_zone_is_scorable() {
        let placement = placement_of(&resolved("/etc/cron.d/evil"), &zones());
        assert_eq!(placement, Placement::Outside);
        assert!(placement.is_scorable_as_outside());
    }

    #[test]
    fn an_unresolved_path_is_never_scorable_in_either_direction() {
        // THE guard this module exists for. Phase 2's aya backend produces mostly-unresolved paths
        // because it reads the raw syscall argument. Scoring those as Outside would make every install
        // critical; scoring them as Inside would hide a real escape.
        let relative = TracedPath::new("node_modules/.bin/thing", PathOrigin::Unresolved);
        let placement = placement_of(&relative, &zones());
        assert_eq!(placement, Placement::Unresolvable);
        assert!(!placement.is_scorable_as_outside());
        assert!(placement.is_unresolvable());
    }

    #[test]
    fn an_absolute_looking_path_marked_unresolved_stays_unresolvable() {
        // A backend may report something that looks absolute while flagging that it could not trust the
        // resolution — a truncated path, for instance. The origin is authoritative, not the shape.
        let lying = TracedPath::new("/etc/passwd", PathOrigin::Unresolved);
        assert_eq!(placement_of(&lying, &zones()), Placement::Unresolvable);
    }

    #[test]
    fn zone_matching_respects_component_boundaries() {
        // A substring match here would silently exempt a sibling directory from the critical rule.
        assert_eq!(
            placement_of(&resolved("/work/project-evil/payload"), &zones()),
            Placement::Outside
        );
        assert_eq!(
            placement_of(&resolved("/work/projectile"), &zones()),
            Placement::Outside
        );
        // And the reverse: a path that merely shares a prefix with a zone name.
        assert_eq!(
            placement_of(&resolved("/tmpfoo/x"), &zones()),
            Placement::Outside
        );
    }

    #[test]
    fn kernel_interfaces_are_runtime_not_outside() {
        // Every real recording is full of these. Scoring them as critical writes outside the project
        // would bury genuine findings — the false-positive failure PRD.md:43 warns about.
        for path in [
            "/proc/self/status",
            "/sys/kernel/mm/transparent_hugepage/enabled",
            "/dev/null",
            "/dev/urandom",
            "/run/systemd/notify",
            "/var/run/nscd/socket",
        ] {
            let placement = placement_of(&resolved(path), &zones());
            assert_eq!(placement, Placement::Runtime, "{path} must be Runtime");
            assert!(
                !placement.is_scorable_as_outside(),
                "{path} must not raise the critical rule"
            );
        }
    }

    #[test]
    fn a_zone_of_root_is_rejected_rather_than_matching_everything() {
        // "/" as a zone would place every path Inside and disable the critical rule entirely. A
        // misconfiguration should not silently switch off the product's most severe finding.
        let everything = Zones {
            project: Some("/".to_string()),
            ..Zones::default()
        };
        assert_eq!(
            placement_of(&resolved("/etc/shadow"), &everything),
            Placement::Outside
        );
    }

    #[test]
    fn an_empty_zone_string_matches_nothing() {
        let empty = Zones {
            project: Some(String::new()),
            ..Zones::default()
        };
        assert_eq!(
            placement_of(&resolved("/etc/shadow"), &empty),
            Placement::Outside
        );
    }

    #[test]
    fn with_no_zones_declared_everything_real_is_outside() {
        // Honest but useless, and worth asserting: a caller who declares no zones gets a recording where
        // every write looks like an escape. The CLI infers zones precisely so this does not happen, and
        // the shape of this result is what makes that inference load-bearing rather than cosmetic.
        let none = Zones::default();
        assert_eq!(
            placement_of(&resolved("/work/project/index.js"), &none),
            Placement::Outside
        );
        // Runtime paths are still excluded, because that judgment does not depend on zones.
        assert_eq!(
            placement_of(&resolved("/proc/self/environ"), &none),
            Placement::Runtime
        );
    }

    #[test]
    fn trailing_slashes_in_a_zone_do_not_break_matching() {
        let sloppy = Zones {
            project: Some("/work/project/".to_string()),
            ..Zones::default()
        };
        assert_eq!(
            placement_of(&resolved("/work/project/x"), &sloppy),
            Placement::Inside(Zone::Project)
        );
    }

    #[test]
    fn zone_precedence_is_deterministic() {
        // Nested zones are common: a cache inside a project, or a tmp inside home. The first match wins
        // in a fixed order, so a report never attributes the same path to different zones across runs.
        let nested = Zones {
            project: Some("/work".to_string()),
            cache: Some("/work/cache".to_string()),
            ..Zones::default()
        };
        assert_eq!(
            placement_of(&resolved("/work/cache/blob"), &nested),
            Placement::Inside(Zone::Project),
            "project is checked first, and the answer must not vary between runs"
        );
    }
}
