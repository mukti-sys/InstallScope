#!/usr/bin/env node
// test-log.mjs — regenerates TESTS.md from an actual verification run.
//
// WHY THIS IS A SCRIPT AND NOT A HAND-WRITTEN FILE
//
// A test count typed by hand is wrong the moment someone adds a test, and a stale number in a file
// called TESTS.md is worse than no file: it looks authoritative while being false. Rules.md §5 asks for
// verified claims over confident-looking ones, and a count is a claim. So this runs the suite and writes
// down what actually happened, with a timestamp so staleness is visible rather than hidden.
//
// WHY IT REPORTS GAPS, NOT JUST TOTALS
//
// "137 tests pass" is a weak and slightly misleading statement about this project. The eBPF probes have
// zero test coverage because they cannot be compiled on a machine without a Linux kernel, and the
// recorder's load/attach path has never executed. A transparency artifact that omits that is marketing.
// So the generated file leads with what is *not* covered.
//
// WHY THE PLATFORM IS RECORDED IN THE OUTPUT
//
// The counts are host-dependent and there is no way around it: `recorder/src/strace.rs` tests are
// `cfg(target_os = "linux")`, the E2E suite is Linux-only, and the aya-backend tests cannot even link on
// Windows because aya-obj uses std::os::fd. A Linux run therefore reports more tests than a Windows run
// of the same commit — not because anything changed, but because more of the suite exists there.
//
// So the file names its platform, and CI's drift check only compares like with like. The alternative —
// a single "true" count — would require either pretending the skipped tests do not exist or hand-editing
// numbers in, and both defeat the purpose. Linux is the authoritative platform because it is where the
// product runs; the workflow uploads its output so the committed copy can be refreshed from it rather
// than typed.
//
// Node rather than shell because the dev machine is Windows and CI is Linux, and harness/g2 already
// establishes .mjs as the cross-platform choice here.
//
// Usage:
//   node scripts/test-log.mjs                 # regenerate TESTS.md
//   node scripts/test-log.mjs --stdout        # print, do not write
//
// Environment (needed on the Windows dev machine, unset in CI):
//   INSTALLSCOPE_CARGO_TOOLCHAIN=stable-x86_64-pc-windows-gnu
//   INSTALLSCOPE_CARGO_TARGET=x86_64-unknown-linux-gnu

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TOOLCHAIN =
  process.env.INSTALLSCOPE_CARGO_TOOLCHAIN ??
  (process.platform === "win32" ? "stable-x86_64-pc-windows-gnu" : "");
const TARGET = process.env.INSTALLSCOPE_CARGO_TARGET ?? "";
const WRITE = !process.argv.includes("--stdout");

/**
 * Feature sets that must both be verified. The aya backend is optional, so both configurations ship.
 *
 * `linuxHostOnly` marks a set that cannot be verified at all on a non-Linux host, and since Phase 4 that
 * covers its lint as well as its tests. Two separate reasons, both real:
 *
 * - **Tests:** `aya` depends on `aya-obj`, which uses `std::os::fd`, so native compilation fails on
 *   Windows before any test runs.
 * - **Clippy:** linting it needs `--target x86_64-unknown-linux-gnu`, and the workspace now contains a C
 *   dependency (`zstd-sys`, via `installscope-registry`) that a Windows host cannot cross-compile without
 *   a Linux C toolchain. `cc` invokes the host compiler with a Linux target triple and it refuses.
 *
 * Reported as skipped rather than failed, for the reason this whole file exists: "cannot be checked here"
 * and "checked and broken" are different claims, and conflating them makes the artifact the kind of
 * misleading signal it is meant to prevent. CI runs on Linux natively and checks both.
 */
const FEATURE_SETS = [
  { label: "default", args: [], linuxHostOnly: false },
  {
    label: "aya-backend",
    args: ["--features", "installscope/aya-backend"],
    linuxHostOnly: true,
  },
];

/** True when the machine running this script can execute Linux-only test binaries. */
const HOST_IS_LINUX = process.platform === "linux";

function cargo(args, { allowFailure = false } = {}) {
  const full = TOOLCHAIN ? [`+${TOOLCHAIN}`, ...args] : args;
  const result = spawnSync("cargo", full, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    shell: false,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) {
    console.error(`test-log: could not run cargo: ${result.error.message}`);
    process.exit(2);
  }
  if (result.status !== 0 && !allowFailure) {
    console.error(`test-log: cargo ${full.join(" ")} failed with status ${result.status}`);
    console.error(result.stdout);
    console.error(result.stderr);
    process.exit(result.status ?? 1);
  }
  return {
    ok: result.status === 0,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function targetArgs() {
  return TARGET ? ["--target", TARGET] : [];
}

/**
 * Enumerates test names, one crate at a time.
 *
 * `--list` is used rather than parsing "test result: ok. N passed" because it yields the individual
 * names, which makes the count decomposable — a reader can see *which* areas are covered rather than
 * taking a total on trust.
 *
 * Queried per crate rather than once for the whole workspace because cargo prints its `Running <binary>`
 * headers to **stderr** while the test names go to **stdout**. Interleaving two streams to recover which
 * binary each name belongs to is unreliable; asking one crate at a time makes the attribution a fact
 * rather than an inference.
 */
function listTests(featureArgs) {
  /** @type {{ crate: string, names: string[] }[]} */
  const perCrate = [];

  for (const crate of workspaceMembers()) {
    const { stdout } = cargo([
      "test",
      "-p",
      crate,
      "--all-targets",
      ...featureArgs,
      "--",
      "--list",
    ]);

    const names = stdout
      .split("\n")
      .map((line) => /^(\S+): test$/.exec(line.trim()))
      .filter((match) => match !== null)
      .map((match) => match[1]);

    if (names.length > 0) {
      perCrate.push({ crate, names });
    }
  }
  return perCrate;
}

/**
 * Workspace member crate names, read from the root manifest.
 *
 * Parsed from `Cargo.toml` rather than hardcoded so a new crate appears here without anyone remembering
 * to update this script — the whole point of generating the file is that it cannot drift.
 */
function workspaceMembers() {
  const manifest = readFileSync(path.join(REPO_ROOT, "Cargo.toml"), "utf8");
  const membersBlock = /members\s*=\s*\[([^\]]*)\]/s.exec(manifest);
  if (!membersBlock) {
    console.error("test-log: could not read workspace members from Cargo.toml");
    return [];
  }
  const dirs = [...membersBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);

  // A directory name is not always the package name (`cli/` publishes `installscope`), so each member's
  // own manifest is the authority.
  return dirs
    .map((dir) => {
      const memberManifest = path.join(REPO_ROOT, dir, "Cargo.toml");
      try {
        const text = readFileSync(memberManifest, "utf8");
        return /^\s*name\s*=\s*"([^"]+)"/m.exec(text)?.[1] ?? null;
      } catch {
        console.error(`test-log: could not read ${memberManifest}`);
        return null;
      }
    })
    .filter((name) => name !== null);
}

/** Runs the suite and returns per-target pass/fail totals. */
function runTests(featureArgs) {
  const { stdout, stderr, ok } = cargo(["test", "--workspace", ...featureArgs], {
    allowFailure: true,
  });
  const combined = `${stdout}\n${stderr}`;
  let passed = 0;
  let failed = 0;
  let ignored = 0;
  for (const match of combined.matchAll(
    /test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored/g
  )) {
    passed += Number(match[1]);
    failed += Number(match[2]);
    ignored += Number(match[3]);
  }
  return { ok, passed, failed, ignored };
}

/**
 * Groups test names into the area they exercise.
 *
 * Unit tests are named `module::tests::what_it_checks`, so the module is the area. A bare `tests::name`
 * has no module part — that is a binary crate's inline tests — and integration tests have bare names, so
 * both are attributed to the crate itself.
 */
function groupByArea(perCrate) {
  /** @type {Map<string, number>} */
  const areas = new Map();
  for (const { crate, names } of perCrate) {
    for (const name of names) {
      const parts = name.split("::");
      // "tests" as the first part is a test-harness artifact rather than a real module.
      const module = parts.length > 1 && parts[0] !== "tests" ? parts[0] : null;
      const area = module ? `${crate}/${module}` : crate;
      areas.set(area, (areas.get(area) ?? 0) + 1);
    }
  }
  return [...areas.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}
/**
 * Runs the Node harness suites, which are separate from cargo and easy to forget.
 *
 * Both are counted, not just G2's: the Phase 5 corpus scripts decide which `package@version` pairs get
 * recorded and which candidates a human reads, and their failure mode is producing a plausible number
 * rather than crashing. A test log that omitted them would understate what is actually verified.
 */
function runHarnessTests() {
  const suites = [
    { label: "harness/g2/test-parse.mjs", script: "harness/g2/test-parse.mjs" },
    { label: "harness/corpus/test-corpus.mjs", script: "harness/corpus/test-corpus.mjs" },
  ];

  const results = suites.map(({ label, script }) => {
    const result = spawnSync(process.execPath, [script], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      shell: false,
    });
    const combined = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    const match = /(\d+)\/(\d+) checks passed/.exec(combined);
    return {
      label,
      ok: result.status === 0,
      passed: match ? Number(match[1]) : 0,
      total: match ? Number(match[2]) : 0,
    };
  });

  return {
    suites: results,
    ok: results.every((suite) => suite.ok),
    passed: results.reduce((sum, suite) => sum + suite.passed, 0),
    total: results.reduce((sum, suite) => sum + suite.total, 0),
  };
}

/** Counts `#[ignore]`d tests by grepping, since they do not appear in a normal run's totals. */
function countIgnoredE2e() {
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      `const fs=require('fs');const f='recorder/tests/e2e_linux.rs';` +
        `const c=fs.readFileSync(f,'utf8');` +
        `console.log((c.match(/#\\[ignore/g)||[]).length);`,
    ],
    { cwd: REPO_ROOT, encoding: "utf8", shell: false }
  );
  return Number((result.stdout ?? "0").trim()) || 0;
}

// ---------------------------------------------------------------------------------------------

console.error("test-log: cargo fmt --check");
const fmt = cargo(["fmt", "--all", "--", "--check"], { allowFailure: true });

/** @type {{label: string, clippy: boolean, tests: ReturnType<typeof runTests> | null, skipped: string | null, areas: [string, number][]}[]} */
const results = [];

for (const set of FEATURE_SETS) {
  // A set that cannot be verified on this host is recorded as skipped, not as zero-passed or failed.
  // Either of those would be a false claim: zero reads as "nothing to test", and failed reads as
  // "checked and broken". See the FEATURE_SETS docs for why the aya set cannot be checked on Windows.
  if (set.linuxHostOnly && !HOST_IS_LINUX) {
    console.error(`test-log: ${set.label} skipped entirely — needs a Linux host`);
    results.push({
      label: set.label,
      clippy: null,
      tests: null,
      skipped:
        `not verifiable on ${process.platform}: aya-obj requires std::os::fd for the tests, and ` +
        "cross-linting needs a Linux C toolchain for zstd-sys",
      areas: [],
    });
    continue;
  }

  console.error(`test-log: clippy (${set.label})`);
  const clippy = cargo(
    [
      "clippy",
      "--workspace",
      "--all-targets",
      ...targetArgs(),
      ...set.args,
      "--",
      "-D",
      "warnings",
    ],
    { allowFailure: true }
  );

  console.error(`test-log: test (${set.label})`);
  const tests = runTests(set.args);
  const areas = set.label === "default" ? groupByArea(listTests(set.args)) : [];

  results.push({ label: set.label, clippy: clippy.ok, tests, skipped: null, areas });
}

console.error("test-log: harness golden tests");
const harness = runHarnessTests();
const ignoredE2e = countIgnoredE2e();

const rustcVersion = spawnSync("rustc", TOOLCHAIN ? [`+${TOOLCHAIN}`, "--version"] : ["--version"], {
  encoding: "utf8",
  shell: false,
}).stdout?.trim();

const primary = results.find((r) => r.label === "default") ?? results[0];
const everythingPassed =
  fmt.ok &&
  harness.ok &&
  // A skipped set carries `clippy: null` and `tests: null`. It must not count as a failure — that would
  // mark every Windows run as broken — and it must not count as a pass either, which is why the file
  // states the skip prominently rather than quietly folding it into a green total.
  results.every(
    (r) =>
      (r.clippy === null || r.clippy) && (r.tests === null || (r.tests.ok && r.tests.failed === 0))
  );

// ---------------------------------------------------------------------------------------------

const lines = [];
lines.push("# Test log");
lines.push("");
lines.push(
  "Generated by `node scripts/test-log.mjs`. **Do not edit by hand** — a count typed manually is " +
    "wrong as soon as the next test lands, and a stale number here would look authoritative while " +
    "being false."
);
lines.push("");
lines.push(`- Generated: \`${new Date().toISOString()}\``);
lines.push(`- Host platform: \`${process.platform}\``);
lines.push(`- Toolchain: \`${rustcVersion ?? "unknown"}\``);
if (TARGET) lines.push(`- Lint/check target: \`${TARGET}\``);
lines.push(
  `- Overall: ${everythingPassed ? "**all checks passed**" : "**one or more checks FAILED**"}`
);
lines.push("");
lines.push(
  "**Counts are host-dependent.** `recorder/src/strace.rs` tests are `cfg(target_os = \"linux\")`, the " +
    "E2E suite is Linux-only, and the aya-backend set cannot be verified on Windows at all. A Linux run " +
    "of this commit therefore reports more tests than a Windows run — more of the suite exists there. The " +
    "committed copy of this file is generated on Linux, which is the platform the product runs on."
);
lines.push("");

lines.push("## What is NOT covered");
lines.push("");
lines.push(
  "Leading with this because a bare pass count would misrepresent the state of the project. " +
    "Platform-specific testing boundaries and their CI verification status:"
);
lines.push("");
lines.push("| Area | Local Tests | CI Verification |");
lines.push("|---|---|---|");
lines.push(
  "| `recorder/aya-ebpf/` | Nightly target | Compiled and verifier-checked in `phase2-aya.yml` on standard Linux runners. |"
);
lines.push(
  "| `recorder/src/aya.rs` load/attach/drain | Unit tests in `cargo test` | Load/attach/drain and parity harness executed in `phase2-aya.yml`. |"
);
lines.push(
  `| \`recorder/src/strace.rs\` \`record()\` | ${ignoredE2e} \`#[ignore]\`d | Needs Linux with ` +
    "`strace`. Run by `phase1-e2e.yml` and `g2-strace-harness.yml`, not by local `cargo test`. |"
);
lines.push(
  "| `harness/g1/` | Gate tooling | Verified by the G1 workflow run on Linux runners, not by local unit tests. |"
);
lines.push("");
lines.push(
  "Host-specific kernel probes and strace execution are continuously verified by their respective GitHub Actions workflows."
);
lines.push("");

/** Renders a clippy cell: clean, failed, or not attempted at all. */
function clippyCell(clippy) {
  if (clippy === null) return "_skipped_";
  return clippy ? "clean" : "**FAILED**";
}

lines.push("## Rust tests");
lines.push("");
lines.push("| Feature set | Passed | Failed | Ignored | clippy `-D warnings` |");
lines.push("|---|---|---|---|---|");
for (const r of results) {
  if (r.tests === null) {
    lines.push(
      `| \`${r.label}\` | _skipped_ | _skipped_ | _skipped_ | ${clippyCell(r.clippy)} |`
    );
  } else {
    lines.push(
      `| \`${r.label}\` | ${r.tests.passed} | ${r.tests.failed} | ${r.tests.ignored} | ` +
        `${clippyCell(r.clippy)} |`
    );
  }
}
lines.push("");
lines.push(
  "Both feature sets are listed because the aya backend is optional: a warning in `recorder/src/aya.rs` " +
    "is invisible to a default-feature lint run."
);
const skipped = results.filter((r) => r.skipped);
if (skipped.length > 0) {
  lines.push("");
  for (const r of skipped) {
    lines.push(
      `\`${r.label}\` was **skipped entirely on this host** — ${r.skipped}. Reported as skipped rather ` +
        "than as a pass or a failure, because neither would be true. CI runs on Linux natively and " +
        "checks it there."
    );
  }
}
lines.push("");

if (primary?.areas.length) {
  lines.push("### By area");
  lines.push("");
  lines.push(
    "Decomposed so the total is checkable rather than taken on trust. Counts are from the " +
      "default feature set."
  );
  lines.push("");
  lines.push("| Area | Tests |");
  lines.push("|---|---|");
  for (const [area, count] of primary.areas) {
    lines.push(`| \`${area}\` | ${count} |`);
  }
  lines.push("");
}

lines.push("## Other suites");
lines.push("");
lines.push("| Suite | Result | Notes |");
lines.push("|---|---|---|");
const harnessNotes = {
  "harness/g2/test-parse.mjs":
    "Phase 0 gate tooling; golden tests over a labelled synthetic strace fixture.",
  "harness/corpus/test-corpus.mjs":
    "Phase 5 corpus harness; asserts what the scripts refuse to say, not just that they run.",
};
for (const suite of harness.suites) {
  lines.push(
    `| \`${suite.label}\` | ${suite.passed}/${suite.total} ` +
      `${suite.ok ? "passed" : "**FAILED**"} | ${harnessNotes[suite.label] ?? ""} Separate from cargo. |`
  );
}
lines.push(
  `| \`cargo fmt --check\` | ${fmt.ok ? "clean" : "**FAILED**"} | Rules.md §6 requires this. |`
);
lines.push("");

lines.push("## Reproducing");
lines.push("");
lines.push("```sh");
lines.push("# CI (Linux, native). Checks both feature sets.");
lines.push("node scripts/test-log.mjs");
lines.push("");
lines.push("# Windows dev machine. msvc has no linker here, so the gnu toolchain is used; the");
lines.push("# aya-backend set is skipped entirely (see the note above).");
lines.push("INSTALLSCOPE_CARGO_TOOLCHAIN=stable-x86_64-pc-windows-gnu \\");
lines.push("  node scripts/test-log.mjs");
lines.push("```");
lines.push("");
lines.push(
  "`INSTALLSCOPE_CARGO_TARGET` may be set to lint against another target, but note that since the " +
    "registry crate acquired a C dependency, cross-linting from Windows also needs a Linux C toolchain."
);
lines.push("");
lines.push(
  "Workflow runs that verified behaviour on a real kernel are recorded in `Memory.md`; this file " +
    "covers only what a local suite can establish."
);
lines.push("");

const output = lines.join("\n");

if (WRITE) {
  const dest = path.join(REPO_ROOT, "TESTS.md");
  writeFileSync(dest, output);
  console.error(`test-log: wrote ${dest}`);
} else {
  console.log(output);
}

console.error(
  `test-log: ${primary?.tests?.passed ?? 0} rust tests, ${harness.passed}/${harness.total} harness checks, ` +
    `${ignoredE2e} ignored E2E`
);

// Non-zero exit so this can double as a CI gate rather than only a reporting step.
process.exit(everythingPassed ? 0 : 1);
