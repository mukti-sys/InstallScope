# Design.md — InstallScope visual system
Terminal-native forensic tool: austere, high-contrast, zero decoration. A flight recorder, not a dashboard.

## Palette (dark default)
| Token | Hex | Use |
|---|---|---|
| bg | `#0B0F14` | page |
| panel | `#131A22` | cards/evidence |
| line | `#1E2A36` | borders |
| text | `#E6EDF3` | body |
| dim | `#7D8B99` | metadata |
| **beacon** | `#FF6A3D` | brand accent: logo, score ring, links — the "recorder light" |
| critical | `#E5484D` | critical findings |
| high | `#F5A524` | high findings |
| medium | `#3B82C4` | medium |
| pass | `#3DD68C` | clean / partial-safe |
| diff-add | `#1E3A2A` (bg tint over `#0B0F14`) | version-diff added behavior |

## Type
- Code/evidence/scores: **JetBrains Mono** (fallback: ui-monospace). Everything numeric is mono.
- Body/headers: **Inter**. Weights: 400/600 only. Sizes: 13 (body) / 15 (headers) / 11 (meta). No display fonts.

## Logo / wordmark
Concept: square recorder beacon (cockpit black-box indicator) — single dot in beacon orange that
"blinks" (CSS keyframes, 1.4s ease) next to `installscope` in mono lowercase. SVG only, no gradients.
Favicon = the dot on `#0B0F14`.

## Report layout (HTML + PR comment, same hierarchy)
```
┌──────────────────────────────────────────────┐
│ ● 45 / 100  surprise index        [PARTIAL]* │
│══════════════════════════════════════════════│
│ ▸ 3 bullets max (mono, verb-first):          │
│   • POSTed to telemetry.example during install
│   • wrote ~13 MB outside project dir         │
│   • spawned curl | sh (critical)             │
│ [view full evidence ▸]  [SARIF ▸]            │
│   <details>: every event, ts-ordered, zipped │
└──────────────────────────────────────────────┘
  * PARTIAL prints only when recording incomplete — impossible to miss
```
- No redundancy: no second summary, no row of badges, no emojis in findings, ever.
- Clean installs render too: `● 0/100 — nothing outside expected behavior` in pass green. Silence is
  a *designed* state and also evidence.

## README (star conversion is the point)
Order: 15s GIF → positioning sentence ("attestations verify who signed; InstallScope records what it
did") → ≤3-command quickstart → neighbor table → receipts section (3 teaser findings, screenshot-able)
→ backfill dataset link. GIF: dark bg, real PR, real comment post, real HTML open. No stock footage.

## Diff report (the moat made visible)
Two-column: v1.2.3 | v1.2.4, added behaviors highlighted diff-add, removed struck-through dim.
Header: "This package's behavior changed between installs." This screenshot is launch content.
