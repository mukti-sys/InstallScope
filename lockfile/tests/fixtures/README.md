# Lockfile fixtures

**Real output from real package managers. Not hand-written, and not to be hand-edited.**

Every file here was produced by running the actual tool on this machine and copying its output
verbatim. `Rules.md` §5 is the reason: a fixture someone typed from memory tests the parser against
that person's belief about the format, which is exactly the belief the parser already encodes. Three
things in these files would have been guessed wrong:

- npm `lockfileVersion: 1` records an alias as `"version": "npm:ms@2.1.3"` — the alias target lives in
  the *version* field, not in a `name` field as it does in v2/v3.
- npm records a `file:` dependency as **two** entries: `node_modules/thing` with `"link": true` and a
  separate `vendor/thing` entry carrying the version. Reading only the first yields a versionless
  package; reading only the second misses the install path.
- pnpm resolves a `github:` specifier to a **codeload tarball URL**, not to a git URL. pnpm 9.0 keys it
  `ms@https://codeload.github.com/...` and pnpm 5.4 keys it `github.com/vercel/ms/<sha>`, with the
  package name in a separate `name:` field. npm, for the same specifier, records `git+ssh://...`.

## How these were generated

| Fixture | Command |
|---|---|
| `npm/v1-*` | `npm install --package-lock-only --lockfile-version 1` |
| `npm/v2-*` | `npm install --package-lock-only --lockfile-version 2` |
| `npm/v3-*` | `npm install --package-lock-only` (npm 11.12.1 default) |
| `pnpm/v5-*` | `npx pnpm@7 install --lockfile-only` → `lockfileVersion: 5.4` |
| `pnpm/v6-*` | `npx pnpm@8 install --lockfile-only` → `lockfileVersion: '6.0'` |
| `pnpm/v9-*` | `npx pnpm@9 install --lockfile-only` → `lockfileVersion: '9.0'` |

Generated with npm 11.12.1 and Node 24.15.0 on 2026-09-01.

## What each fixture pins

| Fixture | The case it exists for |
|---|---|
| `npm/v1-nested-duplicate.json` | Same package at two versions — `ms` 2.1.3 at the root and 2.1.2 nested under `debug`. The reason identity is `(name, version)`. |
| `npm/v1-alias-git-groups.json` | v1 alias notation (`"version": "npm:ms@2.1.3"`), a git dependency with no `resolved`, plus `dev` and `optional` flags. |
| `npm/v2-dual-representation.json` | v2 carries both the v3 `packages` map and the v1 `dependencies` tree. Reading both would double-count every package. |
| `npm/v3-alias-scoped-nested.json` | Scoped names (`@babel/code-frame`), an alias with a `name` field, and a nested `supports-color` at a different version than the top-level one. |
| `npm/v3-workspace-groups.json` | A workspace link (`"link": true`) next to its `packages/local-a` entry, with dev and optional dependencies. |
| `npm/v3-git-tarball.json` | A git dependency resolved to `git+ssh://…#sha`, and a direct tarball URL that carries an integrity hash like a registry entry does. |
| `npm/v3-install-script.json` | `hasInstallScript: true` (esbuild), and platform-optional packages carrying `"optional": true` with `os`/`cpu` constraints. |
| `npm/v3-file-link.json` | The two-entry `file:` shape described above. |
| `pnpm/v*-basic.yaml` | The three key notations for the same tree: `/ms/2.1.2`, `/ms@2.1.2`, `ms@2.1.2`. |
| `pnpm/v*-alias-peer.yaml` | Aliases (`ms-alias`), scoped quoted keys, and peer-suffixed keys — `debug@4.3.4(supports-color@9.4.0)` in v6/v9, `debug/4.3.4_supports-color@9.4.0` in v5. |
| `pnpm/v*-git-file.yaml` | A `github:` specifier resolved to a codeload tarball, and a `file:` directory entry whose name lives in a `name:` field. |
| `pnpm/v*-groups.yaml` | `dev: true` / `dev: false` per package in v5 and v6; v9 moves `optional: true` into `snapshots` and drops per-package `dev` entirely. |
| `pnpm/v*-workspace.yaml` | The `importers` section, present in v9 always and in v5/v6 only for workspaces. |
| `pnpm/v9-git-only.yaml` | A git-only dependency in v9, where the package key *is* a URL containing `@` and `/`. Splitting the key naively produces nonsense. |

## The `dev` trap, stated because it is the one to get wrong

pnpm's `dev: false` on a package does not mean "not a dev dependency" in the sense a reader expects. It
means "reachable from a production dependency". A package reachable from **both** graphs is written
`dev: false`, so treating `dev: false` as "production-only" is right, but treating the *absence* of a
`dev` key as "production" is wrong — v9 has no per-package `dev` key at all and every package would be
misreported as production.

That is why the parser derives groups from the importer sections for v9, and why
`pnpm/v9-groups.yaml` exists next to `pnpm/v6-groups.yaml` with identical inputs.
