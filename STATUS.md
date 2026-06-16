# STATUS — gh-aegis v0.3.1 release prep

Live status of the autonomous release-readiness run. See [PLAN.md](./PLAN.md) for the gap analysis.

**Target:** tag `v0.3.1`, publish-ready (maintainer runs `npm publish`).

## Progress

| Slice | State | Notes |
|-------|-------|-------|
| 1. Read state + PLAN/STATUS | ✅ done | Full read of README, package.json, src, tests, w6 branch, PR #1. |
| 2. Fix PII redaction bug | ✅ done | Position-based redaction w/ overlap precedence; 2 main failures fixed. |
| 3. Merge PR #1 + delete branch | ✅ merged | `--no-ff`, `Closes #1`. Remote branch deletion pending push. |
| 4. README rewrite | ✅ done | reality + badges + OWASP map + redaction docs + security section. |
| 5. Publish-ready + `npm pack` | ✅ done | LICENSE, metadata, ESM build, `.npmignore`, bump 0.3.1; tarball verified. |
| 6. CI + lint | ✅ done | `ci.yml` (Node 20/22/24: typecheck·lint·test·build) + ESLint flat config. |
| 7. Release workflow | ✅ done | `release.yml` publishes on `v*` via `NPM_TOKEN` + provenance. |
| 8. Push + delete branch + tag v0.3.1 | ⏳ in progress | push main, delete remote w6, verify PR #1 merged, tag. |

## Verification (local, all green)

- `npm run lint` (eslint) — clean.
- `npm run typecheck` (tsc --noEmit) — clean.
- `npm test` (vitest) — **80/80 passed**.
- `npm run build` — emits `dist/` (ESM `.js` + `.d.ts` + sourcemaps).
- `node import('./dist/index.js')` — exports resolve, scan works under Node ESM.
- `npm pack --dry-run` — 31 files: `dist/` + `README.md` + `LICENSE` only (no src/tests/configs).

## Baseline (main, before changes)

- `vitest run`: 59 passed / 2 failed — redaction interference bug (now fixed).

## Decisions / log

- PR #1 (`w6/tests`) is the only open issue/PR — merging it satisfies both "merge tests"
  and "resolve open issue". Closed via the referencing merge commit.
- Redaction bug was a **code** defect (fixed in `pii-output.ts`), not a test defect.
- Two of the merged PR's routing tests built a *disabled* guard and never exercised routing —
  enabled them so they assert what they claim.
- `engines.node >= 18` is the consumer floor (dist is plain ESM); CI runs on 20/22/24
  because vitest 4 requires Node ≥ 20.
- Provenance is set only in the release workflow (`--provenance`), not `publishConfig`, so a
  manual local `npm publish` by the maintainer still works.

## Action required from maintainer

- Add repo secret **`NPM_TOKEN`** (npm automation token) — see `.github/workflows/release.yml`.
- Run `npm publish` yourself, or push the `v0.3.1` tag once `NPM_TOKEN` is set, to publish.
  This run does **not** publish or touch credentials.
