# STATUS — gh-aegis v0.3.1 release prep

Live status of the autonomous release-readiness run. See [PLAN.md](./PLAN.md) for the gap analysis.

**Target:** tag `v0.3.1`, publish-ready (maintainer runs `npm publish`).

## Progress

| Slice | State | Notes |
|-------|-------|-------|
| 1. Read state + PLAN/STATUS | ✅ done | Full read of README, package.json, src, tests, w6 branch, PR #1. |
| 2. Fix PII redaction bug | ⏳ in progress | 2 failing tests on `main` (phone pattern eats digits inside IBAN/API keys). |
| 3. Merge PR #1 + delete branch | ☐ todo | `--no-ff`, `Closes #1`. |
| 4. README rewrite | ☐ todo | reality + badges + OWASP map + security. |
| 5. Publish-ready + `npm pack` | ☐ todo | LICENSE, metadata, build, `.npmignore`, bump 0.3.1. |
| 6. CI + lint | ☐ todo | `ci.yml` + ESLint. |
| 7. Release workflow | ☐ todo | `release.yml` on `v*` via `NPM_TOKEN`. |
| 8. Tag v0.3.1 | ☐ todo | after all slices verified. |

## Baseline (main, before changes)

- `tsc --noEmit`: clean.
- `vitest run`: **59 passed / 2 failed** (61 total) — redaction interference bug.

## Decisions / log

- PR #1 (`w6/tests`) is the only open issue/PR — merging it satisfies both "merge tests"
  and "resolve open issue".
- Redaction bug is a **code** defect (fix `pii-output.ts`), not a test defect.

## Action required from maintainer

- Add repo secret **`NPM_TOKEN`** (npm automation token) before tagging triggers a publish.
- Run `npm publish` yourself (or push the `v0.3.1` tag once `NPM_TOKEN` is set) — not done by this run.
