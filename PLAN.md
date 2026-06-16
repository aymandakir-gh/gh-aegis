# PLAN — ship gh-aegis v0.3.1

Gap analysis (current `main` vs. goal) and the slice-by-slice plan to close it.
Target tag: **v0.3.1**. Owner: autonomous run. Last updated as work proceeds — see STATUS.md for live state.

## Where the code actually is

- `src/` implements **v0.3**: 4 guards (prompt-injection LLM01, jailbreak LLM01,
  PII-output LLM02 with `sanitized` redaction, tool-call-OOB LLM08), an orchestrator
  (`createAegisGuard`), fail-closed error contract, `AEGIS_ENABLED` env activation.
- `package.json` is `0.3.0` but has **no build/publish metadata** (no `main`/`types`/
  `exports`/`files`, `build` is just `tsc --noEmit`).
- 4 test files in `tests/` (61 tests). **2 fail on `main`** — a real redaction bug.
- Branch `origin/w6/tests-20260610-1903` (PR #1) adds `src/guards/pii-output.test.ts`
  (19 tests). PR #1 is the only open issue/PR.

## Gaps vs. goal

| # | Gap | Action |
|---|-----|--------|
| 1 | README claims v0.1 / private / not-on-npm; imports from `./src`; lists shipped v0.2/v0.3 as future | Rewrite README to reality + badges + security section |
| 2 | PR #1 / `w6/tests` branch unmerged | Merge (`--no-ff`, `Closes #1`), delete branch |
| 3 | Open issue (PR #1) unresolved | Closed by the referencing merge commit |
| 4 | **2 failing tests** — PII redaction interference bug | Fix `pii-output.ts` (overlap-resolving redaction) |
| 5 | Not publish-ready | name/version, `main`/`types`/`exports`, `files`, real build, `prepublishOnly`, `.npmignore`, MIT LICENSE; verify with `npm pack` |
| 6 | ESM output not Node-runnable (extensionless relative imports) | Add `.js` extensions in `src`; `tsconfig.build.json` emits `dist/` |
| 7 | No CI | `.github/workflows/ci.yml`: install → typecheck → lint → test |
| 8 | No release automation | `.github/workflows/release.yml`: `npm publish` on `v*` tag via `NPM_TOKEN` |
| 9 | No linter (CI needs a lint step) | Add ESLint flat config + `lint` script |

## Slices (each verified: build + test + `npm pack` where relevant)

1. **Read state → PLAN.md / STATUS.md** ✅
2. **Fix redaction bug** — `pii-output.ts`; full suite green.
3. **Merge PR #1** (`--no-ff`, `Closes #1`); delete `w6/tests` branch; suite green.
4. **README rewrite** — features, OWASP map, install, usage, redaction docs, examples, badges, security.
5. **Publish-ready** — LICENSE (MIT), package.json metadata, `.js` import extensions,
   `tsconfig.build.json`, `.npmignore`, bump → `0.3.1`; `npm run build` + `npm pack` inspected.
6. **CI + lint** — ESLint config + `ci.yml` (install/typecheck/lint/test).
7. **Release workflow** — `release.yml` publishing on tag via `NPM_TOKEN` (documented; secret added by maintainer).
8. **Tag v0.3.1** — after every slice verified. `npm publish` left for the maintainer.

## Non-goals / decisions

- **Do not publish.** `npm publish` is the maintainer's to run; CI only publishes on a tag once `NPM_TOKEN` exists.
- Keep package name `gh-aegis` (matches repo + README).
- Keep the zero-ML TypeScript stack; no runtime deps added.
- The redaction fix changes `pii-output.ts` (the code), not the tests — under-redacting a
  secret is the exact LLM02 failure this guard exists to prevent.
