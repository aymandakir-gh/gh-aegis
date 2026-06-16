# PLAN — gh-aegis v0.4.0

Level up from a shipped utility (v0.3.1) to a best-in-class **deterministic, zero-ML** LLM-security
guard. No model downloads, no inference, no runtime network — speed + auditability is the whole
differentiator. Target tag: **v0.4.0**. Live state in STATUS.md.

## Starting point (v0.3.1)

- `scan(text, {scope})` routes by scope: `input` → injection→jailbreak (LLM01),
  `output` → PII+redaction (LLM02), `tool` → allowlist OOB (LLM08).
- Position-based PII redaction; fail-closed; `AEGIS_ENABLED` gate; ESM build; 80 tests; CI green.

## OWASP LLM Top 10 coverage (v0.4.0)

| OWASP | Detector | Scope(s) | ThreatType |
|---|---|---|---|
| **LLM01** Prompt Injection | `prompt-injection` + `jailbreak` (instruction-override, jailbreak, delimiter/role-escape) | input | `PROMPT_INJECTION`, `JAILBREAK` |
| **LLM02** Insecure Output / PII | `pii-output` (detect + redact) | output | `PII_OUTPUT` |
| **LLM06** Sensitive Disclosure | `sensitive-disclosure` (secrets, credentials, private keys, system-prompt leakage) | output | `SENSITIVE_DISCLOSURE` |
| **LLM08** Excessive Agency | `tool-call-oob` (allowlist) + `excessive-agency` (dangerous shell/SQL/URL/SSRF/code-exec) | tool, output | `TOOL_CALL_OOB`, `EXCESSIVE_AGENCY` |
| **LLM10** Unbounded Consumption | `unbounded-consumption` (length, char-run, token-repeat, "repeat forever") | input | `UNBOUNDED_CONSUMPTION` |

### Orchestrator routing (priority order, first finding wins)

- `input`  → unbounded-consumption (on **raw** pre-truncation input) → prompt-injection → jailbreak
- `output` → pii-output → sensitive-disclosure → excessive-agency (always returns `sanitized`)
- `tool`   → tool-call-oob → excessive-agency

`inspect(text)` runs **all** detectors and returns every finding + a merged redaction — used by the CLI.

## Deliverables / slices (each: detector/feature + tests + docs, verified by build+test+bench)

1. **Detectors** — 3 new (`sensitive-disclosure`, `excessive-agency`, `unbounded-consumption`),
   new `ThreatType`s, new `AegisOptions` (`maxLength`, `maxCharRun`, `maxTokenRepeat`),
   orchestrator wiring, `inspect()`. Unit tests per detector. Existing 80 tests stay green.
2. **Benchmark** (credibility centerpiece) — `datasets/` of labeled malicious+benign samples per
   category (self-authored, CC0; provenance in `datasets/README.md`). `npm run bench` (tsx) runs
   detectors → writes `bench/report.json` + markdown table → **exits non-zero** if any category
   drops below `bench/thresholds.json`. Honest baselines from the first real run.
3. **Adapters** — `gh-aegis/express`, `gh-aegis/fastify` middleware + `gh-aegis/ai` (Vercel AI SDK
   `LanguageModelV1Middleware`). Subpath exports; express/fastify/ai as **optional peers** (zero
   runtime deps shipped). Real integration tests (supertest; MockLanguageModelV1).
4. **CLI** — `npx gh-aegis scan <file|->`: reads file/stdin, human + `--json` output, **exits
   non-zero on findings**. `bin/gh-aegis.mjs` → `dist/cli.js`. Tested via `run(argv)`.
5. **Tune FP** — iterate detectors against the benchmark; report FP rate honestly; set CI thresholds
   conservatively below the measured baseline so real regressions fail.
6. **Docs + CI + package** — README: OWASP map, real benchmark table, 3-line integration snippets,
   CLI usage. CI adds `bench` + `build`. Bump `0.4.0`; `npm pack` audited (dist+bin only). Tag.

## Threshold strategy

Run bench first, read real per-category precision/recall/F1, then set `thresholds.json` a margin
below measured (e.g. measured 0.95 → gate 0.85–0.90). Never fake numbers; never set a gate above the
real baseline. CI `npm run bench` enforces the gates.

## Non-negotiables / decisions

- **Zero-ML, zero runtime deps, offline.** Adapters use `import type` only; frameworks are optional peers.
- Backward compatible: existing `scan()` semantics and all v0.3.1 tests unchanged.
- Dataset is self-authored under CC0 to guarantee permissive licensing and category purity
  (each malicious sample exercises exactly one detector family; benign set includes FP traps).
- **Do not publish to npm.** Tag only; publish is the maintainer's (via NPM_TOKEN).
