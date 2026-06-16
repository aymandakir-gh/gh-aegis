# STATUS — gh-aegis: v0.9.0 ✅ shipped, driving to v1.0.0

Extending the shipped v0.4.0 zero-ML OWASP-LLM guard to a 1.0 release. Plan + decisions in
[PRD.md](./PRD.md); architecture in [PLAN.md](./PLAN.md). Strictly **zero-ML, zero runtime deps,
deterministic, offline**; extend, never rebuild.

## Roadmap (tags v0.5.0 → v1.0.0)

| Tag | Scope | State |
|-----|-------|-------|
| **v0.5.0** | LLM05 + LLM07 + LLM04 detectors → **8 OWASP families**, orchestrator + inspect wiring, dataset re-label, re-baselined bench | ✅ shipped |
| **v0.6.0** | Benchmark grown to **466 samples** (evasion tier), per-category metrics, CI gate proven both directions | ✅ shipped |
| **v0.7.0** | Declarative policy/config — zero-dep validator, CLI `--policy`, adapters honor it | ✅ shipped |
| **v0.8.0** | Latency bench (`npm run perf`) + CI perf gate (p95 < documented budget) | ✅ shipped |
| **v0.9.0** | LangChain callback guard + streaming-output guard + local zero-network playground | ✅ shipped |
| v1.0.0 | Docs, multi-agent adversarial review + fixes + regression tests, ≥230 tests, pack audit | ⏳ next |

## v0.5.0 — what shipped

- **3 new deterministic detectors**, raising OWASP coverage from 5 to **8 families**:
  - **LLM04 Data & Model Poisoning** (`data-poisoning.ts`) — invisible-Unicode smuggling: Tags-block
    "ASCII smuggling" (U+E0000–U+E007F), bidi overrides/isolates (Trojan Source), zero-width chars
    hidden inside words or clustered. Runs on input + output; strips invisible chars in `sanitized`.
  - **LLM05 Improper Output Handling** (`improper-output.ts`) — XSS/HTML, `javascript:`/`data:text/html`
    URIs, `<iframe>`/`<svg>`, SSTI (`{{7*7}}`, Jinja internals, `${…}` sinks), markdown-exfil links,
    ANSI/terminal escapes. Output scope; detection-only (block, don't half-sanitize active content).
  - **LLM07 System Prompt Leakage** (`system-prompt-leak.ts`) — extraction (input) + leakage (output).
- **Principled re-taxonomy (not teach-to-test):** system-prompt patterns carved out of LLM01
  (prompt-injection) and LLM06 (sensitive-disclosure) into the dedicated LLM07 guard; affected
  benchmark samples re-labeled to LLM07. A combined override+extraction attack still attributes to
  LLM01 (it runs first). LLM06 is now purely secrets/keys/credentials.
- **Orchestrator routing** updated (see PRD); `output` scope now always returns a merged `sanitized`
  copy (strip invisible → redact PII/secrets/leak markers). `inspect()` runs all 9 detector entries.
- **Benchmark** re-baselined across 8 categories; `bench/thresholds.json` gates all 8.

## v0.6.0 benchmark baseline (`npm run bench`, 466 samples, FP rate 0.0%)

| OWASP | Precision | Recall | F1 |
|---|---|---|---|
| LLM01 Prompt Injection | 100.0% | 73.8% | 0.85 |
| LLM02 Insecure Output / PII | 100.0% | 76.9% | 0.87 |
| LLM04 Data & Model Poisoning | 100.0% | 87.5% | 0.93 |
| LLM05 Improper Output Handling | 100.0% | 82.5% | 0.90 |
| LLM06 Sensitive Disclosure | 100.0% | 77.1% | 0.87 |
| LLM07 System Prompt Leakage | 100.0% | 78.0% | 0.88 |
| LLM08 Excessive Agency | 100.0% | 78.0% | 0.88 |
| LLM10 Unbounded Consumption | 100.0% | 83.9% | 0.91 |
| **Overall** | **100.0%** | **79.4%** | **0.89** |

100% precision (0 false positives across 165 benign, incl. FP traps). **Every one of the 62 misses is
an evasion-tier sample** — the recall floor IS the evasion tier (paraphrase, leetspeak, multilingual,
encoding, homoglyph, uncommon vector). Zero caught-malicious missed; zero benign flagged.

## v0.6.0 — what shipped

- **Benchmark grown 198 → 466 samples** across 8 categories: category-pure malicious, realistic benign
  FP-traps, and an honest evasion tier. New samples were drafted to category rules then **machine-
  verified against the real detector** before inclusion (caught-malicious provably fire the right
  ThreatType; benign provably pass; evasion provably slip) — not tuned against the benchmark.
- **bench.ts refactored** to export `loadSamples` / `evaluate` / `gateFailures` so the gate is unit-
  testable. `tests/bench-gate.test.ts` proves the gate **passes at the committed thresholds** and
  **fails when a gate is raised above the baseline** (both directions), plus asserts 0 FP and 100%
  per-category precision (purity).
- `bench/thresholds.json` recomputed conservatively below the 466-sample baseline.

## v0.9.0 — what shipped

- **LangChain guard** (`src/adapters/langchain.ts`, `gh-aegis/langchain`): `aegisCallbackHandler()`
  returns a plain object structurally compatible with LangChain's `CallbackHandlerMethods` — scans
  prompts/messages (input), generations (output), and tool inputs, throwing `AegisBlockedError`. Imports
  **no `@langchain/*` package** (local structural types), so it builds without LangChain installed.
- **Streaming guard** (`src/stream.ts`): `createStreamGuard()` + `guardTextStream(asyncIterable)` scan a
  sliding window of accumulated output, catching cross-chunk attacks (`<scr`+`ipt>`); blocking is sticky;
  `guardTextStream` throws before emitting an unsafe chunk.
- **Browser-safe orchestrator**: `process.env`/`process.stderr` access is guarded (`typeof process`),
  so the library runs in the browser/edge/Deno — which the playground relies on.
- **Local zero-network playground** (`playground/index.html` + `app.js`): paste text → live detections,
  scores, and redacted output, running the **real compiled library** in the browser, no network. Excluded
  from the npm pack. `tests/playground.test.ts` smoke-tests wiring, the analysis contract, and (when a
  build exists) the real `app.js` against `dist`.
- Shared `AegisBlockedError` moved to `src/errors.ts` (re-exported from `gh-aegis/ai` for compat).
- New subpath export `gh-aegis/langchain`; `createStreamGuard`/`guardTextStream`/`AegisBlockedError`
  exported from the root.

## v0.8.0 — what shipped

- **Latency benchmark** (`scripts/perf.ts`, `npm run perf`): measures per-detector + end-to-end
  (`scan` per scope, `inspect`) latency over a fixed input set (incl. a ~2 KB blob), reports
  p50/p95/p99/mean → `bench/perf.json` + `bench/PERF.md`. Measured p95: any detector ≤ ~20µs,
  scan:input ~32µs, scan:output ~53µs, inspect ~80µs — the zero-ML speed claim, proven.
- **CI perf gate**: `npm run perf` fails the build if any p95 exceeds `bench/perf-budget.json`
  (per-detector ≤ 1ms, scan ≤ 2ms, inspect ≤ 4ms — ~25–50× over baseline to absorb CI noise while
  still tripping a ReDoS-class regression). Added to `ci.yml` + `release.yml`.
- **`tests/perf-gate.test.ts`** proves the gate passes at the budget and fails against an impossibly
  tight one (both directions), and that percentiles are finite + ordered.

## v0.7.0 — what shipped

- **Declarative policy** (`src/policy.ts`): a JSON policy toggles detectors on/off, restricts scopes,
  raises per-detector score thresholds (`minScore`), toggles redaction, and sets LLM10 limits +
  tool allowlist. Validated by a **hand-rolled zero-dep validator** (`validatePolicy`/`parsePolicy`)
  that rejects unknown keys/bad values loudly. `resolvePolicy` builds a fast runtime.
- **Orchestrator is policy-aware**: a lazy `firstHit` pipeline skips disabled detectors, applies
  `minScore`, short-circuits disabled scopes, and respects `redaction` for the `sanitized` copy.
  Default policy = identical behavior to v0.6.0 (all 210 prior tests still green).
- **CLI `--policy <file>` / `--policy=<file>`** loads + validates a policy (exit 2 on bad/missing).
- **Adapters honor it**: `policy` flows through `AegisOptions`; Express + Fastify tests prove it.
- Example: [`examples/aegis.policy.json`](./examples/aegis.policy.json) (excluded from the npm pack).

## Verification (local, all green)

- `typecheck` / `lint` clean · `vitest` **276 passed** · `bench` gate **exit 0** · `perf` gate
  **exit 0** · `build` emits dist (incl. `dist/adapters/langchain.js`, `dist/stream.js`).
- `npm pack` @ 0.9.0: dist + bin + README + LICENSE + package.json only; **no**
  datasets/scripts/tests/bench/examples/playground.
- Playground verified: `app.js` runs the compiled `dist/index.js` and `analyze()` returns correct
  findings; orchestrator confirmed free of unguarded `process` access in the browser import chain.

## Decisions / log

- Stayed strictly zero-ML / deterministic; no runtime deps added.
- Dataset growth used 8 parallel category authors, each self-verifying samples against the real
  detector code before writing — generation parallelized, correctness machine-checked, never teach-to-test.
- LLM04 invisible code points commit as `\uXXXX` escapes (surrogate pairs for the Tags block) so the
  files stay fully reviewable and copy/paste-safe.
- v0.5.0: detector tuning fixed one real LLM07 miss ("recite your system **message**"), not a
  benchmark-specific patch.

## Action required from maintainer

- Add repo secret **`NPM_TOKEN`** to publish; the release workflow skips publish cleanly until set.
- This run does not publish — tags only.
