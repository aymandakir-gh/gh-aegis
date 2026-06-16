# STATUS — gh-aegis: v0.5.0 ✅ shipped, driving to v1.0.0

Extending the shipped v0.4.0 zero-ML OWASP-LLM guard to a 1.0 release. Plan + decisions in
[PRD.md](./PRD.md); architecture in [PLAN.md](./PLAN.md). Strictly **zero-ML, zero runtime deps,
deterministic, offline**; extend, never rebuild.

## Roadmap (tags v0.5.0 → v1.0.0)

| Tag | Scope | State |
|-----|-------|-------|
| **v0.5.0** | LLM05 + LLM07 + LLM04 detectors → **8 OWASP families**, orchestrator + inspect wiring, dataset re-label, re-baselined bench | ✅ shipped |
| v0.6.0 | Benchmark ≥400 samples (evasion tier), per-category metrics, CI gate proven both directions | ⏳ next |
| v0.7.0 | Declarative policy/config (load + validate + test; CLI + adapters honor) | ⏳ |
| v0.8.0 | Latency bench + CI perf gate (p95 < budget) | ⏳ |
| v0.9.0 | LangChain guard + streaming guard + local playground | ⏳ |
| v1.0.0 | Docs, multi-agent adversarial review + fixes + regression tests, ≥230 tests, pack audit | ⏳ |

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

## v0.5.0 benchmark baseline (`npm run bench`, 198 samples, FP rate 0.0%)

| OWASP | Precision | Recall | F1 |
|---|---|---|---|
| LLM01 Prompt Injection | 100.0% | 72.2% | 0.84 |
| LLM02 Insecure Output / PII | 100.0% | 80.0% | 0.89 |
| LLM04 Data & Model Poisoning | 100.0% | 100.0% | 1.00 |
| LLM05 Improper Output Handling | 100.0% | 93.8% | 0.97 |
| LLM06 Sensitive Disclosure | 100.0% | 81.8% | 0.90 |
| LLM07 System Prompt Leakage | 100.0% | 82.4% | 0.90 |
| LLM08 Excessive Agency | 100.0% | 82.4% | 0.90 |
| LLM10 Unbounded Consumption | 100.0% | 85.7% | 0.92 |
| **Overall** | **100.0%** | **83.9%** | **0.91** |

100% precision (0 false positives, incl. FP traps like `arr[0]`, "the javascript: protocol",
handlebars `{{ total }}`, a leading BOM, an emoji ZWJ). Recall is suppressed on purpose by the
evasion tier (paraphrase/leetspeak/multilingual/encoding) that deterministic regex cannot catch.

## Verification (local, all green)

- `typecheck` / `lint` clean · `vitest` **203 passed** · `bench` gate **exit 0** · `build` emits dist.
- `npm pack` @ 0.5.0: 76 files — dist (72) + bin + README + LICENSE + package.json; **no**
  datasets/scripts/tests/bench.
- CLI verified end-to-end for the new detectors (LLM05 XSS, LLM07 extraction).

## Decisions / log

- Stayed strictly zero-ML / deterministic; no runtime deps added.
- New detectors authored by principled generalization, not tuned against the benchmark.
- LLM04 dataset commits invisible code points as `\uXXXX` escapes (surrogate pairs for the Tags
  block) so the file is fully reviewable and copy/paste-safe.
- Detector tuning fixed one real LLM07 miss ("recite your system **message**" — added "system
  message" as a system-prompt synonym), not a benchmark-specific patch.

## Action required from maintainer

- Add repo secret **`NPM_TOKEN`** to publish; the release workflow skips publish cleanly until set.
- This run does not publish — tags only.
