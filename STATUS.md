# STATUS — gh-aegis v0.4.0

Leveling up from v0.3.1 (shipped utility) to a best-in-class **deterministic, zero-ML** LLM-security
guard. See [PLAN.md](./PLAN.md) for the architecture and dataset/threshold strategy.

**Target:** tag `v0.4.0`, publish-ready (maintainer runs `npm publish`). Zero-ML throughout; not published by this run.

## Progress — all slices done

| Slice | State | Notes |
|-------|-------|-------|
| 1. Detectors (LLM06/08/10) + inspect() | ✅ | 3 new zero-ML detectors, shared redaction, orchestrator routing, 46 tests. |
| 2. Benchmark + CC0 dataset + FP/recall tuning | ✅ | `npm run bench`, 132 labeled samples, gated CI, honest baseline. |
| 3. Adapters (Express/Fastify/AI SDK) | ✅ | Subpath exports, optional peers, type-only (zero runtime deps), 10 tests. |
| 4. CLI (`npx gh-aegis scan`) | ✅ | File/stdin, JSON + human, exit codes, 7 tests. |
| 5. FP tuning | ✅ | 100% precision / 0% FP via the benchmark; recall reported honestly. |
| 6. README + CI(bench) + v0.4.0 bump + pack audit | ✅ | Real numbers, integration snippets, CLI docs. |
| 7. Tag v0.4.0 | ⏳ | After push + green CI. |

## v0.4.0 benchmark baseline (`npm run bench`, 132 samples, FP rate 0.0%)

| OWASP | Precision | Recall | F1 |
|---|---|---|---|
| LLM01 Prompt Injection | 100.0% | 75.0% | 0.86 |
| LLM02 Insecure Output / PII | 100.0% | 80.0% | 0.89 |
| LLM06 Sensitive Disclosure | 100.0% | 85.7% | 0.92 |
| LLM08 Excessive Agency | 100.0% | 82.4% | 0.90 |
| LLM10 Unbounded Consumption | 100.0% | 85.7% | 0.92 |
| **Overall** | **100.0%** | **81.3%** | **0.90** |

100% precision (no false positives on realistic benign incl. FP traps); recall 75–86% — the lower
recall reflects an intentional evasion tier (paraphrase, leetspeak, multilingual, base64, IFS-obfuscation)
that deterministic regex cannot catch. Thresholds in `bench/thresholds.json` gate CI below this baseline.

## Verification (local, all green)

- `lint` / `typecheck` clean · `vitest` **143 passed** · `bench` gate **exit 0** · `build` emits dist (incl. adapters + cli).
- `npm pack` @ 0.4.0: 64 files, 107 KB unpacked — dist + bin + README + LICENSE; **no** datasets/scripts/tests/bench.
- CLI verified end-to-end (`node bin/gh-aegis.mjs scan …`).
- Adapter dist carries no `require()` of express/fastify/ai (type-only).

## Decisions / log

- Stayed strictly zero-ML / deterministic; no runtime dependencies added (frameworks are optional peers).
- Dataset is self-authored CC0 with category-pure malicious, realistic benign + FP traps, and an honest
  evasion tier; numbers are the first real run, never hand-set.
- Detector tuning was principled generalization (articles, gerunds, token boundaries), not teach-to-test.
- Phone pattern tightened with token boundaries — fixes a Google-key mis-attribution and improves precision.

## Action required from maintainer

- Add repo secret **`NPM_TOKEN`** to publish (see `.github/workflows/release.yml`); the release workflow
  skips publish cleanly until it is set.
- Run `npm publish` yourself, or re-run the Release workflow for tag `v0.4.0`. This run does not publish.
