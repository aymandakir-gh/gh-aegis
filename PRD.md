# PRD — gh-aegis v0.5.0 → v1.0.0

Extend the shipped v0.4.0 deterministic, zero-ML OWASP-LLM guard to a 1.0 release. **Extend, do not
rebuild.** Strictly **zero-ML, zero runtime deps, deterministic, offline.** Backward compatible:
`scan()` / `inspect()` semantics and every v0.4.0 test stay green. Live state in [STATUS.md](./STATUS.md);
architecture context in [PLAN.md](./PLAN.md).

## v1.0.0 acceptance (all must hold, CI green at every tag)

1. **≥8 OWASP LLM Top-10 families** with deterministic detectors (was 5: LLM01/02/06/08/10). Add
   **LLM05** (Improper Output Handling), **LLM07** (System Prompt Leakage), **LLM04** (Data & Model
   Poisoning). Each: tests + documented OWASP mapping.
2. **Benchmark ≥400 labeled samples** (CC0, provenance documented): category-pure malicious, realistic
   benign FP-traps, honest evasion tier. Per-category P/R/F1 + FP rate → `bench/report.json` + README.
   CI gates on thresholds and **fails on a breach (proven both directions)**. Real first-run numbers,
   never hand-set; recall floor documented honestly.
3. **Declarative policy/config file** (detectors on/off, scopes, thresholds, redaction on/off) —
   loaded + validated (zero-dep validator) + tested; CLI and adapters honor it.
4. **Latency benchmark** (p50/p95 per detector + full `inspect`) committed; **CI perf gate** asserts
   p95 < a documented budget.
5. **Two more integration surfaces**: LangChain-compatible callback/guard + a generic streaming-output
   guard, each tested.
6. **Local zero-network playground** (static page) — paste text, see live detections + scores;
   smoke-tested. Excluded from the npm package.
7. **≥230 passing tests**, no padding; `npm pack` audited (dist + bin only).
8. **README** with real benchmark + latency numbers, OWASP map, policy + integration snippets,
   playground. Released through tags **v0.5.0 → v1.0.0**. Publish-ready, **do NOT publish** (maintainer
   holds NPM_TOKEN). Before v1.0.0: multi-agent adversarial review → fix every real finding → regression
   tests.

## OWASP LLM Top-10 coverage (target: 8 families)

Existing IDs are kept exactly as shipped in v0.4.0 (no breaking re-numbering). New detectors follow the
OWASP 2025 names the goal specifies.

| OWASP | Detector | Scope(s) | ThreatType | Status |
|---|---|---|---|---|
| **LLM01** Prompt Injection | `prompt-injection` + `jailbreak` | input | `PROMPT_INJECTION`, `JAILBREAK` | shipped |
| **LLM02** Insecure Output / PII | `pii-output` (detect + redact) | output | `PII_OUTPUT` | shipped |
| **LLM04** Data & Model Poisoning | `data-poisoning` (invisible-unicode / bidi / ASCII-smuggling) | input, output | `DATA_POISONING` | **new** |
| **LLM05** Improper Output Handling | `improper-output` (XSS/HTML, `javascript:`/`data:`, SSTI, markdown-exfil, ANSI) | output | `IMPROPER_OUTPUT` | **new** |
| **LLM06** Sensitive Disclosure | `sensitive-disclosure` (secrets/keys/credentials) | output | `SENSITIVE_DISCLOSURE` | shipped |
| **LLM07** System Prompt Leakage | `system-prompt-leak` (extraction + leakage) | input, output | `SYSTEM_PROMPT_LEAK` | **new** |
| **LLM08** Excessive Agency | `tool-call-oob` + `excessive-agency` | tool, output | `TOOL_CALL_OOB`, `EXCESSIVE_AGENCY` | shipped |
| **LLM10** Unbounded Consumption | `unbounded-consumption` | input | `UNBOUNDED_CONSUMPTION` | shipped |

### Clean carving decision (principled re-taxonomy, not teach-to-test)

System-prompt **extraction** (input) and **leakage** (output) are OWASP **LLM07** in 2025 — they do not
belong in LLM01 (prompt injection) or LLM06 (sensitive disclosure). Therefore:

- Move `reveal-system-prompt` / `print-system-prompt` out of `prompt-injection` (LLM01) into LLM07
  extraction. A combined "ignore previous instructions **and** reveal your prompt" still matches LLM01's
  override pattern (which runs first) → stays LLM01. A pure "print your system prompt" → LLM07.
- Move `system-prompt-leak` / `system-persona-echo` out of `sensitive-disclosure` (LLM06) into LLM07
  leakage. LLM06 becomes purely secrets/keys/credentials — more category-pure.
- Re-label the affected benchmark samples to LLM07 (correct taxonomy). Numbers re-baseline on the first
  real run.

### Orchestrator routing (priority order, first finding wins)

- `input`  → unbounded(LLM10, raw) → prompt-injection(LLM01) → jailbreak(LLM01) → system-prompt-extract(LLM07) → poisoning(LLM04)
- `output` → pii(LLM02) → system-prompt-leak(LLM07) → sensitive-disclosure(LLM06) → improper-output(LLM05) → excessive-agency(LLM08) → poisoning(LLM04)
- `tool`   → tool-call-oob(LLM08) → excessive-agency(LLM08)

`output` scope always returns a `sanitized` copy (merged redaction of every redactable match).
`inspect(text)` runs **all** detectors and returns every finding + a merged redaction (used by the CLI).

## New detector specs (deterministic, principled — never tuned against the benchmark)

- **LLM04 data-poisoning** — obfuscation/smuggling channels used to hide poisoned/injected payloads:
  any Unicode **Tags** block char (U+E0000–U+E007F, "ASCII smuggling"); any **bidi override/isolate**
  control (U+202A–U+202E, U+2066–U+2069 — Trojan Source); **zero-width** chars (U+200B–U+200D, U+FEFF,
  U+2060) clustered or word-internal above a small threshold. Detection only (no redaction of invisible
  chars beyond stripping in sanitized). Scopes: input + output.
- **LLM05 improper-output** — model output that, passed unsanitized to a downstream interpreter, injects:
  `<script>`/event-handler XSS, `javascript:`/`vbscript:`/`data:text/html` URIs, `<iframe>`/`<object>`,
  SSTI markers (`${…}`, `{{…}}`, `<%…%>`, `#{…}`) with payload, markdown image/link exfiltration to an
  external URL with interpolated data, and ANSI/terminal escape sequences. Disjoint from LLM08 (shell/SQL/
  SSRF *actions*) and LLM06 (secrets). Redactable.
- **LLM07 system-prompt-leak** — extraction (input): "reveal / print / show / output / repeat your
  system prompt / instructions / initial directives"; leakage (output): "my system prompt is…",
  "here are my instructions: I was instructed to…", verbatim persona echo. Redactable.

## Slices → tags

- **v0.5.0** — LLM05 + LLM07 + LLM04 detectors (8 families), orchestrator + inspect wiring, types,
  unit tests, dataset re-label, re-baselined bench, README OWASP map.
- **v0.6.0** — benchmark ≥400 samples (evasion tier), per-category metrics, CI gate proven both ways.
- **v0.7.0** — declarative policy/config (load + validate + test; CLI + adapters honor).
- **v0.8.0** — latency bench + CI perf gate (p95 < budget).
- **v0.9.0** — LangChain guard + streaming guard + local playground (smoke-tested).
- **v1.0.0** — docs, multi-agent adversarial review + fixes + regression tests, ≥230 tests, pack audit, tag.

## Non-negotiables

- Zero-ML, zero runtime deps, offline. Adapters/integrations use `import type` only; frameworks are
  optional peers. Validators and the playground are hand-rolled (no deps).
- Every feature ships with a test asserting **real behavior**. Verify each slice by building + running
  tests + bench (+ perf gate) before moving on. Never claim done without running it.
- Detector tuning is **principled generalization**, never teach-to-test against the benchmark.
- Conventional commits, push to `main`, keep STATUS.md current. Do **not** publish to npm.
