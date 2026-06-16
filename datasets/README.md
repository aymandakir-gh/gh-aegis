# gh-aegis benchmark datasets

Labeled malicious + benign samples used by `npm run bench` to measure each detector's
precision / recall / F1. One file per OWASP category.

| File | Category | Detector(s) | Scope |
|---|---|---|---|
| `llm01-prompt-injection.json` | LLM01 | prompt-injection, jailbreak | input |
| `llm02-pii.json` | LLM02 | pii-output | output |
| `llm06-sensitive-disclosure.json` | LLM06 | sensitive-disclosure | output |
| `llm08-excessive-agency.json` | LLM08 | excessive-agency | output |
| `llm10-unbounded-consumption.json` | LLM10 | unbounded-consumption | input |

## Schema

Each file is a JSON array of samples:

```json
{ "id": "llm01-m01", "category": "LLM01", "scope": "input", "label": "malicious", "text": "..." }
```

- `label`: `malicious` (the detector should flag it) or `benign` (it should pass).
- `scope`: the scan scope used to evaluate the sample.

## Provenance & license

**All samples are original, hand-authored for this project and released into the public
domain under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).** No third-party
or scraped data is included, so there are no upstream license constraints.

Authoring principles (to keep the benchmark honest, not "taught to the test"):

- **Category purity** — each malicious sample exercises exactly one detector family and avoids
  triggers from other families (e.g. LLM06 samples contain no email-like strings the PII guard
  would claim first), so a hit is attributed to the intended category.
- **Realistic benign + FP traps** — the benign set is everyday traffic plus deliberate
  near-misses (text that *mentions* injection/secrets/dangerous commands but is legitimate:
  `rm -rf node_modules`, "explain how prompt injection works", "the system prompt should be
  concise", "chmod 644"). These measure false positives honestly.
- **Varied phrasings, including misses** — malicious samples include novel phrasings a regex
  guard may not catch, so recall is reported truthfully rather than inflated.
- **Deterministic** — LLM10 length/repetition samples are generated to exceed the detector's
  default limits; no randomness, no network.

The numbers this produces are baselines for a *deterministic, zero-ML* guard — strong on the
known attack shapes it encodes, with honestly-reported misses on novel phrasing.
