# gh-aegis

[![npm version](https://img.shields.io/npm/v/gh-aegis.svg)](https://www.npmjs.com/package/gh-aegis)
[![CI](https://github.com/aymandakir-gh/gh-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/aymandakir-gh/gh-aegis/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)
[![types](https://img.shields.io/badge/types-TypeScript-blue.svg)](#)

**Defensive AI security middleware for the OWASP LLM Top 10 — zero-ML, just regex + a rule engine.**

`gh-aegis` is a tiny, dependency-free guard you wrap around your LLM calls. It checks
**user input** before the model sees it, **model output** before your user sees it, and
**tool calls** before your agent runs them. No model, no network, no telemetry — deterministic
pattern matching that returns a verdict in microseconds and **never throws**.

```ts
import { createAegisGuard } from "gh-aegis";

const aegis = createAegisGuard({ enabled: true });
const result = await aegis.scan(userMessage, { scope: "input" });
if (!result.safe) throw new Error(`Blocked: ${result.threatType}`);
```

---

## Install

```bash
npm install gh-aegis
```

Requires Node ≥ 18. Ships as ESM with TypeScript types. Zero runtime dependencies.

## What it catches

| OWASP | Threat | `ThreatType` | Examples it blocks |
|---|---|---|---|
| **LLM01** | Prompt injection | `PROMPT_INJECTION` | "ignore previous instructions", "reveal your system prompt", `<system>` tag injection, "override your safety rules" |
| **LLM01** (variant) | Jailbreak / role-escape | `JAILBREAK` | DAN variants, `[JAILBREAK]`/`[SUDO]` tags, "developer mode enabled", "bypass your content policy", "act with no restrictions" |
| **LLM02** | Insecure output / PII leak | `PII_OUTPUT` | email, phone, IBAN, OpenAI/Stripe keys, GitHub tokens, Anthropic keys, Italian codice fiscale, `Bearer` tokens — **detected _and_ redacted** |
| **LLM08** | Excessive agency / tool OOB | `TOOL_CALL_OOB` | any tool name not in the session allowlist; an empty allowlist blocks everything (fail-closed) |

Each scan returns a `score` (0–100). Input/jailbreak guards block at **≥ 80**, the PII guard at
**≥ 75**, and an out-of-bounds tool call is always **100**.

## Quick start

`scan(input, context)` routes to the right guard based on `context.scope`:

```ts
import { createAegisGuard, ThreatType } from "gh-aegis";

const aegis = createAegisGuard({ enabled: true });

// 1. Pre-LLM — check user input (prompt injection + jailbreak)
const input = await aegis.scan(userMessage, { scope: "input" });
if (!input.safe) {
  // input.threatType is PROMPT_INJECTION or JAILBREAK
  return reject(input.threatType);
}

// 2. Post-LLM — check model output for PII, surface the redacted copy
const output = await aegis.scan(llmResponse, { scope: "output" });
const safeToShow = output.safe ? llmResponse : output.sanitized;

// 3. Tool call — check against the session allowlist
const tool = await aegis.scan(requestedTool, {
  scope: "tool",
  allowedTools: ["kb_search", "github_get_file"],
});
if (!tool.safe) throw new Error("Tool call out of bounds");
```

### Scopes

| `scope` | Guards run | Use it |
|---|---|---|
| `"input"` *(default)* | prompt injection → jailbreak | the user's message, before the model |
| `"output"` | PII detection + redaction | the model's response, before the user |
| `"tool"` | allowlist (OOB) check | a tool/function name your agent wants to call |

## PII redaction

For `scope: "output"`, every result carries a **`sanitized`** string with each PII match
replaced by `[REDACTED:<label>]`. Surface `sanitized` to users; keep the raw output internal.

```ts
const r = await aegis.scan(
  "Email alice@example.com or call (555) 987-6543.",
  { scope: "output" },
);

r.safe;       // false
r.threatType; // "PII_OUTPUT"
r.sanitized;  // "Email [REDACTED:email-address] or call [REDACTED:phone-number]."
```

- **Clean output** → `safe: true` and `sanitized` equals the input unchanged.
- **`input`/`tool` scopes** → `sanitized` is absent (the PII guard doesn't run).
- Redaction is **position-based with overlap resolution**: when patterns overlap (e.g. a phone
  pattern matching digits *inside* an API key), the higher-value pattern wins, so a secret is
  never left partially redacted.

| Label | Detects |
|---|---|
| `email-address` | email addresses |
| `phone-number` | US/international phone numbers |
| `iban` | IBAN bank account numbers |
| `openai-stripe-api-key` | `sk-…`, `sk_live_…`, `rk_live_…` keys |
| `github-token` | `ghp_/gho_/ghu_/ghs_/ghr_` tokens |
| `anthropic-api-key` | `sk-ant-…` keys |
| `codice-fiscale` | Italian tax codes |
| `bearer-token` | `Bearer <token>` (JWT-like, ≥ 32 chars) |

## `ScanResult`

```ts
interface ScanResult {
  safe: boolean;            // true = proceed; false = block
  threatType?: ThreatType;  // set only when safe === false
  score: number;            // 0–100, always present
  details?: string[];       // internal log lines — never echo to end users
  sanitized?: string;       // scope:"output" only — PII-redacted copy of the input
}
```

## Configuration

`createAegisGuard(options?)` — options fall back to environment variables, then to defaults.

| Option | Env var | Default | Purpose |
|---|---|---|---|
| `enabled` | `AEGIS_ENABLED` | `false` | Master switch. Must be `true` (or env `"true"`) to scan; otherwise everything passes through. |
| `verbose` | `AEGIS_VERBOSE` | `false` | Log blocks to stderr. |
| `maxInputLength` | `AEGIS_MAX_INPUT` | `8192` | Input is truncated to this length before scanning. |
| `allowedTools` | `ALLOWED_TOOLS` | `[]` | Default tool allowlist (env is comma-separated); `context.allowedTools` overrides it. |

> **Disabled by default.** A guard with no `enabled` flag and no `AEGIS_ENABLED=true` is a no-op
> that returns `{ safe: true, score: 0 }`. Enable it explicitly in the environments where you
> want enforcement.

## Error contract — fail closed

`scan()` **never throws.** Any internal error returns `{ safe: false, score: 100 }`, so a bug in
the guard blocks the request rather than silently letting it through. Out-of-bounds tool calls
and an empty tool allowlist also fail closed.

## Security & design notes

Built for teams who want a deterministic, auditable first line of defense in front of an LLM:

- **Zero-ML, zero-dependency, offline.** No model weights, no API calls, no data leaves the
  process. Predictable latency and nothing to exfiltrate.
- **Deterministic & testable.** Every rule is a regex with a fixed score; behavior is fully
  covered by the test suite (80 tests across input, output, tool, env, and redaction paths).
- **Fail-closed everywhere.** Errors, unknown tools, and empty allowlists all block.
- **Defense in depth, not a silver bullet.** Pattern matching catches known attack shapes; it is
  not a substitute for least-privilege tool design, output encoding, or human review. Layer it
  with those — see the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/).
- **`details` is internal.** It can describe which rule fired; never echo it to end users
  (information-leakage risk).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm test            # vitest run (80 tests)
npm run build       # emit dist/ (ESM + .d.ts)
npm pack --dry-run  # inspect the publish tarball
```

## Releasing

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which builds, tests, and runs
`npm publish`. The repo must have an **`NPM_TOKEN`** secret (an npm automation token) configured
under *Settings → Secrets and variables → Actions*. See the workflow for details.

## License

[MIT](./LICENSE) © GrowthHackers
