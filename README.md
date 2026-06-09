# gh-aegis

Defensive AI security middleware. Zero-ML: regex + rule engine.

Covers OWASP LLM Top 10: LLM01 (Prompt Injection), LLM01-variant (Jailbreak), LLM02 (Insecure Output / PII), LLM08 (Excessive Agency / Tool OOB).

**Status:** v0.1 — private internal tool (GrowthHackers). Not yet on npm.

---

## Quick start

```typescript
import { createAegisGuard, ThreatType } from "./src/index";

const aegis = createAegisGuard({ enabled: true });

// Pre-LLM — check user input
const inputResult = await aegis.scan(userMessage, { scope: "input" });
if (!inputResult.safe) {
  throw new Error(`Blocked: ${inputResult.threatType}`);
}

// Post-LLM — check model output for PII
const outputResult = await aegis.scan(llmResponse, { scope: "output" });
if (!outputResult.safe) {
  // redact / block response
}

// Tool call — check against session allowlist
const toolResult = await aegis.scan(toolName, {
  scope: "tool",
  allowedTools: ["kb_search", "github_get_file"],
});
```

## Threat types

| ThreatType | OWASP | Trigger |
|---|---|---|
| `PROMPT_INJECTION` | LLM01 | "ignore previous instructions", "reveal system prompt", XML injection |
| `JAILBREAK` | LLM01 | DAN variants, "[JAILBREAK]", "developer mode enabled", bypass attempts |
| `PII_OUTPUT` | LLM02 | email, phone, IBAN, OpenAI/GitHub/Anthropic API keys, codice fiscale |
| `TOOL_CALL_OOB` | LLM08 | tool name not in `allowedTools` list; empty list blocks all |

## ScanResult

```typescript
interface ScanResult {
  safe: boolean;        // true = proceed; false = block
  threatType?: ThreatType;  // set when safe=false
  score: number;        // 0–100; ≥80 = blocked
  details?: string[];   // internal log lines (never echo to user)
}
```

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `AEGIS_ENABLED` | `false` | Master switch — must be `"true"` to activate |
| `AEGIS_VERBOSE` | `false` | Log blocks to stderr |
| `AEGIS_MAX_INPUT` | `8192` | Max chars before truncation |
| `ALLOWED_TOOLS` | `""` | Comma-separated default tool allowlist |

## Error contract

`scan()` **never throws**. Internal errors return `{ safe: false, score: 100 }` (fail-closed).

## Dev

```bash
npm install
npm test          # vitest run (17 tests)
npm run typecheck # tsc --noEmit
```

## Roadmap

| Version | Additions |
|---|---|
| v0.2 | PII redaction (`ScanResult.sanitized`) |
| v0.3 | Structured audit log (`AegisEvent` stream) |
| v0.4 | Dynamic allowlist from env + hot-reload |
| v1.0 | ≥90% test coverage, npm package on GitHub Packages |
