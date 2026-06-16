import type { AegisPolicy } from "./policy.js";

/**
 * Aegis — Type definitions
 * OWASP LLM Top 10 reference (8 families covered):
 *   LLM01 (Prompt Injection), LLM02 (Insecure Output / PII),
 *   LLM04 (Data & Model Poisoning), LLM05 (Improper Output Handling),
 *   LLM06 (Sensitive Information Disclosure), LLM07 (System Prompt Leakage),
 *   LLM08 (Excessive Agency), LLM10 (Unbounded Consumption).
 */

// ─── Threat Type Enum ─────────────────────────────────────────────────────────

export enum ThreatType {
  /** LLM01 — User/system input attempts to hijack agent instructions */
  PROMPT_INJECTION = "PROMPT_INJECTION",

  /** LLM01 variant — Attempts to escape role constraints or safety rules */
  JAILBREAK = "JAILBREAK",

  /** LLM02 — LLM output contains PII (email, phone, IBAN, API key) */
  PII_OUTPUT = "PII_OUTPUT",

  /** LLM04 — Hidden/obfuscated payload smuggled via invisible Unicode, bidi override, or tag chars */
  DATA_POISONING = "DATA_POISONING",

  /** LLM05 — Output carries active content (XSS/HTML, dangerous URI, SSTI, ANSI) that a downstream interpreter would mishandle */
  IMPROPER_OUTPUT = "IMPROPER_OUTPUT",

  /** LLM06 — Output leaks secrets, credentials, or private keys */
  SENSITIVE_DISCLOSURE = "SENSITIVE_DISCLOSURE",

  /** LLM07 — System-prompt extraction attempt (input) or system-prompt leakage (output) */
  SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK",

  /** LLM08 — Tool call targets a resource outside the session allowlist */
  TOOL_CALL_OOB = "TOOL_CALL_OOB",

  /** LLM08 — Dangerous shell/SQL/code-exec/URL action (agent over-reach) */
  EXCESSIVE_AGENCY = "EXCESSIVE_AGENCY",

  /** LLM10 — Input is oversized, highly repetitive, or requests unbounded generation */
  UNBOUNDED_CONSUMPTION = "UNBOUNDED_CONSUMPTION",
}

/** Maps a ThreatType to its OWASP LLM Top 10 entry (id + human name). */
export const OWASP_LLM: Record<ThreatType, { id: string; name: string }> = {
  [ThreatType.PROMPT_INJECTION]: { id: "LLM01", name: "Prompt Injection" },
  [ThreatType.JAILBREAK]: { id: "LLM01", name: "Prompt Injection (Jailbreak)" },
  [ThreatType.PII_OUTPUT]: { id: "LLM02", name: "Insecure Output / PII" },
  [ThreatType.DATA_POISONING]: {
    id: "LLM04",
    name: "Data & Model Poisoning (hidden-payload smuggling)",
  },
  [ThreatType.IMPROPER_OUTPUT]: {
    id: "LLM05",
    name: "Improper Output Handling",
  },
  [ThreatType.SENSITIVE_DISCLOSURE]: {
    id: "LLM06",
    name: "Sensitive Information Disclosure",
  },
  [ThreatType.SYSTEM_PROMPT_LEAK]: {
    id: "LLM07",
    name: "System Prompt Leakage",
  },
  [ThreatType.TOOL_CALL_OOB]: { id: "LLM08", name: "Excessive Agency (tool OOB)" },
  [ThreatType.EXCESSIVE_AGENCY]: { id: "LLM08", name: "Excessive Agency" },
  [ThreatType.UNBOUNDED_CONSUMPTION]: {
    id: "LLM10",
    name: "Unbounded Consumption",
  },
};

// ─── Scan Context ─────────────────────────────────────────────────────────────

export interface ScanContext {
  /**
   * Scope of this scan:
   * - "input"  = pre-LLM check (injection + jailbreak guards active)
   * - "output" = post-LLM check (PII guard active)
   * - "tool"   = tool call check (OOB allowlist guard active)
   * Default: "input"
   */
  scope?: "input" | "output" | "tool";

  /**
   * Allowed tool names for TOOL_CALL_OOB checks.
   * If empty, all tool calls are blocked (fail-closed).
   * Only relevant when scope = "tool".
   */
  allowedTools?: string[];

  /**
   * Session metadata for audit logging.
   * Never include PII — use session ID or hashed user ID only.
   */
  sessionId?: string;
}

// ─── Scan Result ──────────────────────────────────────────────────────────────

export interface ScanResult {
  /** true = safe to proceed; false = block */
  safe: boolean;

  /** Populated only when safe = false. */
  threatType?: ThreatType;

  /**
   * Risk score 0–100.
   * 0 = no risk detected. 80+ = block. 50–79 = flag for review.
   * Always present, even when safe = true.
   */
  score: number;

  /**
   * Human-readable detail lines for logging/debugging.
   * Never echo these back to the end user (information leakage risk).
   */
  details?: string[];

  /**
   * Sanitized version of the scanned string.
   * Populated for scope = "output" (PII and sensitive-disclosure redaction).
   * - Match detected: each match replaced with [REDACTED:<pattern-label>]
   * - No match detected: equals the original (truncated) input unchanged
   * - scope = "input" | "tool": field is absent (undefined)
   *
   * Safe to surface to end-users; original input must remain internal.
   */
  sanitized?: string;
}

// ─── Comprehensive inspection (CLI / multi-detector) ──────────────────────────

/** A single detector hit, annotated with its OWASP LLM Top 10 entry. */
export interface Finding {
  threatType: ThreatType;
  /** OWASP id, e.g. "LLM01". */
  owaspId: string;
  /** OWASP name, e.g. "Prompt Injection". */
  owaspName: string;
  /** Risk score 0–100. */
  score: number;
  /** Human-readable explanation (which rule fired). */
  detail: string;
}

/** Result of running every detector over one string. */
export interface InspectReport {
  /** true = no findings. */
  safe: boolean;
  /** Every detector hit, highest score first. */
  findings: Finding[];
  /** Input with all detected PII/secrets redacted. */
  sanitized: string;
}

// ─── Main Interface ───────────────────────────────────────────────────────────

export interface AegisGuard {
  /**
   * Scan `input` for threats matching the active scope.
   * Never throws — errors produce { safe: false, score: 100 }.
   */
  scan(input: string, context?: ScanContext): Promise<ScanResult>;

  /**
   * Run EVERY detector over `input` and return all findings (no scope routing).
   * Used by the CLI to scan free text/logs. Never throws.
   */
  inspect(input: string, context?: ScanContext): Promise<InspectReport>;
}

// ─── Factory Options ─────────────────────────────────────────────────────────

export interface AegisOptions {
  /**
   * Master on/off switch. Reads AEGIS_ENABLED env var when not set.
   * Default: false (disabled in dev; must be explicitly enabled).
   */
  enabled?: boolean;

  /**
   * Log rule matches to stderr. Reads AEGIS_VERBOSE env var.
   * Default: false.
   */
  verbose?: boolean;

  /**
   * Max input chars before truncation. Reads AEGIS_MAX_INPUT env var.
   * Default: 8192.
   */
  maxInputLength?: number;

  /**
   * Default tool allowlist used when context.allowedTools is not provided.
   * Reads ALLOWED_TOOLS env var (comma-separated).
   */
  allowedTools?: string[];

  /**
   * LLM10 — max raw input length (chars) before flagging unbounded consumption.
   * Evaluated against the original input, before maxInputLength truncation.
   * Reads AEGIS_MAX_LENGTH env var. Default: 20000.
   */
  maxLength?: number;

  /**
   * LLM10 — max run of a single repeated character before flagging.
   * Reads AEGIS_MAX_CHAR_RUN env var. Default: 800.
   */
  maxCharRun?: number;

  /**
   * LLM10 — max number of repeats of any single whitespace-delimited token.
   * Reads AEGIS_MAX_TOKEN_REPEAT env var. Default: 200.
   */
  maxTokenRepeat?: number;

  /**
   * Declarative policy: which detectors run, which scopes are active, per-detector
   * score thresholds, and redaction on/off. Explicit AegisOptions fields take
   * precedence over the policy; the policy takes precedence over env/defaults.
   * Load one from disk with `parsePolicy(JSON.parse(...))`.
   */
  policy?: AegisPolicy;
}
