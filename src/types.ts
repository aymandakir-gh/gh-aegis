/**
 * Aegis v0.1 — Type definitions
 * OWASP LLM Top 10 reference: LLM01 (Prompt Injection), LLM02 (Insecure Output),
 * LLM08 (Excessive Agency)
 */

// ─── Threat Type Enum ─────────────────────────────────────────────────────────

export enum ThreatType {
  /** LLM01 — User/system input attempts to hijack agent instructions */
  PROMPT_INJECTION = "PROMPT_INJECTION",

  /** LLM01 variant — Attempts to escape role constraints or safety rules */
  JAILBREAK = "JAILBREAK",

  /** LLM02 — LLM output contains PII (email, phone, IBAN, API key) */
  PII_OUTPUT = "PII_OUTPUT",

  /** LLM08 — Tool call targets a resource outside the session allowlist */
  TOOL_CALL_OOB = "TOOL_CALL_OOB",
}

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
}

// ─── Main Interface ───────────────────────────────────────────────────────────

export interface AegisGuard {
  /**
   * Scan `input` for threats matching the active scope.
   * Never throws — errors produce { safe: false, score: 100 }.
   */
  scan(input: string, context?: ScanContext): Promise<ScanResult>;
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
}
