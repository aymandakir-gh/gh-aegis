/**
 * PII Output guard — LLM02
 * Detects personally identifiable information in LLM responses.
 * Patterns: email, phone, IBAN, API keys, GitHub tokens, codice fiscale.
 *
 * v0.2: adds `sanitized` to every ScanResult — each PII match is replaced
 * with `[REDACTED:<pattern-label>]` so callers can surface safe output.
 * v0.3.1: redaction is position-based with overlap resolution (highest-score
 * pattern wins) so a broad pattern can no longer partially clobber a secret.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";
import { redact, type RedactPattern } from "./redact.js";

export const PII_PATTERNS: RedactPattern[] = [
  // Email addresses
  {
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
    score: 80,
    label: "email-address",
  },
  // US/international phone numbers (3-3-4 groups, optional country code)
  {
    pattern: /(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)/,
    score: 75,
    label: "phone-number",
  },
  // IBAN (2-letter country code + 2 digits + 11–30 alphanumeric)
  {
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/,
    score: 85,
    label: "iban",
  },
  // OpenAI API key (sk-...) and Stripe live/restricted keys
  {
    pattern: /\b(sk-[a-zA-Z0-9]{20,}|sk_live_[a-zA-Z0-9]{20,}|rk_live_[a-zA-Z0-9]{20,})/,
    score: 95,
    label: "openai-stripe-api-key",
  },
  // GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
  {
    pattern: /\bgh[pousr]_[a-zA-Z0-9]{36,}\b/,
    score: 95,
    label: "github-token",
  },
  // Anthropic API key
  {
    pattern: /\bsk-ant-[a-zA-Z0-9-]{20,}\b/,
    score: 95,
    label: "anthropic-api-key",
  },
  // Italian Codice Fiscale (6 letters + 2 digits + letter + 2 digits + letter + 3 digits + letter)
  {
    pattern: /\b[A-Z]{6}[0-9]{2}[A-EHLMPR-T][0-9]{2}[A-Z][0-9]{3}[A-Z]\b/i,
    score: 85,
    label: "codice-fiscale",
  },
  // Generic high-entropy tokens (Bearer tokens, JWT-like strings ≥32 hex chars)
  {
    pattern: /\bBearer\s+[a-zA-Z0-9\-_]{32,}\b/,
    score: 90,
    label: "bearer-token",
  },
];

/**
 * Scan an LLM output string for PII and produce a redacted copy.
 * Redaction is position-based with overlap resolution (see ./redact.ts).
 */
export function scanPiiOutput(
  input: string,
  _context?: ScanContext,
): ScanResult {
  const { labels, maxScore, sanitized, count } = redact(input, PII_PATTERNS);

  // No PII — sanitized equals the original input unchanged.
  if (count === 0) {
    return { safe: true, score: 0, sanitized: input };
  }

  return {
    safe: false,
    threatType: ThreatType.PII_OUTPUT,
    score: maxScore,
    details: [`PII detected in LLM output: ${labels.join(", ")}`],
    sanitized,
  };
}
