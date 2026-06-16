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

/**
 * ISO 7064 mod-97 IBAN check. Used as a `validate` so the IBAN regex (a loose
 * shape: 2 letters, 2 digits, 11–30 alphanumerics) does not flag look-alike
 * identifiers (tracking numbers, build hashes, SKUs) as PII. A real IBAN passes;
 * a coincidental shape does not. Deterministic, O(n), zero-dep.
 */
export function isValidIban(raw: string): boolean {
  const s = raw.toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const value =
      ch >= "A" && ch <= "Z" ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (let i = 0; i < value.length; i++) {
      remainder = (remainder * 10 + (value.charCodeAt(i) - 48)) % 97;
    }
  }
  return remainder === 1;
}

export const PII_PATTERNS: RedactPattern[] = [
  // Email addresses. Quantifiers are bounded (RFC-ish: local ≤64, ≤8 labels of
  // ≤63, TLD ≤24) and the domain is structured as label-dot groups with no class
  // overlap, so there is no catastrophic backtracking on adversarial input.
  {
    pattern: /[a-zA-Z0-9._%+-]{1,64}@(?:[a-zA-Z0-9-]{1,63}\.){1,8}[a-zA-Z]{2,24}/,
    score: 80,
    label: "email-address",
  },
  // US/international phone numbers (3-3-4 groups, optional country code).
  // Token boundaries (no surrounding alphanumeric) prevent matching a 10-digit
  // run embedded inside a longer secret (e.g. an API key).
  {
    pattern:
      /(?<![A-Za-z0-9])(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?![A-Za-z0-9])/,
    score: 75,
    label: "phone-number",
  },
  // IBAN (2-letter country code + 2 digits + 11–30 alphanumeric), validated by a
  // mod-97 checksum so look-alike identifiers are not flagged as PII.
  {
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/,
    score: 85,
    label: "iban",
    validate: isValidIban,
  },
  // OpenAI API keys (sk-…, incl. the current sk-proj-… project keys) and Stripe
  // live/restricted keys. The OpenAI body allows hyphens/underscores.
  {
    pattern: /\b(sk-(?!ant-)[a-zA-Z0-9_-]{20,}|sk_live_[a-zA-Z0-9]{20,}|rk_live_[a-zA-Z0-9]{20,})/,
    score: 95,
    label: "openai-stripe-api-key",
  },
  // GitHub classic personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
  {
    pattern: /\bgh[pousr]_[a-zA-Z0-9]{36,}\b/,
    score: 95,
    label: "github-token",
  },
  // GitHub fine-grained personal access tokens (github_pat_…)
  {
    pattern: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
    score: 95,
    label: "github-fine-grained-pat",
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
