/**
 * PII Output guard — LLM02
 * Detects personally identifiable information in LLM responses.
 * Patterns: email, phone, IBAN, API keys, GitHub tokens, codice fiscale.
 *
 * v0.2: adds `sanitized` to every ScanResult — each PII match is replaced
 * with `[REDACTED:<pattern-label>]` so callers can surface safe output.
 */
import type { ScanContext, ScanResult } from "../types";
import { ThreatType } from "../types";

interface PiiPattern {
  pattern: RegExp;
  score: number;
  label: string;
}

const PII_PATTERNS: PiiPattern[] = [
  // Email addresses
  {
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,
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
    pattern: /\bsk-ant-[a-zA-Z0-9\-]{20,}\b/,
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
 * Build a global-flag version of a regex for replace-all operations.
 * Preserves existing flags (e.g. 'i') and appends 'g' if missing.
 */
function toGlobal(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  return new RegExp(re.source, flags);
}

export function scanPiiOutput(
  input: string,
  _context?: ScanContext,
): ScanResult {
  let maxScore = 0;
  const matched: string[] = [];
  // sanitized is built up cumulatively — each matched pattern redacts in place
  let sanitized = input;

  for (const { pattern, score, label } of PII_PATTERNS) {
    // Detect against original input (pattern has no 'g' flag — test() is stateless)
    if (pattern.test(input)) {
      matched.push(label);
      if (score > maxScore) maxScore = score;
      // Replace ALL occurrences in the accumulating sanitized string
      sanitized = sanitized.replace(toGlobal(pattern), `[REDACTED:${label}]`);
    }
  }

  if (maxScore >= 75) {
    return {
      safe: false,
      threatType: ThreatType.PII_OUTPUT,
      score: maxScore,
      details: [`PII detected in LLM output: ${matched.join(", ")}`],
      sanitized,
    };
  }

  // No PII — sanitized equals the original input unchanged
  return { safe: true, score: 0, sanitized: input };
}
