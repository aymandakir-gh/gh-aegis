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

interface PiiPattern {
  pattern: RegExp;
  score: number;
  label: string;
}

const PII_PATTERNS: PiiPattern[] = [
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
 * Build a global-flag version of a regex for find-all (exec-loop) operations.
 * Preserves existing flags (e.g. 'i') and appends 'g' if missing.
 */
function toGlobal(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  return new RegExp(re.source, flags);
}

interface PiiMatch {
  start: number;
  end: number;
  label: string;
  score: number;
}

/**
 * Scan an LLM output string for PII and produce a redacted copy.
 *
 * Redaction is **position-based**, not cumulative-replace. Every pattern is
 * matched against the *original* input, all matches are collected with their
 * offsets, and overlaps are resolved by precedence (highest score wins, then
 * longest, then leftmost) before a single left-to-right rebuild.
 *
 * This avoids a class of bugs where a broad pattern (e.g. phone) matches a digit
 * run *inside* a higher-value secret (IBAN, API key) and a naive cumulative
 * `String.replace` then mutates the text so the secret's own pattern no longer
 * matches — leaving the secret only partially redacted. Under-redacting a secret
 * is the exact LLM02 failure this guard exists to prevent.
 */
export function scanPiiOutput(
  input: string,
  _context?: ScanContext,
): ScanResult {
  const matches: PiiMatch[] = [];

  for (const { pattern, score, label } of PII_PATTERNS) {
    const global = toGlobal(pattern);
    let m: RegExpExecArray | null;
    while ((m = global.exec(input)) !== null) {
      // Guard against zero-length matches (none of our patterns can, but be safe).
      if (m[0].length === 0) {
        global.lastIndex++;
        continue;
      }
      matches.push({
        start: m.index,
        end: m.index + m[0].length,
        label,
        score,
      });
    }
  }

  // No PII — sanitized equals the original input unchanged.
  if (matches.length === 0) {
    return { safe: true, score: 0, sanitized: input };
  }

  // Resolve overlaps: prefer higher score, then longer span, then earlier start.
  // Greedily accept matches that do not overlap an already-accepted one.
  matches.sort(
    (a, b) =>
      b.score - a.score ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start,
  );
  const accepted: PiiMatch[] = [];
  for (const cand of matches) {
    const overlaps = accepted.some(
      (a) => cand.start < a.end && a.start < cand.end,
    );
    if (!overlaps) accepted.push(cand);
  }

  // Rebuild the sanitized string left-to-right from the accepted, non-overlapping spans.
  accepted.sort((a, b) => a.start - b.start);
  const labels: string[] = [];
  let maxScore = 0;
  let sanitized = "";
  let cursor = 0;
  for (const a of accepted) {
    sanitized += input.slice(cursor, a.start) + `[REDACTED:${a.label}]`;
    cursor = a.end;
    if (!labels.includes(a.label)) labels.push(a.label);
    if (a.score > maxScore) maxScore = a.score;
  }
  sanitized += input.slice(cursor);

  return {
    safe: false,
    threatType: ThreatType.PII_OUTPUT,
    score: maxScore,
    details: [`PII detected in LLM output: ${labels.join(", ")}`],
    sanitized,
  };
}
