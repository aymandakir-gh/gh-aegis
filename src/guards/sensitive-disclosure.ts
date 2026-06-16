/**
 * Sensitive Disclosure guard — LLM06
 *
 * Detects when model output leaks secrets, credentials, or private keys —
 * categories the PII guard (LLM02) does not cover. Matches are redacted
 * (position-based, shared with the PII guard) so callers can surface a safe
 * `sanitized` copy. System-prompt leakage is handled separately by the LLM07
 * guard (system-prompt-leak.ts).
 *
 * Deliberately disjoint from PII patterns (email/phone/IBAN/sk-…/ghp_…/Bearer) so
 * an output containing those still reports as PII_OUTPUT, not SENSITIVE_DISCLOSURE.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";
import { redact, type RedactPattern } from "./redact.js";

export const DISCLOSURE_PATTERNS: RedactPattern[] = [
  // PEM private key blocks (RSA/EC/OpenSSH/DSA/PGP).
  {
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    score: 98,
    label: "private-key",
  },
  // AWS access key id.
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    score: 97,
    label: "aws-access-key",
  },
  // Google API key.
  {
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    score: 95,
    label: "google-api-key",
  },
  // Slack token.
  {
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    score: 95,
    label: "slack-token",
  },
  // Credentialed connection string (user:pass@host).
  {
    pattern:
      /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|https?):\/\/[^\s:@/]+:[^\s:@/]+@[^\s/]+/,
    score: 92,
    label: "connection-string-credentials",
  },
  // Generic credential assignment: password/secret/api_key/token = <value>.
  {
    pattern:
      /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|aws_secret_access_key)\b\s*[:=]\s*["']?[^\s"']{6,}/i,
    score: 88,
    label: "credential-assignment",
  },
];
// NOTE: system-prompt leakage / persona-echo patterns moved to the dedicated LLM07
// guard (system-prompt-leak.ts). LLM06 is now purely secrets / keys / credentials.

export function scanSensitiveDisclosure(
  input: string,
  _context?: ScanContext,
): ScanResult {
  const { labels, maxScore, sanitized, count } = redact(
    input,
    DISCLOSURE_PATTERNS,
  );

  if (count === 0) {
    return { safe: true, score: 0, sanitized: input };
  }

  return {
    safe: false,
    threatType: ThreatType.SENSITIVE_DISCLOSURE,
    score: maxScore,
    details: [`Sensitive disclosure detected: ${labels.join(", ")}`],
    sanitized,
  };
}
