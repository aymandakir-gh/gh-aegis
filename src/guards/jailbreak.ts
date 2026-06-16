/**
 * Jailbreak guard — LLM01 variant
 * Detects role-escape, DAN variants, and "no restrictions" bypass attempts.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";

interface JailbreakPattern {
  pattern: RegExp;
  score: number;
  label: string;
}

const JAILBREAK_PATTERNS: JailbreakPattern[] = [
  {
    pattern: /you\s+are\s+now\s+DAN/i,
    score: 95,
    label: "you-are-now-dan",
  },
  {
    pattern: /\bDAN\b.{0,60}(do\s+anything\s+now|no\s+restrictions?|without\s+restrictions?)/i,
    score: 95,
    label: "dan-variant",
  },
  {
    pattern: /do\s+anything\s+now\s+without\s+(limits?|restrictions?|constraints?|rules?)/i,
    score: 90,
    label: "do-anything-now",
  },
  {
    pattern: /\bjailbreak\b/i,
    score: 85,
    label: "explicit-jailbreak-keyword",
  },
  {
    pattern: /\[JAILBREAK\]|\[DAN\]|\[SUDO\]|\[UNRESTRICTED\]/i,
    score: 90,
    label: "jailbreak-tag",
  },
  {
    pattern: /pretend\s+(you\s+)?(are|have\s+no)\s+(an?\s+)?(AI|bot|restrictions?|guidelines?|safety|filter)/i,
    score: 85,
    label: "pretend-no-restrictions",
  },
  {
    pattern: /roleplay\s+as\s+(an?\s+)?(AI|bot|assistant)\s+(with\s+no|without)\s+(restrictions?|limits?|filters?|safety)/i,
    score: 88,
    label: "roleplay-unrestricted",
  },
  {
    pattern: /developer\s+mode\s+(enabled|on|activated)/i,
    score: 85,
    label: "developer-mode-activation",
  },
  {
    pattern: /\bsuperuser\s+mode\b/i,
    score: 80,
    label: "superuser-mode",
  },
  {
    pattern: /bypass\s+(your\s+)?(safety|content\s+policy|guidelines?|filter|moderation)/i,
    score: 90,
    label: "bypass-safety",
  },
  {
    pattern: /act\s+as\s+(if\s+)?(you\s+have\s+)?(no|zero)\s+(restrictions?|limitations?|filters?|guidelines?)/i,
    score: 88,
    label: "act-no-restrictions",
  },
  {
    pattern: /respond\s+(to\s+.{0,30}\s+)?(without|ignoring)\s+(any\s+)?(filters?|restrictions?|safety|moderation)/i,
    score: 85,
    label: "respond-without-filters",
  },
];

export function scanJailbreak(
  input: string,
  _context?: ScanContext,
): ScanResult {
  let maxScore = 0;
  const matched: string[] = [];

  for (const { pattern, score, label } of JAILBREAK_PATTERNS) {
    if (pattern.test(input)) {
      matched.push(label);
      if (score > maxScore) maxScore = score;
    }
  }

  if (maxScore >= 80) {
    return {
      safe: false,
      threatType: ThreatType.JAILBREAK,
      score: maxScore,
      details: [`Jailbreak attempt detected: ${matched.join(", ")}`],
    };
  }

  return { safe: true, score: 0 };
}
