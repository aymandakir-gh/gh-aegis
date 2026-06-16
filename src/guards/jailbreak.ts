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
    // "jailbreak" as a directive against the model — not the bare noun, which is
    // an everyday word (iOS jailbreaking, jailbreak detection, security education).
    pattern:
      /\bjailbreak\s+(?:the\s+|this\s+|your\s+|my\s+|an?\s+)?(?:ai|bot|assistant|model|llm|gpt|chatbot|system|prompt|filters?|guardrails?|safety)\b|\b(?:enable|activate|enter|initiate|trigger|run|perform|do|start)\s+(?:a\s+|the\s+)?jailbreak\b/i,
    score: 85,
    label: "jailbreak-directive",
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
    pattern: /roleplay\s+as\s+(?:an?\s+)?(?:AI|bot|assistant)\s+(?:with\s+no|without)\s+(?:any\s+)?(?:restrictions?|limits?|filters?|safety|guidelines?)/i,
    score: 88,
    label: "roleplay-unrestricted",
  },
  {
    pattern: /\b(?:set\s+aside|disable|turn\s+off|drop|remove|lift|disregard|circumvent)\s+(?:your\s+|all\s+|the\s+|any\s+)?(?:guardrails?|safeguards?|safety(?:\s+(?:filters?|measures?|guidelines?|rules?))?|restrictions?|guidelines?|content\s+filters?|filters?)\b/i,
    score: 88,
    label: "disable-guardrails",
  },
  {
    // "developer mode" only as a jailbreak directive — the bare phrase is normal
    // for Android Developer Options, Chrome unpacked extensions, IDE/CMS settings.
    pattern:
      /\bdeveloper\s+mode\b[^.?!]{0,60}\b(?:no\s+restrictions?|unrestricted|unfiltered|jailbreak|jailbroken|bypass|ignore|do\s+anything|disregard|skip\s+(?:all\s+)?(?:the\s+)?[a-z]*\s*(?:warnings?|filters?|rules?|safety|checks?|restrictions?|guardrails?)|without\s+(?:any\s+)?(?:limits?|restrictions?|filters?|rules?))\b/i,
    score: 85,
    label: "developer-mode-jailbreak",
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
