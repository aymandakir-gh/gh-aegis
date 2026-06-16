/**
 * PromptInjection guard — LLM01
 * Detects attempts to override, replace, or extract system-level instructions.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";

interface InjectionPattern {
  pattern: RegExp;
  score: number;
  label: string;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context|directives?)/i,
    score: 95,
    label: "ignore-previous-instructions",
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    score: 90,
    label: "disregard-instructions",
  },
  {
    pattern: /forget\s+(all\s+)?(previous|prior|above|what\s+i\s+told\s+you)/i,
    score: 85,
    label: "forget-instructions",
  },
  {
    pattern: /\bnew\s+(instructions?|task|directives?|system\s+prompt)\s*:/i,
    score: 80,
    label: "new-instructions-prefix",
  },
  {
    pattern: /\bsystem\s*:\s*\[/i,
    score: 85,
    label: "system-prompt-injection",
  },
  {
    pattern: /reveal\s+(your\s+)?(system\s+prompt|instructions?|training\s+data|internal\s+prompt)/i,
    score: 85,
    label: "reveal-system-prompt",
  },
  {
    pattern: /\boverride\s+(your\s+)?(safety|guidelines?|rules?|restrictions?|instructions?)/i,
    score: 90,
    label: "override-safety",
  },
  {
    pattern: /\byou\s+(are|must|should)\s+now\s+(ignore|bypass|disregard|forget)\s+/i,
    score: 85,
    label: "now-ignore-directive",
  },
  {
    pattern: /<\s*system\s*>/i,
    score: 80,
    label: "xml-system-tag-injection",
  },
  {
    pattern: /print\s+(your\s+)?(full\s+)?(system|initial)\s+(prompt|instructions?)/i,
    score: 85,
    label: "print-system-prompt",
  },
];

export function scanPromptInjection(
  input: string,
  _context?: ScanContext,
): ScanResult {
  let maxScore = 0;
  const matched: string[] = [];

  for (const { pattern, score, label } of INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      matched.push(label);
      if (score > maxScore) maxScore = score;
    }
  }

  if (maxScore >= 80) {
    return {
      safe: false,
      threatType: ThreatType.PROMPT_INJECTION,
      score: maxScore,
      details: [`Prompt injection detected: ${matched.join(", ")}`],
    };
  }

  return { safe: true, score: 0 };
}
