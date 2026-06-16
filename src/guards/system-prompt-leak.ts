/**
 * System Prompt Leakage guard — LLM07
 *
 * Two faces of the same OWASP family:
 *   - extraction (scope "input"):  a user trying to make the model dump its own
 *     system prompt / hidden instructions / initial directives.
 *   - leakage    (scope "output"): the model actually revealing those instructions
 *     ("my system prompt is …", "I was instructed to …", verbatim persona echo).
 *
 * These patterns were previously split across the prompt-injection (LLM01) and
 * sensitive-disclosure (LLM06) guards. OWASP 2025 makes system-prompt leakage its
 * own category (LLM07), so they live here. A combined "ignore previous instructions
 * AND reveal your prompt" still trips LLM01 first (it runs before this guard in the
 * input pipeline), so override-style attacks stay attributed to LLM01.
 *
 * The pattern list is exported as RedactPattern[] so the orchestrator can redact a
 * leaked marker in the `sanitized` output copy. Deterministic; zero-ML.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";
import type { RedactPattern } from "./redact.js";

export const SYSTEM_PROMPT_LEAK_PATTERNS: RedactPattern[] = [
  // ── Extraction (input): make the model surface its own instructions ──────────
  // A possessive determiner ("your/its/this") is required so "write a GOOD system
  // prompt" / "a system prompt for a bot" (generic, benign) does not match — only
  // a reference to the model's OWN prompt does.
  {
    pattern:
      /\b(?:reveal|print|show|output|repeat|dump|paste|display|echo|disclose|expose|leak|recite|regurgitate|spit\s+out|tell\s+me|give\s+me)\b[^.?!]{0,40}\b(?:your|its|this)\s+(?:own\s+|full\s+|entire\s+|exact\s+|initial\s+|original\s+|internal\s+|hidden\s+|secret\s+|verbatim\s+|complete\s+|actual\s+|underlying\s+|raw\s+|system\s+)*(?:prompt|instructions?|directives?|preamble)\b/i,
    score: 90,
    label: "system-prompt-extraction",
  },
  // Definite reference to *the system prompt* after an extraction verb.
  {
    pattern:
      /\b(?:reveal|print|show|output|repeat|dump|paste|display|echo|disclose|expose|leak|recite|regurgitate|spit\s+out|tell\s+me|give\s+me)\b[^.?!]{0,40}\bthe\s+(?:own\s+|full\s+|entire\s+|exact\s+|initial\s+|original\s+|internal\s+|hidden\s+|secret\s+|verbatim\s+|complete\s+|actual\s+|underlying\s+|raw\s+)*system\s+(?:prompt|instructions?|message)\b/i,
    score: 88,
    label: "system-prompt-extraction-definite",
  },
  // "your/the system message" — a common synonym for the system prompt. Requires
  // the word "system" so "repeat your message" (benign) does not match.
  {
    pattern:
      /\b(?:reveal|print|show|output|repeat|dump|paste|display|echo|disclose|expose|leak|recite|regurgitate|spit\s+out|tell\s+me|give\s+me)\b[^.?!]{0,40}\b(?:your|its|this|the)\s+(?:full\s+|entire\s+|exact\s+|initial\s+|original\s+|internal\s+|hidden\s+|secret\s+|verbatim\s+)*system\s+message\b/i,
    score: 86,
    label: "system-message-extraction",
  },
  // Question form: "what is your system prompt", "what are your initial instructions".
  {
    pattern:
      /\bwhat\s+(?:is|are|was|were|exactly\s+is)\b[^.?!]{0,30}\byour\s+(?:full\s+|initial\s+|original\s+|system\s+|hidden\s+|secret\s+){0,2}(?:system\s+)?(?:prompt|instructions?|directives?)\b/i,
    score: 85,
    label: "system-prompt-question",
  },
  // "repeat everything above / the text above" — classic prompt-extraction trick.
  {
    pattern:
      /\b(?:repeat|print|output|show|reproduce)\b[^.?!]{0,20}\b(?:everything|all\s+(?:the\s+)?(?:text|words|content)|the\s+text)\b[^.?!]{0,20}\babove\b/i,
    score: 82,
    label: "repeat-text-above",
  },

  // ── Leakage (output): the model actually disclosing its instructions ─────────
  {
    pattern:
      /\b(?:my (?:system )?(?:prompt|instructions?) (?:is|are|were)|here (?:is|are) my (?:system )?(?:prompt|instructions?)|the system prompt (?:is|says)|i (?:was|am) (?:instructed|programmed|told|configured) to|my (?:initial|original) (?:prompt|instructions?))\b/i,
    score: 85,
    label: "system-prompt-leak",
  },
  // Verbatim system-prompt persona echo (classic leak signature).
  {
    pattern:
      /\byou are (?:a|an) [a-z ]{0,40}\bassistant\b[^.]{0,60}\b(?:created|trained|developed|made) by\b/i,
    score: 82,
    label: "system-persona-echo",
  },
];

const BLOCK_THRESHOLD = 80;

export function scanSystemPromptLeak(
  input: string,
  _context?: ScanContext,
): ScanResult {
  let maxScore = 0;
  const matched: string[] = [];

  for (const { pattern, score, label } of SYSTEM_PROMPT_LEAK_PATTERNS) {
    if (pattern.test(input)) {
      matched.push(label);
      if (score > maxScore) maxScore = score;
    }
  }

  if (maxScore >= BLOCK_THRESHOLD) {
    return {
      safe: false,
      threatType: ThreatType.SYSTEM_PROMPT_LEAK,
      score: maxScore,
      details: [`System prompt leakage: ${matched.join(", ")}`],
    };
  }

  return { safe: true, score: 0 };
}
