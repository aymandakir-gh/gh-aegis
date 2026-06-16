/**
 * Data & Model Poisoning guard — LLM04
 *
 * Detects the *obfuscation channels* used to smuggle poisoned or injected payloads
 * past a human reviewer and into a prompt, a RAG document, or a fine-tuning corpus:
 *
 *   - Unicode Tags block (U+E0000–U+E007F) — "ASCII smuggling": fully invisible
 *     characters that encode hidden instructions an LLM still reads.
 *   - Bidirectional override / isolate controls (U+202A–U+202E, U+2066–U+2069) —
 *     "Trojan Source" (CVE-2021-42574): reorder displayed text vs. logical text.
 *   - Zero-width characters (ZWSP/ZWNJ/ZWJ/WJ/BOM) used as a hidden channel —
 *     flagged only when embedded *inside* an ASCII word or clustered, so ordinary
 *     emoji ZWJ sequences and a leading BOM do not trip it.
 *
 * Visible text alone can look benign while carrying an invisible payload, so this
 * guard runs on both input and output. The `sanitized` copy (built by the
 * orchestrator) strips these characters entirely rather than tagging them.
 *
 * Deterministic; O(n); zero-ML.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";

// Fully-invisible Unicode Tags block — essentially only ever used to smuggle text.
const TAG_BLOCK = /[\u{E0000}-\u{E007F}]/u;
// Bidi embedding / override / isolate controls (Trojan Source). Plain RTL text uses
// the RLM/LRM *marks* (U+200E/U+200F), which are intentionally NOT in this set.
const BIDI_OVERRIDE = /[\u202A-\u202E\u2066-\u2069]/;
// Zero-width / joiner / BOM characters used as a covert channel.
// eslint-disable-next-line no-misleading-character-class
const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060\uFEFF]/g;
// A zero-width char wedged between two ASCII word characters — the classic
// "hide a payload inside a normal-looking word" steganography signature.
// eslint-disable-next-line no-misleading-character-class
const ZERO_WIDTH_IN_WORD = /[A-Za-z0-9][\u200B\u200C\u200D\u2060\uFEFF][A-Za-z0-9]/;
// Above this many zero-width chars, treat as a covert channel even if not word-internal.
const ZERO_WIDTH_CLUSTER = 4;

export interface PoisoningSignal {
  score: number;
  label: string;
}

/** Pure signal evaluation, shared by the guard and the sanitizer. */
export function evaluatePoisoning(input: string): PoisoningSignal | null {
  if (TAG_BLOCK.test(input)) {
    return { score: 95, label: "unicode-tag-smuggling" };
  }
  if (BIDI_OVERRIDE.test(input)) {
    return { score: 90, label: "bidi-override" };
  }
  if (ZERO_WIDTH_IN_WORD.test(input)) {
    return { score: 85, label: "zero-width-in-word" };
  }
  const zeroWidthCount = (input.match(ZERO_WIDTH) ?? []).length;
  if (zeroWidthCount >= ZERO_WIDTH_CLUSTER) {
    return { score: 82, label: `zero-width-cluster(${zeroWidthCount})` };
  }
  return null;
}

/** Remove every smuggling/obfuscation character so a safe copy can be surfaced. */
export function stripInvisible(input: string): string {
  return input
    .replace(/[\u{E0000}-\u{E007F}]/gu, "")
    .replace(/[\u202A-\u202E\u2066-\u2069]/g, "")
    .replace(ZERO_WIDTH, "");
}

export function scanDataPoisoning(
  input: string,
  _context?: ScanContext,
): ScanResult {
  const signal = evaluatePoisoning(input);
  if (signal) {
    return {
      safe: false,
      threatType: ThreatType.DATA_POISONING,
      score: signal.score,
      details: [`Hidden-payload smuggling detected: ${signal.label}`],
    };
  }
  return { safe: true, score: 0 };
}
