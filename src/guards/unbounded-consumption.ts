/**
 * Unbounded Consumption guard — LLM10
 *
 * Flags input designed to exhaust resources: oversized payloads, long runs of a
 * single repeated character, a single token repeated many times, or explicit
 * requests for unbounded/“forever” generation.
 *
 * Evaluated against the RAW input (before maxInputLength truncation) so the size
 * signal is not hidden by truncation. Deterministic; O(n) over the input.
 */
import type { ScanResult } from "../types.js";
import { ThreatType } from "../types.js";

export interface ConsumptionLimits {
  /** Max raw input length (chars). Default 20000. */
  maxLength: number;
  /** Max run of a single repeated character. Default 800. */
  maxCharRun: number;
  /** Max repeats of any single whitespace-delimited token. Default 200. */
  maxTokenRepeat: number;
}

export const DEFAULT_CONSUMPTION_LIMITS: ConsumptionLimits = {
  maxLength: 20000,
  maxCharRun: 800,
  maxTokenRepeat: 200,
};

// Explicit "generate without bound" requests.
const UNBOUNDED_REQUEST =
  /\b(?:repeat|print|output|say|generate|write|list|count)\b[^.?!]{0,60}\b(?:forever|indefinitely|infinitely|endlessly|for ?ever|without (?:stopping|end|limit|ceasing)|until (?:you run out|the end of time)|(?:\d[\d,]{3,})\s*(?:times|words|tokens|lines))\b/i;

/** Longest run of a single repeated character. O(n). */
function longestCharRun(s: string): number {
  let max = 0;
  let run = 0;
  let prev = "";
  for (const ch of s) {
    if (ch === prev) {
      run++;
    } else {
      run = 1;
      prev = ch;
    }
    if (run > max) max = run;
  }
  return max;
}

/** Highest repeat count of any single whitespace-delimited token. O(n). */
function maxTokenCount(s: string): number {
  const counts = new Map<string, number>();
  let max = 0;
  for (const tok of s.split(/\s+/)) {
    if (!tok) continue;
    const n = (counts.get(tok) ?? 0) + 1;
    counts.set(tok, n);
    if (n > max) max = n;
  }
  return max;
}

export function scanUnboundedConsumption(
  input: string,
  limits: ConsumptionLimits = DEFAULT_CONSUMPTION_LIMITS,
): ScanResult {
  const signals: string[] = [];
  let score = 0;

  if (input.length > limits.maxLength) {
    signals.push(`length=${input.length}>${limits.maxLength}`);
    score = Math.max(score, 90);
  }

  const charRun = longestCharRun(input);
  if (charRun > limits.maxCharRun) {
    signals.push(`char-run=${charRun}>${limits.maxCharRun}`);
    score = Math.max(score, 88);
  }

  // Token-repeat only matters once there are enough tokens to be abusive.
  const tokenRepeat = maxTokenCount(input);
  if (tokenRepeat > limits.maxTokenRepeat) {
    signals.push(`token-repeat=${tokenRepeat}>${limits.maxTokenRepeat}`);
    score = Math.max(score, 85);
  }

  if (UNBOUNDED_REQUEST.test(input)) {
    signals.push("unbounded-generation-request");
    score = Math.max(score, 85);
  }

  if (score >= 80) {
    return {
      safe: false,
      threatType: ThreatType.UNBOUNDED_CONSUMPTION,
      score,
      details: [`Unbounded consumption: ${signals.join(", ")}`],
    };
  }

  return { safe: true, score: 0 };
}
