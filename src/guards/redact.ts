/**
 * Shared position-based redaction.
 *
 * Every pattern is matched against the ORIGINAL input, all matches are collected
 * with offsets, overlaps are resolved by precedence (highest score, then longest,
 * then leftmost), and the sanitized string is rebuilt in a single left-to-right
 * pass. This avoids the cumulative-replace bug where a broad pattern partially
 * clobbers a higher-value secret. Used by both the PII (LLM02) and the
 * sensitive-disclosure (LLM06) guards.
 */

export interface RedactPattern {
  pattern: RegExp;
  score: number;
  label: string;
}

interface Match {
  start: number;
  end: number;
  label: string;
  score: number;
}

export interface RedactionResult {
  /** Distinct labels that fired, in left-to-right position order. */
  labels: string[];
  /** Highest score among accepted matches (0 if none). */
  maxScore: number;
  /** Input with every accepted match replaced by `[REDACTED:<label>]`. */
  sanitized: string;
  /** Number of accepted (non-overlapping) redactions. */
  count: number;
}

/** Global-flag clone of a regex for exec-loop find-all; preserves other flags. */
function toGlobal(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  return new RegExp(re.source, flags);
}

export function redact(
  input: string,
  patterns: RedactPattern[],
): RedactionResult {
  const matches: Match[] = [];

  for (const { pattern, score, label } of patterns) {
    const global = toGlobal(pattern);
    let m: RegExpExecArray | null;
    while ((m = global.exec(input)) !== null) {
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

  if (matches.length === 0) {
    return { labels: [], maxScore: 0, sanitized: input, count: 0 };
  }

  // Resolve overlaps: prefer higher score, then longer span, then earlier start.
  matches.sort(
    (a, b) =>
      b.score - a.score ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start,
  );
  const accepted: Match[] = [];
  for (const cand of matches) {
    const overlaps = accepted.some(
      (a) => cand.start < a.end && a.start < cand.end,
    );
    if (!overlaps) accepted.push(cand);
  }

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

  return { labels, maxScore, sanitized, count: accepted.length };
}
