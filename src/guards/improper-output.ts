/**
 * Improper Output Handling guard — LLM05
 *
 * Flags model OUTPUT that, if passed unsanitized to a downstream interpreter
 * (browser, markdown renderer, template engine, terminal), would execute or
 * exfiltrate: HTML/JS XSS, dangerous URI schemes (javascript:/vbscript:/data:html),
 * embedded frames, server-side template-injection fingerprints, markdown
 * image/link data-exfiltration, and ANSI/terminal escape sequences.
 *
 * Deliberately disjoint from:
 *   - LLM08 excessive-agency — shell / SQL / SSRF *actions* an agent might run.
 *   - LLM06 sensitive-disclosure — secrets / keys / credentials.
 * This guard is about *rendering context confusion*, not commands or secrets.
 *
 * Detection only (the correct response is to BLOCK the output, not pass a partially
 * "sanitized" copy of active content). Deterministic; zero-ML.
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";

interface OutputPattern {
  pattern: RegExp;
  score: number;
  label: string;
}

// ESC (U+001B) then a CSI (`[ … final`) or OSC (`] … BEL|ST`) sequence. The
// leading ESC is required, so ordinary text like "arr[0]" never matches.
// eslint-disable-next-line no-control-regex
const ANSI_ESCAPE = /\u001b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\))/;

const OUTPUT_PATTERNS: OutputPattern[] = [
  // <script> … </script> — the canonical XSS sink.
  {
    pattern: /<\s*script\b[^>]*>/i,
    score: 92,
    label: "script-tag",
  },
  // Inline event handler bound to a call: onerror=alert(…), onload=fetch(…).
  {
    pattern:
      /\bon(?:error|load|click|mouseover|mouseenter|focus|submit|toggle|animationstart|beforeprint|pageshow)\s*=\s*["']?\s*[a-z_$][\w$.]*\s*\(/i,
    score: 88,
    label: "inline-event-handler",
  },
  // javascript:/vbscript: URI carrying code (no space after the colon → not prose).
  {
    pattern: /\b(?:javascript|vbscript):(?=\S)[^\s"'<>]{2,}/i,
    score: 85,
    label: "script-uri-scheme",
  },
  // data:text/html (and base64 html) — renders arbitrary markup.
  {
    pattern: /\bdata:text\/html[;,]/i,
    score: 85,
    label: "data-html-uri",
  },
  // Framed/active embeds.
  {
    pattern: /<\s*(?:iframe|object|embed|svg|math|form)\b[^>]*>/i,
    score: 80,
    label: "active-embed-tag",
  },
  // Server-side template injection — arithmetic probe ({{7*7}}) or engine internals.
  {
    pattern: /\{\{\s*\d+\s*[*]\s*\d+\s*\}\}/,
    score: 84,
    label: "ssti-arithmetic-probe",
  },
  {
    pattern:
      /\{\{[^}]*(?:self|config|request|cycler|joiner|__class__|__mro__|__subclasses__|__globals__|__builtins__)[^}]*\}\}/,
    score: 86,
    label: "ssti-jinja-internals",
  },
  // ${ … } / #{ … } expression injection reaching a dangerous runtime sink.
  {
    pattern:
      /[$#]\{[^}]*(?:Runtime|ProcessBuilder|java\.lang|require\s*\(|process\.|global\.|child_process|__proto__|constructor\s*\.)[^}]*\}/,
    score: 86,
    label: "expression-injection-sink",
  },
  // <% … %> scriptlet (ERB/EJS/JSP) containing code.
  {
    pattern: /<%[=-]?[^%]*\b(?:system|exec|eval|require|import|Runtime|process)\b[^%]*%>/i,
    score: 84,
    label: "scriptlet-injection",
  },
  // Markdown image/link exfiltration: external URL whose query smuggles data out.
  {
    pattern:
      /!?\[[^\]]*\]\(\s*https?:\/\/[^)]*[?&](?:c|q|x|d|data|token|secret|cookie|key|session|payload|exfil|leak|prompt)=/i,
    score: 82,
    label: "markdown-exfil-link",
  },
  // ANSI / OSC terminal escape sequences (log-spoofing, hidden text, link injection).
  {
    pattern: ANSI_ESCAPE,
    score: 80,
    label: "ansi-terminal-escape",
  },
];

const BLOCK_THRESHOLD = 80;

export function scanImproperOutput(
  input: string,
  _context?: ScanContext,
): ScanResult {
  let maxScore = 0;
  const matched: string[] = [];

  for (const { pattern, score, label } of OUTPUT_PATTERNS) {
    if (pattern.test(input)) {
      matched.push(label);
      if (score > maxScore) maxScore = score;
    }
  }

  if (maxScore >= BLOCK_THRESHOLD) {
    return {
      safe: false,
      threatType: ThreatType.IMPROPER_OUTPUT,
      score: maxScore,
      details: [`Improper output handling risk: ${matched.join(", ")}`],
    };
  }

  return { safe: true, score: 0 };
}
