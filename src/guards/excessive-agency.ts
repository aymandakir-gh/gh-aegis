/**
 * Excessive Agency guard — LLM08
 *
 * Flags dangerous actions an over-empowered agent (or its tool arguments / output)
 * might attempt: destructive shell commands, fork bombs, pipe-to-shell installers,
 * disk wipes, privilege escalation, destructive SQL, code-exec sinks, and
 * SSRF / dangerous URLs (cloud metadata, localhost, private ranges, file://).
 *
 * Detection only — returns the highest-scoring match. Complements the allowlist
 * tool-call OOB guard (also LLM08).
 */
import type { ScanContext, ScanResult } from "../types.js";
import { ThreatType } from "../types.js";

interface AgencyPattern {
  pattern: RegExp;
  score: number;
  label: string;
  /** Only evaluate on the "tool" scope (an actual request/command target). */
  toolOnly?: boolean;
}

const AGENCY_PATTERNS: AgencyPattern[] = [
  // rm -rf (or -fr, -rfv, …) against a dangerous root (/, ~, *, $HOME, .). The
  // flag run is a single bounded class with two lookaheads asserting r AND f are
  // present, so there is no catastrophic backtracking on `rm -rrrr…`.
  {
    pattern:
      /\brm\s+-(?=[a-z]{0,9}r)(?=[a-z]{0,9}f)[a-z]{1,10}\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|\*)|\/\s|~|\$HOME|\*|\.\s*$)/i,
    score: 97,
    label: "rm-rf-root",
  },
  // Fork bomb.
  {
    pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    score: 97,
    label: "fork-bomb",
  },
  // curl/wget piped into a shell.
  {
    pattern:
      /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*|perl|node)\b/i,
    score: 95,
    label: "pipe-to-shell",
  },
  // Disk overwrite via dd or writing to a raw block device.
  {
    pattern: /\bdd\s+if=\S+\s+of=\/dev\/(?:sd|hd|nvme|disk|vd)[a-z0-9]*/i,
    score: 96,
    label: "disk-overwrite",
  },
  {
    pattern: /\b(?:mkfs(?:\.\w+)?|fdisk)\s+\/dev\//i,
    score: 94,
    label: "format-disk",
  },
  // Recursive chmod/chown 777 / world-writable on broad paths.
  {
    pattern: /\bchmod\s+(?:-R\s+)?0?777\b/i,
    score: 85,
    label: "chmod-777",
  },
  // Privilege escalation wrapping a destructive command.
  {
    pattern: /\bsudo\s+(?:rm|dd|mkfs|chmod|chown|shutdown|reboot|halt)\b/i,
    score: 88,
    label: "sudo-destructive",
  },
  // Destructive SQL.
  {
    pattern: /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b/i,
    score: 90,
    label: "destructive-sql",
  },
  {
    pattern: /;\s*(?:DROP|DELETE|TRUNCATE|UPDATE)\b/i,
    score: 86,
    label: "sql-injection-chain",
  },
  // Code-exec sinks invoked with a DANGEROUS argument — a quoted command line
  // (string containing a space), a template literal with interpolation, or a
  // concatenation. A bare mention like `eval(userInput)` or `subprocess.run()`
  // in prose / code discussion no longer trips it (that was a major false positive
  // on coding-assistant output), only an actually-weaponized call.
  {
    pattern:
      /\b(?:os\.system|subprocess\.(?:call|run|Popen)|child_process\.(?:exec|execSync|spawn)|eval|exec)\s*\(\s*(?:[a-z]{0,2}["'][^"'\n]*\s[^"'\n]*["']|`[^`\n]*\$\{|[\w$.[\]'"]+\s*\+)/i,
    score: 84,
    label: "code-exec-sink",
  },
  {
    pattern: /\bsubprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True/,
    score: 88,
    label: "subprocess-shell-true",
  },
  // Cloud metadata SSRF (AWS/GCP/Azure 169.254.169.254).
  {
    pattern: /https?:\/\/169\.254\.169\.254\b/,
    score: 95,
    label: "ssrf-cloud-metadata",
  },
  // Localhost / private-range / 0.0.0.0 URLs (SSRF). Tool-scope only: a localhost
  // URL in model OUTPUT prose ("open http://localhost:3000") is a normal dev
  // instruction, not an SSRF action — only a real request target (tool scope) is.
  {
    pattern:
      /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?:[:/]|\b)/i,
    score: 80,
    label: "ssrf-internal-url",
    toolOnly: true,
  },
  // file:// access.
  {
    pattern: /\bfile:\/\/\/?\S+/i,
    score: 82,
    label: "file-url",
  },
];

export function scanExcessiveAgency(
  input: string,
  context?: ScanContext,
): ScanResult {
  let maxScore = 0;
  const matched: string[] = [];

  for (const { pattern, score, label, toolOnly } of AGENCY_PATTERNS) {
    if (toolOnly && context?.scope !== "tool") continue;
    if (pattern.test(input)) {
      matched.push(label);
      if (score > maxScore) maxScore = score;
    }
  }

  if (maxScore >= 80) {
    return {
      safe: false,
      threatType: ThreatType.EXCESSIVE_AGENCY,
      score: maxScore,
      details: [`Dangerous action detected: ${matched.join(", ")}`],
    };
  }

  return { safe: true, score: 0 };
}
