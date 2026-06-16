/**
 * AegisGuard — orchestrator
 * Routes scan calls to the appropriate guard based on scope, in priority order
 * (first finding wins). `inspect()` runs every detector for the CLI.
 * Never throws: all internal errors produce safe=false, score=100 (fail-closed).
 *
 * Policy-aware: a resolved AegisPolicy decides which detectors run, which scopes
 * are active, per-detector score thresholds, and whether output is redacted.
 *
 * OWASP coverage: LLM01, LLM02, LLM04, LLM05, LLM06, LLM07, LLM08, LLM10.
 */
import type {
  AegisGuard,
  AegisOptions,
  Finding,
  InspectReport,
  ScanContext,
  ScanResult,
} from "./types.js";
import { OWASP_LLM, ThreatType } from "./types.js";
import {
  resolvePolicy,
  type DetectorId,
  type ResolvedPolicy,
} from "./policy.js";
import { scanPromptInjection } from "./guards/prompt-injection.js";
import { scanJailbreak } from "./guards/jailbreak.js";
import { scanPiiOutput, PII_PATTERNS } from "./guards/pii-output.js";
import {
  scanSensitiveDisclosure,
  DISCLOSURE_PATTERNS,
} from "./guards/sensitive-disclosure.js";
import {
  scanSystemPromptLeak,
  SYSTEM_PROMPT_LEAK_PATTERNS,
} from "./guards/system-prompt-leak.js";
import { scanImproperOutput } from "./guards/improper-output.js";
import { scanDataPoisoning, stripInvisible } from "./guards/data-poisoning.js";
import { scanExcessiveAgency } from "./guards/excessive-agency.js";
import {
  scanUnboundedConsumption,
  type ConsumptionLimits,
} from "./guards/unbounded-consumption.js";
import { scanToolCallOob } from "./guards/tool-call-oob.js";
import { redact, type RedactPattern } from "./guards/redact.js";

const INTERNAL_ERROR_RESULT: ScanResult = {
  safe: false,
  score: 100,
  details: ["AegisInternalError — scan aborted, request blocked as precaution"],
};

/**
 * Substring-redactable patterns surfaced in the `sanitized` copy. Active-content
 * threats (improper-output / excessive-agency) and invisible-char smuggling are
 * deliberately excluded — those are blocked, not partially "sanitized". Invisible
 * chars are stripped separately via stripInvisible().
 */
const SANITIZE_PATTERNS: RedactPattern[] = [
  ...PII_PATTERNS,
  ...DISCLOSURE_PATTERNS,
  ...SYSTEM_PROMPT_LEAK_PATTERNS,
];

/** Produce a safe copy: strip invisible smuggling chars, then redact secrets/PII. */
function sanitizeOutput(text: string): string {
  return redact(stripInvisible(text), SANITIZE_PATTERNS).sanitized;
}

/** Convert an unsafe ScanResult into an OWASP-annotated Finding. */
function toFinding(r: ScanResult): Finding {
  const threatType = r.threatType ?? ThreatType.PROMPT_INJECTION;
  const meta = OWASP_LLM[threatType];
  return {
    threatType,
    owaspId: meta.id,
    owaspName: meta.name,
    score: r.score,
    detail: r.details?.[0] ?? meta.name,
  };
}

/** A lazily-evaluated detector entry in a scope pipeline. */
type Entry = [id: DetectorId, run: () => ScanResult];

class DefaultAegisGuard implements AegisGuard {
  private readonly enabled: boolean;
  private readonly verbose: boolean;
  private readonly maxInputLength: number;
  private readonly defaultAllowedTools: string[];
  private readonly consumptionLimits: ConsumptionLimits;
  private readonly policy: ResolvedPolicy;

  constructor(options: AegisOptions = {}) {
    const p = options.policy;
    this.policy = resolvePolicy(p);
    // Precedence: explicit option > policy > env > default.
    this.enabled =
      options.enabled ?? p?.enabled ?? process.env["AEGIS_ENABLED"] === "true";
    this.verbose =
      options.verbose ?? p?.verbose ?? process.env["AEGIS_VERBOSE"] === "true";
    this.maxInputLength =
      options.maxInputLength ??
      p?.limits?.maxInputLength ??
      Number(process.env["AEGIS_MAX_INPUT"] ?? "8192");
    this.defaultAllowedTools =
      options.allowedTools ??
      p?.allowedTools ??
      (process.env["ALLOWED_TOOLS"]
        ?.split(",")
        .map((t) => t.trim())
        .filter(Boolean) ?? []);
    this.consumptionLimits = {
      maxLength:
        options.maxLength ??
        p?.limits?.maxLength ??
        Number(process.env["AEGIS_MAX_LENGTH"] ?? "20000"),
      maxCharRun:
        options.maxCharRun ??
        p?.limits?.maxCharRun ??
        Number(process.env["AEGIS_MAX_CHAR_RUN"] ?? "800"),
      maxTokenRepeat:
        options.maxTokenRepeat ??
        p?.limits?.maxTokenRepeat ??
        Number(process.env["AEGIS_MAX_TOKEN_REPEAT"] ?? "200"),
    };
  }

  /** Run a pipeline of detectors, honoring policy (enabled + minScore). First hit wins. */
  private firstHit(entries: Entry[]): ScanResult | undefined {
    for (const [id, run] of entries) {
      if (!this.policy.detectorEnabled(id)) continue;
      const r = run();
      if (r.safe) continue;
      if (r.score < this.policy.detectorMinScore(id)) continue; // below policy threshold
      return r;
    }
    return undefined;
  }

  async scan(input: string, context?: ScanContext): Promise<ScanResult> {
    // Disabled → pass everything through (dev-mode default)
    if (!this.enabled) {
      return { safe: true, score: 0 };
    }

    try {
      const scope = context?.scope ?? "input";

      // A scope switched off by policy passes everything through.
      if (!this.policy.scopeActive(scope)) {
        return scope === "output"
          ? { safe: true, score: 0, sanitized: input }
          : { safe: true, score: 0 };
      }

      // Truncate oversized input before regex evaluation.
      const text =
        input.length > this.maxInputLength
          ? input.slice(0, this.maxInputLength)
          : input;

      let result: ScanResult;

      switch (scope) {
        case "tool": {
          const effectiveContext: ScanContext = {
            ...context,
            allowedTools: context?.allowedTools ?? this.defaultAllowedTools,
          };
          result =
            this.firstHit([
              ["tool-call-oob", () => scanToolCallOob(text, effectiveContext)],
              ["excessive-agency", () => scanExcessiveAgency(text, effectiveContext)],
            ]) ?? { safe: true, score: 0 };
          break;
        }

        case "output": {
          // pii(LLM02) → system-prompt-leak(LLM07) → sensitive-disclosure(LLM06)
          // → improper-output(LLM05) → excessive-agency(LLM08) → poisoning(LLM04).
          const sanitized = this.policy.redaction ? sanitizeOutput(text) : text;
          const hit = this.firstHit([
            ["pii", () => scanPiiOutput(text, context)],
            ["system-prompt-leak", () => scanSystemPromptLeak(text, context)],
            ["sensitive-disclosure", () => scanSensitiveDisclosure(text, context)],
            ["improper-output", () => scanImproperOutput(text, context)],
            ["excessive-agency", () => scanExcessiveAgency(text, context)],
            ["data-poisoning", () => scanDataPoisoning(text, context)],
          ]);
          result = hit
            ? { ...hit, sanitized }
            : { safe: true, score: 0, sanitized };
          break;
        }

        case "input":
        default: {
          // Unbounded consumption (LLM10) examines RAW input (pre-truncation);
          // the rest run on the truncated text. injection(LLM01) → jailbreak(LLM01)
          // → system-prompt-extraction(LLM07) → poisoning(LLM04). First hit wins.
          result =
            this.firstHit([
              ["unbounded-consumption", () => scanUnboundedConsumption(input, this.consumptionLimits)],
              ["prompt-injection", () => scanPromptInjection(text, context)],
              ["jailbreak", () => scanJailbreak(text, context)],
              ["system-prompt-leak", () => scanSystemPromptLeak(text, context)],
              ["data-poisoning", () => scanDataPoisoning(text, context)],
            ]) ?? { safe: true, score: 0 };
          break;
        }
      }

      if (this.verbose && !result.safe) {
        process.stderr.write(
          `[Aegis] BLOCKED scope=${scope} threat=${result.threatType ?? "UNKNOWN"} ` +
            `score=${result.score} session=${context?.sessionId ?? "none"}\n`,
        );
      }

      return result;
    } catch {
      if (this.verbose) {
        process.stderr.write(
          "[Aegis] Internal error during scan — failing closed\n",
        );
      }
      return INTERNAL_ERROR_RESULT;
    }
  }

  async inspect(
    input: string,
    _context?: ScanContext,
  ): Promise<InspectReport> {
    // Disabled → no findings (consistent with scan()).
    if (!this.enabled) {
      return { safe: true, findings: [], sanitized: input };
    }

    try {
      const text =
        input.length > this.maxInputLength
          ? input.slice(0, this.maxInputLength)
          : input;

      // Every detector entry, gated by policy (enabled + minScore).
      const entries: Entry[] = [
        ["unbounded-consumption", () => scanUnboundedConsumption(input, this.consumptionLimits)],
        ["prompt-injection", () => scanPromptInjection(text)],
        ["jailbreak", () => scanJailbreak(text)],
        ["system-prompt-leak", () => scanSystemPromptLeak(text)],
        ["data-poisoning", () => scanDataPoisoning(text)],
        ["pii", () => scanPiiOutput(text)],
        ["sensitive-disclosure", () => scanSensitiveDisclosure(text)],
        ["improper-output", () => scanImproperOutput(text)],
        ["excessive-agency", () => scanExcessiveAgency(text)],
      ];

      const findings: Finding[] = entries
        .filter(([id]) => this.policy.detectorEnabled(id))
        .map(([id, run]) => [id, run()] as const)
        .filter(([id, r]) => !r.safe && r.score >= this.policy.detectorMinScore(id))
        .map(([, r]) => toFinding(r))
        .sort((a, b) => b.score - a.score);

      const sanitized = this.policy.redaction ? sanitizeOutput(text) : text;

      return { safe: findings.length === 0, findings, sanitized };
    } catch {
      return {
        safe: false,
        findings: [
          {
            threatType: ThreatType.PROMPT_INJECTION,
            owaspId: "AEGIS",
            owaspName: "Internal error (failed closed)",
            score: 100,
            detail: "AegisInternalError — inspection aborted",
          },
        ],
        sanitized: input,
      };
    }
  }
}

/**
 * Factory — create a configured AegisGuard instance.
 *
 * @example
 * const aegis = createAegisGuard({ enabled: true });
 * const result = await aegis.scan(userInput, { scope: "input" });
 * if (!result.safe) throw new Error("Blocked: " + result.threatType);
 */
export function createAegisGuard(options?: AegisOptions): AegisGuard {
  return new DefaultAegisGuard(options);
}
