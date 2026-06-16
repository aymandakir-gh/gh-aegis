/**
 * AegisGuard — orchestrator
 * Routes scan calls to the appropriate guard based on scope, in priority order
 * (first finding wins). `inspect()` runs every detector for the CLI.
 * Never throws: all internal errors produce safe=false, score=100 (fail-closed).
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
import {
  scanDataPoisoning,
  stripInvisible,
} from "./guards/data-poisoning.js";
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

class DefaultAegisGuard implements AegisGuard {
  private readonly enabled: boolean;
  private readonly verbose: boolean;
  private readonly maxInputLength: number;
  private readonly defaultAllowedTools: string[];
  private readonly consumptionLimits: ConsumptionLimits;

  constructor(options: AegisOptions = {}) {
    this.enabled = options.enabled ?? process.env["AEGIS_ENABLED"] === "true";
    this.verbose = options.verbose ?? process.env["AEGIS_VERBOSE"] === "true";
    this.maxInputLength =
      options.maxInputLength ??
      Number(process.env["AEGIS_MAX_INPUT"] ?? "8192");
    this.defaultAllowedTools =
      options.allowedTools ??
      (process.env["ALLOWED_TOOLS"]
        ?.split(",")
        .map((t) => t.trim())
        .filter(Boolean) ?? []);
    this.consumptionLimits = {
      maxLength:
        options.maxLength ?? Number(process.env["AEGIS_MAX_LENGTH"] ?? "20000"),
      maxCharRun:
        options.maxCharRun ??
        Number(process.env["AEGIS_MAX_CHAR_RUN"] ?? "800"),
      maxTokenRepeat:
        options.maxTokenRepeat ??
        Number(process.env["AEGIS_MAX_TOKEN_REPEAT"] ?? "200"),
    };
  }

  async scan(input: string, context?: ScanContext): Promise<ScanResult> {
    // Disabled → pass everything through (dev-mode default)
    if (!this.enabled) {
      return { safe: true, score: 0 };
    }

    try {
      // Truncate oversized input before regex evaluation
      const text =
        input.length > this.maxInputLength
          ? input.slice(0, this.maxInputLength)
          : input;

      const scope = context?.scope ?? "input";
      let result: ScanResult;

      switch (scope) {
        case "tool": {
          // Merge instance-level allowedTools as fallback
          const effectiveContext: ScanContext = {
            ...context,
            allowedTools: context?.allowedTools ?? this.defaultAllowedTools,
          };
          const oob = scanToolCallOob(text, effectiveContext);
          result = oob.safe ? scanExcessiveAgency(text, effectiveContext) : oob;
          break;
        }

        case "output": {
          // pii(LLM02) → system-prompt-leak(LLM07) → sensitive-disclosure(LLM06)
          // → improper-output(LLM05) → excessive-agency(LLM08) → poisoning(LLM04).
          // `sanitized` is ALWAYS present for output scope (safe copy of the text).
          const sanitized = sanitizeOutput(text);
          const ordered: ScanResult[] = [
            scanPiiOutput(text, context),
            scanSystemPromptLeak(text, context),
            scanSensitiveDisclosure(text, context),
            scanImproperOutput(text, context),
            scanExcessiveAgency(text, context),
            scanDataPoisoning(text, context),
          ];
          const hit = ordered.find((r) => !r.safe);
          result = hit
            ? { ...hit, sanitized }
            : { safe: true, score: 0, sanitized };
          break;
        }

        case "input":
        default: {
          // Unbounded consumption (LLM10) examines RAW input (pre-truncation).
          const consumption = scanUnboundedConsumption(
            input,
            this.consumptionLimits,
          );
          if (!consumption.safe) {
            result = consumption;
            break;
          }
          // injection(LLM01) → jailbreak(LLM01) → system-prompt-extraction(LLM07)
          // → poisoning(LLM04). First finding wins.
          const ordered: ScanResult[] = [
            scanPromptInjection(text, context),
            scanJailbreak(text, context),
            scanSystemPromptLeak(text, context),
            scanDataPoisoning(text, context),
          ];
          result = ordered.find((r) => !r.safe) ?? { safe: true, score: 0 };
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

      const results: ScanResult[] = [
        scanUnboundedConsumption(input, this.consumptionLimits),
        scanPromptInjection(text),
        scanJailbreak(text),
        scanSystemPromptLeak(text),
        scanDataPoisoning(text),
        scanPiiOutput(text),
        scanSensitiveDisclosure(text),
        scanImproperOutput(text),
        scanExcessiveAgency(text),
      ];

      const findings: Finding[] = results
        .filter((r) => !r.safe)
        .map(toFinding)
        .sort((a, b) => b.score - a.score);

      // Safe copy: strip invisible smuggling chars, then redact PII/secrets/leaks.
      const sanitized = sanitizeOutput(text);

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
