/**
 * AegisGuard — orchestrator
 * Routes scan calls to the appropriate guard based on scope.
 * Never throws: all internal errors produce safe=false, score=100 (fail-closed).
 */
import type { AegisGuard, AegisOptions, ScanContext, ScanResult } from "./types.js";
import { scanPromptInjection } from "./guards/prompt-injection.js";
import { scanJailbreak } from "./guards/jailbreak.js";
import { scanPiiOutput } from "./guards/pii-output.js";
import { scanToolCallOob } from "./guards/tool-call-oob.js";

const INTERNAL_ERROR_RESULT: ScanResult = {
  safe: false,
  score: 100,
  details: ["AegisInternalError — scan aborted, request blocked as precaution"],
};

class DefaultAegisGuard implements AegisGuard {
  private readonly enabled: boolean;
  private readonly verbose: boolean;
  private readonly maxInputLength: number;
  private readonly defaultAllowedTools: string[];

  constructor(options: AegisOptions = {}) {
    this.enabled =
      options.enabled ?? process.env["AEGIS_ENABLED"] === "true";
    this.verbose =
      options.verbose ?? process.env["AEGIS_VERBOSE"] === "true";
    this.maxInputLength =
      options.maxInputLength ??
      Number(process.env["AEGIS_MAX_INPUT"] ?? "8192");
    this.defaultAllowedTools =
      options.allowedTools ??
      (process.env["ALLOWED_TOOLS"]
        ?.split(",")
        .map((t) => t.trim())
        .filter(Boolean) ?? []);
  }

  async scan(input: string, context?: ScanContext): Promise<ScanResult> {
    // Disabled → pass everything through (dev-mode default)
    if (!this.enabled) {
      return { safe: true, score: 0 };
    }

    try {
      // Truncate oversized input before evaluation
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
            allowedTools:
              context?.allowedTools ?? this.defaultAllowedTools,
          };
          result = scanToolCallOob(text, effectiveContext);
          break;
        }

        case "output": {
          result = scanPiiOutput(text, context);
          break;
        }

        case "input":
        default: {
          // Run injection first; if clean, check jailbreak
          const injResult = scanPromptInjection(text, context);
          result = injResult.safe ? scanJailbreak(text, context) : injResult;
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
