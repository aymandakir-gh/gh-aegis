/**
 * Shared error type for the blocking integrations (AI SDK, LangChain, streaming).
 */
import type { ScanResult } from "./types.js";

/** Thrown when gh-aegis blocks a model input or output. */
export class AegisBlockedError extends Error {
  readonly phase: "input" | "output" | "tool";
  readonly result: ScanResult;
  constructor(phase: "input" | "output" | "tool", result: ScanResult) {
    super(
      `gh-aegis blocked model ${phase}: ${result.threatType ?? "THREAT"} (score ${result.score})`,
    );
    this.name = "AegisBlockedError";
    this.phase = phase;
    this.result = result;
  }
}
